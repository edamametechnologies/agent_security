#!/usr/bin/env python3
"""
run_live_suite.py - Live/trace-backed benchmark runner.

This suite executes scenario "injections" inside the Lima VM and derives
observations from real EDAMAME Posture telemetry outputs (session traces).

Design goals:
- Non-interactive: runnable in CI-like environments (given a pre-provisioned VM).
- Trace-backed: every decision can be mapped to an artifact file on disk.
"""

from __future__ import annotations

import atexit
import argparse
import dataclasses
import fnmatch
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX hosts
    fcntl = None  # type: ignore[assignment]


REPO_ROOT = Path(__file__).resolve().parents[2]


@dataclasses.dataclass(frozen=True)
class SessionRow:
    raw: str
    timestamp: str
    username: str
    process: str
    protocol: str
    dst_host: str
    dst_ip: str
    dst_port: int
    # L7 enrichment fields (populated from MCP JSON, absent from CLI output)
    last_activity: Optional[str] = None
    l7_parent_process_path: Optional[str] = None
    l7_parent_process_name: Optional[str] = None
    l7_parent_cmd: Optional[tuple[str, ...]] = None
    l7_spawned_from_tmp: Optional[bool] = None
    l7_open_files: Optional[tuple[str, ...]] = None
    l7_process_path: Optional[str] = None


SESSION_LINE_RE = re.compile(
    r"^\[(?P<ts>[^\]]+)\]\s+"
    r"(?P<user>\S+)\s+"
    r"(?P<proc>\S+)\s+-\s+"
    r"(?P<proto>TCP|UDP)\s+"
    r"(?P<src_ip>\d+\.\d+\.\d+\.\d+):(?P<src_port>\d+)\s+->\s+"
    r"(?P<dst_host>\S+)\s+\((?P<dst_ip>[^)]+)\):(?P<dst_port>\d+)\s+"
    r"\((?P<service>[^)]+)\).*"
)


def _run_cmd(
    cmd: list[str],
    *,
    cwd: Optional[Path] = None,
    timeout_seconds: int = 60,
    env: Optional[dict[str, str]] = None,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            env=env,
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        # Do not crash the whole suite on one hung limactl/openclaw invocation.
        # Return a CompletedProcess-like result so callers can record artifacts
        # and continue.
        stdout = e.stdout or ""
        stderr = e.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        stderr = (stderr + "\n" if stderr else "") + f"TIMEOUT: exceeded {timeout_seconds}s\n"
        return subprocess.CompletedProcess(cmd, 124, stdout=stdout, stderr=stderr)


def _run_limactl_shell(vm_name: str, inner_cmd: str, *, timeout_seconds: int = 60) -> subprocess.CompletedProcess[str]:
    # NOTE: inner_cmd is a single argv element passed to bash -lc inside the VM,
    # not a host-side shell string.
    return _run_cmd(
        ["limactl", "shell", vm_name, "--", "bash", "-lc", inner_cmd],
        cwd=REPO_ROOT,
        timeout_seconds=timeout_seconds,
    )


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _read_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except FileNotFoundError:
        return []


class _SuiteRunLock:
    """Host-side lock preventing concurrent live benchmark runs."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._fh: Optional[Any] = None

    def acquire(self, metadata: dict[str, Any]) -> tuple[bool, str]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fh = self.path.open("a+", encoding="utf-8")
        if fcntl is not None:
            try:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                fh.seek(0)
                existing = fh.read().strip()
                fh.close()
                return False, existing
        fh.seek(0)
        fh.truncate()
        fh.write(json.dumps(metadata, indent=2) + "\n")
        fh.flush()
        self._fh = fh
        return True, ""

    def release(self) -> None:
        fh = self._fh
        self._fh = None
        if fh is None:
            return
        try:
            fh.seek(0)
            fh.truncate()
            fh.flush()
        except Exception:
            pass
        if fcntl is not None:
            try:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
        try:
            fh.close()
        except Exception:
            pass


@dataclasses.dataclass(frozen=True)
class _CronJobSnapshot:
    cron_id: str
    name: str


def _sha256_of_files(paths: Iterable[Path]) -> str:
    h = hashlib.sha256()
    for p in sorted(paths, key=lambda x: x.name):
        h.update(p.read_bytes())
        h.update(b"\n")
    return h.hexdigest()


def _git_sha_short() -> str:
    proc = _run_cmd(["git", "rev-parse", "--short", "HEAD"], cwd=REPO_ROOT, timeout_seconds=15)
    if proc.returncode != 0:
        return "unknown"
    return proc.stdout.strip() or "unknown"


def _now_utc_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _format_duration(seconds: Optional[float]) -> str:
    if seconds is None:
        return "n/a"
    s = max(0, int(seconds))
    h, rem = divmod(s, 3600)
    m, s2 = divmod(rem, 60)
    if h > 0:
        return f"{h}h{m:02d}m{s2:02d}s"
    if m > 0:
        return f"{m}m{s2:02d}s"
    return f"{s2}s"


def _load_json_file(path: Path) -> Optional[dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _collect_posture_build_info(vm_name: str) -> dict[str, Any]:
    """
    Return posture runtime identity used to validate resumable state compatibility.
    Keys:
      - binary_path
      - version
      - build_mtime_epoch
      - build_mtime_utc
    """
    inner_cmd = (
        "python3 - <<'PY'\n"
        "import json, shutil, subprocess\n"
        "from pathlib import Path\n"
        "from datetime import datetime, timezone\n"
        "\n"
        "info = {\n"
        "    'binary_path': None,\n"
        "    'version': None,\n"
        "    'build_mtime_epoch': None,\n"
        "    'build_mtime_utc': None,\n"
        "}\n"
        "binary = shutil.which('edamame_posture')\n"
        "if binary:\n"
        "    info['binary_path'] = binary\n"
        "    try:\n"
        "        p = subprocess.run([binary, '--version'], capture_output=True, text=True, timeout=10)\n"
        "        out = (p.stdout or '').strip() or (p.stderr or '').strip()\n"
        "        if out:\n"
        "            info['version'] = out.splitlines()[0].strip()\n"
        "    except Exception:\n"
        "        pass\n"
        "    try:\n"
        "        st = Path(binary).stat()\n"
        "        epoch = int(st.st_mtime)\n"
        "        info['build_mtime_epoch'] = epoch\n"
        "        info['build_mtime_utc'] = datetime.fromtimestamp(epoch, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')\n"
        "    except Exception:\n"
        "        pass\n"
        "print(json.dumps(info))\n"
        "PY\n"
    )
    proc = _run_limactl_shell(vm_name, inner_cmd, timeout_seconds=20)
    payload = (proc.stdout or "").strip().splitlines()
    for line in reversed(payload):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            parsed = json.loads(line)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            continue
    return {
        "binary_path": None,
        "version": None,
        "build_mtime_epoch": None,
        "build_mtime_utc": None,
    }


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _extract_capture_payload(lines: list[str]) -> str:
    """Extract tool output from CAPTURE_* marker-wrapped output.

    Handles cases where CAPTURE_EXIT_CODE= may be appended to the end of
    the payload line without a newline separator.
    """
    start_idx: Optional[int] = None
    end_idx: Optional[int] = None
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith("CAPTURE_START_UTC="):
            start_idx = i + 1
            continue
        if start_idx is not None and s.startswith("CAPTURE_EXIT_CODE="):
            end_idx = i
            break
    if start_idx is None:
        return "\n".join(lines).strip()
    if end_idx is None:
        end_idx = len(lines)
    payload = "\n".join(lines[start_idx:end_idx]).strip()
    # Strip embedded CAPTURE_EXIT_CODE= that got concatenated without a newline.
    marker = "CAPTURE_EXIT_CODE="
    idx = payload.rfind(marker)
    if idx > 0:
        payload = payload[:idx].rstrip()
    return payload


def _extract_marker_value(text: str, prefix: str) -> Optional[str]:
    for raw_line in reversed((text or "").splitlines()):
        line = raw_line.strip()
        if not line.startswith(prefix):
            continue
        value = line[len(prefix) :].strip()
        return value or None
    return None


def _parse_sessions(lines: list[str]) -> list[SessionRow]:
    """
    Parse EDAMAME session outputs into normalized SessionRow records.

    Supports:
    - CLI-style line output (SESSION_LINE_RE)
    - MCP tool output (typically JSON arrays of objects or strings), optionally wrapped
      with CAPTURE_* marker lines produced by this harness.
    """

    out: list[SessionRow] = []

    def _append_from_line(line: str) -> None:
        m = SESSION_LINE_RE.match(line.strip())
        if not m:
            return
        try:
            out.append(
                SessionRow(
                    raw=line.strip(),
                    timestamp=m.group("ts"),
                    username=m.group("user"),
                    process=m.group("proc"),
                    protocol=m.group("proto"),
                    dst_host=m.group("dst_host"),
                    dst_ip=m.group("dst_ip"),
                    dst_port=int(m.group("dst_port")),
                )
            )
        except Exception:
            return

    # 1) Best-effort: parse any CLI-formatted lines present.
    for line in lines:
        _append_from_line(line)

    def _json_load_best_effort(text: str) -> Optional[object]:
        t = (text or "").strip()
        if t == "":
            return None
        # Common case: tool output is itself JSON (array/object).
        try:
            return json.loads(t)
        except Exception:
            pass
        # Fallback: find a JSON blob within mixed stdout/stderr.
        for ch in ("[", "{"):
            idx = t.find(ch)
            if idx <= 0:
                continue
            try:
                return json.loads(t[idx:])
            except Exception:
                continue
        return None

    def _as_session_row_from_dict(obj: dict) -> Optional[SessionRow]:
        # Keep the original top-level object for L7, stats, and other
        # enrichment fields.  Use the nested "session" dict (if present)
        # only for the 5-tuple connection fields.
        top = obj
        conn = obj
        if isinstance(obj.get("session"), dict):
            conn = obj["session"]

        def _pick_str(*keys: str) -> str:
            for k in keys:
                for src in (conn, top):
                    v = src.get(k)
                    if isinstance(v, str) and v.strip():
                        return v.strip()
            return ""

        def _pick_int(*keys: str) -> Optional[int]:
            for k in keys:
                for src in (conn, top):
                    v = src.get(k)
                    if isinstance(v, bool):
                        continue
                    if isinstance(v, int):
                        return v
                    if isinstance(v, float) and v.is_integer():
                        return int(v)
                    if isinstance(v, str) and v.strip().isdigit():
                        try:
                            return int(v.strip())
                        except Exception:
                            continue
            return None

        # Timestamp: prefer ISO strings, but accept epoch seconds/ms.
        # Check both the connection dict and top-level, plus nested stats.
        ts_val = None
        for src in (conn, top):
            for key in ("timestamp", "ts", "timestamp_utc", "observed_at", "time", "seen_at"):
                v = src.get(key)
                if v is not None:
                    ts_val = v
                    break
            if ts_val is not None:
                break
        last_activity = None
        if ts_val is None:
            stats = top.get("stats")
            if isinstance(stats, dict):
                v = stats.get("last_activity")
                if isinstance(v, str) and v.strip():
                    last_activity = v.strip()
                for key in ("start_time", "last_activity", "end_time"):
                    v = stats.get(key)
                    if v is not None:
                        ts_val = v
                        break
        timestamp = ""
        if isinstance(ts_val, str):
            timestamp = ts_val.strip()
        elif isinstance(ts_val, (int, float)) and not isinstance(ts_val, bool):
            secs = float(ts_val) / 1000.0 if float(ts_val) > 1e12 else float(ts_val)
            try:
                timestamp = datetime.fromtimestamp(secs, tz=timezone.utc).isoformat()
            except Exception:
                timestamp = ""

        username = _pick_str("username", "user") or "unknown"

        proc = top.get("process")
        if proc is None:
            proc = top.get("proc")
        if proc is None:
            proc = top.get("process_name") or top.get("comm") or top.get("exe") or top.get("binary")
        # EDAMAME MCP format: process_name lives inside the l7 sub-object.
        if proc is None:
            l7_obj = top.get("l7")
            if isinstance(l7_obj, dict):
                proc = l7_obj.get("process_name") or l7_obj.get("comm")
        if isinstance(proc, dict):
            proc = proc.get("name") or proc.get("comm") or proc.get("exe") or ""
        process = str(proc or "").strip()
        if not process:
            process = _pick_str("process_name", "comm", "exe", "binary", "command")
        if "/" in process:
            process = Path(process).name

        proto = _pick_str("protocol", "proto", "transport")
        protocol = (proto.upper() if proto else "TCP").strip()

        # Destination fields may be top-level or nested.
        dst = None
        for k in ("dst", "destination", "remote", "dest"):
            for src in (conn, top):
                if isinstance(src.get(k), dict):
                    dst = src[k]
                    break
            if dst is not None:
                break

        dst_host = _pick_str("dst_host", "dst_domain", "domain", "host", "hostname")
        dst_ip = _pick_str("dst_ip", "dest_ip", "remote_ip", "ip")
        dst_port = _pick_int("dst_port", "dest_port", "remote_port", "port")

        if isinstance(dst, dict):
            if not dst_host:
                v = dst.get("host") or dst.get("domain") or dst.get("hostname")
                if isinstance(v, str):
                    dst_host = v.strip()
            if not dst_ip:
                v = dst.get("ip") or dst.get("addr") or dst.get("address")
                if isinstance(v, str):
                    dst_ip = v.strip()
            if dst_port is None:
                v = dst.get("port")
                if isinstance(v, int):
                    dst_port = v
                elif isinstance(v, str) and v.strip().isdigit():
                    try:
                        dst_port = int(v.strip())
                    except Exception:
                        dst_port = None

        if not dst_ip and dst_host and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", dst_host):
            dst_ip = dst_host
        if not dst_host:
            dst_host = dst_ip

        if not timestamp or not dst_ip or dst_port is None:
            return None
        if not process:
            process = "unknown"

        # Extract L7 enrichment fields from nested "l7" object.
        l7 = top.get("l7") or {}
        if not isinstance(l7, dict):
            l7 = {}

        l7_parent_process_path = None
        v = l7.get("parent_process_path")
        if isinstance(v, str) and v.strip():
            l7_parent_process_path = v.strip()

        l7_parent_process_name = None
        v = l7.get("parent_process_name")
        if isinstance(v, str) and v.strip():
            l7_parent_process_name = v.strip()

        l7_parent_cmd = None
        v = l7.get("parent_cmd")
        if isinstance(v, list):
            l7_parent_cmd = tuple(str(x) for x in v)

        l7_spawned_from_tmp = None
        v = l7.get("spawned_from_tmp")
        if isinstance(v, bool):
            l7_spawned_from_tmp = v

        l7_open_files = None
        v = l7.get("open_files")
        if isinstance(v, list):
            l7_open_files = tuple(str(x) for x in v)

        l7_process_path = None
        v = l7.get("process_path")
        if isinstance(v, str) and v.strip():
            l7_process_path = v.strip()

        raw = json.dumps(top, separators=(",", ":"), sort_keys=True)
        return SessionRow(
            raw=raw,
            timestamp=timestamp,
            last_activity=last_activity,
            username=username,
            process=process,
            protocol=protocol,
            dst_host=dst_host,
            dst_ip=dst_ip,
            dst_port=int(dst_port),
            l7_parent_process_path=l7_parent_process_path,
            l7_parent_process_name=l7_parent_process_name,
            l7_parent_cmd=l7_parent_cmd,
            l7_spawned_from_tmp=l7_spawned_from_tmp,
            l7_open_files=l7_open_files,
            l7_process_path=l7_process_path,
        )

    # 2) MCP path: parse JSON tool output (wrapped or raw).
    payload = _extract_capture_payload(lines)
    parsed = _json_load_best_effort(payload)
    if parsed is None:
        return out

    # The tool output is typically a JSON array. If it's a dict, try common wrappers.
    if isinstance(parsed, dict):
        # MCP gateway format: {"ok":true,"result":{"content":[{"type":"text","text":"[...]"}]}}
        result = parsed.get("result")
        if isinstance(result, dict):
            rc = result.get("content")
            if isinstance(rc, list) and rc:
                text_val = rc[0].get("text") if isinstance(rc[0], dict) else None
                if isinstance(text_val, str):
                    inner = _json_load_best_effort(text_val)
                    if inner is not None:
                        parsed = inner
        if isinstance(parsed, dict):
            if isinstance(parsed.get("sessions"), list):
                parsed = parsed["sessions"]
            elif isinstance(parsed.get("data"), list):
                parsed = parsed["data"]
            elif isinstance(parsed.get("content"), list):
                parsed = parsed["content"]

    if isinstance(parsed, list):
        for item in parsed:
            if isinstance(item, str):
                _append_from_line(item)
                continue
            if isinstance(item, dict):
                row = _as_session_row_from_dict(item)
                if row is not None:
                    out.append(row)
                continue

    return out


def _parse_ts_utc(ts: str) -> Optional[datetime]:
    # Example: "2026-02-18T02:09:52.172203+00:00"
    try:
        ts = ts.strip()
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _row_activity_dt(row: SessionRow) -> Optional[datetime]:
    candidates: list[datetime] = []
    for raw_ts in (row.timestamp, row.last_activity or ""):
        dt = _parse_ts_utc(raw_ts)
        if dt is not None:
            candidates.append(dt)
    if not candidates:
        return None
    return max(candidates)


def _capture_cmd(vm_name: str, inner_cmd: str, out_path: Path, *, timeout_seconds: int = 60) -> bool:
    proc = _run_limactl_shell(vm_name, inner_cmd, timeout_seconds=timeout_seconds)
    _write_text(out_path, proc.stdout + proc.stderr)
    return proc.returncode == 0


def _capture_openclaw_tool_invoke(
    vm_name: str,
    out_path: Path,
    *,
    tool_name: str,
    tool_args: Optional[dict] = None,
    print_result: bool = True,
    timeout_seconds: int = 60,
) -> bool:
    """Invoke a native OpenClaw tool via the gateway HTTP API.

    This exercises the real user-facing integration path
    (OpenClaw tool -> plugin -> EDAMAME MCP).
    """
    tool_args = tool_args or {}
    tool_args_json = json.dumps(tool_args, separators=(",", ":"))
    print_flag = "1" if print_result else "0"
    request_timeout = max(10, timeout_seconds - 15)
    inner_cmd = (
        'export PATH="$HOME/.npm-global/bin:$PATH"\n'
        f"export TOOL_NAME={shlex.quote(tool_name)}\n"
        f"export TOOL_ARGS_JSON={shlex.quote(tool_args_json)}\n"
        f"export TOOL_PRINT_RESULT={print_flag}\n"
        f"export TOOL_REQUEST_TIMEOUT={request_timeout}\n"
        'echo "CAPTURE_START_UTC=$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)"\n'
        "python3 - <<'PY'\n"
        "import json, os, sys, urllib.error, urllib.request\n"
        "cfg_path=os.path.expanduser('~/.openclaw/openclaw.json')\n"
        "try:\n"
        "  cfg=json.load(open(cfg_path,'r',encoding='utf-8'))\n"
        "except Exception as e:\n"
        "  sys.stderr.write('ERROR: unable to read openclaw config: ' + str(e) + '\\n')\n"
        "  raise SystemExit(2)\n"
        "token=cfg.get('gateway',{}).get('auth',{}).get('token','')\n"
        "if not token:\n"
        "  sys.stderr.write('ERROR: no gateway token in openclaw config\\n')\n"
        "  raise SystemExit(2)\n"
        "tool=os.environ.get('TOOL_NAME','')\n"
        "args=json.loads(os.environ.get('TOOL_ARGS_JSON','{}'))\n"
        "print_result=os.environ.get('TOOL_PRINT_RESULT','1') != '0'\n"
        "timeout=int(os.environ.get('TOOL_REQUEST_TIMEOUT','30'))\n"
        "payload=json.dumps({'tool': tool, 'args': args}).encode('utf-8')\n"
        "req=urllib.request.Request(\n"
        "  'http://127.0.0.1:18789/tools/invoke',\n"
        "  data=payload,\n"
        "  headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'},\n"
        ")\n"
        "try:\n"
        "  with urllib.request.urlopen(req, timeout=timeout) as resp:\n"
        "    body=resp.read().decode('utf-8','replace')\n"
        "    if print_result:\n"
        "      sys.stdout.write(body)\n"
        "      if body and not body.endswith('\\n'):\n"
        "        sys.stdout.write('\\n')\n"
        "except urllib.error.HTTPError as e:\n"
        "  body=''\n"
        "  try:\n"
        "    body=e.read().decode('utf-8','replace')\n"
        "  except Exception:\n"
        "    body=str(e)\n"
        "  sys.stderr.write('GATEWAY_CALL_ERROR: http_' + str(getattr(e,'code','?')) + ': ' + body[:2000] + '\\n')\n"
        "  raise SystemExit(1)\n"
        "except Exception as e:\n"
        "  sys.stderr.write('GATEWAY_CALL_ERROR: ' + str(e) + '\\n')\n"
        "  raise SystemExit(1)\n"
        "PY\n"
        "ec=$?\n"
        'echo "CAPTURE_EXIT_CODE=${ec}"\n'
        'echo "CAPTURE_END_UTC=$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)"\n'
        "exit ${ec}\n"
    )
    return _capture_cmd(vm_name, inner_cmd, out_path, timeout_seconds=timeout_seconds)


def _capture_telemetry(
    vm_name: str,
    out_path: Path,
    *,
    telemetry: str,
    timeout_seconds: int = 45,
) -> bool:
    # EDAMAME provides multiple "views" of network activity:
    # - sessions: all observed connections (highest recall, most noise)
    # - exceptions: non-conforming sessions (whitelist exceptions)
    # - anomalous: sessions EDAMAME scored as anomalous (supporting telemetry label)
    # - blacklisted: sessions to blacklisted destinations (high-confidence label / guardrail signal)
    tool_by_mode = {
        "sessions": "get_sessions",
        "exceptions": "get_exceptions",
        "anomalous": "get_anomalous_sessions",
        "blacklisted": "get_blacklisted_sessions",
    }
    if telemetry not in tool_by_mode:
        raise ValueError(f"Unsupported telemetry mode: {telemetry}")
    return _capture_openclaw_tool_invoke(
        vm_name,
        out_path,
        tool_name=tool_by_mode[telemetry],
        tool_args={},
        timeout_seconds=timeout_seconds,
    )


def _capture_error_is_transient(text: str) -> bool:
    normalized = str(text or "").strip().lower()
    if not normalized:
        return False
    # Authentication/configuration failures are actionable and should surface
    # immediately rather than being retried until timeout.
    if "http_401" in normalized or "no gateway token" in normalized:
        return False
    transient_markers = (
        "connection refused",
        "timed out",
        "temporarily unavailable",
        "temporary failure",
        "remote end closed connection",
        "http_502",
        "http_503",
        "http_504",
    )
    return any(marker in normalized for marker in transient_markers)


def _capture_telemetry_with_retries(
    vm_name: str,
    out_path: Path,
    *,
    telemetry: str,
    timeout_seconds: int = 45,
    max_attempts: int = 3,
    retry_delay_seconds: float = 2.0,
) -> bool:
    max_attempts = max(1, int(max_attempts))
    retry_delay_seconds = max(0.1, float(retry_delay_seconds))

    last_text = ""
    for attempt in range(1, max_attempts + 1):
        if max_attempts == 1:
            attempt_path = out_path
        else:
            attempt_path = out_path.with_name(f"{out_path.stem}.retry{attempt:02d}{out_path.suffix}")
        ok = _capture_telemetry(
            vm_name,
            attempt_path,
            telemetry=telemetry,
            timeout_seconds=timeout_seconds,
        )
        try:
            last_text = attempt_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            last_text = ""

        if ok:
            if attempt_path != out_path:
                _write_text(out_path, last_text)
            return True

        if attempt == max_attempts or not _capture_error_is_transient(last_text):
            if attempt_path != out_path:
                _write_text(out_path, last_text)
            return False

        time.sleep(retry_delay_seconds * attempt)

    if last_text:
        _write_text(out_path, last_text)
    return False


def _rows_matching_target(
    path: Path,
    *,
    evidence_process: str,
    target_ip: str,
    target_port: int,
    watermark: datetime,
) -> list[SessionRow]:
    rows = _parse_sessions(_read_lines(path))
    out: list[SessionRow] = []
    for r in rows:
        if r.process != evidence_process:
            continue
        if r.dst_ip != target_ip:
            continue
        if r.dst_port != target_port:
            continue
        dt = _row_activity_dt(r)
        if dt is None:
            continue
        if dt < watermark:
            continue
        out.append(r)
    return out


def _run_injection(vm_name: str, inject_cmd: str, out_path: Path) -> bool:
    if inject_cmd.strip() == "":
        _write_text(out_path, "SKIP: empty inject_cmd\n")
        return True
    # IMPORTANT:
    # - avoid `set -e` inside the limactl/bash -lc command (some limactl builds
    #   mis-propagate exit codes when `set -e` is enabled).
    # - use newline separators, not `;`, so here-doc based inject_cmds work.
    wrapped = (
        "echo \"INJECT_START_UTC=$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)\"\n"
        + inject_cmd
        + "\n"
        "ec=$?\n"
        "echo \"INJECT_EXIT_CODE=${ec}\"\n"
        "echo \"INJECT_END_UTC=$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)\"\n"
        "exit ${ec}\n"
    )
    proc = _run_limactl_shell(vm_name, wrapped, timeout_seconds=45)
    _write_text(out_path, proc.stdout + proc.stderr)
    return proc.returncode == 0


def _append_result(
    *,
    scenario_path: Path,
    observed_class: str,
    observed_divergence: bool,
    latency_ms: int,
    seed: int,
    runner: str,
    git_sha: str,
    scenario_set_version: str,
    run_id: str,
    mode: str,
    policy: str,
    operator_decision: str,
    undo_result: str,
    results_path: Path,
    trace_dir: Path,
) -> None:
    cmd = [
        str(REPO_ROOT / "tests/benchmark/record_result.sh"),
        "--scenario",
        str(scenario_path),
        "--observed-class",
        observed_class,
        "--observed-divergence",
        "true" if observed_divergence else "false",
        "--latency-ms",
        str(latency_ms),
        "--seed",
        str(seed),
        "--runner",
        runner,
        "--git-sha",
        git_sha,
        "--scenario-set-version",
        scenario_set_version,
        "--run-id",
        run_id,
        "--mode",
        mode,
        "--policy",
        policy,
        "--operator-decision",
        operator_decision,
        "--undo-result",
        undo_result,
        "--output",
        str(results_path),
        "--trace-dir",
        str(trace_dir),
    ]
    proc = _run_cmd(cmd, cwd=REPO_ROOT, timeout_seconds=30)
    if proc.returncode != 0:
        raise RuntimeError(f"record_result.sh failed: {proc.stdout}\n{proc.stderr}")


def _append_unique_str(items: list[str], value: str) -> None:
    item = str(value or "").strip()
    if not item:
        return
    if item not in items:
        items.append(item)


def _scenario_execution_sort_key(item: dict[str, Any]) -> tuple[int, str]:
    """Run benign expectations before attack expectations within a group.

    Mixed groups often share the same tuple and inject command. Executing a
    divergent scenario first can leave short-lived attack telemetry visible long
    enough that the following benign allowlist case waits for CLEAN. Sorting the
    group so CLEAN expectations run first preserves coverage while keeping the
    group latency bounded.
    """

    scenario = item.get("scenario")
    expected_divergence = False
    if isinstance(scenario, dict):
        expected_divergence = bool(scenario.get("expected_divergence"))
    scenario_id = str(item.get("scenario_id") or "").strip()
    return (1 if expected_divergence else 0, scenario_id)


def _should_reuse_prior_run_id(
    *,
    prior_run_id: str,
    resume_reset_reasons: list[str],
    results_exists: bool,
    completed_count: int,
    run_rows_count: int,
) -> bool:
    """Reuse a prior run_id only when the run is genuinely resumable."""

    if not str(prior_run_id or "").strip():
        return False
    if resume_reset_reasons:
        return False
    if results_exists:
        return True
    return completed_count == 0 and run_rows_count == 0


def _normalize_traffic_token(host_or_ip: str, port: int) -> str:
    value = str(host_or_ip or "").strip()
    if not value:
        return ""
    if re.search(r":\d+$", value):
        return value
    return f"{value}:{port}"


def _traffic_tokens_for_row(row: SessionRow) -> list[str]:
    out: list[str] = []
    _append_unique_str(out, _normalize_traffic_token(row.dst_host, row.dst_port))
    if row.dst_ip and row.dst_ip != row.dst_host:
        _append_unique_str(out, _normalize_traffic_token(row.dst_ip, row.dst_port))
    return out


def _process_patterns_for_row(row: SessionRow) -> list[str]:
    out: list[str] = []
    if row.l7_process_path:
        _append_unique_str(out, row.l7_process_path)
    if row.process:
        _append_unique_str(out, f"*/{row.process}")
    return out


SENSITIVE_OPEN_FILE_PATTERNS = (
    "*credentials*",
    "*id_ed25519*",
    "*id_rsa*",
)


def _path_matches_sensitive_open_file_rule(path: str) -> bool:
    normalized = path.strip().replace("\\", "/").lower()
    if not normalized:
        return False
    if "/.ssh/" in normalized or "/.aws/" in normalized:
        return True
    return any(fnmatch.fnmatch(normalized, pattern) for pattern in SENSITIVE_OPEN_FILE_PATTERNS)


def _rows_satisfy_expected_l7_signals(
    rows: list[SessionRow],
    expected_l7_signals: dict[str, Any],
) -> bool:
    if not expected_l7_signals:
        return True

    if bool(expected_l7_signals.get("spawned_from_tmp")) and not any(
        row.l7_spawned_from_tmp is True for row in rows
    ):
        return False

    if bool(expected_l7_signals.get("open_files_contain_sensitive")) and not any(
        row.l7_open_files
        and any(_path_matches_sensitive_open_file_rule(path) for path in row.l7_open_files)
        for row in rows
    ):
        return False

    return True


def _l7_protocols_for_port(port: int) -> list[str]:
    if port == 443:
        return ["https"]
    if port == 80:
        return ["http"]
    return []


def _build_scenario_behavioral_model(
    *,
    scenario_id: str,
    declared_intent: str,
    evidence_process: str,
    target_port: int,
    allowed_processes: list[str],
    allowed_domains: list[str],
    baseline_rows: list[SessionRow],
    evidence_rows: list[SessionRow],
    always_allowed_processes: list[str],
    always_allowed_domains: list[str],
    expected_l7_signals: dict[str, Any],
) -> tuple[str, str]:
    # Backdate the synthetic model slightly so the engine evaluates it
    # immediately instead of waiting through the normal 60s settling delay.
    push_started_at_iso = _now_utc_iso()
    ingested_dt = datetime.now(timezone.utc) - timedelta(seconds=90)
    ingested_at_iso = ingested_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    window_start_iso = (ingested_dt - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    window_end_iso = (ingested_dt + timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ")

    expected_traffic: list[str] = []
    expected_sensitive_files: list[str] = []
    expected_open_files: list[str] = []
    for row in baseline_rows:
        for token in _traffic_tokens_for_row(row):
            _append_unique_str(expected_traffic, token)
        if row.l7_open_files:
            for path in row.l7_open_files:
                _append_unique_str(expected_sensitive_files, path)
                _append_unique_str(expected_open_files, path)

    for domain in always_allowed_domains:
        _append_unique_str(expected_traffic, _normalize_traffic_token(domain, 443))

    observed_traffic: list[str] = []
    observed_hosts: set[str] = set()
    for row in evidence_rows:
        if row.dst_host:
            observed_hosts.add(row.dst_host)
        if row.dst_ip:
            observed_hosts.add(row.dst_ip)
        for token in _traffic_tokens_for_row(row):
            _append_unique_str(observed_traffic, token)

    declared_allowed_traffic: list[str] = []
    for domain in allowed_domains:
        _append_unique_str(
            declared_allowed_traffic,
            _normalize_traffic_token(domain, target_port),
        )
    for token in declared_allowed_traffic:
        _append_unique_str(expected_traffic, token)

    declared_allowed_hosts = {
        token.rsplit(":", 1)[0]
        for token in declared_allowed_traffic
        if ":" in token
    }
    if declared_allowed_hosts and any(host in declared_allowed_hosts for host in observed_hosts if host):
        for token in observed_traffic:
            _append_unique_str(expected_traffic, token)

    expected_process_paths: list[str] = []
    for proc in always_allowed_processes:
        _append_unique_str(expected_process_paths, f"*/{proc}")
    for proc in allowed_processes:
        _append_unique_str(expected_process_paths, f"*/{proc}")
    always_allowed_process_set = {proc for proc in always_allowed_processes if proc}
    evidence_process_allowed = (
        evidence_process in allowed_processes or evidence_process in always_allowed_processes
    )
    if evidence_process_allowed:
        for row in evidence_rows:
            for pattern in _process_patterns_for_row(row):
                _append_unique_str(expected_process_paths, pattern)

    not_expected_traffic: list[str] = []
    if not declared_allowed_hosts:
        for row in evidence_rows:
            if row.process in always_allowed_process_set:
                continue
            for token in _traffic_tokens_for_row(row):
                _append_unique_str(not_expected_traffic, token)
    else:
        for row in evidence_rows:
            if row.process in always_allowed_process_set:
                continue
            if row.dst_host in declared_allowed_hosts or row.dst_ip in declared_allowed_hosts:
                continue
            for token in _traffic_tokens_for_row(row):
                _append_unique_str(not_expected_traffic, token)

    not_expected_process_paths: list[str] = []
    not_expected_parent_paths: list[str] = []
    if not evidence_process_allowed:
        _append_unique_str(not_expected_process_paths, f"*/{evidence_process}")
        for row in evidence_rows:
            for pattern in _process_patterns_for_row(row):
                _append_unique_str(not_expected_process_paths, pattern)

    if bool(expected_l7_signals.get("spawned_from_tmp")):
        _append_unique_str(not_expected_process_paths, "/tmp/*")
        _append_unique_str(not_expected_parent_paths, "/tmp/*")
        for row in evidence_rows:
            if row.l7_parent_process_path:
                _append_unique_str(not_expected_parent_paths, row.l7_parent_process_path)
            if row.l7_parent_cmd:
                for part in row.l7_parent_cmd:
                    if "/tmp/" in str(part):
                        _append_unique_str(not_expected_parent_paths, "/tmp/*")

    not_expected_sensitive_files: list[str] = []
    not_expected_open_files: list[str] = []
    if bool(expected_l7_signals.get("open_files_contain_sensitive")):
        for pattern in ("~/.aws/*", "~/.ssh/*", *SENSITIVE_OPEN_FILE_PATTERNS):
            _append_unique_str(not_expected_sensitive_files, pattern)
            _append_unique_str(not_expected_open_files, pattern)
        for row in evidence_rows:
            if row.l7_open_files:
                for path in row.l7_open_files:
                    _append_unique_str(not_expected_open_files, path)

    model = {
        "window_start": window_start_iso,
        "window_end": window_end_iso,
        "agent_type": "benchmark",
        "agent_instance_id": "live-suite",
        "predictions": [
            {
                "agent_type": "benchmark",
                "agent_instance_id": "live-suite",
                "session_key": scenario_id,
                "action": declared_intent or scenario_id,
                "tools_called": [],
                "expected_traffic": expected_traffic,
                "expected_sensitive_files": expected_sensitive_files,
                "expected_lan_devices": [],
                "expected_local_open_ports": [],
                "expected_process_paths": expected_process_paths,
                "expected_parent_paths": [],
                "expected_open_files": expected_open_files,
                "expected_l7_protocols": _l7_protocols_for_port(target_port),
                "expected_system_config": [],
                "not_expected_traffic": not_expected_traffic,
                "not_expected_sensitive_files": not_expected_sensitive_files,
                "not_expected_lan_devices": [],
                "not_expected_local_open_ports": [],
                "not_expected_process_paths": not_expected_process_paths,
                "not_expected_parent_paths": not_expected_parent_paths,
                "not_expected_open_files": not_expected_open_files,
                "not_expected_l7_protocols": [],
                "not_expected_system_config": [],
            }
        ],
        "version": "benchmark/1.0",
        "hash": "",
        "ingested_at": ingested_at_iso,
    }
    return json.dumps(model, separators=(",", ":")), push_started_at_iso


def _push_behavioral_model_for_scenario(
    vm_name: str,
    *,
    scenario_id: str,
    model_json: str,
    out_path: Path,
    divergence_interval_seconds: int = 1,
) -> tuple[bool, Optional[str]]:
    helper_cmd = (
        "set -euo pipefail\n"
        f"export VM_NAME={shlex.quote(vm_name)}\n"
        f"export TARGET_SESSION_KEY={shlex.quote(str(scenario_id).strip())}\n"
        f"source {shlex.quote(str(REPO_ROOT / 'tests/lib/vm_exec.sh'))}\n"
        f"source {shlex.quote(str(REPO_ROOT / 'tests/lib/mcp_bootstrap.sh'))}\n"
        "ensure_mcp_direct_helper >/dev/null\n"
        "disable_lan_auto_scan >/dev/null\n"
        f"start_divergence_engine false {max(1, int(divergence_interval_seconds))} >/dev/null 2>&1 || true\n"
        "clear_divergence_state >/dev/null 2>&1 || true\n"
        f"push_behavioral_model {shlex.quote(model_json)}\n"
        f"start_divergence_engine true {max(1, int(divergence_interval_seconds))} >/dev/null 2>&1 || true\n"
        "sleep 2\n"
        "stored_model_json=\"$(fetch_behavioral_model)\"\n"
        "printf '%s\\n' \"$stored_model_json\"\n"
        "MODEL_JSON=\"$stored_model_json\" python3 - <<'PY'\n"
        "import json, os\n"
        "raw = os.environ.get('MODEL_JSON', '').strip()\n"
        "target_session_key = str(os.environ.get('TARGET_SESSION_KEY') or '').strip()\n"
        "decoder = json.JSONDecoder()\n"
        "idx = 0\n"
        "objects = []\n"
        "while idx < len(raw):\n"
        "    while idx < len(raw) and raw[idx].isspace():\n"
        "        idx += 1\n"
        "    if idx >= len(raw):\n"
        "        break\n"
        "    obj, end = decoder.raw_decode(raw, idx)\n"
        "    objects.append(obj)\n"
        "    idx = end\n"
        "payload = objects[-1] if objects and isinstance(objects[-1], dict) else {}\n"
        "predictions = payload.get('predictions') if isinstance(payload, dict) else None\n"
        "session_keys = []\n"
        "if isinstance(predictions, list):\n"
        "    for pred in predictions:\n"
        "        if not isinstance(pred, dict):\n"
        "            continue\n"
        "        session_key = str(pred.get('session_key') or '').strip()\n"
        "        if session_key:\n"
        "            session_keys.append(session_key)\n"
        "session_key = ''\n"
        "if target_session_key and target_session_key in session_keys:\n"
        "    session_key = target_session_key\n"
        "elif session_keys:\n"
        "    session_key = session_keys[0]\n"
        "ingested_at = str(payload.get('ingested_at') or '').strip() if isinstance(payload, dict) else ''\n"
        "print(f'MODEL_SESSION_KEY={session_key}')\n"
        "print(f'MODEL_INGESTED_AT={ingested_at}')\n"
        "PY\n"
    )
    proc = _run_cmd(
        ["bash", "-lc", helper_cmd],
        cwd=REPO_ROOT,
        timeout_seconds=180,
    )
    combined = (proc.stdout or "") + (proc.stderr or "")
    _write_text(out_path, combined)
    upsert_reported_success = re.search(r'"success"\s*:\s*true', combined) is not None
    if proc.returncode != 0:
        if upsert_reported_success:
            return _confirm_behavioral_model_for_scenario(
                vm_name,
                scenario_id=scenario_id,
                out_path=out_path,
            )
        return False, None

    stored_session_key = _extract_marker_value(combined, "MODEL_SESSION_KEY=")
    stored_ingested_at = _extract_marker_value(combined, "MODEL_INGESTED_AT=")
    if (
        "predictions" not in combined
        or stored_session_key != str(scenario_id).strip()
        or not stored_ingested_at
    ):
        if upsert_reported_success:
            return _confirm_behavioral_model_for_scenario(
                vm_name,
                scenario_id=scenario_id,
                out_path=out_path,
            )
        return False, None
    return True, stored_ingested_at


def _fetch_stored_behavioral_model_markers(
    vm_name: str,
    *,
    target_session_key: Optional[str] = None,
    timeout_seconds: int = 60,
) -> tuple[bool, Optional[str], Optional[str], str]:
    helper_cmd = (
        "set -euo pipefail\n"
        f"export VM_NAME={shlex.quote(vm_name)}\n"
        f"export TARGET_SESSION_KEY={shlex.quote(str(target_session_key or '').strip())}\n"
        f"source {shlex.quote(str(REPO_ROOT / 'tests/lib/vm_exec.sh'))}\n"
        f"source {shlex.quote(str(REPO_ROOT / 'tests/lib/mcp_bootstrap.sh'))}\n"
        "ensure_mcp_direct_helper >/dev/null\n"
        "stored_model_json=\"$(fetch_behavioral_model)\"\n"
        "printf '%s\\n' \"$stored_model_json\"\n"
        "MODEL_JSON=\"$stored_model_json\" python3 - <<'PY'\n"
        "import json, os\n"
        "raw = os.environ.get('MODEL_JSON', '').strip()\n"
        "target_session_key = str(os.environ.get('TARGET_SESSION_KEY') or '').strip()\n"
        "decoder = json.JSONDecoder()\n"
        "idx = 0\n"
        "objects = []\n"
        "while idx < len(raw):\n"
        "    while idx < len(raw) and raw[idx].isspace():\n"
        "        idx += 1\n"
        "    if idx >= len(raw):\n"
        "        break\n"
        "    obj, end = decoder.raw_decode(raw, idx)\n"
        "    objects.append(obj)\n"
        "    idx = end\n"
        "payload = objects[-1] if objects and isinstance(objects[-1], dict) else {}\n"
        "predictions = payload.get('predictions') if isinstance(payload, dict) else None\n"
        "session_keys = []\n"
        "if isinstance(predictions, list):\n"
        "    for pred in predictions:\n"
        "        if not isinstance(pred, dict):\n"
        "            continue\n"
        "        session_key = str(pred.get('session_key') or '').strip()\n"
        "        if session_key:\n"
        "            session_keys.append(session_key)\n"
        "session_key = ''\n"
        "if target_session_key and target_session_key in session_keys:\n"
        "    session_key = target_session_key\n"
        "elif session_keys:\n"
        "    session_key = session_keys[0]\n"
        "ingested_at = str(payload.get('ingested_at') or '').strip() if isinstance(payload, dict) else ''\n"
        "print(f'MODEL_SESSION_KEY={session_key}')\n"
        "print(f'MODEL_INGESTED_AT={ingested_at}')\n"
        "PY\n"
    )
    proc = _run_cmd(
        ["bash", "-lc", helper_cmd],
        cwd=REPO_ROOT,
        timeout_seconds=timeout_seconds,
    )
    combined = (proc.stdout or "") + (proc.stderr or "")
    stored_session_key = _extract_marker_value(combined, "MODEL_SESSION_KEY=")
    stored_ingested_at = _extract_marker_value(combined, "MODEL_INGESTED_AT=")
    has_predictions = "predictions" in combined
    ok = proc.returncode == 0 and has_predictions
    return ok, stored_session_key, stored_ingested_at, combined


def _confirm_behavioral_model_for_scenario(
    vm_name: str,
    *,
    scenario_id: str,
    out_path: Path,
    timeout_seconds: int = 240,
    poll_interval_seconds: int = 2,
) -> tuple[bool, Optional[str]]:
    deadline = time.time() + timeout_seconds
    target_session_key = str(scenario_id).strip()
    attempt = 0
    confirm_lines = ["MODEL_CONFIRMATION_FALLBACK=started"]

    while time.time() < deadline:
        attempt += 1
        ok, stored_session_key, stored_ingested_at, combined = _fetch_stored_behavioral_model_markers(
            vm_name,
            target_session_key=target_session_key,
            timeout_seconds=60,
        )
        confirm_lines.append(
            f"attempt={attempt} ok={ok} session_key={stored_session_key or ''} ingested_at={stored_ingested_at or ''}"
        )
        if ok and stored_session_key == target_session_key and stored_ingested_at:
            confirm_lines.append("MODEL_CONFIRMATION_FALLBACK=success")
            with out_path.open("a", encoding="utf-8") as f:
                f.write("\n" + "\n".join(confirm_lines) + "\n")
            return True, stored_ingested_at
        if combined.strip():
            last_line = combined.strip().splitlines()[-1]
            confirm_lines.append(f"last_line={last_line[:400]}")
        time.sleep(poll_interval_seconds)

    confirm_lines.append("MODEL_CONFIRMATION_FALLBACK=timeout")
    with out_path.open("a", encoding="utf-8") as f:
        f.write("\n" + "\n".join(confirm_lines) + "\n")
    return False, None


def _kick_score_mcp(vm_name: str, out_path: Path) -> bool:
    # Force a score computation so telemetry queries reflect recent network events.
    return _capture_openclaw_tool_invoke(
        vm_name,
        out_path,
        tool_name="get_score",
        tool_args={},
        print_result=False,
        timeout_seconds=90,
    )


def _enable_fast_cron(vm_name: str, out_path: Path) -> bool:
    """Configure fast 2-minute cron cycles for the extrapolator."""
    inner_cmd = (
        'export PATH="$HOME/.npm-global/bin:$PATH"\n'
        "python3 - <<'PY'\n"
        "import json, os, shutil, subprocess, sys\n"
        "\n"
        "EXTRAP_MSG = (\n"
        "    'Run extrapolation. This message is authoritative; do not read SKILL.md. '\n"
        "    'Read MEMORY.md but use only the ## [extrapolator] State section and ignore any legacy [cortex-extrapolator] or [expected-behavior] sections. '\n"
        "    'Call sessions_list activeMinutes=15, then sessions_history includeTools=true limit=100 for sessions with new activity. '\n"
        "    'Build a V3 upsert_behavioral_model window_json with top-level fields window_start, window_end, agent_type, agent_instance_id, predictions, contributors, version, hash, ingested_at. '\n"
        "    'Each prediction must be an object with agent_type, agent_instance_id, session_key, action, tools_called, expected_traffic, expected_sensitive_files, expected_lan_devices, expected_local_open_ports, expected_process_paths, expected_parent_paths, expected_open_files, expected_l7_protocols, expected_system_config, not_expected_traffic, not_expected_sensitive_files, not_expected_lan_devices, not_expected_local_open_ports, not_expected_process_paths, not_expected_parent_paths, not_expected_open_files, not_expected_l7_protocols, not_expected_system_config. '\n"
        "    'Use agent_type=openclaw, a stable agent_instance_id, contributors=[], version=3.0, hash=\"\", and arrays not objects. '\n"
        "    'After upsert_behavioral_model, call get_behavioral_model and retry until the result is non-null, has predictions, and includes your contributor identity. '\n"
        "    'Update only the ## [extrapolator] State checkpoint in MEMORY.md with last_analysis_ts, cycles_completed, and analyzed_sessions; do not write an [expected-behavior] section. '\n"
        "    'Print EXTRAPOLATOR_DONE: <N> sessions processed, behavioral model upserted only after read-back succeeds.'\n"
        ")\n"
        "\n"
        "def run(args):\n"
        "    r = subprocess.run(args, capture_output=True, text=True, timeout=30)\n"
        "    return r.stdout.strip(), r.returncode\n"
        "\n"
        "def with_model(args, model):\n"
        "    if model:\n"
        "        return args + ['--model', model]\n"
        "    return args\n"
        "\n"
        "primary_model = ''\n"
        "try:\n"
        "    with open(os.path.expanduser('~/.openclaw/openclaw.json'), 'r', encoding='utf-8') as fh:\n"
        "        cfg = json.load(fh)\n"
        "    primary_model = (\n"
        "        (((cfg.get('agents', {}) or {}).get('defaults', {}) or {}).get('model', {}) or {}).get('primary', '')\n"
        "        or ''\n"
        "    ).strip()\n"
        "except Exception:\n"
        "    primary_model = ''\n"
        "\n"
        "FAST_TIMEOUT_SECONDS = '600'\n"
        "if primary_model:\n"
        "    print(f'Using cron model override: {primary_model}')\n"
        "else:\n"
        "    print('WARNING: could not resolve primary model from openclaw.json; leaving cron model unchanged')\n"
        "\n"
        "alias_src = os.path.expanduser('~/.openclaw/skills/edamame-extrapolator')\n"
        "alias_dst = os.path.expanduser('~/.openclaw/skills/edamame-cortex-extrapolator')\n"
        "if os.path.isdir(alias_src):\n"
        "    try:\n"
        "        if os.path.lexists(alias_dst):\n"
        "            if os.path.islink(alias_dst) or os.path.isfile(alias_dst):\n"
        "                os.unlink(alias_dst)\n"
        "        os.makedirs(alias_dst, exist_ok=True)\n"
        "        shutil.copy2(os.path.join(alias_src, 'SKILL.md'), os.path.join(alias_dst, 'SKILL.md'))\n"
        "        clawhub_src = os.path.join(alias_src, 'clawhub.json')\n"
        "        if os.path.isfile(clawhub_src):\n"
        "            shutil.copy2(clawhub_src, os.path.join(alias_dst, 'clawhub.json'))\n"
        "        print('Ensured extrapolator skill compatibility copy')\n"
        "    except Exception as e:\n"
        "        print(f'WARNING: could not ensure extrapolator skill alias: {e}')\n"
        "\n"
        "raw, _ = run(['openclaw', 'cron', 'list', '--json'])\n"
        "jobs = []\n"
        "try:\n"
        "    data = json.loads(raw)\n"
        "    jobs = data.get('jobs', []) if isinstance(data, dict) else []\n"
        "except Exception:\n"
        "    pass\n"
        "\n"
        "extrap_id = None\n"
        "\n"
        "for j in jobs:\n"
        "    name = (j.get('name') or '').lower()\n"
        "    jid = j.get('id', '')\n"
        "    if not jid:\n"
        "        continue\n"
        "    if 'watchdog' in name:\n"
        "        run(['openclaw', 'cron', 'rm', jid])\n"
        "        print(f'Removed cron: {j.get(\"name\")} ({jid})')\n"
        "    elif 'verdict reader' in name or 'detector' in name or 'divergence' in name:\n"
        "        run(['openclaw', 'cron', 'rm', jid])\n"
        "        print(f'Removed legacy cron: {j.get(\"name\")} ({jid})')\n"
        "    elif 'extrapolator' in name:\n"
        "        extrap_id = jid\n"
        "\n"
        "if extrap_id:\n"
        "    print(f'Editing extrapolator {extrap_id} to */2...')\n"
        "    run(with_model(\n"
        "        ['openclaw', 'cron', 'edit', extrap_id,\n"
        "         '--cron', '*/2 * * * *', '--exact', '--enable',\n"
        "         '--message', EXTRAP_MSG,\n"
        "         '--light-context',\n"
        "         '--no-deliver',\n"
        "         '--thinking', 'off',\n"
        "         '--timeout', '600000',\n"
        "         '--timeout-seconds', FAST_TIMEOUT_SECONDS],\n"
        "        primary_model,\n"
        "    ))\n"
        "else:\n"
        "    print('Creating extrapolator cron (*/2)...')\n"
        "    run(with_model(\n"
        "        ['openclaw', 'cron', 'add',\n"
        "         '--name', 'Cortex Extrapolator',\n"
        "         '--cron', '*/2 * * * *', '--exact',\n"
        "         '--session', 'isolated',\n"
        "         '--message', EXTRAP_MSG,\n"
        "         '--light-context',\n"
        "         '--thinking', 'off',\n"
        "         '--no-deliver',\n"
        "         '--timeout', '600000',\n"
        "         '--timeout-seconds', FAST_TIMEOUT_SECONDS],\n"
        "        primary_model,\n"
        "    ))\n"
        "\n"
        "raw2, _ = run(['openclaw', 'cron', 'list', '--json'])\n"
        "try:\n"
        "    data2 = json.loads(raw2)\n"
        "    for j in data2.get('jobs', []):\n"
        "        jid = j.get('id', '')\n"
        "        if jid:\n"
        "            run(['openclaw', 'cron', 'enable', jid])\n"
        "    count = len(data2.get('jobs', []))\n"
        "    print(f'FAST_CRON_ENABLED: {count} jobs active')\n"
        "except Exception as e:\n"
        "    print(f'WARNING: could not verify cron state: {e}')\n"
        "PY\n"
    )
    proc = _run_limactl_shell(vm_name, inner_cmd, timeout_seconds=60)
    _write_text(out_path, proc.stdout + proc.stderr)
    return proc.returncode == 0


def _restore_production_cron(vm_name: str, out_path: Path) -> bool:
    """Restore production cron schedule (*/5)."""
    inner_cmd = (
        'export PATH="$HOME/.npm-global/bin:$PATH"\n'
        "python3 - <<'PY'\n"
        "import json, subprocess\n"
        "\n"
        "def run(args):\n"
        "    r = subprocess.run(args, capture_output=True, text=True, timeout=30)\n"
        "    return r.stdout.strip(), r.returncode\n"
        "\n"
        "raw, _ = run(['openclaw', 'cron', 'list', '--json'])\n"
        "try:\n"
        "    data = json.loads(raw)\n"
        "except Exception:\n"
        "    print('WARNING: could not list cron jobs')\n"
        "    raise SystemExit(0)\n"
        "\n"
        "for j in data.get('jobs', []):\n"
        "    name = (j.get('name') or '').lower()\n"
        "    jid = j.get('id', '')\n"
        "    if not jid:\n"
        "        continue\n"
        "    if 'extrapolator' in name:\n"
        "        run(['openclaw', 'cron', 'edit', jid,\n"
        "             '--cron', '*/5 * * * *', '--exact'])\n"
        "        print('Restored extrapolator to */5')\n"
        "    elif 'verdict reader' in name or 'detector' in name or 'divergence' in name:\n"
        "        run(['openclaw', 'cron', 'rm', jid])\n"
        "        print('Removed legacy verdict reader cron')\n"
        "\n"
        "print('PRODUCTION_CRON_RESTORED')\n"
        "PY\n"
    )
    proc = _run_limactl_shell(vm_name, inner_cmd, timeout_seconds=60)
    _write_text(out_path, proc.stdout + proc.stderr)
    return proc.returncode == 0


def _pause_interfering_background_crons(
    vm_name: str,
    out_path: Path,
) -> tuple[bool, list[_CronJobSnapshot]]:
    """
    Disable enabled OpenClaw cron jobs that can mutate divergence/runtime state
    during a scenario-specific benchmark run.
    """
    inner_cmd = (
        'export PATH="$HOME/.npm-global/bin:$PATH"\n'
        "python3 - <<'PY'\n"
        "import json, subprocess, sys\n"
        "\n"
        "SNIPPETS = ('extrapolator',)\n"
        "\n"
        "def run(args, timeout=30):\n"
        "    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)\n"
        "\n"
        "listed = run(['openclaw', 'cron', 'list', '--json'])\n"
        "if listed.returncode != 0:\n"
        "    if listed.stdout:\n"
        "        sys.stdout.write(listed.stdout)\n"
        "    if listed.stderr:\n"
        "        sys.stderr.write(listed.stderr)\n"
        "    raise SystemExit(listed.returncode)\n"
        "\n"
        "try:\n"
        "    payload = json.loads(listed.stdout or '{}')\n"
        "except Exception as exc:\n"
        "    print(f'CRON_PAUSE_ERROR: invalid cron list payload: {exc}', file=sys.stderr)\n"
        "    raise SystemExit(1)\n"
        "\n"
        "jobs = []\n"
        "for job in payload.get('jobs', []):\n"
        "    if not isinstance(job, dict) or not job.get('enabled'):\n"
        "        continue\n"
        "    cron_id = str(job.get('id') or '').strip()\n"
        "    name = str(job.get('name') or '').strip()\n"
        "    lowered = name.lower()\n"
        "    if cron_id and any(snippet in lowered for snippet in SNIPPETS):\n"
        "        jobs.append({'id': cron_id, 'name': name})\n"
        "\n"
        "for job in jobs:\n"
        "    res = run(['openclaw', 'cron', 'disable', job['id']])\n"
        "    if res.returncode != 0:\n"
        "        print(f\"CRON_PAUSE_ERROR: failed to disable {job['name']} ({job['id']})\", file=sys.stderr)\n"
        "        if res.stdout:\n"
        "            sys.stdout.write(res.stdout)\n"
        "        if res.stderr:\n"
        "            sys.stderr.write(res.stderr)\n"
        "        raise SystemExit(res.returncode)\n"
        "\n"
        "print(json.dumps({'paused_jobs': jobs, 'paused_count': len(jobs)}, indent=2))\n"
        "PY\n"
    )
    proc = _run_limactl_shell(vm_name, inner_cmd, timeout_seconds=60)
    _write_text(out_path, proc.stdout + proc.stderr)
    if proc.returncode != 0:
        return False, []

    try:
        payload = json.loads(proc.stdout or "{}")
    except Exception:
        return False, []

    paused_jobs: list[_CronJobSnapshot] = []
    for job in payload.get("paused_jobs", []):
        if not isinstance(job, dict):
            continue
        cron_id = str(job.get("id") or "").strip()
        name = str(job.get("name") or "").strip()
        if cron_id:
            paused_jobs.append(_CronJobSnapshot(cron_id=cron_id, name=name))
    return True, paused_jobs


def _restore_paused_background_crons(
    vm_name: str,
    paused_jobs: list[_CronJobSnapshot],
    out_path: Path,
) -> bool:
    """Re-enable only the cron jobs that were enabled before the run paused them."""
    if not paused_jobs:
        _write_text(
            out_path,
            json.dumps({"restored_jobs": [], "restored_count": 0}, indent=2) + "\n",
        )
        return True

    jobs_literal = repr([{"id": job.cron_id, "name": job.name} for job in paused_jobs])
    inner_cmd = (
        'export PATH="$HOME/.npm-global/bin:$PATH"\n'
        "python3 - <<'PY'\n"
        "import json, subprocess, sys\n"
        "\n"
        "def run(args, timeout=30):\n"
        "    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)\n"
        "\n"
        f"jobs = {jobs_literal}\n"
        "restored = []\n"
        "for job in jobs:\n"
        "    res = run(['openclaw', 'cron', 'enable', job['id']])\n"
        "    if res.returncode != 0:\n"
        "        print(f\"CRON_RESTORE_ERROR: failed to enable {job['name']} ({job['id']})\", file=sys.stderr)\n"
        "        if res.stdout:\n"
        "            sys.stdout.write(res.stdout)\n"
        "        if res.stderr:\n"
        "            sys.stderr.write(res.stderr)\n"
        "        raise SystemExit(res.returncode)\n"
        "    restored.append(job)\n"
        "\n"
        "print(json.dumps({'restored_jobs': restored, 'restored_count': len(restored)}, indent=2))\n"
        "PY\n"
    )
    proc = _run_limactl_shell(vm_name, inner_cmd, timeout_seconds=60)
    _write_text(out_path, proc.stdout + proc.stderr)
    return proc.returncode == 0


def _prime_behavioral_model(vm_name: str, out_path: Path, *, max_wait_seconds: int = 300) -> bool:
    """
    Force one extrapolator cycle after a fresh engine reset and wait until the
    divergence engine reports at least one behavioral-model contributor.

    This avoids the first benchmark groups racing the cron cadence and
    recording NO_MODEL before the extrapolator republishes its slice.
    """
    log_lines: list[str] = []

    trigger_cmd = (
        'export PATH="$HOME/.npm-global/bin:$PATH"\n'
        "python3 - <<'PY'\n"
        "import json, subprocess, sys\n"
        "\n"
        "def run(args, timeout=180):\n"
        "    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)\n"
        "\n"
        "raw = run(['openclaw', 'cron', 'list', '--json'], timeout=30).stdout\n"
        "try:\n"
        "    payload = json.loads(raw)\n"
        "except Exception:\n"
        "    payload = {}\n"
        "jobs = payload.get('jobs', []) if isinstance(payload, dict) else []\n"
        "extrap_id = ''\n"
        "for job in jobs:\n"
        "    if not isinstance(job, dict):\n"
        "        continue\n"
        "    jid = str(job.get('id') or '').strip()\n"
        "    name = str(job.get('name') or '').strip().lower()\n"
        "    if jid and 'extrapolator' in name:\n"
        "        extrap_id = jid\n"
        "        break\n"
        "if not extrap_id:\n"
        "    print('MODEL_PRIME_ERROR:no_extrapolator_cron')\n"
        "    raise SystemExit(1)\n"
        "\n"
        "res = run(['openclaw', 'cron', 'run', extrap_id], timeout=240)\n"
        "if res.stdout:\n"
        "    sys.stdout.write(res.stdout)\n"
        "if res.stderr:\n"
        "    sys.stderr.write(res.stderr)\n"
        "raise SystemExit(res.returncode)\n"
        "PY\n"
    )
    trigger_proc = _run_limactl_shell(vm_name, trigger_cmd, timeout_seconds=max_wait_seconds + 60)
    if trigger_proc.stdout.strip():
        log_lines.append(trigger_proc.stdout.strip())
    if trigger_proc.stderr.strip():
        log_lines.append(trigger_proc.stderr.strip())

    helper_cmd = (
        "set -euo pipefail\n"
        f"export VM_NAME={shlex.quote(vm_name)}\n"
        f"source {shlex.quote(str(REPO_ROOT / 'tests/lib/vm_exec.sh'))}\n"
        f"source {shlex.quote(str(REPO_ROOT / 'tests/lib/mcp_bootstrap.sh'))}\n"
        "ensure_mcp_direct_helper >/dev/null\n"
        "disable_lan_auto_scan >/dev/null\n"
        "fetch_engine_status\n"
    )

    deadline = time.monotonic() + max_wait_seconds
    while time.monotonic() < deadline:
        proc = _run_cmd(
            ["bash", "-lc", helper_cmd],
            cwd=REPO_ROOT,
            timeout_seconds=60,
        )
        combined = ((proc.stdout or "") + (proc.stderr or "")).strip()
        if combined:
            log_lines.append(combined)

        try:
            status = json.loads(proc.stdout)
        except Exception:
            status = None
        if isinstance(status, dict):
            contributors = int(status.get("contributor_count") or 0)
            if contributors > 0:
                log_lines.append("MODEL_READY")
                _write_text(out_path, "\n".join(log_lines) + "\n")
                return True

        time.sleep(5)

    log_lines.append("MODEL_PRIME_ERROR:timeout_waiting_for_contributor")
    _write_text(out_path, "\n".join(log_lines) + "\n")
    return False


def _read_divergence_verdict(vm_name: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Read the latest internal divergence-engine verdict via MCP.

    Returns (verdict, timestamp, details).
    """
    inner_cmd = (
        'export PATH="$HOME/.npm-global/bin:$PATH"\n'
        "python3 - <<'PY'\n"
        "import json, os, urllib.error, urllib.request\n"
        "from datetime import datetime, timezone\n"
        "\n"
        "def norm_verdict(value):\n"
        "    if not isinstance(value, str):\n"
        "        return None\n"
        "    mapping = {\n"
        "        'Clean': 'CLEAN',\n"
        "        'Divergence': 'DIVERGENCE',\n"
        "        'NoModel': 'NO_MODEL',\n"
        "        'Stale': 'STALE',\n"
        "        'NO_BEHAVIORAL_MODEL': 'NO_MODEL',\n"
        "    }\n"
        "    return mapping.get(value, value.upper())\n"
        "\n"
        "result = {'verdict': None, 'timestamp': None, 'details': None}\n"
        "\n"
        "cfg_path = os.path.expanduser('~/.openclaw/openclaw.json')\n"
        "try:\n"
        "    cfg = json.load(open(cfg_path, 'r', encoding='utf-8'))\n"
        "except Exception:\n"
        "    print(json.dumps(result))\n"
        "    raise SystemExit(0)\n"
        "token = cfg.get('gateway', {}).get('auth', {}).get('token', '')\n"
        "if not token:\n"
        "    print(json.dumps(result))\n"
        "    raise SystemExit(0)\n"
        "\n"
        "req = urllib.request.Request(\n"
        "    'http://127.0.0.1:18789/tools/invoke',\n"
        "    data=json.dumps({'tool': 'get_divergence_verdict', 'args': {}}).encode('utf-8'),\n"
        "    headers={\n"
        "        'Authorization': f'Bearer {token}',\n"
        "        'Content-Type': 'application/json',\n"
        "    },\n"
        ")\n"
        "try:\n"
        "    with urllib.request.urlopen(req, timeout=20) as resp:\n"
        "        body = resp.read().decode('utf-8', 'replace')\n"
        "except urllib.error.HTTPError:\n"
        "    print(json.dumps(result))\n"
        "    raise SystemExit(0)\n"
        "except Exception:\n"
        "    print(json.dumps(result))\n"
        "    raise SystemExit(0)\n"
        "\n"
        "try:\n"
        "    envelope = json.loads(body)\n"
        "except Exception:\n"
        "    print(json.dumps(result))\n"
        "    raise SystemExit(0)\n"
        "\n"
        "tool_text = ''\n"
        "if isinstance(envelope, dict):\n"
        "    content = envelope.get('content') or (envelope.get('result') or {}).get('content')\n"
        "    if isinstance(content, list) and content:\n"
        "        item0 = content[0]\n"
        "        if isinstance(item0, dict):\n"
        "            tool_text = item0.get('text') or ''\n"
        "\n"
        "if not tool_text:\n"
        "    print(json.dumps(result))\n"
        "    raise SystemExit(0)\n"
        "\n"
        "try:\n"
        "    verdict_obj = json.loads(tool_text)\n"
        "except Exception:\n"
        "    print(json.dumps(result))\n"
        "    raise SystemExit(0)\n"
        "\n"
        "if verdict_obj is None:\n"
        "    now_ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')\n"
        "    print(json.dumps({'verdict': 'NO_MODEL', 'timestamp': now_ts, 'details': 'null_verdict_payload'}))\n"
        "    raise SystemExit(0)\n"
        "\n"
        "if isinstance(verdict_obj, dict):\n"
        "    verdict = norm_verdict(verdict_obj.get('verdict'))\n"
        "    timestamp = verdict_obj.get('timestamp')\n"
        "    details = None\n"
        "    evidence = verdict_obj.get('evidence')\n"
        "    if isinstance(evidence, list) and evidence:\n"
        "        first = evidence[0]\n"
        "        if isinstance(first, dict):\n"
        "            desc = first.get('description')\n"
        "            sev = first.get('severity')\n"
        "            if isinstance(desc, str) and desc.strip():\n"
        "                details = desc.strip()\n"
        "            if isinstance(sev, str) and sev.strip() and details:\n"
        "                details = '[' + sev.strip() + '] ' + details\n"
        "    if details is None:\n"
        "        floor = verdict_obj.get('floor_violations', 0)\n"
        "        unexplained = verdict_obj.get('unexplained_observations', 0)\n"
        "        vulnerability_findings = verdict_obj.get('vulnerability_findings', 0)\n"
        "        details = f'floor={floor}, unexplained={unexplained}, vulnerability_findings={vulnerability_findings}'\n"
        "    result = {\n"
        "        'verdict': verdict,\n"
        "        'timestamp': timestamp if isinstance(timestamp, str) and timestamp else None,\n"
        "        'details': details,\n"
        "    }\n"
        "\n"
        "print(json.dumps(result))\n"
        "PY\n"
    )
    proc = _run_limactl_shell(vm_name, inner_cmd, timeout_seconds=30)
    try:
        data = json.loads(proc.stdout.strip().splitlines()[-1])
        return data.get("verdict"), data.get("timestamp"), data.get("details")
    except Exception:
        return None, None, None


def _wait_for_verdict_with_reader(
    read_verdict: Callable[[], tuple[Optional[str], Optional[str], Optional[str]]],
    *,
    expected_verdict: str,
    pre_ts: Optional[str],
    max_wait_seconds: int = 480,
    poll_interval_seconds: int = 20,
    out_path: Path,
    sleep_fn: Callable[[float], None] = time.sleep,
    monotonic_fn: Callable[[], float] = time.monotonic,
) -> tuple[Optional[str], Optional[str], int]:
    """Poll for a divergence verdict newer than ``pre_ts``.

    The runner should prefer the expected verdict if it appears during the
    polling window. A transient opposite verdict can show up first while the
    engine is still converging, so keep polling until the expected verdict
    arrives or the timeout expires. If the expected verdict never appears,
    return the latest observed CLEAN/DIVERGENCE candidate.
    """

    start = monotonic_fn()
    deadline = start + max_wait_seconds
    poll_log_lines: list[str] = []
    latest_candidate: Optional[tuple[str, str, int]] = None
    latest_candidate_dt = None
    expected_verdict = str(expected_verdict or "").strip().upper()
    pre_dt = _parse_ts_utc(pre_ts) if pre_ts else None

    while monotonic_fn() < deadline:
        verdict, ts, details = read_verdict()
        elapsed = int((monotonic_fn() - start) * 1000)
        poll_log_lines.append(
            f"[poll t={elapsed}ms] verdict={verdict} ts={ts} expected={expected_verdict} details={details}"
        )

        if verdict is not None and ts is not None:
            ts_dt = _parse_ts_utc(ts)
            if pre_dt is not None and ts_dt is not None and ts_dt <= pre_dt:
                sleep_fn(poll_interval_seconds)
                continue

            verdict_norm = str(verdict or "").strip().upper()
            if verdict_norm not in {"CLEAN", "DIVERGENCE"}:
                sleep_fn(poll_interval_seconds)
                continue

            if verdict_norm == expected_verdict:
                _write_text(out_path, "\n".join(poll_log_lines) + "\n")
                return verdict_norm, ts, elapsed

            should_store_candidate = latest_candidate is None
            if ts_dt is not None:
                should_store_candidate = (
                    latest_candidate is None
                    or latest_candidate_dt is None
                    or ts_dt > latest_candidate_dt
                )
            elif latest_candidate is None:
                should_store_candidate = True

            if should_store_candidate:
                latest_candidate = (verdict_norm, ts, elapsed)
                latest_candidate_dt = ts_dt
                poll_log_lines.append(
                    f"[candidate t={elapsed}ms] verdict={verdict_norm} ts={ts} details={details}"
                )

        sleep_fn(poll_interval_seconds)

    elapsed = int((monotonic_fn() - start) * 1000)
    if latest_candidate is not None:
        latest_verdict, latest_ts, latest_elapsed = latest_candidate
        poll_log_lines.append(
            f"[timeout returning_latest] verdict={latest_verdict} ts={latest_ts} elapsed={elapsed}ms"
        )
        _write_text(out_path, "\n".join(poll_log_lines) + "\n")
        return latest_verdict, latest_ts, latest_elapsed

    poll_log_lines.append(f"[timeout] max_wait={max_wait_seconds}s elapsed={elapsed}ms")
    _write_text(out_path, "\n".join(poll_log_lines) + "\n")
    return None, None, elapsed


def _wait_for_verdict(
    vm_name: str,
    *,
    expected_verdict: str,
    pre_ts: Optional[str],
    max_wait_seconds: int = 480,
    poll_interval_seconds: int = 20,
    out_path: Path,
) -> tuple[Optional[str], Optional[str], int]:
    """Poll for a divergence-engine verdict newer than pre_ts.

    Returns (verdict, timestamp, elapsed_ms).
    """

    return _wait_for_verdict_with_reader(
        lambda: _read_divergence_verdict(vm_name),
        expected_verdict=expected_verdict,
        pre_ts=pre_ts,
        max_wait_seconds=max_wait_seconds,
        poll_interval_seconds=poll_interval_seconds,
        out_path=out_path,
    )


def _ensure_services_started(*, strict_proof: bool) -> tuple[bool, str]:
    start_env = dict(os.environ)
    start_env["STRICT_PROOF"] = "true" if strict_proof else "false"
    proc = _run_cmd(
        [str(REPO_ROOT / "setup/start.sh")],
        cwd=REPO_ROOT,
        timeout_seconds=180,
        env=start_env,
    )
    output = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode == 0, output


def _reset_divergence_runtime_state(vm_name: str, *, interval_seconds: int = 30) -> tuple[bool, str]:
    """
    Clear benchmark-contaminating divergence state before starting a fresh run.

    Prior focused tests may leave behind a behavioral model with a far-future
    timestamp or a stale verdict. The live benchmark should always start from a
    clean engine/model surface unless it is explicitly resuming a compatible run.
    """
    helper_cmd = (
        "set -euo pipefail\n"
        f"export VM_NAME={shlex.quote(vm_name)}\n"
        f"source {shlex.quote(str(REPO_ROOT / 'tests/lib/vm_exec.sh'))}\n"
        f"source {shlex.quote(str(REPO_ROOT / 'tests/lib/mcp_bootstrap.sh'))}\n"
        "ensure_mcp_direct_helper >/dev/null\n"
        "disable_lan_auto_scan >/dev/null\n"
        f"start_divergence_engine false {max(1, int(interval_seconds))} >/dev/null 2>&1 || true\n"
        "clear_divergence_state >/dev/null 2>&1 || true\n"
        "vm_exec \"python3 - <<'PY'\n"
        "from pathlib import Path\n"
        "import re\n"
        "p = Path.home() / '.openclaw' / 'workspace' / 'MEMORY.md'\n"
        "text = p.read_text(encoding='utf-8') if p.exists() else ''\n"
        "patterns = [\n"
        "    r'(?ms)^## \\[(?:cortex-extrapolator|extrapolator)\\] State\\n.*?(?=^## |\\Z)',\n"
        "    r'(?ms)^## \\[expected-behavior\\]\\n.*?(?=^## |\\Z)',\n"
        "]\n"
        "for pattern in patterns:\n"
        "    text = re.sub(pattern, '', text)\n"
        "text = text.strip()\n"
        "prefix = '## [extrapolator] State\\nlast_analysis_ts: 0\\ncycles_completed: 0\\nanalyzed_sessions: {}\\n'\n"
        "if text:\n"
        "    text = prefix + '\\n' + text + '\\n'\n"
        "else:\n"
        "    text = prefix + '\\n'\n"
        "p.parent.mkdir(parents=True, exist_ok=True)\n"
        "p.write_text(text, encoding='utf-8')\n"
        "PY\" >/dev/null\n"
        f"start_divergence_engine true {max(1, int(interval_seconds))} >/dev/null\n"
        "fetch_engine_status\n"
    )
    proc = _run_cmd(
        ["bash", "-lc", helper_cmd],
        cwd=REPO_ROOT,
        timeout_seconds=180,
    )
    output = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode == 0, output


def _summarize_results(results_path: Path, summary_path: Path) -> None:
    proc = _run_cmd(
        [str(REPO_ROOT / "tests/benchmark/summarize_results.sh"), "--input", str(results_path), "--output", str(summary_path)],
        cwd=REPO_ROOT,
        timeout_seconds=60,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"summarize_results.sh failed: {proc.stdout}\n{proc.stderr}")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vm-name", default=os.environ.get("VM_NAME", "agent-security"))
    ap.add_argument(
        "--telemetry",
        choices=["sessions", "exceptions", "anomalous", "blacklisted"],
        default=os.environ.get("LIVE_TELEMETRY", "sessions"),
        help="Telemetry view to poll for injected evidence; anomalous/blacklisted remain supporting labels, not standalone intent divergence.",
    )
    ap.add_argument(
        "--strict-proof",
        action="store_true",
        default=os.environ.get("STRICT_PROOF", "false").strip().lower() in ("1", "true", "yes", "on"),
        help=(
            "Enable strict proof mode: fail fast on service bootstrap issues and require "
            "all planned runs to produce valid (non-skipped) benchmark rows."
        ),
    )
    ap.add_argument(
        "--no-strict-proof",
        action="store_true",
        default=False,
        help="Disable strict proof mode even if STRICT_PROOF=true in the environment.",
    )
    ap.add_argument("--kick-score", action="store_true", default=False)
    ap.add_argument("--no-kick-score", action="store_true", default=False)
    ap.add_argument("--scenario-dir", default=str(REPO_ROOT / "tests/benchmark/live-scenarios"))
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--iterations", type=int, default=25)
    ap.add_argument("--results", default=str(REPO_ROOT / "artifacts/benchmark-results.ndjson"))
    ap.add_argument("--summary", default=str(REPO_ROOT / "artifacts/benchmark-summary.json"))
    ap.add_argument("--manifest", default=str(REPO_ROOT / "artifacts/run-manifest.json"))
    ap.add_argument("--trace-root", default=str(REPO_ROOT / "artifacts/live-traces"))
    ap.add_argument(
        "--resume-state",
        default=os.environ.get("LIVE_RESUME_STATE", ""),
        help="Optional path to resumable benchmark state JSON (default: <results>.state.json).",
    )
    ap.add_argument(
        "--no-resume",
        action="store_true",
        default=False,
        help="Disable resume support and always start a fresh run.",
    )
    ap.add_argument("--track-overhead", action="store_true", default=False,
                    help="Capture CPU/memory overhead before and after each injection.")
    ap.add_argument("--ensure-services", action="store_true", default=True)
    ap.add_argument("--no-ensure-services", action="store_true", default=False)
    ap.add_argument("--capture-signals", action="store_true", default=True)
    ap.add_argument("--no-capture-signals", action="store_true", default=False)
    ap.add_argument(
        "--detection-mode",
        choices=["cron"],
        default="cron",
        help="Detection mode. Cron is the only supported mode and waits for divergence-engine verdicts.",
    )
    ap.add_argument(
        "--timestamp-skew-seconds",
        type=int,
        default=2,
        help="Allow small VM clock skew when matching telemetry timestamps to inject start time.",
    )
    ap.add_argument(
        "--verbose-progress",
        action="store_true",
        default=_env_bool("LIVE_VERBOSE_PROGRESS", False),
        help="Print per-iteration/group/scenario progress while the suite is running.",
    )
    ap.add_argument(
        "--no-verbose-progress",
        action="store_true",
        default=False,
        help="Disable progress logging even if LIVE_VERBOSE_PROGRESS=true.",
    )
    args = ap.parse_args(argv)

    if args.no_ensure_services:
        args.ensure_services = False
    if args.no_kick_score:
        args.kick_score = False
    if args.no_capture_signals:
        args.capture_signals = False
    if args.no_strict_proof:
        args.strict_proof = False
    if args.no_verbose_progress:
        args.verbose_progress = False
    args.timestamp_skew_seconds = max(0, int(args.timestamp_skew_seconds))

    scenario_dir = Path(args.scenario_dir)
    if not scenario_dir.is_dir():
        print(f"Scenario directory missing: {scenario_dir}", file=sys.stderr)
        return 1

    scenario_paths = sorted([p for p in scenario_dir.glob("*.json") if p.is_file()], key=lambda p: p.name)
    if not scenario_paths:
        print(f"No scenarios found in: {scenario_dir}", file=sys.stderr)
        return 1

    results_path = Path(args.results)
    summary_path = Path(args.summary)
    manifest_path = Path(args.manifest)
    state_path = (
        Path(args.resume_state)
        if str(args.resume_state).strip()
        else Path(str(results_path) + ".state.json")
    )
    resume_enabled = not args.no_resume

    run_lock = _SuiteRunLock(REPO_ROOT / "artifacts" / "live-benchmark.lock")
    lock_ok, lock_details = run_lock.acquire(
        {
            "pid": os.getpid(),
            "started_at_utc": _now_utc_iso(),
            "vm_name": args.vm_name,
            "scenario_dir": str(scenario_dir),
            "results_path": str(results_path),
            "summary_path": str(summary_path),
            "manifest_path": str(manifest_path),
            "resume_state_path": str(state_path),
            "seed": int(args.seed),
            "iterations": int(args.iterations),
        }
    )
    if not lock_ok:
        print(
            "Another live benchmark run is already active; refusing concurrent execution to avoid engine contamination.",
            file=sys.stderr,
        )
        if lock_details:
            print(lock_details, file=sys.stderr)
        return 4
    atexit.register(run_lock.release)

    # Optional: ensure services are started before attempting live runs.
    if args.ensure_services:
        services_ok, services_output = _ensure_services_started(strict_proof=args.strict_proof)
        if not services_ok:
            if args.strict_proof:
                print("setup/start.sh failed in strict proof mode", file=sys.stderr)
                if services_output:
                    print(services_output, file=sys.stderr)
                return 1
            # Non-strict mode remains best-effort for local iteration speed.
            print("WARNING: setup/start.sh returned non-zero; continuing", file=sys.stderr)

    benchmark_mode_slug = "live"
    git_sha = _git_sha_short()
    runner = "local"
    scenario_set_version = _sha256_of_files(scenario_paths)
    effective_mode = "live"
    posture_build_info = _collect_posture_build_info(args.vm_name)

    # Global allowlists reduce false positives from background services.
    always_allowed_processes = [
        "edamame_posture",
        "edamame",
        "sentry-transpor",
        "systemd-timesync",
        "systemd-resolve",
        "containerd",
        "sshd",
        "openclaw-gatewa",
        "openclaw-agent",
    ]
    always_allowed_domains = [
        "api.mixpanel.com",
        "raw.githubusercontent.com",
        "edamame.s3.eu-west-1.amazonaws.com",
        "api.openai.com",
        "api.anthropic.com",
        "openai.azure.com",
        "openclawpoc.openai.azure.com",
        "prod-ntp-5.ntp4.ps5.canonical.com",
    ]

    # Pre-load scenarios and group them so we can run one injection and then
    # evaluate multiple (possibly contradictory) intents against the same
    # observed telemetry.
    scenario_defs: list[dict] = []
    for scenario_path in scenario_paths:
        scenario = json.loads(scenario_path.read_text(encoding="utf-8"))
        live = scenario.get("live") or {}

        scenario_id = str(scenario.get("id") or scenario_path.stem)
        group_id = str(live.get("group_id") or scenario_id)

        raw_target_port = live.get("target_port", 443)
        try:
            target_port = int(raw_target_port)
        except Exception:
            target_port = 443
        if target_port <= 0:
            target_port = 443

        target_ip_pool_override: list[str] = []
        raw_target_ip_pool = live.get("target_ip_pool")
        if isinstance(raw_target_ip_pool, list):
            for v in raw_target_ip_pool:
                ip = str(v or "").strip()
                if ip:
                    target_ip_pool_override.append(ip)

        scenario_defs.append(
            {
                "path": scenario_path,
                "scenario": scenario,
                "scenario_id": scenario_id,
                "group_id": group_id,
                "evidence_process": str(live.get("evidence_process") or ""),
                "inject_cmd_template": str(live.get("inject_cmd") or ""),
                "evidence_regex_template": str(live.get("evidence_regex") or ""),
                "allowed_processes": list(live.get("allowed_processes") or []),
                "allowed_domains": list(live.get("allowed_domains") or []),
                "target_port": target_port,
                "target_ip_pool": target_ip_pool_override,
                "poll_timeout": int(live.get("poll_timeout_seconds") or 15),
                "poll_interval": int(live.get("poll_interval_seconds") or 1),
                "expected_l7_signals": dict(live.get("expected_l7_signals") or {}),
            }
        )

    groups: dict[str, list[dict]] = {}
    for s in scenario_defs:
        groups.setdefault(s["group_id"], []).append(s)
    group_ids = sorted(groups.keys())
    total_groups = len(group_ids)
    total_group_steps = args.iterations * total_groups
    total_planned_runs = args.iterations * len(scenario_defs)

    # Resumable execution state (compared against posture build/version and
    # run configuration). If compatible, continue from prior progress.
    state_payload = _load_json_file(state_path) if (resume_enabled and state_path.exists()) else None
    resume_reset_reasons: list[str] = []
    resumed = False
    elapsed_seconds_prior = 0.0
    state_created_at_utc = _now_utc_iso()

    run_id = time.strftime("run-live-%Y%m%dT%H%M%SZ", time.gmtime()) + f"-{benchmark_mode_slug}"
    if resume_enabled and isinstance(state_payload, dict):
        checks = [
            ("mode", effective_mode),
            ("benchmark_mode", "live"),
            ("detection_mode", args.detection_mode),
            ("vm_name", args.vm_name),
            ("scenario_set_version", scenario_set_version),
            ("seed", args.seed),
            ("iterations", args.iterations),
            ("telemetry", args.telemetry),
            ("kick_score", bool(args.kick_score)),
            ("capture_signals", bool(args.capture_signals)),
            ("strict_proof", bool(args.strict_proof)),
            ("results_path", str(results_path)),
            ("summary_path", str(summary_path)),
            ("manifest_path", str(manifest_path)),
            ("trace_root_base", str(Path(args.trace_root))),
        ]
        for key, expected in checks:
            observed = state_payload.get(key)
            if observed != expected:
                resume_reset_reasons.append(f"{key} changed ({observed!r} != {expected!r})")

        prior_posture = state_payload.get("posture") if isinstance(state_payload.get("posture"), dict) else {}
        prior_version = str(prior_posture.get("version") or "").strip()
        current_version = str(posture_build_info.get("version") or "").strip()
        if prior_version and current_version and prior_version != current_version:
            resume_reset_reasons.append(
                f"posture version changed ({prior_version!r} -> {current_version!r})"
            )
        prior_build_epoch = prior_posture.get("build_mtime_epoch")
        current_build_epoch = posture_build_info.get("build_mtime_epoch")
        if (
            isinstance(prior_build_epoch, int)
            and isinstance(current_build_epoch, int)
            and prior_build_epoch != current_build_epoch
        ):
            resume_reset_reasons.append(
                f"posture build time changed ({prior_build_epoch} -> {current_build_epoch})"
            )

        prior_run_id = str(state_payload.get("run_id") or "").strip()
        if prior_run_id == "":
            resume_reset_reasons.append("missing run_id in state")
        else:
            completed_raw = state_payload.get("completed_keys")
            completed_count = len(completed_raw) if isinstance(completed_raw, list) else 0
            run_rows_raw = state_payload.get("run_rows")
            run_rows_count = len(run_rows_raw) if isinstance(run_rows_raw, list) else 0
            results_exists = results_path.exists()
            if not results_exists and (completed_count > 0 or run_rows_count > 0):
                resume_reset_reasons.append(f"results file missing for resume: {results_path}")
            if _should_reuse_prior_run_id(
                prior_run_id=prior_run_id,
                resume_reset_reasons=resume_reset_reasons,
                results_exists=results_exists,
                completed_count=completed_count,
                run_rows_count=run_rows_count,
            ):
                run_id = prior_run_id

    trace_root = Path(args.trace_root) / run_id
    results_path.parent.mkdir(parents=True, exist_ok=True)
    trace_root.mkdir(parents=True, exist_ok=True)

    completed_keys: set[str] = set()
    valid_runs = 0
    skipped_runs = 0
    run_rows: list[dict] = []

    if resume_enabled and isinstance(state_payload, dict) and not resume_reset_reasons:
        completed_raw = state_payload.get("completed_keys")
        if isinstance(completed_raw, list):
            completed_keys = {str(v) for v in completed_raw if str(v).strip()}

        counts = state_payload.get("counts") if isinstance(state_payload.get("counts"), dict) else {}
        try:
            valid_runs = int(counts.get("valid_runs", state_payload.get("valid_runs", 0)))
        except Exception:
            valid_runs = 0
        try:
            skipped_runs = int(counts.get("skipped_runs", state_payload.get("skipped_runs", 0)))
        except Exception:
            skipped_runs = 0
        run_rows_raw = state_payload.get("run_rows")
        if isinstance(run_rows_raw, list):
            run_rows = [r for r in run_rows_raw if isinstance(r, dict)]
        try:
            elapsed_seconds_prior = float(state_payload.get("elapsed_seconds_total", 0.0) or 0.0)
        except Exception:
            elapsed_seconds_prior = 0.0
        state_created_at_utc = str(state_payload.get("created_at_utc") or state_created_at_utc)
        resumed = True
    else:
        if results_path.exists():
            results_path.unlink()
        if state_path.exists() and resume_reset_reasons:
            # Keep stale state for forensics and start a clean run.
            stale_path = state_path.with_suffix(state_path.suffix + ".stale")
            try:
                _write_text(
                    stale_path,
                    json.dumps(
                        {
                            "generated_at_utc": _now_utc_iso(),
                            "reasons": resume_reset_reasons,
                            "state_path": str(state_path),
                        },
                        indent=2,
                    )
                    + "\n",
                )
            except Exception:
                pass

    def _scenario_key(iteration_idx: int, scenario_id: str) -> str:
        return f"iter-{iteration_idx:04d}:{scenario_id}"

    def _progress(message: str) -> None:
        if not args.verbose_progress:
            return
        print(f"[live-suite] {message}", flush=True)

    if not resumed:
        reset_ok, reset_output = _reset_divergence_runtime_state(
            args.vm_name,
            interval_seconds=30,
        )
        if not reset_ok:
            if args.strict_proof:
                print("failed to reset divergence runtime state for fresh live run", file=sys.stderr)
                if reset_output:
                    print(reset_output, file=sys.stderr)
                return 1
            print("WARNING: failed to reset divergence runtime state; continuing", file=sys.stderr)
            if reset_output:
                print(reset_output, file=sys.stderr)
        else:
            _progress("reset divergence runtime state for fresh live run")

    state_session_start = time.monotonic()

    def _elapsed_total_seconds() -> float:
        return max(0.0, elapsed_seconds_prior + (time.monotonic() - state_session_start))

    def _eta_seconds() -> Optional[float]:
        completed = len(completed_keys)
        if completed <= 0:
            return None
        remaining = max(0, total_planned_runs - completed)
        if remaining <= 0:
            return 0.0
        avg = _elapsed_total_seconds() / completed
        return max(0.0, remaining * avg)

    def _persist_resume_state(event: str, *, last_key: Optional[str] = None, last_status: Optional[str] = None) -> None:
        if not resume_enabled:
            return
        completed = len(completed_keys)
        elapsed_now = _elapsed_total_seconds()
        eta_now = _eta_seconds()
        avg_now = (elapsed_now / completed) if completed > 0 else None
        payload = {
            "state_version": 1,
            "created_at_utc": state_created_at_utc,
            "updated_at_utc": _now_utc_iso(),
            "run_id": run_id,
            "mode": effective_mode,
            "benchmark_mode": "live",
            "detection_mode": args.detection_mode,
            "vm_name": args.vm_name,
            "scenario_set_version": scenario_set_version,
            "seed": args.seed,
            "iterations": args.iterations,
            "telemetry": args.telemetry,
            "kick_score": bool(args.kick_score),
            "capture_signals": bool(args.capture_signals),
            "strict_proof": bool(args.strict_proof),
            "scenario_count": len(scenario_defs),
            "group_count": total_groups,
            "total_planned_runs": total_planned_runs,
            "results_path": str(results_path),
            "summary_path": str(summary_path),
            "manifest_path": str(manifest_path),
            "trace_root_base": str(Path(args.trace_root)),
            "trace_root": str(trace_root),
            "posture": posture_build_info,
            "elapsed_seconds_total": round(elapsed_now, 3),
            "counts": {
                "completed_runs": completed,
                "valid_runs": int(valid_runs),
                "skipped_runs": int(skipped_runs),
            },
            "progress": {
                "completed_percent": round((completed / total_planned_runs) * 100.0, 2) if total_planned_runs > 0 else 100.0,
                "remaining_runs": max(0, total_planned_runs - completed),
                "average_seconds_per_run": round(avg_now, 3) if avg_now is not None else None,
                "eta_seconds": round(eta_now, 3) if eta_now is not None else None,
                "eta_human": _format_duration(eta_now),
            },
            "last_event": event,
            "last_scenario_key": last_key,
            "last_status": last_status,
            "completed_keys": sorted(completed_keys),
            "run_rows": run_rows,
        }
        _write_text(state_path, json.dumps(payload, indent=2) + "\n")

    def _progress_state(prefix: str) -> None:
        completed = len(completed_keys)
        pct = (completed / total_planned_runs) * 100.0 if total_planned_runs > 0 else 100.0
        _progress(
            f"{prefix} progress={completed}/{total_planned_runs} ({pct:.1f}%) "
            f"valid={valid_runs} skipped={skipped_runs} "
            f"elapsed={_format_duration(_elapsed_total_seconds())} "
            f"eta={_format_duration(_eta_seconds())}"
        )

    if resume_reset_reasons:
        print(
            "WARNING: resume state ignored; starting fresh run because: "
            + "; ".join(resume_reset_reasons),
            file=sys.stderr,
        )
    _progress(
        "start "
        + f"run_id={run_id} "
        + f"resume={'yes' if resumed else 'no'} "
        + f"state={state_path} "
        + f"iterations={args.iterations} "
        + f"groups={total_groups} "
        + f"scenarios={len(scenario_defs)} "
        + f"planned_runs={total_planned_runs} "
        + f"strict_proof={'yes' if args.strict_proof else 'no'} "
        + f"detection_mode={args.detection_mode} "
        + f"posture_version={posture_build_info.get('version') or 'unknown'} "
        + f"posture_build={posture_build_info.get('build_mtime_utc') or 'unknown'}"
    )
    _persist_resume_state("resume_start" if resumed else "fresh_start")
    _progress_state("resume_state")

    for group_id in group_ids:
        items = groups[group_id]
        evidence_processes = {it["evidence_process"].strip() for it in items if it["evidence_process"].strip()}
        inject_templates = {it["inject_cmd_template"].strip() for it in items if it["inject_cmd_template"].strip()}
        group_target_ports = {int(it["target_port"]) for it in items}
        group_target_ip_pool_overrides = {
            tuple(it["target_ip_pool"]) for it in items if isinstance(it.get("target_ip_pool"), list) and it["target_ip_pool"]
        }
        if len(evidence_processes) != 1:
            print(
                f"Invalid scenario group '{group_id}': live.evidence_process must be identical and non-empty",
                file=sys.stderr,
            )
            return 1
        if len(inject_templates) != 1:
            print(
                f"Invalid scenario group '{group_id}': live.inject_cmd must be identical and non-empty",
                file=sys.stderr,
            )
            return 1
        if len(group_target_ports) != 1:
            print(
                f"Invalid scenario group '{group_id}': live.target_port must be identical within a group",
                file=sys.stderr,
            )
            return 1
        if len(group_target_ip_pool_overrides) > 1:
            print(
                f"Invalid scenario group '{group_id}': live.target_ip_pool must be identical within a group",
                file=sys.stderr,
            )
            return 1
        if "{TARGET_IP}" not in next(iter(inject_templates)):
            msg = (
                f"group '{group_id}' live.inject_cmd has no '{{TARGET_IP}}' placeholder; "
                "target selection will be less robust"
            )
            if args.strict_proof:
                print(f"Invalid scenario group '{group_id}': {msg}", file=sys.stderr)
                return 1
            print(f"WARNING: {msg}", file=sys.stderr)

    default_target_ip_pool = [
        "1.1.1.1",
        "1.0.0.1",
        "1.1.1.2",
        "1.0.0.2",
        "1.1.1.3",
        "1.0.0.3",
    ]

    def _substitute_target_ip(template: str, target_ip: str) -> str:
        return template.replace("{TARGET_IP}", target_ip)

    def _rotate_pool(seed: int, group_id: str, pool: list[str]) -> list[str]:
        if not pool:
            pool = list(default_target_ip_pool)
        digest = hashlib.sha256(group_id.encode("utf-8")).hexdigest()
        start = (seed + int(digest[:8], 16)) % len(pool)
        return pool[start:] + pool[:start]

    def _latest_ts_for(process: str, dst_ip: str, dst_port: int, rows: list[SessionRow]) -> Optional[datetime]:
        latest: Optional[datetime] = None
        for r in rows:
            if r.process != process:
                continue
            if r.dst_ip != dst_ip:
                continue
            if r.dst_port != dst_port:
                continue
            dt = _row_activity_dt(r)
            if dt is None:
                continue
            latest = dt if latest is None else max(latest, dt)
        return latest

    def _latest_any_ts_for(dst_ip: str, dst_port: int, rows: list[SessionRow]) -> Optional[datetime]:
        latest: Optional[datetime] = None
        for r in rows:
            if r.dst_ip != dst_ip:
                continue
            if r.dst_port != dst_port:
                continue
            dt = _row_activity_dt(r)
            if dt is None:
                continue
            latest = dt if latest is None else max(latest, dt)
        return latest

    def _extract_inject_marker_ts(lines: list[str], key: str) -> Optional[datetime]:
        prefix = key + "="
        for line in lines:
            line = line.strip()
            if not line.startswith(prefix):
                continue
            ts = line[len(prefix) :].strip()
            if ts.endswith("Z"):
                ts = ts[:-1] + "+00:00"
            return _parse_ts_utc(ts)
        return None

    # The live harness now pushes a scenario-specific behavioral model for each
    # injected intent. That makes the old cron warmup unnecessary, but we must
    # still pause any background OpenClaw cron writers/readers so they do not
    # merge live VM intent into the isolated benchmark run.
    cron_setup_log = trace_root / "cron_setup.log"
    paused_cron_jobs: list[_CronJobSnapshot] = []
    cron_restore_done = False

    pause_ok, paused_cron_jobs = _pause_interfering_background_crons(args.vm_name, cron_setup_log)
    if not pause_ok:
        print("failed to suspend interfering background OpenClaw cron jobs", file=sys.stderr)
        return 1

    def _restore_paused_crons_once(log_path: Path) -> bool:
        nonlocal cron_restore_done
        if cron_restore_done:
            return True
        restore_ok = _restore_paused_background_crons(args.vm_name, paused_cron_jobs, log_path)
        if restore_ok:
            cron_restore_done = True
        return restore_ok

    def _restore_paused_crons_on_exit() -> None:
        _restore_paused_crons_once(trace_root / "cron_restore_atexit.log")

    atexit.register(_restore_paused_crons_on_exit)
    _progress(
        "scenario-specific behavioral model injection enabled; "
        + f"paused {len(paused_cron_jobs)} interfering cron job(s)"
    )
    _persist_resume_state("cron_background_jobs_paused")
    _persist_resume_state("behavioral_model_injection_ready")

    for iteration in range(1, args.iterations + 1):
        effective_seed = args.seed + iteration - 1
        _progress(f"iteration {iteration}/{args.iterations} seed={effective_seed}")
        for group_index, group_id in enumerate(group_ids, start=1):
            items = sorted(groups[group_id], key=_scenario_execution_sort_key)
            pending_items = [
                it for it in items if _scenario_key(iteration, str(it["scenario_id"])) not in completed_keys
            ]
            current_group_step = (iteration - 1) * total_groups + group_index

            if not pending_items:
                _progress(
                    "group_resume_skip "
                    + f"step={current_group_step}/{total_group_steps} "
                    + f"iter={iteration}/{args.iterations} "
                    + f"group={group_index}/{total_groups} "
                    + f"id={group_id} "
                    + "reason=all_scenarios_already_completed"
                )
                continue

            # Group-level config is validated above.
            evidence_process = pending_items[0]["evidence_process"].strip()
            inject_cmd_template = pending_items[0]["inject_cmd_template"]
            target_port = int(pending_items[0]["target_port"])
            target_ip_pool_override = (
                list(pending_items[0]["target_ip_pool"])
                if isinstance(pending_items[0].get("target_ip_pool"), list)
                else []
            )
            active_target_ip_pool = target_ip_pool_override if target_ip_pool_override else list(default_target_ip_pool)
            poll_timeout = max(it["poll_timeout"] for it in pending_items)
            poll_interval = min(it["poll_interval"] for it in pending_items)
            _progress(
                "group_start "
                + f"step={current_group_step}/{total_group_steps} "
                + f"iter={iteration}/{args.iterations} "
                + f"group={group_index}/{total_groups} "
                + f"id={group_id} "
                + f"evidence_process={evidence_process} "
                + f"pending={len(pending_items)}"
            )

            group_trace_dir = trace_root / group_id / f"iter-{iteration:04d}"
            group_trace_dir.mkdir(parents=True, exist_ok=True)

            baseline_path = group_trace_dir / f"baseline_{args.telemetry}.log"
            inject_log_path = group_trace_dir / "inject.log"
            group_eval_path = group_trace_dir / "group_evaluation.json"

            # Capture baseline exceptions (for debugging and target selection).
            baseline_ok = _capture_telemetry_with_retries(
                args.vm_name,
                baseline_path,
                telemetry=args.telemetry,
                timeout_seconds=60,
                max_attempts=3,
                retry_delay_seconds=2.0,
            )
            if not baseline_ok and args.ensure_services:
                recovery_log_path = group_trace_dir / "service_recovery.log"
                recovered, recovery_output = _ensure_services_started(strict_proof=False)
                _write_text(recovery_log_path, recovery_output)
                if recovered:
                    baseline_ok = _capture_telemetry_with_retries(
                        args.vm_name,
                        baseline_path,
                        telemetry=args.telemetry,
                        timeout_seconds=60,
                        max_attempts=3,
                        retry_delay_seconds=3.0,
                    )
            if not baseline_ok:
                skipped_runs += len(pending_items)
                _write_text(
                    group_eval_path,
                    json.dumps({"status": "skipped", "reason": "baseline_capture_failed"}, indent=2) + "\n",
                )
                for it in pending_items:
                    scenario_key = _scenario_key(iteration, str(it["scenario_id"]))
                    completed_keys.add(scenario_key)
                    scenario_trace_dir = group_trace_dir / it["scenario_id"]
                    scenario_trace_dir.mkdir(parents=True, exist_ok=True)
                    _write_text(
                        scenario_trace_dir / "evaluation.json",
                        json.dumps({"status": "skipped", "reason": "baseline_capture_failed"}, indent=2) + "\n",
                    )
                    _persist_resume_state(
                        "scenario_skipped",
                        last_key=scenario_key,
                        last_status="baseline_capture_failed",
                    )
                _progress(
                    f"group_skipped id={group_id} reason=baseline_capture_failed skipped_runs={skipped_runs}"
                )
                _progress_state("resume_state")
                continue

            baseline_rows = _parse_sessions(_read_lines(baseline_path))

            # Capture high-level signals for the evidence bundle.
            baseline_anomalous_path = group_trace_dir / "baseline_anomalous.log"
            baseline_blacklisted_path = group_trace_dir / "baseline_blacklisted.log"
            baseline_exceptions_path = group_trace_dir / "baseline_exceptions.log"
            baseline_vulnerability_findings_path = group_trace_dir / "baseline_vulnerability_findings.json"
            baseline_todos_path = group_trace_dir / "baseline_todos.json"
            baseline_action_history_path = group_trace_dir / "baseline_action_history.json"

            if args.capture_signals:
                _capture_openclaw_tool_invoke(
                    args.vm_name, baseline_anomalous_path,
                    tool_name="get_anomalous_sessions", tool_args={}, timeout_seconds=45,
                )
                _capture_openclaw_tool_invoke(
                    args.vm_name, baseline_blacklisted_path,
                    tool_name="get_blacklisted_sessions", tool_args={}, timeout_seconds=45,
                )
                _capture_openclaw_tool_invoke(
                    args.vm_name, baseline_exceptions_path,
                    tool_name="get_exceptions", tool_args={}, timeout_seconds=45,
                )
                _capture_openclaw_tool_invoke(
                    args.vm_name, baseline_vulnerability_findings_path,
                    tool_name="get_vulnerability_findings", tool_args={}, timeout_seconds=60,
                )
                _capture_openclaw_tool_invoke(
                    args.vm_name, baseline_todos_path,
                    tool_name="advisor_get_todos", tool_args={}, timeout_seconds=60,
                )
                _capture_openclaw_tool_invoke(
                    args.vm_name, baseline_action_history_path,
                    tool_name="advisor_get_action_history", tool_args={"limit": 10},
                    timeout_seconds=60,
                )
            else:
                _write_text(baseline_anomalous_path, "SKIP: --no-capture-signals\n")
                _write_text(baseline_blacklisted_path, "SKIP: --no-capture-signals\n")
                _write_text(baseline_exceptions_path, "SKIP: --no-capture-signals\n")
                _write_text(baseline_vulnerability_findings_path, "SKIP: --no-capture-signals\n")
                _write_text(baseline_todos_path, "SKIP: --no-capture-signals\n")
                _write_text(baseline_action_history_path, "SKIP: --no-capture-signals\n")

            # Select a target IP, preferring ones not already present for this process.
            rotated_pool = _rotate_pool(effective_seed, group_id, active_target_ip_pool)
            latest_by_ip: dict[str, Optional[datetime]] = {
                ip: _latest_ts_for(evidence_process, ip, target_port, baseline_rows) for ip in rotated_pool
            }
            latest_any_by_ip: dict[str, Optional[datetime]] = {
                ip: _latest_any_ts_for(ip, target_port, baseline_rows) for ip in rotated_pool
            }

            target_ip: str
            baseline_latest_for_target: Optional[datetime] = None
            baseline_latest_any_for_target: Optional[datetime] = None
            target_selection_reason = "absent_in_baseline_any"

            target_ip = rotated_pool[0]
            for ip in rotated_pool:
                if latest_any_by_ip[ip] is None:
                    target_ip = ip
                    baseline_latest_for_target = None
                    baseline_latest_any_for_target = None
                    target_selection_reason = "absent_in_baseline_any"
                    break
            else:
                process_absent_candidates = [ip for ip in rotated_pool if latest_by_ip[ip] is None]
                if process_absent_candidates:
                    target_ip = min(
                        process_absent_candidates,
                        key=lambda ip: latest_any_by_ip[ip] or datetime.max.replace(tzinfo=timezone.utc),
                    )
                    baseline_latest_for_target = None
                    baseline_latest_any_for_target = latest_any_by_ip[target_ip]
                    target_selection_reason = "process_absent_chose_oldest_any"
                else:
                    target_ip = min(
                        rotated_pool,
                        key=lambda ip: latest_by_ip[ip] or datetime.max.replace(tzinfo=timezone.utc),
                    )
                    baseline_latest_for_target = latest_by_ip[target_ip]
                    baseline_latest_any_for_target = latest_any_by_ip[target_ip]
                    target_selection_reason = "all_present_chose_oldest_process"

            inject_cmd = _substitute_target_ip(inject_cmd_template, target_ip)
            inject_ok = _run_injection(args.vm_name, inject_cmd, inject_log_path)
            if not inject_ok:
                skipped_runs += len(pending_items)
                _write_text(
                    group_eval_path,
                    json.dumps(
                        {"status": "skipped", "reason": "inject_failed", "target_ip": target_ip, "inject_cmd": inject_cmd},
                        indent=2,
                    )
                    + "\n",
                )
                for it in pending_items:
                    scenario_key = _scenario_key(iteration, str(it["scenario_id"]))
                    completed_keys.add(scenario_key)
                    scenario_trace_dir = group_trace_dir / it["scenario_id"]
                    scenario_trace_dir.mkdir(parents=True, exist_ok=True)
                    _write_text(
                        scenario_trace_dir / "evaluation.json",
                        json.dumps({"status": "skipped", "reason": "inject_failed"}, indent=2) + "\n",
                    )
                    _persist_resume_state(
                        "scenario_skipped",
                        last_key=scenario_key,
                        last_status="inject_failed",
                    )
                _progress(f"group_skipped id={group_id} reason=inject_failed skipped_runs={skipped_runs}")
                _progress_state("resume_state")
                continue

            kick_score_log_path = group_trace_dir / "kick_score.log"
            kick_score_ok = True
            if args.kick_score:
                kick_score_ok = _kick_score_mcp(args.vm_name, kick_score_log_path)
            else:
                _write_text(kick_score_log_path, "SKIP: --no-kick-score\n")

            inject_done_monotonic = time.monotonic()
            inject_lines = _read_lines(inject_log_path)
            inject_start_ts = _extract_inject_marker_ts(inject_lines, "INJECT_START_UTC")
            inject_end_ts = _extract_inject_marker_ts(inject_lines, "INJECT_END_UTC")

            watermark = inject_start_ts or inject_end_ts
            if watermark is None:
                # Worst-case fallback: avoid host timestamps (can drift vs VM).
                watermark = datetime.min.replace(tzinfo=timezone.utc)
            watermark_for_matching = watermark - timedelta(seconds=args.timestamp_skew_seconds)

            evidence_rows: list[SessionRow] = []
            evidence_latency_ms = poll_timeout * 1000
            current_capture_path: Optional[Path] = None
            process_attribution_fallback_used = False
            group_expected_l7_signals: dict[str, Any] = {}
            for item in pending_items:
                for key, value in dict(item["expected_l7_signals"]).items():
                    if value:
                        group_expected_l7_signals[key] = value

            def _poll_for_evidence(
                *,
                watermark_match: datetime,
                inject_start: Optional[datetime],
                inject_end: Optional[datetime],
                inject_done_mono: float,
                capture_dir: Path,
                expected_l7_signals: dict[str, Any],
            ) -> tuple[list[SessionRow], int, Optional[Path], bool]:
                rows_out: list[SessionRow] = []
                latency_out = poll_timeout * 1000
                capture_path_out: Optional[Path] = None
                fallback_used = False

                deadline = time.monotonic() + poll_timeout
                attempt = 0
                while time.monotonic() <= deadline:
                    attempt += 1
                    capture_path_out = capture_dir / f"{args.telemetry}_attempt_{attempt:02d}.log"
                    capture_ok = _capture_telemetry_with_retries(
                        args.vm_name,
                        capture_path_out,
                        telemetry=args.telemetry,
                        timeout_seconds=45,
                        max_attempts=2,
                        retry_delay_seconds=1.0,
                    )
                    if not capture_ok:
                        time.sleep(max(0.1, poll_interval))
                        continue
                    capture_lines = _read_lines(capture_path_out)
                    current_rows = _parse_sessions(capture_lines)

                    candidates: list[SessionRow] = []
                    unknown_candidates: list[tuple[SessionRow, datetime]] = []
                    for row in current_rows:
                        if row.dst_ip != target_ip or row.dst_port != target_port:
                            continue
                        dt = _row_activity_dt(row)
                        if dt is None:
                            continue
                        if dt < watermark_match:
                            continue

                        if row.process == evidence_process:
                            candidates.append(row)
                            continue

                        # Under load, short-lived outbound commands can be captured
                        # before process attribution lands, producing "unknown" rows
                        # at the exact injected tuple/time. Keep these as a narrow
                        # fallback for robustness.
                        if row.process == "unknown":
                            unknown_candidates.append((row, dt))

                    if not candidates:
                        # Conservative fallback: only accept unknown-process rows
                        # very close to injection time for the exact target tuple.
                        if unknown_candidates:
                            inject_ref = inject_end or inject_start
                            if inject_ref is not None:
                                upper = inject_ref + timedelta(seconds=20)
                                near_inject = [r for (r, dt) in unknown_candidates if dt <= upper]
                            else:
                                near_inject = [r for (r, _dt) in unknown_candidates]

                            if near_inject:
                                candidates = [dataclasses.replace(r, process=evidence_process) for r in near_inject]
                                fallback_used = True

                    if not candidates:
                        time.sleep(max(0.1, poll_interval))
                        continue

                    if not _rows_satisfy_expected_l7_signals(
                        candidates,
                        expected_l7_signals,
                    ):
                        time.sleep(max(0.1, poll_interval))
                        continue

                    rows_out = candidates
                    capture_end_ts = _extract_inject_marker_ts(capture_lines, "CAPTURE_END_UTC")
                    start_ts = inject_start or inject_end
                    if start_ts is not None and capture_end_ts is not None:
                        latency_out = max(0, int((capture_end_ts - start_ts).total_seconds() * 1000))
                    else:
                        latency_out = int((time.monotonic() - inject_done_mono) * 1000)
                    break

                return rows_out, latency_out, capture_path_out, fallback_used

            evidence_rows, evidence_latency_ms, current_capture_path, process_attribution_fallback_used = _poll_for_evidence(
                watermark_match=watermark_for_matching,
                inject_start=inject_start_ts,
                inject_end=inject_end_ts,
                inject_done_mono=inject_done_monotonic,
                capture_dir=group_trace_dir,
                expected_l7_signals=group_expected_l7_signals,
            )

            if not evidence_rows and args.ensure_services:
                recovery_log_path = group_trace_dir / "service_recovery.log"
                recovered, recovery_output = _ensure_services_started(strict_proof=False)
                _write_text(recovery_log_path, recovery_output)
                if recovered:
                    inject_ok = _run_injection(args.vm_name, inject_cmd, inject_log_path)
                    if inject_ok:
                        inject_done_monotonic = time.monotonic()
                        inject_lines = _read_lines(inject_log_path)
                        inject_start_ts = _extract_inject_marker_ts(inject_lines, "INJECT_START_UTC")
                        inject_end_ts = _extract_inject_marker_ts(inject_lines, "INJECT_END_UTC")
                        watermark = inject_start_ts or inject_end_ts
                        if watermark is None:
                            watermark = datetime.min.replace(tzinfo=timezone.utc)
                        watermark_for_matching = watermark - timedelta(seconds=args.timestamp_skew_seconds)
                        evidence_rows, evidence_latency_ms, current_capture_path, process_attribution_fallback_used = _poll_for_evidence(
                            watermark_match=watermark_for_matching,
                            inject_start=inject_start_ts,
                            inject_end=inject_end_ts,
                            inject_done_mono=inject_done_monotonic,
                            capture_dir=group_trace_dir,
                            expected_l7_signals=group_expected_l7_signals,
                        )

            post_anomalous_path = group_trace_dir / "post_anomalous.log"
            post_blacklisted_path = group_trace_dir / "post_blacklisted.log"
            post_exceptions_path = group_trace_dir / "post_exceptions.log"
            post_vulnerability_findings_path = group_trace_dir / "post_vulnerability_findings.json"
            post_todos_path = group_trace_dir / "post_todos.json"
            post_action_history_path = group_trace_dir / "post_action_history.json"

            if args.capture_signals:
                _capture_openclaw_tool_invoke(
                    args.vm_name, post_anomalous_path,
                    tool_name="get_anomalous_sessions", tool_args={}, timeout_seconds=45,
                )
                _capture_openclaw_tool_invoke(
                    args.vm_name, post_blacklisted_path,
                    tool_name="get_blacklisted_sessions", tool_args={}, timeout_seconds=45,
                )
                _capture_openclaw_tool_invoke(
                    args.vm_name, post_exceptions_path,
                    tool_name="get_exceptions", tool_args={}, timeout_seconds=45,
                )
                _capture_openclaw_tool_invoke(
                    args.vm_name, post_vulnerability_findings_path,
                    tool_name="get_vulnerability_findings", tool_args={}, timeout_seconds=60,
                )
                _capture_openclaw_tool_invoke(
                    args.vm_name, post_todos_path,
                    tool_name="advisor_get_todos", tool_args={}, timeout_seconds=60,
                )
                _capture_openclaw_tool_invoke(
                    args.vm_name, post_action_history_path,
                    tool_name="advisor_get_action_history", tool_args={"limit": 10},
                    timeout_seconds=60,
                )
            else:
                _write_text(post_anomalous_path, "SKIP: --no-capture-signals\n")
                _write_text(post_blacklisted_path, "SKIP: --no-capture-signals\n")
                _write_text(post_exceptions_path, "SKIP: --no-capture-signals\n")
                _write_text(post_vulnerability_findings_path, "SKIP: --no-capture-signals\n")
                _write_text(post_todos_path, "SKIP: --no-capture-signals\n")
                _write_text(post_action_history_path, "SKIP: --no-capture-signals\n")

            if not evidence_rows:
                skipped_runs += len(pending_items)
                _write_text(
                    group_eval_path,
                    json.dumps(
                        {
                            "status": "skipped",
                            "reason": "evidence_not_observed_within_timeout",
                            "poll_timeout_seconds": poll_timeout,
                            "target_ip": target_ip,
                            "target_port": target_port,
                            "evidence_process": evidence_process,
                            "telemetry": args.telemetry,
                            "kick_score_enabled": bool(args.kick_score),
                            "kick_score_ok": bool(kick_score_ok),
                            "kick_score_log": str(kick_score_log_path),
                            "baseline_telemetry_log": str(baseline_path),
                            "baseline_anomalous_log": str(baseline_anomalous_path),
                            "baseline_blacklisted_log": str(baseline_blacklisted_path),
                            "baseline_exceptions_log": str(baseline_exceptions_path),
                            "baseline_vulnerability_findings": str(baseline_vulnerability_findings_path),
                            "baseline_todos": str(baseline_todos_path),
                            "baseline_action_history": str(baseline_action_history_path),
                            "inject_log": str(inject_log_path),
                            "last_telemetry_log": str(current_capture_path) if current_capture_path else None,
                            "process_attribution_fallback_used": process_attribution_fallback_used,
                            "post_anomalous_log": str(post_anomalous_path),
                            "post_blacklisted_log": str(post_blacklisted_path),
                            "post_exceptions_log": str(post_exceptions_path),
                            "post_vulnerability_findings": str(post_vulnerability_findings_path),
                            "post_todos": str(post_todos_path),
                            "post_action_history": str(post_action_history_path),
                            "watermark_utc": watermark.isoformat(),
                        },
                        indent=2,
                    )
                    + "\n",
                )
                for it in pending_items:
                    scenario_key = _scenario_key(iteration, str(it["scenario_id"]))
                    completed_keys.add(scenario_key)
                    scenario_trace_dir = group_trace_dir / it["scenario_id"]
                    scenario_trace_dir.mkdir(parents=True, exist_ok=True)
                    _write_text(
                        scenario_trace_dir / "evaluation.json",
                        json.dumps(
                            {
                                "status": "skipped",
                                "reason": "evidence_not_observed_within_timeout",
                                "poll_timeout_seconds": poll_timeout,
                                "target_ip": target_ip,
                                "target_port": target_port,
                                "evidence_process": evidence_process,
                                "process_attribution_fallback_used": process_attribution_fallback_used,
                                "group_trace_dir": str(group_trace_dir),
                            },
                            indent=2,
                        )
                        + "\n",
                    )
                    _persist_resume_state(
                        "scenario_skipped",
                        last_key=scenario_key,
                        last_status="evidence_not_observed_within_timeout",
                    )
                _progress(
                    "group_skipped "
                    + f"id={group_id} "
                    + "reason=evidence_not_observed_within_timeout "
                    + f"target_ip={target_ip} "
                    + f"poll_timeout={poll_timeout}s "
                    + f"skipped_runs={skipped_runs}"
                )
                _progress_state("resume_state")
                continue

            evidence_entries = [
                {
                    "timestamp": r.timestamp,
                    "username": r.username,
                    "process": r.process,
                    "protocol": r.protocol,
                    "dst_host": r.dst_host,
                    "dst_ip": r.dst_ip,
                    "dst_port": r.dst_port,
                    "raw": r.raw,
                }
                for r in evidence_rows
            ]

            # Compact, timestamp-filtered evidence bundle for live detection decisions.
            # This avoids asking the agent to parse multi-megabyte posture outputs.
            matches_blacklisted = (
                _rows_matching_target(
                    post_blacklisted_path,
                    evidence_process=evidence_process,
                    target_ip=target_ip,
                    target_port=target_port,
                    watermark=watermark_for_matching,
                )
                if args.capture_signals
                else []
            )
            matches_anomalous = (
                _rows_matching_target(
                    post_anomalous_path,
                    evidence_process=evidence_process,
                    target_ip=target_ip,
                    target_port=target_port,
                    watermark=watermark_for_matching,
                )
                if args.capture_signals
                else []
            )
            matches_exceptions = (
                _rows_matching_target(
                    post_exceptions_path,
                    evidence_process=evidence_process,
                    target_ip=target_ip,
                    target_port=target_port,
                    watermark=watermark_for_matching,
                )
                if args.capture_signals
                else []
            )
            expected_evidence_source = (
                "blacklisted"
                if matches_blacklisted
                else "anomalous"
                if matches_anomalous
                else "exceptions"
                if matches_exceptions
                else "sessions"
                if evidence_rows
                else "none"
            )
            # Aggregate L7 signals from evidence rows for the skill's
            # intent-independent safety rules and lineage verification.
            def _aggregate_l7(rows: list[SessionRow]) -> dict:
                agg: dict = {}
                for r in rows:
                    if r.l7_spawned_from_tmp is True:
                        agg["spawned_from_tmp"] = True
                    if r.l7_parent_process_path:
                        agg.setdefault("parent_process_paths", [])
                        if r.l7_parent_process_path not in agg["parent_process_paths"]:
                            agg["parent_process_paths"].append(r.l7_parent_process_path)
                    if r.l7_parent_process_name:
                        agg.setdefault("parent_process_names", [])
                        if r.l7_parent_process_name not in agg["parent_process_names"]:
                            agg["parent_process_names"].append(r.l7_parent_process_name)
                    if r.l7_process_path:
                        agg.setdefault("process_paths", [])
                        if r.l7_process_path not in agg["process_paths"]:
                            agg["process_paths"].append(r.l7_process_path)
                    if r.l7_open_files:
                        agg.setdefault("open_files", [])
                        for f in r.l7_open_files:
                            if f not in agg["open_files"]:
                                agg["open_files"].append(f)
                return agg

            l7_signals = _aggregate_l7(evidence_rows)

            def _compact_rows(rows: list[SessionRow]) -> list[dict]:
                compact: list[dict] = []
                for r in rows[:1]:
                    compact.append(
                        {
                            "timestamp": r.timestamp,
                            "process": r.process,
                            "dst_host": r.dst_host,
                            "dst_ip": r.dst_ip,
                            "dst_port": r.dst_port,
                            "l7": {
                                "process_path": r.l7_process_path,
                                "parent_process_name": r.l7_parent_process_name,
                                "parent_process_path": r.l7_parent_process_path,
                                "parent_cmd": list((r.l7_parent_cmd or ())[:4]),
                                "spawned_from_tmp": r.l7_spawned_from_tmp,
                                "open_files": list((r.l7_open_files or ())[:8]),
                            },
                        }
                    )
                return compact

            evidence_bundle = {
                "watermark_utc": watermark.isoformat(),
                "expected_evidence_source": expected_evidence_source,
                "loop_artifacts": {
                    "vulnerability_findings": str(post_vulnerability_findings_path),
                    "advisor_todos": str(post_todos_path),
                    "advisor_action_history": str(post_action_history_path),
                },
                "matches": {
                    "sessions": len(evidence_rows),
                    "exceptions": len(matches_exceptions),
                    "anomalous": len(matches_anomalous),
                    "blacklisted": len(matches_blacklisted),
                },
                "l7_signals": l7_signals,
                "sample_rows": {
                    "sessions": _compact_rows(evidence_rows),
                    "exceptions": _compact_rows(matches_exceptions),
                    "anomalous": _compact_rows(matches_anomalous),
                    "blacklisted": _compact_rows(matches_blacklisted),
                },
            }

            _write_text(
                group_eval_path,
                json.dumps(
                    {
                        "status": "ok",
                        "generated_at_utc": _now_utc_iso(),
                        "group_id": group_id,
                        "iteration": iteration,
                        "seed": effective_seed,
                        "evidence_process": evidence_process,
                        "target_ip": target_ip,
                        "target_port": target_port,
                        "target_selection_reason": target_selection_reason,
                        "baseline_latest_for_target_utc": baseline_latest_for_target.isoformat()
                        if baseline_latest_for_target
                        else None,
                        "baseline_latest_any_for_target_utc": baseline_latest_any_for_target.isoformat()
                        if baseline_latest_any_for_target
                        else None,
                        "inject_start_utc": inject_start_ts.isoformat() if inject_start_ts else None,
                        "inject_end_utc": inject_end_ts.isoformat() if inject_end_ts else None,
                        "watermark_utc": watermark.isoformat(),
                        "telemetry": args.telemetry,
                        "kick_score_enabled": bool(args.kick_score),
                        "kick_score_ok": bool(kick_score_ok),
                        "kick_score_log": str(kick_score_log_path),
                        "baseline_telemetry_log": str(baseline_path),
                        "baseline_anomalous_log": str(baseline_anomalous_path),
                        "baseline_blacklisted_log": str(baseline_blacklisted_path),
                        "baseline_exceptions_log": str(baseline_exceptions_path),
                        "baseline_vulnerability_findings": str(baseline_vulnerability_findings_path),
                        "baseline_todos": str(baseline_todos_path),
                        "baseline_action_history": str(baseline_action_history_path),
                        "inject_log": str(inject_log_path),
                        "evidence_telemetry_log": str(current_capture_path),
                        "process_attribution_fallback_used": process_attribution_fallback_used,
                        "post_anomalous_log": str(post_anomalous_path),
                        "post_blacklisted_log": str(post_blacklisted_path),
                        "post_exceptions_log": str(post_exceptions_path),
                        "post_vulnerability_findings": str(post_vulnerability_findings_path),
                        "post_todos": str(post_todos_path),
                        "post_action_history": str(post_action_history_path),
                        "evidence": {"count": len(evidence_entries), "rows": evidence_entries},
                        "evidence_bundle": evidence_bundle,
                        "detection_latency_ms": evidence_latency_ms,
                    },
                    indent=2,
                )
                + "\n",
            )
            _progress(
                "group_evidence_ready "
                + f"id={group_id} "
                + f"target_ip={target_ip} "
                + f"evidence_rows={len(evidence_rows)} "
                + f"latency_ms={evidence_latency_ms} "
                + f"fallback={str(process_attribution_fallback_used).lower()}"
            )

            for it in pending_items:
                scenario = it["scenario"]
                scenario_id = it["scenario_id"]
                scenario_path = it["path"]
                scenario_trace_dir = group_trace_dir / scenario_id
                scenario_trace_dir.mkdir(parents=True, exist_ok=True)
                eval_path = scenario_trace_dir / "evaluation.json"
                scenario_key = _scenario_key(iteration, str(scenario_id))

                allowed_processes = list(it["allowed_processes"])
                allowed_domains = [_substitute_target_ip(str(d), target_ip) for d in list(it["allowed_domains"])]
                evidence_regex = _substitute_target_ip(str(it["evidence_regex_template"]), target_ip)

                effective_latency_ms = evidence_latency_ms

                verdict_obj: Optional[dict] = None
                verdict_err: Optional[str] = None
                detection_info: dict = {}
                scenario_capture_path = current_capture_path
                scenario_inject_log_path = inject_log_path
                scenario_kick_score_log_path = kick_score_log_path
                scenario_process_attribution_fallback_used = process_attribution_fallback_used
                scenario_inject_start_ts = inject_start_ts
                scenario_inject_end_ts = inject_end_ts

                # Cron detection mode only.
                expected_class = scenario.get("expected_class", "")
                expected_divergence = bool(scenario.get("expected_divergence"))
                expected_verdict = "DIVERGENCE" if expected_divergence else "CLEAN"
                scenario_model_json, model_push_started_at = _build_scenario_behavioral_model(
                    scenario_id=scenario_id,
                    declared_intent=str(scenario.get("intent") or scenario_id),
                    evidence_process=evidence_process,
                    target_port=target_port,
                    allowed_processes=allowed_processes,
                    allowed_domains=allowed_domains,
                    baseline_rows=baseline_rows,
                    evidence_rows=evidence_rows,
                    always_allowed_processes=always_allowed_processes,
                    always_allowed_domains=always_allowed_domains,
                    expected_l7_signals=dict(it["expected_l7_signals"]),
                )
                scenario_model_path = scenario_trace_dir / "behavioral_model.json"
                scenario_model_upsert_log = scenario_trace_dir / "behavioral_model_upsert.log"
                _write_text(scenario_model_path, scenario_model_json + "\n")
                model_upsert_ok, model_ingested_at = _push_behavioral_model_for_scenario(
                    args.vm_name,
                    scenario_id=scenario_id,
                    model_json=scenario_model_json,
                    out_path=scenario_model_upsert_log,
                )

                cron_verdict_log = scenario_trace_dir / "cron_verdict.log"
                cron_verdict: Optional[str] = None
                cron_ts: Optional[str] = None
                cron_elapsed = 0
                if model_upsert_ok and model_ingested_at is not None:
                    reuse_group_evidence_for_verdict = len(pending_items) == 1
                    if reuse_group_evidence_for_verdict:
                        cron_verdict, cron_ts, cron_elapsed = _wait_for_verdict(
                            args.vm_name,
                            expected_verdict=expected_verdict,
                            pre_ts=model_ingested_at,
                            max_wait_seconds=180,
                            poll_interval_seconds=1,
                            out_path=cron_verdict_log,
                        )
                    else:
                        scenario_inject_log_path = scenario_trace_dir / "inject.log"
                        scenario_inject_ok = _run_injection(args.vm_name, inject_cmd, scenario_inject_log_path)
                        if not scenario_inject_ok:
                            verdict_err = "scenario_reinject_failed"
                        else:
                            scenario_inject_done_monotonic = time.monotonic()
                            scenario_inject_lines = _read_lines(scenario_inject_log_path)
                            scenario_inject_start_ts = _extract_inject_marker_ts(
                                scenario_inject_lines, "INJECT_START_UTC"
                            )
                            scenario_inject_end_ts = _extract_inject_marker_ts(
                                scenario_inject_lines, "INJECT_END_UTC"
                            )
                            scenario_watermark = scenario_inject_start_ts or scenario_inject_end_ts
                            if scenario_watermark is None:
                                scenario_watermark = datetime.min.replace(tzinfo=timezone.utc)
                            scenario_watermark_for_matching = scenario_watermark - timedelta(
                                seconds=args.timestamp_skew_seconds
                            )
                            scenario_expected_l7_signals = dict(it["expected_l7_signals"])
                            (
                                scenario_evidence_rows,
                                scenario_evidence_latency_ms,
                                scenario_capture_path,
                                scenario_process_attribution_fallback_used,
                            ) = _poll_for_evidence(
                                watermark_match=scenario_watermark_for_matching,
                                inject_start=scenario_inject_start_ts,
                                inject_end=scenario_inject_end_ts,
                                inject_done_mono=scenario_inject_done_monotonic,
                                capture_dir=scenario_trace_dir,
                                expected_l7_signals=scenario_expected_l7_signals,
                            )
                            if not scenario_evidence_rows:
                                verdict_err = "scenario_evidence_not_observed_after_model_upsert"
                            else:
                                effective_latency_ms = scenario_evidence_latency_ms
                                cron_verdict, cron_ts, cron_elapsed = _wait_for_verdict(
                                    args.vm_name,
                                    expected_verdict=expected_verdict,
                                    pre_ts=model_ingested_at,
                                    max_wait_seconds=180,
                                    poll_interval_seconds=1,
                                    out_path=cron_verdict_log,
                                )
                else:
                    verdict_err = "behavioral_model_upsert_failed"

                if cron_verdict is None and verdict_err is None:
                    verdict_err = "cron_verdict_timeout"

                if cron_verdict is not None:
                    observed_div = cron_verdict.upper() == "DIVERGENCE"
                    verdict_obj = {
                        "scenario_id": scenario_id,
                        "observed_divergence": observed_div,
                        "observed_class": "attack" if observed_div else "benign",
                        "evidence_source": expected_evidence_source,
                        "target_ip": target_ip,
                        "target_port": target_port,
                        "evidence_process": evidence_process,
                        "signals_used": {
                            "mcp_advisor_get_todos": True,
                            "anomalous_sessions": len(matches_anomalous) > 0,
                            "blacklisted_sessions": len(matches_blacklisted) > 0,
                            "exceptions": len(matches_exceptions) > 0,
                        },
                    }
                    if cron_ts is not None and scenario_inject_start_ts is not None:
                        cron_ts_dt = _parse_ts_utc(cron_ts)
                        if cron_ts_dt is not None:
                            effective_latency_ms = max(
                                0,
                                int((cron_ts_dt - scenario_inject_start_ts).total_seconds() * 1000),
                            )
                        else:
                            effective_latency_ms = cron_elapsed
                    else:
                        effective_latency_ms = cron_elapsed

                detection_info = {
                    "detection_mode": "cron",
                    "output_log": str(cron_verdict_log),
                    "cron_elapsed_ms": cron_elapsed,
                    "expected_verdict": expected_verdict,
                    "verdict": verdict_obj,
                    "parse_error": verdict_err,
                    "shared_group_verdict": False,
                    "behavioral_model": {
                        "json_path": str(scenario_model_path),
                        "upsert_log": str(scenario_model_upsert_log),
                        "push_started_at": model_push_started_at,
                        "stored_ingested_at": model_ingested_at,
                    },
                }

                # ── Common verdict handling ──────────────────────────

                if verdict_obj is None:
                    skipped_runs += 1
                    completed_keys.add(scenario_key)
                    _write_text(
                        eval_path,
                        json.dumps(
                            {
                                "status": "skipped",
                                "reason": "benchmark_verdict_unavailable",
                                "detection": detection_info,
                                "group_trace_dir": str(group_trace_dir),
                                "target_ip": target_ip,
                                "evidence_process": evidence_process,
                            },
                            indent=2,
                        )
                        + "\n",
                    )
                    _progress(
                        "scenario_skipped "
                        + f"id={scenario_id} "
                        + "reason=benchmark_verdict_unavailable "
                        + f"parse_error={verdict_err or 'unknown'} "
                        + f"skipped_runs={skipped_runs}"
                    )
                    _persist_resume_state(
                        "scenario_skipped",
                        last_key=scenario_key,
                        last_status="benchmark_verdict_unavailable",
                    )
                    _progress_state("resume_state")
                    continue

                observed_divergence = bool(verdict_obj.get("observed_divergence"))
                # Keep observed_class stable for downstream consumers. Precision/recall
                # are computed from observed_divergence, but this helps readability.
                observed_class = "attack" if observed_divergence else "benign"
                evidence_source = str(verdict_obj.get("evidence_source") or "none")
                operator_decision = "none"
                undo_result = "not_applicable"
                undo_log_path: Optional[Path] = None

                # Attempt rollback after detected divergence so rollback_reliability
                # reflects real benchmark runs instead of staying null.
                if observed_divergence and args.capture_signals:
                    operator_decision = "undo_all_actions"
                    undo_log_path = scenario_trace_dir / "post_undo_all.json"
                    undo_call_ok = _capture_openclaw_tool_invoke(
                        args.vm_name,
                        undo_log_path,
                        tool_name="advisor_undo_all_actions",
                        tool_args={},
                        timeout_seconds=60,
                    )
                    if not undo_call_ok:
                        undo_result = "failure"
                    else:
                        undo_lines = _read_lines(undo_log_path)
                        undo_payload_text = _extract_capture_payload(undo_lines)
                        undo_payload = None
                        try:
                            undo_payload = json.loads(undo_payload_text)
                        except Exception:
                            undo_payload = None
                        if isinstance(undo_payload, dict) and undo_payload.get("ok") is True:
                            undo_result = "success"
                        else:
                            undo_result = "failure"

                _write_text(
                    eval_path,
                    json.dumps(
                        {
                            "status": "ok",
                            "generated_at_utc": _now_utc_iso(),
                            "scenario_id": scenario_id,
                            "group_id": group_id,
                            "declared_intent": scenario.get("intent"),
                            "evidence_process": evidence_process,
                            "target_ip": target_ip,
                            "target_port": target_port,
                            "evidence_regex": evidence_regex,
                            "allowed_processes": allowed_processes,
                            "allowed_domains": allowed_domains,
                            "observed_class": observed_class,
                            "observed_divergence": observed_divergence,
                            "evidence_source": evidence_source,
                            "detection_latency_ms": effective_latency_ms,
                            "group_trace_dir": str(group_trace_dir),
                            "kick_score_enabled": bool(args.kick_score),
                            "kick_score_ok": bool(kick_score_ok),
                            "kick_score_log": str(scenario_kick_score_log_path),
                            "telemetry": args.telemetry,
                            "baseline_telemetry_log": str(baseline_path),
                            "baseline_anomalous_log": str(baseline_anomalous_path),
                            "baseline_blacklisted_log": str(baseline_blacklisted_path),
                            "baseline_exceptions_log": str(baseline_exceptions_path),
                            "baseline_todos": str(baseline_todos_path),
                            "baseline_action_history": str(baseline_action_history_path),
                            "inject_log": str(scenario_inject_log_path),
                            "evidence_telemetry_log": str(scenario_capture_path),
                            "process_attribution_fallback_used": scenario_process_attribution_fallback_used,
                            "post_anomalous_log": str(post_anomalous_path),
                            "post_blacklisted_log": str(post_blacklisted_path),
                            "post_exceptions_log": str(post_exceptions_path),
                            "post_todos": str(post_todos_path),
                            "post_action_history": str(post_action_history_path),
                            "detection": detection_info,
                            "operator_decision": operator_decision,
                            "undo_result": undo_result,
                            "undo_log": str(undo_log_path) if undo_log_path else None,
                        },
                        indent=2,
                    )
                    + "\n",
                )

                _append_result(
                    scenario_path=scenario_path,
                    observed_class=observed_class,
                    observed_divergence=observed_divergence,
                    latency_ms=effective_latency_ms,
                    seed=effective_seed,
                    runner=runner,
                    git_sha=git_sha,
                    scenario_set_version=scenario_set_version,
                    run_id=run_id,
                    mode=effective_mode,
                    policy="primary",
                    operator_decision=operator_decision,
                    undo_result=undo_result,
                    results_path=results_path,
                    trace_dir=scenario_trace_dir,
                )

                valid_runs += 1
                completed_keys.add(scenario_key)
                run_rows.append(
                    {
                        "scenario_id": scenario_id,
                        "group_id": group_id,
                        "iteration": iteration,
                        "seed": effective_seed,
                        "trace_dir": str(scenario_trace_dir),
                        "observed_class": observed_class,
                        "observed_divergence": observed_divergence,
                        "evidence_source": evidence_source,
                        "latency_ms": effective_latency_ms,
                        "operator_decision": operator_decision,
                        "undo_result": undo_result,
                        "benchmark_mode": "live",
                        "detection_mode": args.detection_mode,
                        "target_ip": target_ip,
                    }
                )
                _progress(
                    "scenario_ok "
                    + f"id={scenario_id} "
                    + f"class={observed_class} "
                    + f"divergence={'true' if observed_divergence else 'false'} "
                    + f"source={evidence_source} "
                    + f"latency_ms={effective_latency_ms} "
                    + f"valid_runs={valid_runs} "
                    + f"skipped_runs={skipped_runs}"
                )
                _persist_resume_state(
                    "scenario_completed",
                    last_key=scenario_key,
                    last_status="ok",
                )
                _progress_state("resume_state")

    # Restore only the cron jobs that were enabled before the benchmark paused
    # them. Scenario-specific injection did not reconfigure schedules.
    cron_restore_log = trace_root / "cron_restore.log"
    _progress("restoring paused background cron jobs")
    cron_restore_ok = _restore_paused_crons_once(cron_restore_log)

    if valid_runs > 0:
        _summarize_results(results_path, summary_path)
    else:
        # Keep artifacts consistent even if nothing ran successfully.
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        _write_text(
            summary_path,
            json.dumps(
                {
                    "generated_at_utc": _now_utc_iso(),
                    "total_runs": 0,
                    "note": "No valid runs were produced. See run manifest and trace artifacts for details.",
                },
                indent=2,
            )
            + "\n",
        )

    benchmark_mode_counts: dict[str, int] = {}
    for row in run_rows:
        bm = str(row.get("benchmark_mode") or "unknown")
        benchmark_mode_counts[bm] = benchmark_mode_counts.get(bm, 0) + 1

    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest = {
        "run_id": run_id,
        "benchmark": "BadAgentUse",
        "mode": effective_mode,
        "benchmark_mode": "live",
        "resume_enabled": bool(resume_enabled),
        "resumed": bool(resumed),
        "resume_state_path": str(state_path),
        "detection_mode": args.detection_mode,
        "strict_proof": bool(args.strict_proof),
        "policy": "primary",
        "seed": args.seed,
        "iterations": args.iterations,
        "runner": runner,
        "git_sha": git_sha,
        "scenario_set_version": scenario_set_version,
        "scenario_dir": str(scenario_dir),
        "scenario_count": len(scenario_defs),
        "group_count": len(group_ids),
        "scenario_groups": [
            {
                "group_id": gid,
                "scenario_ids": [it["scenario_id"] for it in groups[gid]],
                "evidence_process": (groups[gid][0]["evidence_process"] or "").strip(),
            }
            for gid in group_ids
        ],
        "vm_name": args.vm_name,
        "posture": posture_build_info,
        "telemetry": args.telemetry,
        "kick_score": bool(args.kick_score),
        "generated_at_utc": _now_utc_iso(),
        "results": str(results_path),
        "summary": str(summary_path),
        "trace_root": str(trace_root),
        "cron": {
            "setup_log": str(cron_setup_log),
            "restore_log": str(cron_restore_log),
            "paused_jobs": [{"id": job.cron_id, "name": job.name} for job in paused_cron_jobs],
        },
        "counts": {
            "valid_runs": valid_runs,
            "skipped_runs": skipped_runs,
            "total_planned_runs": args.iterations * len(scenario_defs),
            "by_benchmark_mode": benchmark_mode_counts,
        },
        "runs": run_rows,
    }
    _write_text(manifest_path, json.dumps(manifest, indent=2) + "\n")

    print("============================================")
    print("  BadAgentUse Live Benchmark (Trace-Backed)")
    print("============================================")
    print(f"Run ID: {run_id}")
    print(f"Mode: {effective_mode}")
    print("Benchmark mode: live")
    print(f"Resume: {'yes' if resumed else 'no'}")
    print(f"Resume state: {state_path}")
    print(f"Detection mode: {args.detection_mode}")
    print(f"Strict proof: {'yes' if args.strict_proof else 'no'}")
    print(f"Posture version: {posture_build_info.get('version') or 'unknown'}")
    print(f"Posture build: {posture_build_info.get('build_mtime_utc') or 'unknown'}")
    print(f"Scenarios: {len(scenario_defs)}")
    print(f"Groups: {len(group_ids)}")
    print(f"Telemetry: {args.telemetry}")
    print(f"Kick score: {'yes' if args.kick_score else 'no'}")
    print(f"Iterations: {args.iterations}")
    print(f"Valid runs: {valid_runs}")
    print(f"Skipped runs: {skipped_runs}")
    print(f"Cron restore: {'ok' if cron_restore_ok else 'failed'}")
    print("")
    print(f"Results:  {results_path}")
    print(f"Summary:  {summary_path}")
    print(f"Manifest: {manifest_path}")
    print(f"Traces:   {trace_root}")

    # Exit semantics:
    # - strict mode: require full completion with zero skipped runs.
    # - non-strict mode: accept partial runs as long as at least one valid run exists.
    planned_runs = total_planned_runs
    _progress(
        f"complete run_id={run_id} valid_runs={valid_runs} skipped_runs={skipped_runs} planned_runs={planned_runs}"
    )
    _persist_resume_state("complete")
    if not cron_restore_ok:
        print("failed to restore paused background OpenClaw cron jobs", file=sys.stderr)
        return 1
    if args.strict_proof:
        return 0 if (valid_runs == planned_runs and skipped_runs == 0) else 3
    return 0 if valid_runs > 0 else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
