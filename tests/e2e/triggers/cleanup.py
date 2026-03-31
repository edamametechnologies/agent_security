#!/usr/bin/env python3
"""
Stop all running demo injectors and remove files they created.

Reads PID files and created-file markers from the shared state directory,
terminates processes, and deletes only files that demo scripts produced.
"""

from __future__ import annotations

import argparse
import os
import platform
import signal
import sys
from pathlib import Path

from _common import resolve_agent_type, state_dir_for, file_prefix_for, upper_prefix_for

PID_FILES = [
    "blacklist_comm.pid",
    "cve_token_exfil.pid",
    "cve_sandbox.pid",
    "divergence.pid",
    "memory_poisoning.pid",
    "goal_drift.pid",
    "credential_sprawl.pid",
    "tool_poisoning.pid",
    "supply_chain_exfil.pid",
    "npm_rat_beacon.pid",
]

CREATED_MARKERS = [
    "blacklist_comm.created",
    "cve_token_exfil.created",
    "cve_sandbox.created",
    "divergence.created",
    "goal_drift.created",
    "memory_poisoning.created",
    "credential_sprawl.created",
    "tool_poisoning.created",
    "supply_chain_exfil.created",
    "npm_rat_beacon.created",
]


def parse_args():
    p = argparse.ArgumentParser(description="Clean up demo trigger state.")
    p.add_argument("--agent-type", default=None,
                   help="Agent type: openclaw|cursor|claude_code|claude_desktop (default: openclaw or EDAMAME_AGENT_TYPE)")
    p.add_argument("--state-dir", type=Path, default=None)
    return p.parse_args()


def kill_from_pid_file(pid_file: Path) -> None:
    if not pid_file.exists():
        return
    try:
        pid = int(pid_file.read_text("utf-8").strip())
    except (ValueError, OSError):
        pid_file.unlink(missing_ok=True)
        return

    try:
        if platform.system() == "Windows":
            os.kill(pid, signal.SIGTERM)
        else:
            os.kill(pid, signal.SIGTERM)
        print(f"  killed pid={pid} ({pid_file.name})")
    except ProcessLookupError:
        pass
    except PermissionError:
        print(f"  cannot kill pid={pid} (permission denied)")

    pid_file.unlink(missing_ok=True)


def remove_created_files(marker: Path) -> None:
    if not marker.exists():
        return
    for line in marker.read_text("utf-8").splitlines():
        path = line.strip()
        if not path:
            continue
        target = Path(path)
        if target.exists():
            try:
                target.unlink()
                print(f"  removed {target}")
            except OSError as e:
                print(f"  cannot remove {target}: {e}")
    marker.unlink(missing_ok=True)


def main() -> int:
    args = parse_args()
    agent_type = resolve_agent_type(args.agent_type)
    if args.state_dir is None:
        args.state_dir = state_dir_for(agent_type)
    state_dir = args.state_dir
    if not state_dir.exists():
        print("No demo state directory found; nothing to clean up.")
        return 0

    print(f"Cleaning up demo state in {state_dir}")

    for name in PID_FILES:
        kill_from_pid_file(state_dir / name)

    for name in CREATED_MARKERS:
        remove_created_files(state_dir / name)

    try:
        state_dir.rmdir()
        print(f"  removed {state_dir}")
    except OSError:
        remaining = list(state_dir.iterdir())
        if remaining:
            print(f"  state dir not empty ({len(remaining)} files remain)")

    print("Cleanup complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
