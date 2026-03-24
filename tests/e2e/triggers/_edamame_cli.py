#!/usr/bin/env python3
"""
Shared helper for calling edamame_cli RPC methods and parsing results.

RPC methods returning typed Rust structs (Vec<T>, ScoreAPI, etc.) produce
direct JSON.  Methods returning -> String (agentic domain: vuln findings,
divergence verdict, behavioral model) produce a JSON-encoded string
containing JSON, because the inner payload is pre-serialized.  This helper
detects which pattern was used and returns a parsed Python object in both
cases.

Usage as a library:
    from _edamame_cli import cli_rpc
    findings = cli_rpc("get_vulnerability_findings")

Usage from shell:
    python3 _edamame_cli.py get_vulnerability_findings
    python3 _edamame_cli.py get_anomalous_sessions
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def find_cli_binary() -> str:
    for candidate in [
        os.environ.get("EDAMAME_CLI_BIN", ""),
        os.environ.get("EDAMAME_CLI", ""),
    ]:
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate

    workspace = Path(__file__).resolve().parent.parent.parent.parent.parent
    for name in ("edamame_cli", "edamame-cli"):
        for profile in ("release", "debug"):
            p = workspace / "edamame_cli" / "target" / profile / name
            if p.is_file() and os.access(str(p), os.X_OK):
                return str(p)

    for name in ("edamame_cli", "edamame-cli"):
        for d in os.environ.get("PATH", "").split(os.pathsep):
            p = Path(d) / name
            if p.is_file() and os.access(str(p), os.X_OK):
                return str(p)

    raise FileNotFoundError(
        "edamame_cli not found. Set EDAMAME_CLI_BIN or ensure it is on PATH."
    )


def cli_rpc(method: str, args: str | None = None, timeout: float = 30.0) -> object:
    """Call an edamame_cli RPC method and return the parsed Python object."""
    cli = find_cli_binary()
    cmd = [cli, "rpc", method]
    if args:
        cmd.append(args)

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"edamame_cli rpc {method} failed (rc={result.returncode}): "
            f"{result.stderr.strip()}"
        )

    return _parse_cli_output(result.stdout)


def _parse_cli_output(raw: str) -> object:
    text = raw.strip()
    if text.startswith("Result: "):
        text = text[len("Result: "):]

    parsed = json.loads(text)

    if isinstance(parsed, str):
        return json.loads(parsed)

    return parsed


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <method> [json_args]", file=sys.stderr)
        sys.exit(1)

    method = sys.argv[1]
    rpc_args = sys.argv[2] if len(sys.argv) > 2 else None
    try:
        result = cli_rpc(method, rpc_args)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
