#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    target = repo_root / "tests" / "injectors" / "trigger_token_exfil.py"
    env = os.environ.copy()
    env["OPENCLAW_LEGACY_INJECTOR_PATH"] = str(Path(__file__).resolve())
    return subprocess.call([sys.executable, str(target), *sys.argv[1:]], env=env)


if __name__ == "__main__":
    raise SystemExit(main())
