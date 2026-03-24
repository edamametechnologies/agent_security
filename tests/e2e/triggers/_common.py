"""
Shared constants and helpers for parameterized E2E trigger scripts.

Each trigger accepts --agent-type (or reads EDAMAME_AGENT_TYPE env var)
to derive STATE_DIR and file-name prefixes. This module centralizes that
logic so individual triggers stay focused on their detection scenario.
"""

from __future__ import annotations

import os
import platform
from pathlib import Path

VALID_AGENT_TYPES = ("openclaw", "cursor", "claude_code")
DEFAULT_AGENT_TYPE = "openclaw"


def resolve_agent_type(cli_value: str | None) -> str:
    raw = (cli_value or "").strip() or os.environ.get("EDAMAME_AGENT_TYPE", "").strip()
    agent_type = raw or DEFAULT_AGENT_TYPE
    if agent_type not in VALID_AGENT_TYPES:
        raise SystemExit(
            f"Invalid agent type '{agent_type}'. "
            f"Valid: {', '.join(VALID_AGENT_TYPES)}"
        )
    return agent_type


def state_dir_for(agent_type: str) -> Path:
    name = f"edamame_{agent_type}_demo"
    if platform.system() == "Windows":
        return Path(os.environ.get("TEMP", "C:\\Temp")) / name
    return Path(f"/tmp/{name}")


def file_prefix_for(agent_type: str) -> str:
    return f"demo_{agent_type}"


def upper_prefix_for(agent_type: str) -> str:
    return f"DEMO_{agent_type.upper()}"
