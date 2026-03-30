#!/usr/bin/env python3
import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Set


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def registry_path() -> Path:
    return repo_root() / "supported_agents" / "index.json"


def load_registry() -> Dict:
    return json.loads(registry_path().read_text(encoding="utf-8"))


def resolve_repo_path(agent: Dict) -> Path:
    env_var = ((agent.get("e2e") or {}).get("repo_env_var")) or ""
    if env_var and os.environ.get(env_var):
        return Path(os.environ[env_var]).expanduser()
    return repo_root().parent / agent["repo_name"]


def iter_agents(registry: Dict) -> List[Dict]:
    agents: List[Dict] = []
    for agent in registry.get("agents", []):
        enriched = dict(agent)
        enriched["sort_order"] = int(agent.get("sort_order") or 0)
        enriched["repo_path"] = str(resolve_repo_path(agent))
        agents.append(enriched)
    agents.sort(key=lambda a: (a["sort_order"], a["display_name"]))
    return agents


def iter_intent_agents(registry: Dict) -> List[Dict]:
    agents: List[Dict] = []
    for agent in iter_agents(registry):
        e2e = agent.get("e2e") or {}
        intent_script = e2e.get("intent_script")
        if not intent_script:
            continue
        repo_path = Path(agent["repo_path"])
        agents.append(
            {
                "agent_type": agent["agent_type"],
                "display_name": agent["display_name"],
                "repo_name": agent["repo_name"],
                "sort_order": agent["sort_order"],
                "repo_path": agent["repo_path"],
                "repo_env_var": e2e.get("repo_env_var"),
                "intent_script": str(repo_path / intent_script),
                "intent_timeout_seconds": int(e2e.get("intent_timeout_seconds") or 900),
            }
        )
    return agents


def cmd_types(_: argparse.Namespace) -> int:
    registry = load_registry()
    types = [agent["agent_type"] for agent in iter_agents(registry)]
    print(json.dumps(types))
    return 0


def cmd_get_agent(args: argparse.Namespace) -> int:
    registry = load_registry()
    for agent in iter_agents(registry):
        if agent["agent_type"] == args.agent_type:
            print(json.dumps(agent))
            return 0
    print(f"unknown agent_type: {args.agent_type}", file=sys.stderr)
    return 1


def cmd_list_intent(_: argparse.Namespace) -> int:
    print(json.dumps(iter_intent_agents(load_registry())))
    return 0


def cmd_validate(_: argparse.Namespace) -> int:
    registry = load_registry()
    repo = repo_root()
    errors: List[str] = []
    seen_types: Set[str] = set()

    for agent in registry.get("agents", []):
        agent_type = agent["agent_type"]
        if agent_type in seen_types:
            errors.append(f"duplicate agent_type in registry: {agent_type}")
        seen_types.add(agent_type)

        icon_relpath = agent.get("registry_icon_relpath")
        if icon_relpath:
            icon_path = repo / "supported_agents" / icon_relpath
            if not icon_path.is_file():
                errors.append(f"{agent_type}: missing registry icon {icon_path}")

        repo_path = resolve_repo_path(agent)
        if not repo_path.is_dir():
            errors.append(f"{agent_type}: missing repo directory {repo_path}")
            continue

        repo_scripts = agent.get("repo_scripts") or {}
        for field in ("install_unix", "install_windows", "uninstall_unix", "uninstall_windows"):
            relpath = repo_scripts.get(field)
            if relpath and not (repo_path / relpath).is_file():
                errors.append(f"{agent_type}: missing {field} at {repo_path / relpath}")

        healthcheck_relpath = repo_scripts.get("healthcheck_relpath")
        if healthcheck_relpath and not (repo_path / healthcheck_relpath).is_file():
            errors.append(
                f"{agent_type}: missing healthcheck_relpath at {repo_path / healthcheck_relpath}"
            )

        e2e = agent.get("e2e") or {}
        intent_script = e2e.get("intent_script")
        if intent_script and not (repo_path / intent_script).is_file():
            errors.append(f"{agent_type}: missing intent script at {repo_path / intent_script}")

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read the supported-agent registry for E2E harnesses.")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("types")
    get_agent = sub.add_parser("get-agent")
    get_agent.add_argument("--agent-type", required=True)
    sub.add_parser("list-intent")
    sub.add_parser("validate")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "types":
        return cmd_types(args)
    if args.command == "get-agent":
        return cmd_get_agent(args)
    if args.command == "list-intent":
        return cmd_list_intent(args)
    if args.command == "validate":
        return cmd_validate(args)
    parser.error(f"unknown command {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
