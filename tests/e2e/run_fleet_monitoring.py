#!/usr/bin/env python3
"""
Consolidated fleet monitoring E2E driver.

Installs every supported EDAMAME agent plugin from its checked-out repo,
bootstraps activity, and verifies that EDAMAME's host-side transcript
observer detects each agent, that pausing an agent's observer raises its
`unsecured_<agent>` internal threat, that the divergence engine reaches a
DIVERGENCE verdict against a seeded behavioral model, and that the host
blast-radius surface reports the expected structure.

This is the multi-agent, multi-platform counterpart to each plugin repo's
own `tests/e2e_inject_intent.sh` + per-repo `test_e2e.yml`. It reuses the
exact proven recipe (install -> pair PSK -> intent -> observer probe ->
divergence verdict) in a registry-driven loop and adds the net-new
host-blast-radius assertion.

Per-agent verification levels:
  - install            HARD  (the plugin must install from its repo)
  - observer detection HARD  (collected; the agent must become `discovered`)
  - unsecured toggle   HARD  (collected; pause -> threat active, resume -> inactive)
  - intent (LLM push)  SOFT  (behavioral-model push is the flaky LLM leg; warn only)

Fleet-wide verification (run once):
  - divergence verdict HARD  (seed model + trigger + assert DIVERGENCE)
  - host blast radius   HARD  (structural assertion on get_host_blast_radius)

HARD failures (per-agent install/detection/unsecured, or the fleet-wide
divergence/blast-radius legs) make the driver exit non-zero. SOFT failures
only print a warning. The driver loops over every agent before reporting,
so a single CI run surfaces all per-agent failures at once.

Prerequisites (set up by the calling workflow):
  - edamame_posture daemon running (disconnected mode + packet capture)
  - MCP server started on 127.0.0.1:3000 with a PSK
  - edamame_cli installed and reachable (EDAMAME_CLI env var)
  - each agent plugin repo checked out, with its <REPO_ENV_VAR> exported
    (e.g. CURSOR_REPO, CLAUDE_REPO, ...) so supported_agents can locate it
  - Node.js 18+ and Python 3 on PATH

Environment:
  EDAMAME_CLI              Path to edamame_cli binary (forwarded to children)
  EDAMAME_MCP_PSK          Daemon MCP PSK (written into each agent's PSK file)
  EDAMAME_AGENTS           Optional CSV of agent_types to restrict the run
  FLEET_REPRESENTATIVE     Agent type used for the divergence leg (default openclaw)
  FLEET_SKIP_DIVERGENCE    If "1", skip the divergence leg
  FLEET_SKIP_BLAST_RADIUS  If "1", skip the blast-radius leg
  FLEET_SCORE_WAIT_SECS    Seconds to wait for score recompute (default 8)
  GITHUB_RUN_ID            Used to derive a unique divergence agent_instance_id
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "triggers"))

from _edamame_cli import cli_rpc  # noqa: E402
import supported_agents as reg  # noqa: E402


# ── Logging ──────────────────────────────────────────────────────────────

def log(msg: str = "") -> None:
    print(msg, flush=True)


def section(msg: str) -> None:
    log("")
    log("=" * 70)
    log(msg)
    log("=" * 70)


def is_windows() -> bool:
    msystem = os.environ.get("MSYSTEM") or ""
    return platform.system() == "Windows" or msystem.startswith(("MINGW", "MSYS", "CYGWIN"))


# ── Subprocess helpers ───────────────────────────────────────────────────

def run_cmd(cmd: list[str], cwd: Path | None, env: dict | None, timeout: int | None) -> int:
    """Run a command, streaming output, returning the exit code (124 on timeout)."""
    log(f"  $ {' '.join(cmd)}")
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            env=full_env,
            timeout=timeout,
            text=True,
            capture_output=True,
        )
    except subprocess.TimeoutExpired as exc:
        if exc.stdout:
            sys.stdout.write(exc.stdout if isinstance(exc.stdout, str) else exc.stdout.decode("utf-8", "replace"))
        if exc.stderr:
            sys.stderr.write(exc.stderr if isinstance(exc.stderr, str) else exc.stderr.decode("utf-8", "replace"))
        log(f"  (timeout after {timeout}s)")
        return 124
    if proc.stdout:
        sys.stdout.write(proc.stdout)
    if proc.stderr:
        sys.stderr.write(proc.stderr)
    sys.stdout.flush()
    sys.stderr.flush()
    return proc.returncode


# ── Observer / score RPC helpers ─────────────────────────────────────────

def rpc_quiet(method: str, args: str | None = None) -> object | None:
    """Fire-and-forget RPC: swallow non-asserted failures, log a warning.

    Used for mutators whose return value the driver does not assert on
    (toggles, divergence engine control, capture start, ticks). The
    asserted reads (get_*) still go through cli_rpc directly so genuine
    failures surface.
    """
    try:
        return cli_rpc(method, args)
    except Exception as exc:  # noqa: BLE001
        log(f"  WARN: {method} failed: {exc}")
        return None


def observer_status() -> dict:
    st = cli_rpc("get_transcript_observer_status")
    return st if isinstance(st, dict) else {}


def observer_row(agent_type: str) -> dict | None:
    for row in observer_status().get("agents", []):
        if isinstance(row, dict) and row.get("agent_type") == agent_type:
            return row
    return None


def observer_tick(agent_type: str) -> dict | None:
    """Force a single-agent observer tick.

    `run_transcript_observer_tick_for` returns that agent's fresh status
    object directly, so the caller can use it without racing a follow-up
    get_transcript_observer_status read.
    """
    row = rpc_quiet("run_transcript_observer_tick_for", json.dumps({"agent_type": agent_type}))
    return row if isinstance(row, dict) else None


def set_observer_enabled(agent_type: str, enabled: bool) -> None:
    rpc_quiet("set_transcript_observer_enabled", json.dumps({"agent_type": agent_type, "enabled": enabled}))


def recompute_score() -> None:
    rpc_quiet("compute_score")


def threat_active(name: str) -> bool:
    score = cli_rpc("get_score", json.dumps({"complete_only": False}))
    if not isinstance(score, dict):
        return False
    active = score.get("active") or []
    return any(isinstance(t, dict) and t.get("name") == name for t in active)


# ── Per-agent steps ──────────────────────────────────────────────────────

def install_agent(agent: dict, repo_path: Path, workspace: Path) -> int:
    scripts = agent.get("repo_scripts") or {}
    requires_ws = bool(agent.get("requires_workspace_arg"))
    if is_windows():
        rel = scripts.get("install_windows")
        if not rel:
            log("  WARN: no install_windows script in registry")
            return 1
        script = repo_path / rel
        cmd = ["pwsh", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)]
        if requires_ws:
            cmd += ["-WorkspaceRoot", str(workspace)]
    else:
        rel = scripts.get("install_unix")
        if not rel:
            log("  WARN: no install_unix script in registry")
            return 1
        script = repo_path / rel
        cmd = ["bash", str(script)]
        if requires_ws:
            cmd += [str(workspace)]
    if not script.is_file():
        log(f"  FAIL: install script missing: {script}")
        return 1
    return run_cmd(cmd, cwd=repo_path, env=None, timeout=600)


def write_psk(paths: dict, psk: str) -> Path | None:
    """Write the daemon PSK into the agent's PSK file.

    Prefer the path declared by the installed config.json
    (`edamame_mcp_psk_file`); fall back to the registry-resolved psk_path.
    """
    if not psk:
        return None
    psk_path: Path | None = None
    config_json = paths.get("config_json")
    if config_json and Path(config_json).is_file():
        try:
            cfg = json.loads(Path(config_json).read_text(encoding="utf-8"))
            key = cfg.get("edamame_mcp_psk_file") or cfg.get("edamameMcpPskFile")
            if key:
                psk_path = Path(os.path.expanduser(str(key)))
        except Exception:  # noqa: BLE001
            pass
    if psk_path is None and paths.get("psk_path"):
        psk_path = Path(os.path.expanduser(paths["psk_path"]))
    if psk_path is None:
        return None
    psk_path.parent.mkdir(parents=True, exist_ok=True)
    psk_path.write_text(psk, encoding="utf-8")
    return psk_path


def run_intent(agent: dict, repo_path: Path) -> int:
    e2e = agent.get("e2e") or {}
    intent_rel = e2e.get("intent_script")
    if not intent_rel:
        log("  (no intent script in registry; skipping intent leg)")
        return 0
    script = repo_path / intent_rel
    if not script.is_file():
        log(f"  WARN: intent script missing: {script}")
        return 1
    timeout = int(e2e.get("intent_timeout_seconds") or 900)
    env = {
        "E2E_SKIP_PROVISION_STRICT": "1",
        "E2E_SKIP_PLUGIN_CHECK": "1",
        "E2E_SKIP_REPO_VERSION_CHECK": "1",
        "E2E_POLL_ATTEMPTS": os.environ.get("E2E_POLL_ATTEMPTS", "36"),
        "E2E_POLL_INTERVAL_SECS": os.environ.get("E2E_POLL_INTERVAL_SECS", "5"),
        "EDAMAME_MCP_PSK": os.environ.get("EDAMAME_MCP_PSK", ""),
        "EDAMAME_CLI": os.environ.get("EDAMAME_CLI", ""),
    }
    return run_cmd(["bash", str(script)], cwd=repo_path, env=env, timeout=timeout)


def verify_detection(agent_type: str, row_before: dict | None) -> tuple[bool, dict | None]:
    """Tick the observer and confirm the agent is `discovered`.

    Fallback: if not discovered but the observer advertised a transcripts
    root it could not access, create that root + a tiny probe transcript and
    re-tick. This is registry-free (uses the observer's own advertised root)
    and only nudges discovery; it never fabricates behavioral content.
    """
    row = observer_tick(agent_type) or observer_row(agent_type)
    if row and bool(row.get("discovered")):
        return True, row
    roots = (row or {}).get("last_transcripts_roots") or []
    if roots:
        try:
            root = Path(os.path.expanduser(str(roots[0])))
            root.mkdir(parents=True, exist_ok=True)
            probe = root / "edamame_e2e_probe.jsonl"
            if not probe.exists():
                probe.write_text(
                    '{"role":"user","content":"edamame fleet e2e discovery probe"}\n',
                    encoding="utf-8",
                )
            log(f"  (discovery fallback: seeded advertised root {root})")
        except Exception as exc:  # noqa: BLE001
            log(f"  WARN: discovery fallback failed: {exc}")
        row = observer_tick(agent_type) or observer_row(agent_type)
    return bool(row and row.get("discovered")), row


def verify_unsecured_toggle(agent_type: str, score_wait: int) -> tuple[bool, str]:
    name = f"unsecured_{agent_type}"
    set_observer_enabled(agent_type, False)
    observer_tick(agent_type)
    recompute_score()
    time.sleep(score_wait)
    active_when_paused = threat_active(name)

    set_observer_enabled(agent_type, True)
    observer_tick(agent_type)
    recompute_score()
    time.sleep(score_wait)
    inactive_when_resumed = not threat_active(name)

    ok = active_when_paused and inactive_when_resumed
    detail = f"paused_active={active_when_paused} resumed_inactive={inactive_when_resumed}"
    return ok, detail


# ── Fleet-wide legs ──────────────────────────────────────────────────────

def assert_blast_radius() -> tuple[bool, str]:
    br = cli_rpc("get_host_blast_radius")
    if not isinstance(br, dict):
        return False, "blast radius did not return an object"
    required = {"host_privilege", "agent_sandboxes", "harnesses", "blast_radius_agents"}
    missing = required - set(br)
    if missing:
        return False, f"missing keys: {sorted(missing)}"
    hp = br.get("host_privilege") or {}
    if hp.get("assessed") is not True:
        return False, "host_privilege.assessed is not true"
    sandboxes = br.get("agent_sandboxes")
    if not isinstance(sandboxes, list) or not sandboxes:
        return False, "agent_sandboxes is empty"
    if not isinstance(br.get("blast_radius_agents"), list):
        return False, "blast_radius_agents is not a list"
    if not isinstance(br.get("harnesses"), list):
        return False, "harnesses is not a list"
    detail = (
        f"sandboxes={len(sandboxes)} "
        f"blast_radius_agents={len(br['blast_radius_agents'])} "
        f"harnesses={len(br['harnesses'])} "
        f"platform={hp.get('platform')} passwordless_root={hp.get('passwordless_root')}"
    )
    return True, detail


def _divergence_window(agent_type: str, agent_instance_id: str) -> dict:
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    blocked = [f"one.one.one.one:{p}" for p in range(63169, 63184)]
    blocked += [f"1.0.0.1:{p}" for p in range(63169, 63184)]
    blocked += [f"one.one.one.one:{p}" for p in range(63200, 63215)]
    blocked += [f"1.1.1.1:{p}" for p in range(63200, 63215)]
    return {
        "window_start": (now - datetime.timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
        "window_end": (now - datetime.timedelta(minutes=4)).isoformat().replace("+00:00", "Z"),
        "agent_type": agent_type,
        "agent_instance_id": agent_instance_id,
        "predictions": [
            {
                "agent_type": agent_type,
                "agent_instance_id": agent_instance_id,
                "session_key": "e2e_divergence_probe_scope",
                "action": "Workflow divergence probe scope",
                "tools_called": ["run"],
                "scope_process_paths": ["*/divergence_probe*"],
                "scope_parent_paths": [],
                "scope_grandparent_paths": [],
                "scope_any_lineage_paths": [],
                "expected_traffic": ["api.anthropic.com:443"],
                "expected_sensitive_files": [],
                "expected_lan_devices": [],
                "expected_local_open_ports": [],
                "expected_process_paths": ["*/divergence_probe*"],
                "expected_parent_paths": [],
                "expected_grandparent_paths": [],
                "expected_open_files": [],
                "expected_l7_protocols": [],
                "expected_system_config": [],
                "not_expected_traffic": blocked,
                "not_expected_sensitive_files": [],
                "not_expected_lan_devices": [],
                "not_expected_local_open_ports": [],
                "not_expected_process_paths": [],
                "not_expected_parent_paths": [],
                "not_expected_grandparent_paths": [],
                "not_expected_open_files": [],
                "not_expected_l7_protocols": [],
                "not_expected_system_config": [],
                "raw_input": None,
            }
        ],
        "contributors": [],
        "version": "e2e/divergence-probe",
        "hash": "",
        "ingested_at": now.isoformat().replace("+00:00", "Z"),
    }


def _divergence_status() -> tuple[bool, int, int]:
    s = cli_rpc("get_divergence_engine_status")
    if not isinstance(s, dict):
        return False, 0, 0
    return (
        bool(s.get("running")),
        int(s.get("contributor_count") or 0),
        int(s.get("model_age_secs") or 0),
    )


def run_divergence(agent_type: str, triggers_dir: Path, min_age: int = 65) -> tuple[bool, str]:
    run_id = os.environ.get("GITHUB_RUN_ID", "local")
    agent_instance_id = f"e2e-divergence-ci-{agent_type}-{run_id}"
    trigger = triggers_dir / "trigger_divergence.py"
    if not trigger.is_file():
        return False, f"trigger_divergence.py not found at {trigger}"

    log("--- Starting packet capture ---")
    rpc_quiet("start_capture")
    time.sleep(10)

    log("--- Seeding divergence harness model ---")
    rpc_quiet("clear_divergence_state")
    rpc_quiet("clear_divergence_history")
    rpc_quiet("start_divergence_engine", "[true, 300]")
    window = _divergence_window(agent_type, agent_instance_id)
    rpc_quiet("upsert_behavioral_model", json.dumps({"window_json": json.dumps(window)}))

    log("--- Waiting for divergence model readiness ---")
    waited = 0
    max_wait = min_age + 60
    while waited <= max_wait:
        running, contrib, age = _divergence_status()
        if running and contrib > 0 and age >= min_age:
            break
        log(f"  divergence model warming: running={running} contributors={contrib} age={age}s")
        time.sleep(5)
        waited += 5
    else:
        return False, "divergence model did not become ready"

    log("--- Starting divergence trigger (60s) ---")
    proc = subprocess.Popen(
        [sys.executable, str(trigger), "--agent-type", agent_type, "--duration", "60"]
    )
    try:
        log("--- Waiting 30s for session ingestion ---")
        time.sleep(30)

        log("--- Checking divergence verdict semantics ---")
        verdict = ""
        for attempt in range(1, 13):
            rpc_quiet("debug_run_divergence_tick")
            summary = cli_rpc("get_divergence_verdict")
            if isinstance(summary, str):
                summary = json.loads(summary)
            verdict = str((summary or {}).get("verdict") or "").strip().upper()
            evidence = (summary or {}).get("evidence") or []
            categories = {
                str(item.get("category") or "").strip()
                for item in evidence
                if isinstance(item, dict)
            }
            running, contrib, age = _divergence_status()
            ok = (
                verdict == "DIVERGENCE"
                and running
                and contrib > 0
                and age >= min_age
                and "correlation:not_expected" in categories
            )
            log(
                f"  attempt {attempt}/12: verdict={verdict or 'NONE'} running={running} "
                f"contributors={contrib} age={age}s "
                f"categories={','.join(sorted(c for c in categories if c)) or 'none'}"
            )
            if ok:
                return True, f"verdict=DIVERGENCE age={age}s contributors={contrib}"
            time.sleep(10)
        return False, f"verdict not satisfied (last verdict={verdict or 'NONE'})"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:  # noqa: BLE001
            proc.kill()
        cleanup = triggers_dir / "cleanup.py"
        if cleanup.is_file():
            run_cmd([sys.executable, str(cleanup), "--agent-type", agent_type], cwd=None, env=None, timeout=60)


# ── Main ─────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Consolidated EDAMAME fleet monitoring E2E driver.")
    p.add_argument(
        "--agents",
        default=os.environ.get("EDAMAME_AGENTS", ""),
        help="Optional CSV of agent_types to run (default: all in registry).",
    )
    p.add_argument(
        "--representative-agent",
        default=os.environ.get("FLEET_REPRESENTATIVE", "openclaw"),
        help="Agent type used for the divergence leg (default: openclaw).",
    )
    p.add_argument("--skip-divergence", action="store_true", default=os.environ.get("FLEET_SKIP_DIVERGENCE") == "1")
    p.add_argument("--skip-blast-radius", action="store_true", default=os.environ.get("FLEET_SKIP_BLAST_RADIUS") == "1")
    p.add_argument("--skip-install", action="store_true", help="Skip install/intent legs (detection only; local dev).")
    p.add_argument("--score-wait", type=int, default=int(os.environ.get("FLEET_SCORE_WAIT_SECS", "8")))
    return p.parse_args()


def main() -> int:
    args = parse_args()
    registry = reg.load_registry()
    agents = reg.iter_agents(registry)

    wanted = {a.strip() for a in args.agents.split(",") if a.strip()}
    if wanted:
        agents = [a for a in agents if a["agent_type"] in wanted]
    if not agents:
        log("FAIL: no agents selected")
        return 1

    psk = os.environ.get("EDAMAME_MCP_PSK", "")
    workspace = Path(os.environ.get("GITHUB_WORKSPACE", os.getcwd())).resolve()
    score_wait = args.score_wait

    section("EDAMAME fleet monitoring E2E")
    log(f"Agents: {', '.join(a['agent_type'] for a in agents)}")
    log(f"Platform: {platform.system()}  Workspace: {workspace}")
    log(f"edamame_cli: {os.environ.get('EDAMAME_CLI', '(auto)')}")

    # Sanity: the core must be reachable before we start.
    try:
        observer_status()
    except Exception as exc:  # noqa: BLE001
        log(f"FAIL: cannot reach edamame core via edamame_cli: {exc}")
        return 1

    results: dict[str, dict] = {}

    for agent in agents:
        agent_type = agent["agent_type"]
        repo_path = Path(agent["repo_path"])
        section(f"Agent: {agent_type}  ({agent['display_name']})")
        log(f"Repo: {repo_path}")

        res = {"install": None, "detected": None, "unsecured": None, "intent": None, "notes": []}
        results[agent_type] = res

        if not repo_path.is_dir():
            log(f"FAIL: repo not found at {repo_path} (set {((agent.get('e2e') or {}).get('repo_env_var')) or 'the repo env var'})")
            res["install"] = False
            res["notes"].append("repo missing")
            continue

        try:
            paths = reg.resolve_install_paths(agent)
        except Exception as exc:  # noqa: BLE001
            log(f"WARN: could not resolve install paths: {exc}")
            paths = {}

        if args.skip_install:
            log("--- Skipping install/intent (--skip-install) ---")
            res["install"] = True
        else:
            log("--- Install ---")
            rc = install_agent(agent, repo_path, workspace)
            res["install"] = rc == 0
            if rc != 0:
                log(f"FAIL: install returned {rc}")
                res["notes"].append("install failed")
                continue
            log("  install OK")

            psk_file = write_psk(paths, psk)
            if psk_file:
                log(f"  PSK written: {psk_file}")

            log("--- Intent (LLM behavioral-model push; SOFT) ---")
            rc = run_intent(agent, repo_path)
            res["intent"] = rc == 0
            if rc != 0:
                log(f"  WARN: intent leg returned {rc} (non-fatal; native transcripts still written for discovery)")

        log("--- Observer detection ---")
        detected, row = verify_detection(agent_type, observer_row(agent_type))
        res["detected"] = detected
        if row is not None:
            res["notes"].append(
                f"discovered={row.get('discovered')} sessions={row.get('last_session_count')} "
                f"roots={row.get('last_transcripts_roots')}"
            )
        if detected:
            log(f"  OK: {agent_type} discovered (sessions={row.get('last_session_count') if row else '?'})")
        else:
            log(f"  FAIL: {agent_type} not discovered by observer")
            continue

        log("--- Unsecured threat toggle ---")
        ok, detail = verify_unsecured_toggle(agent_type, score_wait)
        res["unsecured"] = ok
        if ok:
            log(f"  OK: unsecured_{agent_type} toggles correctly ({detail})")
        else:
            log(f"  FAIL: unsecured_{agent_type} did not toggle ({detail})")

    # ── Fleet-wide legs ───────────────────────────────────────────────
    divergence_ok = None
    if not args.skip_divergence:
        section(f"Divergence verdict (representative agent: {args.representative_agent})")
        triggers_dir = HERE / "triggers"
        try:
            divergence_ok, detail = run_divergence(args.representative_agent, triggers_dir)
        except Exception as exc:  # noqa: BLE001
            divergence_ok, detail = False, f"exception: {exc}"
        log(("PASS: " if divergence_ok else "FAIL: ") + f"divergence -- {detail}")

    blast_ok = None
    if not args.skip_blast_radius:
        section("Host blast radius")
        try:
            blast_ok, detail = assert_blast_radius()
        except Exception as exc:  # noqa: BLE001
            blast_ok, detail = False, f"exception: {exc}"
        log(("PASS: " if blast_ok else "FAIL: ") + f"blast radius -- {detail}")

    # ── Summary ───────────────────────────────────────────────────────
    section("Fleet monitoring summary")
    hard_failures = 0
    log(f"{'agent':<16} {'install':<9} {'detected':<10} {'unsecured':<11} {'intent':<8}")
    log("-" * 60)

    def cell(v):
        if v is None:
            return "-"
        return "OK" if v else "FAIL"

    for agent_type, res in results.items():
        log(
            f"{agent_type:<16} {cell(res['install']):<9} {cell(res['detected']):<10} "
            f"{cell(res['unsecured']):<11} {cell(res['intent']):<8}"
        )
        for note in res["notes"]:
            log(f"    {note}")
        # HARD: install, detected, unsecured (intent is SOFT)
        if res["install"] is False:
            hard_failures += 1
        if res["detected"] is False:
            hard_failures += 1
        if res["unsecured"] is False:
            hard_failures += 1

    log("")
    log(f"divergence:   {cell(divergence_ok)}")
    log(f"blast radius: {cell(blast_ok)}")
    if divergence_ok is False:
        hard_failures += 1
    if blast_ok is False:
        hard_failures += 1

    log("")
    if hard_failures:
        log(f"RESULT: FAIL ({hard_failures} hard failure(s))")
        return 1
    log("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
