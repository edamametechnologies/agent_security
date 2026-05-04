#!/bin/bash
# Shared helper: deploy /tmp/mcp_call.py and /tmp/mcp_direct.py inside the Lima VM.
#
# mcp_call.py  — routes through the OpenClaw gateway (tools/invoke).
# mcp_direct.py — calls the EDAMAME MCP server directly (port 3000).
#                 Used for engine-internal tools not exposed by the gateway.
#
# Also provides convenience wrappers for divergence engine tools.
#
# Requires vm_exec() from tests/lib/vm_exec.sh.

sync_openclaw_skill_state() {
    vm_exec 'set -euo pipefail
OPENCLAW_HOME="$HOME/.openclaw"
SKILLS_DIR="$OPENCLAW_HOME/skills"
EXT_DIR="$OPENCLAW_HOME/extensions/edamame-mcp"
SRC_ROOT="${AGENT_SECURITY_ROOT:-$HOME/Programming/agent_security}"
SRC_OPENCLAW="${EDAMAME_OPENCLAW_ROOT:-$HOME/Programming/edamame_openclaw}"
SRC_SKILLS="$SRC_OPENCLAW/skill"
SRC_EXT="$SRC_OPENCLAW/extensions/edamame-mcp"

mkdir -p "$SKILLS_DIR" "$OPENCLAW_HOME/extensions"

# Remove stale EDAMAME skill directories that can mask current behavior,
# including the legacy edamame-extrapolator skill that has been removed in
# favour of the compiled extrapolator_run_cycle plugin tool plus EDAMAME's
# host-side transcript observer.
for stale_dir in "$SKILLS_DIR"/edamame-*; do
    [ -d "$stale_dir" ] || continue
    stale_base="$(basename "$stale_dir")"
    case "$stale_base" in
        edamame-posture) ;;
        *) rm -rf "$stale_dir" ;;
    esac
done

# Always refresh current skills from source-of-truth in this workspace.
for skill in edamame-posture; do
    if [ ! -f "$SRC_SKILLS/$skill/SKILL.md" ]; then
        echo "ERROR: missing source skill file: $SRC_SKILLS/$skill/SKILL.md" >&2
        exit 1
    fi
    rm -rf "$SKILLS_DIR/$skill"
    cp -R "$SRC_SKILLS/$skill" "$SKILLS_DIR/$skill"
done

# Refresh plugin wrapper source so gateway resolves current skill names.
if [ ! -f "$SRC_EXT/openclaw.plugin.json" ] || [ ! -f "$SRC_EXT/index.ts" ]; then
    echo "ERROR: missing extension source files in $SRC_EXT" >&2
    exit 1
fi
rm -rf "$EXT_DIR"
mkdir -p "$EXT_DIR"
cp "$SRC_EXT/openclaw.plugin.json" "$EXT_DIR/openclaw.plugin.json"
cp "$SRC_EXT/index.ts" "$EXT_DIR/index.ts"

# Mirror bundled skills under the extension path to satisfy plugin skill lookup.
mkdir -p "$EXT_DIR/skills"
for skill in edamame-posture; do
    mkdir -p "$EXT_DIR/skills/$skill"
    cp "$SRC_SKILLS/$skill/SKILL.md" "$EXT_DIR/skills/$skill/SKILL.md"
    if [ -f "$SRC_SKILLS/$skill/clawhub.json" ]; then
        cp "$SRC_SKILLS/$skill/clawhub.json" "$EXT_DIR/skills/$skill/clawhub.json"
    fi
done

# Pin explicit plugin trust to avoid auto-load warnings.
python3 - <<'"'"'PYEOF'"'"'
import json
import os

cfg_path = os.path.expanduser("~/.openclaw/openclaw.json")
if not os.path.exists(cfg_path):
    raise SystemExit(f"ERROR: missing OpenClaw config: {cfg_path}")

with open(cfg_path, "r", encoding="utf-8") as f:
    cfg = json.load(f)

plugins = cfg.setdefault("plugins", {})
allow = plugins.get("allow")
if not isinstance(allow, list):
    allow = []
if "edamame-mcp" not in allow:
    allow.append("edamame-mcp")
plugins["allow"] = allow
entries = plugins.setdefault("entries", {})
# Scrub invalid keys (for example experimental `path`) to keep config valid.
entries["edamame-mcp"] = {"enabled": True}

# Keep test runs deterministic; cron skills do not require memorySearch.
agents = cfg.setdefault("agents", {})
defaults = agents.setdefault("defaults", {})
memory_search = defaults.get("memorySearch")
if not isinstance(memory_search, dict):
    memory_search = {}
memory_search["enabled"] = False
defaults["memorySearch"] = memory_search

with open(cfg_path, "w", encoding="utf-8") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
PYEOF

# Verify no stale plugin skill references remain.
python3 - <<'"'"'PYEOF'"'"'
import json
import os

manifest = os.path.expanduser("~/.openclaw/extensions/edamame-mcp/openclaw.plugin.json")
with open(manifest, "r", encoding="utf-8") as f:
    data = json.load(f)
skills = data.get("skills") or []

if "skills/edamame-posture" not in skills:
    raise SystemExit("ERROR: plugin manifest missing skills/edamame-posture")

# edamame-extrapolator was removed; flag any leftover references and any other
# unknown edamame-* skills.
expected = {"skills/edamame-posture"}
unexpected = [
    s for s in skills
    if isinstance(s, str) and s.startswith("skills/edamame-") and s not in expected
]
if unexpected:
    raise SystemExit(
        "ERROR: stale skill reference remains in plugin manifest: " + ", ".join(unexpected)
    )
PYEOF

export PATH="$HOME/.npm-global/bin:$PATH"
openclaw plugins enable edamame-mcp >/dev/null 2>&1 || true
if ss -tln 2>/dev/null | grep -q ":18789 "; then
    openclaw gateway restart >/tmp/openclaw-gateway-restart.log 2>&1 || true
fi
'
}

ensure_mcp_direct_helper() {
    vm_exec 'cat > /tmp/mcp_direct.py << '"'"'PYEOF'"'"'
# mcp_direct.py - Invoke MCP tools directly on the EDAMAME MCP server.
# Bypasses the OpenClaw gateway. Used for engine-internal tools (divergence
# engine management, behavioral model) that are not exposed by the gateway.

import json
import os
import sys
import urllib.error
import urllib.request

_REQ_ID = 1
_SESSION_ID = None
_PSK = None

def _read_psk():
    env = os.environ.get("EDAMAME_MCP_PSK", "").strip()
    if env:
        return env
    psk_path = os.path.expanduser("~/.edamame_psk")
    try:
        with open(psk_path, "r") as f:
            return f.read().strip()
    except Exception:
        return ""

def _post(endpoint, body, psk, session_id=None, timeout=30):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": "Bearer " + psk,
    }
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(endpoint, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        ct = resp.headers.get("Content-Type", "")
        sid = resp.headers.get("Mcp-Session-Id", "")
        raw = resp.read().decode("utf-8", "replace")
        if "text/event-stream" in ct:
            for line in raw.splitlines():
                if line.startswith("data:"):
                    chunk = line[5:].strip()
                    if chunk:
                        try:
                            return json.loads(chunk), sid
                        except json.JSONDecodeError:
                            pass
            return None, sid
        return json.loads(raw) if raw.strip() else None, sid

def _initialize(endpoint, psk):
    global _REQ_ID, _SESSION_ID
    body = {
        "jsonrpc": "2.0", "id": _REQ_ID, "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "mcp_direct_test", "version": "0.1"},
        },
    }
    _REQ_ID += 1
    resp, sid = _post(endpoint, body, psk)
    _SESSION_ID = sid or None
    notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    _post(endpoint, notif, psk, _SESSION_ID, timeout=10)

def main():
    global _REQ_ID, _PSK
    endpoint = os.environ.get("EDAMAME_MCP_ENDPOINT", "http://127.0.0.1:3000/mcp")
    _PSK = _read_psk()
    if not _PSK:
        sys.stderr.write("ERROR: no PSK found (~/.edamame_psk or EDAMAME_MCP_PSK)\n")
        sys.exit(2)
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: python3 mcp_direct.py <tool_name> [json_args]\n")
        sys.exit(1)
    tool = sys.argv[1]
    args = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}

    _initialize(endpoint, _PSK)
    body = {
        "jsonrpc": "2.0", "id": _REQ_ID, "method": "tools/call",
        "params": {"name": tool, "arguments": args},
    }
    _REQ_ID += 1
    resp, _ = _post(endpoint, body, _PSK, _SESSION_ID, timeout=60)
    if not resp:
        print("ERROR: empty_response")
        sys.exit(1)
    if resp.get("error"):
        print("ERROR: " + resp["error"].get("message", str(resp["error"])))
        sys.exit(1)
    result = resp.get("result", {})
    content = result.get("content", [])
    for item in content:
        if item.get("type") == "text":
            print(item["text"])
            return
    print(json.dumps(result))

if __name__ == "__main__":
    main()
PYEOF
chmod +x /tmp/mcp_direct.py
test -f /tmp/mcp_direct.py
'
}

ensure_mcp_call_helper() {
    sync_openclaw_skill_state

    vm_exec 'cat > /tmp/mcp_call.py << '"'"'PYEOF'"'"'
# mcp_call.py - Invoke MCP tools via OpenClaw gateway (tools/invoke).
# Uses ~/.openclaw/openclaw.json for gateway.auth.token. Stdlib only.

import json
import os
import sys
import urllib.error
import urllib.request

def main():
    cfg_path = os.path.expanduser("~/.openclaw/openclaw.json")
    if not os.path.isfile(cfg_path):
        sys.stderr.write("ERROR: openclaw config not found: " + cfg_path + "\n")
        sys.exit(2)
    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception as e:
        sys.stderr.write("ERROR: unable to read openclaw config: " + str(e) + "\n")
        sys.exit(2)
    token = cfg.get("gateway", {}).get("auth", {}).get("token", "")
    if not token:
        sys.stderr.write("ERROR: no gateway.auth.token in openclaw config\n")
        sys.exit(2)

    if len(sys.argv) < 2:
        sys.stderr.write("Usage: python3 mcp_call.py <tool_name> [json_args]\n")
        sys.exit(1)
    tool = sys.argv[1]
    args = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}

    url = "http://127.0.0.1:18789/tools/invoke"
    payload = json.dumps({"tool": tool, "args": args}).encode("utf-8")
    headers = {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
    }
    req = urllib.request.Request(url, data=payload, headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            body = str(e)
        msg = "ERROR: gateway_http_" + str(getattr(e, "code", "?")) + ": " + body[:2000]
        print(msg)
        sys.exit(1)
    except Exception as e:
        print("ERROR: gateway_" + str(e))
        sys.exit(1)

    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        print(body.strip())
        return

    content = data.get("content") or data.get("result", {}).get("content")
    if content and isinstance(content, list) and len(content) > 0:
        text = content[0].get("text", "")
        if text:
            print(text)
            return
    print(body.strip())

if __name__ == "__main__":
    main()
PYEOF
chmod +x /tmp/mcp_call.py
test -f /tmp/mcp_call.py
'

    ensure_mcp_direct_helper
}

vm_transport_error() {
    local raw="${1:-}"
    printf '%s' "$raw" | grep -Eiq \
        'connection timed out during banner exchange|kex_exchange_identification|connection reset by peer|connection closed by|ssh: connect to host|broken pipe|operation timed out'
}

mcp_vm_exec_retry() {
    local command="$1"
    local attempts="${2:-4}"
    local attempt
    local out=""

    for attempt in $(seq 1 "$attempts"); do
        out=$(vm_exec "$command" 2>&1 || true)
        if [ -n "$out" ] && ! vm_transport_error "$out"; then
            printf '%s\n' "$out"
            return 0
        fi
        sleep "$attempt"
    done

    printf '%s\n' "$out"
    return 0
}

mcp_response_error() {
    local raw="${1:-}"
    printf '%s' "$raw" | grep -Eiq '(^ERROR:|tool not found|gateway_http_|"error"[[:space:]]*:)'
}

mcp_vm_exec_checked() {
    local command="$1"
    local attempts="${2:-4}"
    local out

    out="$(mcp_vm_exec_retry "$command" "$attempts")"
    printf '%s\n' "$out"
    if mcp_response_error "$out"; then
        return 1
    fi
    return 0
}

# Poll get_divergence_verdict until a non-NO_MODEL verdict appears or timeout.
# Outputs the raw JSON verdict on success.
# Usage: poll_divergence_verdict [max_wait_secs] [interval_secs]
poll_divergence_verdict() {
    local max_wait="${1:-300}"
    local interval="${2:-15}"
    local elapsed=0
    local verdict_json=""
    while [ $elapsed -lt $max_wait ]; do
        sleep "$interval"
        elapsed=$((elapsed + interval))
        verdict_json=$(mcp_vm_exec_retry 'python3 /tmp/mcp_direct.py get_divergence_verdict "{}" 2>&1' 4)
        local verdict_kind
        verdict_kind=$(echo "$verdict_json" | python3 -c "
import json, sys
try:
    v = json.loads(sys.stdin.read())
    raw = str(v.get('verdict', 'ERROR') or 'ERROR')
    print(raw.upper())
except Exception:
    print('ERROR')
" 2>/dev/null || echo "ERROR")
        if [ "$verdict_kind" != "NO_MODEL" ] \
            && [ "$verdict_kind" != "NOMODEL" ] \
            && [ "$verdict_kind" != "ERROR" ] \
            && [ "$verdict_kind" != "NULL" ]; then
            echo "$verdict_json"
            return 0
        fi
        printf "." >&2
    done
    echo >&2
    echo "$verdict_json"
    return 1
}

# Read-only/model tools — called directly against EDAMAME MCP (not through gateway).

# Push a behavioral model JSON to the divergence engine via upsert_behavioral_model.
# Usage: push_behavioral_model '<BehavioralWindow JSON>'
push_behavioral_model() {
    local window_json="$1"
    local escaped
    escaped=$(echo "$window_json" | python3 -c "import json,sys; print(json.dumps(sys.stdin.read().strip()))" 2>/dev/null)
    mcp_vm_exec_retry "python3 /tmp/mcp_direct.py upsert_behavioral_model '{\"window_json\":$escaped}' 2>&1" 4
}

# Get the current behavioral model from the engine (raw JSON output).
# Usage: result=$(fetch_behavioral_model)
fetch_behavioral_model() {
    mcp_vm_exec_retry 'python3 /tmp/mcp_direct.py get_behavioral_model 2>&1' 4
}

# Clear behavioral model, verdict history, and engine state.
# Usage: clear_divergence_state
clear_divergence_state() {
    mcp_vm_exec_retry 'python3 /tmp/mcp_direct.py clear_divergence_state "{}" 2>&1' 4
}

# Get the divergence engine status (raw JSON output).
# Usage: result=$(fetch_engine_status)
fetch_engine_status() {
    mcp_vm_exec_retry 'python3 /tmp/mcp_direct.py get_divergence_engine_status 2>&1' 4
}

# Get the latest divergence verdict (raw JSON output, single shot).
# Usage: result=$(fetch_divergence_verdict)
fetch_divergence_verdict() {
    mcp_vm_exec_retry 'python3 /tmp/mcp_direct.py get_divergence_verdict "{}" 2>&1' 4
}

# Start/stop the model-independent vulnerability detector.
# Usage: start_vulnerability_detector_loop true 30
start_vulnerability_detector_loop() {
    local enabled="${1:-true}"
    local interval="${2:-60}"
    if [ "$enabled" = "true" ]; then
        vm_exec "edamame_posture background-vulnerability-start '$interval'"
    else
        vm_exec "edamame_posture background-vulnerability-stop"
    fi
}

# Force a single vulnerability detector cycle immediately.
# Usage: run_vulnerability_detector_tick_direct
run_vulnerability_detector_tick_direct() {
    mcp_vm_exec_checked 'python3 /tmp/mcp_direct.py debug_run_vulnerability_detector_tick "{}" 2>&1' 4
}

# Read current vulnerability detector status.
# Usage: result=$(fetch_vulnerability_detector_status)
fetch_vulnerability_detector_status() {
    vm_exec 'edamame_posture background-vulnerability-status'
}

# Read latest vulnerability findings summary.
# Usage: result=$(fetch_vulnerability_findings)
fetch_vulnerability_findings() {
    mcp_vm_exec_checked 'python3 /tmp/mcp_direct.py get_vulnerability_findings 2>&1' 4
}

# Read recent vulnerability history summaries.
# Usage: result=$(fetch_vulnerability_history 5)
fetch_vulnerability_history() {
    local limit="${1:-5}"
    mcp_vm_exec_checked \
        "python3 /tmp/mcp_direct.py get_vulnerability_history '{\"limit\": $limit}' 2>&1" \
        4
}

# Read vulnerability debug trace for a specific report id.
# Usage: result=$(fetch_vulnerability_debug_trace "$report_id")
fetch_vulnerability_debug_trace() {
    local report_id="$1"
    local escaped
    escaped=$(printf '%s' "$report_id" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')
    mcp_vm_exec_checked \
        "python3 /tmp/mcp_direct.py get_vulnerability_debug_trace '{\"report_id\": $escaped}' 2>&1" \
        4
}

# Clear persisted vulnerability history.
# Usage: clear_vulnerability_history_direct
clear_vulnerability_history_direct() {
    mcp_vm_exec_checked 'python3 /tmp/mcp_direct.py clear_vulnerability_history "{}" 2>&1' 4
}

# Reset dismissed/suppressed vulnerability findings.
# Usage: reset_vulnerability_suppressions_direct
reset_vulnerability_suppressions_direct() {
    mcp_vm_exec_checked 'python3 /tmp/mcp_direct.py reset_vulnerability_suppressions "{}" 2>&1' 4
}

# Start/stop the divergence engine via edamame_posture CLI (not MCP).
# Usage: start_divergence_engine true 60
start_divergence_engine() {
    local enabled="${1:-true}"
    local interval="${2:-60}"
    if [ "$enabled" = "true" ]; then
        vm_exec "edamame_posture divergence-start \"$interval\" 2>&1"
    else
        vm_exec "edamame_posture divergence-stop 2>&1"
    fi
}

# Disable LAN auto-scan to prevent network saturation in the Lima VM.
# The daemon defaults auto_scan=true; this must be called after each daemon start.
# Usage: disable_lan_auto_scan
disable_lan_auto_scan() {
    local out=""
    local attempt
    local posture_syn=0

    for attempt in 1 2 3; do
        out=$(mcp_vm_exec_retry 'python3 /tmp/mcp_direct.py set_lan_auto_scan "{\"enabled\": false}" 2>&1' 3)
        if echo "$out" | python3 -c '
import json, sys
raw = sys.stdin.read().strip()
try:
    obj = json.loads(raw)
    ok = obj.get("success") is True and obj.get("auto_scan") is False
except Exception:
    low = raw.lower()
    ok = "\"success\":true" in low and "\"auto_scan\":false" in low
print("OK" if ok else "FAIL")
' | grep -q "OK"; then
            posture_syn=$(vm_exec 'sudo ss -tnp state syn-sent 2>/dev/null | python3 -c "
import sys
print(sum(1 for line in sys.stdin if \"edamame_posture\" in line))
" 2>/dev/null' || echo "0")

            if [ "${posture_syn:-0}" -gt 0 ] 2>/dev/null; then
                vm_exec 'sudo systemctl restart edamame_posture >/dev/null 2>&1; sleep 4' || true
                out=$(mcp_vm_exec_retry 'python3 /tmp/mcp_direct.py set_lan_auto_scan "{\"enabled\": false}" 2>&1' 3)
            fi

            if echo "$out" | python3 -c '
import json, sys
raw = sys.stdin.read().strip()
try:
    obj = json.loads(raw)
    ok = obj.get("success") is True and obj.get("auto_scan") is False
except Exception:
    low = raw.lower()
    ok = "\"success\":true" in low and "\"auto_scan\":false" in low
print("OK" if ok else "FAIL")
' | grep -q "OK"; then
                echo "$out"
                return 0
            fi
        fi

        sleep $((attempt * 2))
    done

    echo "$out"
    return 1
}
