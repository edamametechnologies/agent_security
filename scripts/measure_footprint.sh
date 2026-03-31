#!/usr/bin/env bash
# measure_footprint.sh -- Measure EDAMAME Posture CPU and memory footprint
#
# Runs inside a Lima VM (or any Linux host) where edamame_posture is already
# running with MCP enabled. Outputs JSON to stdout.
#
# Prerequisites:
#   - edamame_posture daemon running with MCP on port 3000
#   - PSK file at ~/.edamame_psk
#   - sysstat package (for pidstat)
#
# Usage:
#   bash scripts/measure_footprint.sh            # run locally inside VM
#   # Or from macOS host via Lima:
#   limactl shell <vm> -- bash /path/to/measure_footprint.sh

set -euo pipefail

SAMPLE_INTERVAL=5
SAMPLE_COUNT=12  # 12 x 5s = 60s per phase
MCP_URL="http://127.0.0.1:3000/mcp"
PSK_FILE="${EDAMAME_PSK_FILE:-$HOME/.edamame_psk}"

if ! command -v pidstat >/dev/null 2>&1; then
    sudo apt-get install -y sysstat >/dev/null 2>&1
fi

PSK=$(cat "$PSK_FILE" 2>/dev/null) || { echo "ERROR: cannot read PSK from $PSK_FILE" >&2; exit 1; }

PID=$(pgrep -x edamame_posture) || { echo "ERROR: edamame_posture not running" >&2; exit 1; }
VERSION=$(edamame_posture --version 2>&1 | awk '{print $NF}')

log() { echo "[$1] $2" >&2; }

mcp_tool() {
    local tool="$1"
    local args_file="$2"
    python3 << PYEOF
import json, urllib.request, sys

url = "$MCP_URL"
psk = open("$PSK_FILE").read().strip()
hdrs = {"Content-Type":"application/json","Authorization":"Bearer "+psk}

init = json.dumps({"jsonrpc":"2.0","id":1,"method":"initialize",
    "params":{"protocolVersion":"2025-11-25","capabilities":{},
    "clientInfo":{"name":"footprint","version":"1.0"}}}).encode()
req = urllib.request.Request(url, data=init, headers=hdrs)
resp = urllib.request.urlopen(req, timeout=15)
sid = resp.headers.get("Mcp-Session-Id","")
resp.read()

h2 = dict(hdrs)
if sid: h2["Mcp-Session-Id"] = sid
n = json.dumps({"jsonrpc":"2.0","method":"notifications/initialized"}).encode()
try: urllib.request.urlopen(urllib.request.Request(url, data=n, headers=h2), timeout=5).read()
except: pass

with open("$args_file") as f:
    args = json.load(f)
body = json.dumps({"jsonrpc":"2.0","id":2,"method":"tools/call",
    "params":{"name":"$tool","arguments":args}}).encode()
r = urllib.request.urlopen(urllib.request.Request(url, data=body, headers=h2), timeout=60)
ct = r.headers.get("Content-Type","")
raw = r.read().decode()
if "text/event-stream" in ct:
    for line in raw.splitlines():
        if line.startswith("data:"):
            chunk = line[5:].strip()
            if chunk:
                try:
                    d = json.loads(chunk)
                    for c in d.get("result",{}).get("content",[]):
                        if c.get("type")=="text": print(c["text"]); sys.exit(0)
                    print(json.dumps(d.get("result",{})))
                except: pass
                sys.exit(0)
else:
    d = json.loads(raw)
    for c in d.get("result",{}).get("content",[]):
        if c.get("type")=="text": print(c["text"]); sys.exit(0)
    print(json.dumps(d.get("result",{})))
PYEOF
}

capture_phase() {
    local label="$1"
    PID=$(pgrep -x edamame_posture)

    local rss_kb=$(awk '/VmRSS/{print $2}' /proc/$PID/status)
    local vmsize_kb=$(awk '/VmSize/{print $2}' /proc/$PID/status)
    local vmpeak_kb=$(awk '/VmPeak/{print $2}' /proc/$PID/status)
    local threads=$(awk '/Threads/{print $2}' /proc/$PID/status)

    local cpu_avg
    cpu_avg=$(pidstat -p "$PID" "$SAMPLE_INTERVAL" "$SAMPLE_COUNT" 2>/dev/null \
        | awk '/edamame_posture/{sum+=$8; n++} END{if(n>0) printf "%.2f", sum/n; else print "0.00"}')

    local rss_end_kb=$(awk '/VmRSS/{print $2}' /proc/$PID/status)

    local rss_mib=$(( (rss_kb + rss_end_kb) / 2 / 1024 ))
    local vmsize_mib=$(( vmsize_kb / 1024 ))
    local vmpeak_mib=$(( vmpeak_kb / 1024 ))

    echo "{\"phase\":\"$label\",\"cpu_pct\":$cpu_avg,\"rss_mib\":$rss_mib,\"vmsize_mib\":$vmsize_mib,\"vmpeak_mib\":$vmpeak_mib,\"threads\":$threads,\"rss_start_kb\":$rss_kb,\"rss_end_kb\":$rss_end_kb}"
}

log "INFO" "edamame_posture $VERSION (PID $PID)"
log "INFO" "$(uname -r) $(uname -m), $(nproc) vCPU, $(free -m | awk '/Mem:/{print $2}') MiB RAM"

# Disable LAN auto-scan (Lima networking invariant)
log "PREP" "Disabling LAN auto-scan..."
echo '{"enabled":false}' > /tmp/fp_args.json
mcp_tool "set_lan_auto_scan" /tmp/fp_args.json >/dev/null 2>&1 || true
sleep 5

# Phase A: Idle
log "PHASE_A" "Idle -- daemon running, no behavioral model, no divergence engine activity"
PHASE_A=$(capture_phase "idle")
log "PHASE_A" "$PHASE_A"

# Phase B: Push behavioral model, let engine correlate
log "PHASE_B" "Pushing behavioral model..."
cat > /tmp/fp_window.json << 'WEOF'
{"window_start":"2026-03-31T00:00:00Z","window_end":"2026-03-31T23:59:59Z","agent_type":"benchmark","agent_instance_id":"footprint-test-001","predictions":[{"agent_type":"benchmark","agent_instance_id":"footprint-test-001","session_key":"footprint-bench","action":"idle monitoring and posture check","tools_called":["get_score","get_sessions","get_divergence_verdict"],"expected_traffic":["edamame.s3.eu-west-1.amazonaws.com","1.1.1.1","google.com"],"expected_sensitive_files":[],"expected_lan_devices":[],"expected_local_open_ports":["3000"],"expected_process_paths":["/usr/bin/edamame_posture","/usr/bin/python3","/usr/bin/curl"],"expected_parent_paths":[],"expected_open_files":[],"expected_l7_protocols":["HTTPS","DNS"],"expected_system_config":[],"not_expected_traffic":["evil.com","exfil.io"],"not_expected_sensitive_files":["/etc/shadow","/root/.ssh/id_rsa"],"not_expected_lan_devices":[],"not_expected_local_open_ports":["4444","8888"],"not_expected_process_paths":["/tmp/backdoor","/tmp/exploit"],"not_expected_parent_paths":[],"not_expected_open_files":[],"not_expected_l7_protocols":[],"not_expected_system_config":[]}],"contributors":[],"version":"3.0","hash":"","ingested_at":"2026-03-31T00:00:00Z"}
WEOF
python3 -c "
import json
w = json.load(open('/tmp/fp_window.json'))
json.dump({'window_json': json.dumps(w)}, open('/tmp/fp_args.json','w'))
"
mcp_tool "upsert_behavioral_model" /tmp/fp_args.json >&2 || log "PHASE_B" "WARNING: upsert failed (non-fatal)"
sleep 15
log "PHASE_B" "Active -- behavioral model pushed, engine correlating"
PHASE_B=$(capture_phase "active")
log "PHASE_B" "$PHASE_B"

# Phase C: Active under load -- generate benign network traffic
log "PHASE_C" "Generating network traffic while engine evaluates..."
for i in $(seq 1 20); do
    curl -s -o /dev/null https://1.1.1.1 2>/dev/null &
    curl -s -o /dev/null https://google.com 2>/dev/null &
    curl -s -o /dev/null https://example.com 2>/dev/null &
done
sleep 5
log "PHASE_C" "Active under load -- benign traffic + engine correlation"
PHASE_C=$(capture_phase "load")
log "PHASE_C" "$PHASE_C"
wait 2>/dev/null || true

# Collect verdict state
log "VERDICT" "Checking divergence verdict..."
echo '{}' > /tmp/fp_args.json
VERDICT=$(mcp_tool "get_divergence_verdict" /tmp/fp_args.json 2>/dev/null | head -1) || VERDICT="unavailable"
log "VERDICT" "$VERDICT"

# Emit JSON summary to stdout
python3 << PYEOF
import json, platform, os, subprocess

phases = [
    $PHASE_A,
    $PHASE_B,
    $PHASE_C,
]

total_ram = int(subprocess.check_output(["free", "-m"]).decode().split("\n")[1].split()[1])

summary = {
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "edamame_version": "$VERSION",
    "kernel": "$(uname -r)",
    "arch": "$(uname -m)",
    "vcpus": $(nproc),
    "total_ram_mib": total_ram,
    "vm_driver": "vz",
    "sample_interval_s": $SAMPLE_INTERVAL,
    "sample_count": $SAMPLE_COUNT,
    "phases": phases,
    "verdict_after": $(python3 -c "import json; print(json.dumps('$VERDICT'))" 2>/dev/null || echo '"unavailable"'),
}
print(json.dumps(summary, indent=2))
PYEOF

log "DONE" "Measurement complete"
