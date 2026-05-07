# Video Scenario: EDAMAME At The Front Line Of AI Agent Security

## Goal

Make EDAMAME look like the front-line runtime security layer for AI agents.

The video should be credible, simple, and product-forward:

- **Cursor handles the chat risk:** it spots the hidden prompt injection and refuses it.
- **EDAMAME handles the endpoint risk:** it catches what actually executes later.
- **EDAMAME is not a one-demo rule:** the same runtime layer catches litellm-style, axios-style, and future 2026 supply-chain behaviors.

Target length: 5 to 7 minutes.

## The One Sentence

A developer asks Cursor to review a harmless-looking package; Cursor rejects the hidden prompt injection, but a later package verifier still runs a poisoned tool, touches canary credentials, and makes unexpected egress. EDAMAME catches the runtime truth and then shows that this is the same class of protection needed for litellm, axios, and the next AI supply-chain attacks.

## App Surfaces To Show

Keep EDAMAME on screen most of the time.

- Start and end on **`AI Assistant` > `Security`**.
- Show findings in **`AI Assistant` > `History`**.
- Show intent correlation in **`AI Assistant` > `Agents` > `Advanced`**.
- Show the Brain Scan only as a quick visual in **`AI Assistant` > `Agents` > `Easy`** if it looks clean on camera.
- Show notification setup or output via **`AI Assistant` > `Settings`** only if Slack, Telegram, or Portal export is configured.
- Use the **`Capture`** tab only for one proof shot of the process/session, not as the main story.

Screen priority:

- EDAMAME app: 70%
- Cursor: 15%
- Terminal / `edamame_cli`: 10%
- Browser incident report: 5%

## Prep

Use a clean terminal in `agent_security`:

```bash
cd /Users/flyonnet/Programming/agent_security
```

Recommended live command:

```bash
python3 tests/e2e/demos/prompt_injection_rogue_curl/spectacular_demo.py \
  --provider-runner cursor \
  --duration 20 \
  --payload-bytes 256 \
  --reset-agentic-state \
  --open-report
```

Recommended second proof command, litellm-style supply-chain exfiltration:

```bash
python3 tests/e2e/triggers/trigger_supply_chain_exfil.py \
  --agent-type cursor \
  --duration 45
```

Optional third proof command, axios-style npm RAT beacon:

```bash
python3 tests/e2e/triggers/cleanup.py --agent-type cursor
python3 tests/e2e/triggers/trigger_npm_rat_beacon.py \
  --agent-type cursor \
  --duration 45 \
  --interval 5
```

After a trigger, force and read the detector:

```bash
../edamame_cli/target/release/edamame_cli rpc run_vulnerability_detector_tick
../edamame_cli/target/release/edamame_cli rpc get_vulnerability_findings --pretty
```

Keep this fallback ready if the provider phase takes too long:

```bash
python3 tests/e2e/demos/prompt_injection_rogue_curl/spectacular_demo.py \
  --provider-runner none \
  --duration 20 \
  --payload-bytes 256 \
  --reset-agentic-state \
  --open-report
```

## Scene 1: Open On EDAMAME

Visual:

- EDAMAME app open on `AI Assistant` > `Security`.
- The UI should look calm before the incident.
- Terminal is ready but not yet dominant.

Narration:

> AI agents are becoming part of the software supply chain. Provider guardrails are important, but they mostly see text and tool requests. EDAMAME sits on the endpoint and watches what actually runs: processes, network traffic, file access, and whether that behavior matches the agent's declared intent.

Key message:

> EDAMAME is the runtime security layer for AI agent workstations.

## Scene 2: A Realistic Package Review

Action:

Run the command:

```bash
python3 tests/e2e/demos/prompt_injection_rogue_curl/spectacular_demo.py \
  --provider-runner cursor \
  --duration 20 \
  --payload-bytes 256 \
  --reset-agentic-state \
  --open-report
```

Visual callouts from terminal:

- `workspace=.../edamame_live_prompt_injection_rogue_curl/workspace`
- `rogue_curl=.../demo-bin/curl`
- `reset clear_vulnerability_history=ok`

Narration:

> The demo creates a realistic package review. There is a `package.json`, a README, and a provenance verifier. Hidden inside the README is an instruction block targeting automated reviewers. Separately, the endpoint is staged with a poisoned `curl` and canary credentials under a temporary HOME.

Key message:

> The setup is safe: no real credentials, no real attacker infrastructure.

## Scene 3: Provider Catches The Prompt Injection

Visual:

- Terminal section: `== Act 1: cursor Handles The Prompt Injection ==`
- Cursor Agent response text, or the captured Cursor output from the script.

Highlight these provider lines:

- Cursor identifies the hidden HTML comment as prompt injection.
- Cursor refuses to run `npm`, `curl`, or inspect credential paths.

Narration:

> Cursor does the right thing. It sees the hidden instructions and refuses them. That is exactly the right outcome from the agent provider.

Key message:

> Provider safety blocked the instruction. It did not prove the endpoint stayed safe.

Camera direction:

This is the only long Cursor shot. After this, return to EDAMAME.

## Scene 4: The Endpoint Still Moves

Visual:

- Terminal section: `== Act 2a: Declare The Benign Intent EDAMAME Should Enforce ==`
- Terminal section: `== Act 2: Compromised Verifier Runs After Provider Review ==`

Highlight:

```text
policy: package metadata review; no credential reads; no external egress; no demo-bin/curl
running: npm run verify-provenance
```

Narration:

> Now comes the real gap. Something runs later: a CI step, a weaker agent, an MCP tool, a package script, or a human command copied from a README. The command looks normal: `npm run verify-provenance`. But the verifier shells out to `curl`, and PATH resolves `curl` to the poisoned demo binary.

Key message:

> This is no longer a prompt-injection warning. This is runtime behavior.

Camera direction:

Show only enough terminal to prove what ran. The important shot comes next in EDAMAME.

## Scene 5: EDAMAME Catches It

Visual:

- Terminal section: `== Act 3: EDAMAME Evidence ==`
- EDAMAME app `AI Assistant` > `Security`: show active security state.
- EDAMAME app `AI Assistant` > `History`: open the newest vulnerability finding.
- Optional `Capture` tab: one quick process/session proof shot for `curl`.

Highlight findings:

- `curl` executed from a demo-controlled path.
- Canary credential files were opened.
- Outbound traffic occurred.
- The finding severity is `HIGH` or `CRITICAL`.

Highlight process evidence:

```text
process_name: curl
process_path: .../demo-bin/curl
destination: one.one.one.one
```

Narration:

> EDAMAME sees the endpoint truth: the process, the file access, and the egress. It does not matter that the chat model refused the malicious text. A process still ran, touched canaries, and talked out. EDAMAME catches that as runtime evidence.

Key message:

> EDAMAME protects the place where the risk becomes real: the endpoint.

Camera direction:

Use the EDAMAME app first. Use CLI only if the UI has not refreshed yet.

## Scene 6: Intent Makes It Obvious

Visual:

- Terminal `divergence verdict` block.
- EDAMAME app `AI Assistant` > `Agents` > `Advanced` for the divergence monitor.
- Optional `AI Assistant` > `Agents` > `Easy` for a quick Brain Scan visual.

Highlight:

```text
deterministic_verdict: Divergence
verdict: Divergence
parent_script_path: scripts/check_registry.js
process_name: curl
Traffic 'one.one.one.one:63169' matched forbidden pattern 'one.one.one.one'
```

Narration:

> Vulnerability detection says what this looks like. Divergence says why it is rogue for this specific task. The declared intent was package metadata review: no credential reads, no unexpected egress, no poisoned `curl`. The endpoint did the opposite.

Key message:

> Vulnerability tells us what happened. Divergence tells us why it violates intent.

Camera direction:

Keep this short. Do not turn the video into a divergence-engine walkthrough.

## Scene 7: Broader Front-Line Coverage

Visual:

- EDAMAME app `AI Assistant` > `Security`.
- Terminal with the litellm-style trigger command.
- EDAMAME app `AI Assistant` > `History` after the finding appears.

Narration:

> This was one realistic package-review incident. But EDAMAME is not built around this one trick. The broader detector catches attack behaviors that already show up in real supply-chain incidents: broad credential harvesting, package beacons, suspicious child processes, file tampering, and secrets staged in unexpected places.

Run:

```bash
python3 tests/e2e/triggers/trigger_supply_chain_exfil.py \
  --agent-type cursor \
  --duration 45
```

```bash
../edamame_cli/target/release/edamame_cli rpc run_vulnerability_detector_tick
../edamame_cli/target/release/edamame_cli rpc get_vulnerability_findings --pretty
```

Highlight:

- `supply_chain_exfil`
- litellm-style PyPI credential harvesting
- multi-category credential access
- outbound POST behavior

Key message:

> The named incident changes. The runtime behavior class remains detectable.

Camera direction:

Show EDAMAME `History` finding details. If a Slack, Telegram, or Portal notification is configured, show it here. This is the best place to make EDAMAME feel operational, not just analytical.

## Scene 8: Axios And The 2026 Attack Stream

Visual:

- Terminal or browser report showing the Part 2 handoff commands.
- Optional short run of the axios-style trigger.
- EDAMAME `AI Assistant` > `History` stays on screen.

Narration:

> The same replay suite includes axios-style npm RAT beaconing, file-system tampering, temp-stage execution, token exfiltration, blacklist communication, and secrets staged outside normal sensitive paths. This is the point: AI agent security cannot wait for every new package name or CVE. The endpoint needs behavior-based coverage.

Optional axios command:

```bash
python3 tests/e2e/triggers/cleanup.py --agent-type cursor
python3 tests/e2e/triggers/trigger_npm_rat_beacon.py \
  --agent-type cursor \
  --duration 45 \
  --interval 5
```

Then force/read the detector:

```bash
../edamame_cli/target/release/edamame_cli rpc run_vulnerability_detector_tick
../edamame_cli/target/release/edamame_cli rpc get_vulnerability_findings --pretty
```

Key message:

> EDAMAME is positioned for the attack stream, not just the headline incident.

## Scene 9: Notifications And Workflow

Visual:

- EDAMAME app `AI Assistant` > `History`: active findings, read/unread state, dismiss/restore controls.
- EDAMAME app `AI Assistant` > `Settings`: Notifications section.
- If configured, show Slack, Telegram, or Portal notification output.

Narration:

> Front-line security is not just detection. The finding has to reach the operator with evidence. EDAMAME records the incident in Security History and can escalate through Slack, Telegram, or Portal export. The operator can inspect the evidence, dismiss a known test artifact, or restore it later.

Key message:

> Detection is useful only if it reaches the operator with evidence and workflow.

## Close

Narration:

> The point is not that agent providers are weak. Cursor did the right thing. The point is that AI agent security has to continue after the chat window. Scripts, tools, MCP calls, package hooks, and weaker runners can still execute. EDAMAME watches the host, ties behavior back to intent when intent exists, and catches broad runtime attack behavior when it does not.

Final on-screen line:

> EDAMAME: runtime security for the agentic endpoint.

## Recommended Final Edit

1. **Cold open, 15 seconds:** EDAMAME app, front-line claim.
2. **Package review, 60 seconds:** Cursor catches prompt injection.
3. **Runtime gap, 60 seconds:** verifier runs and poisoned `curl` executes.
4. **EDAMAME catch, 90 seconds:** Security, History, finding details.
5. **Intent correlation, 45 seconds:** Agents > Advanced divergence.
6. **Broad coverage, 90 seconds:** litellm trigger live, axios/full suite as proof points.
7. **Workflow, 30 seconds:** notification/history/settings.
8. **Close, 15 seconds:** EDAMAME as agentic endpoint security.

## Simple Screen Timeline

- 0:00 EDAMAME `AI Assistant` > `Security`.
- 0:20 terminal starts `spectacular_demo.py`.
- 0:45 Cursor response shows prompt-injection refusal.
- 1:30 terminal shows `npm run verify-provenance`.
- 2:00 EDAMAME `AI Assistant` > `History` shows vulnerability finding.
- 2:45 EDAMAME `AI Assistant` > `Agents` > `Advanced` shows divergence.
- 3:30 optional browser incident report.
- 4:00 EDAMAME `AI Assistant` > `Security`, transition to broad coverage.
- 4:20 terminal runs `trigger_supply_chain_exfil.py`.
- 5:10 EDAMAME `History` shows litellm-style finding.
- 5:45 optional axios command or montage of supported triggers.
- 6:15 EDAMAME `Settings` / notification output.
- 6:45 close on EDAMAME `Security`.

## Backup Takes

If Cursor is slow or unavailable:

1. Run with `--provider-runner none`.
2. Say:

> In the full run, Cursor flags the hidden README instructions and refuses them. For time, we skip that live provider call and focus on EDAMAME’s runtime coverage.

If divergence is clean but vulnerability findings appear:

1. Rerun with:

```bash
python3 tests/e2e/demos/prompt_injection_rogue_curl/spectacular_demo.py \
  --provider-runner none \
  --duration 20 \
  --payload-bytes 256 \
  --reset-agentic-state \
  --open-report
```

2. Confirm the output includes:
   - `sessions_contain_rogue_curl_path: true`
   - `deterministic_verdict: Divergence`
   - `parent_script_path: scripts/check_registry.js`

If the report does not open:

Copy the printed `incident_report=...` path and open it manually in the browser.

If the litellm-style trigger does not produce a visible app card quickly:

1. Keep the trigger running for another 20 to 30 seconds.
2. Run:

```bash
../edamame_cli/target/release/edamame_cli rpc run_vulnerability_detector_tick
../edamame_cli/target/release/edamame_cli rpc get_vulnerability_findings --pretty
```

3. Show the CLI output as proof, then say:

> The app stream can lag the forced detector tick by a moment. The finding is already in core state and will appear in Security History.

If notification channels are not configured:

1. Show `AI Assistant` > `Settings` > Notifications.
2. Say:

> This build can send the same alert to Slack, Telegram, or Portal export. For this recording we are showing the local Security History card and CLI proof.

If you want one command to prove the broader suite after the video:

```bash
bash tests/e2e/run_demo.sh \
  --focus vuln \
  --iterations 1 \
  --scenario-duration 75 \
  --post-wait 20
```

## What Not To Claim

Do not claim EDAMAME directly detects prompt injection text in this demo.

Say instead:

> Cursor detects the prompt injection text. EDAMAME detects and correlates the runtime consequence.

Do not claim real credentials are accessed.

Say instead:

> The demo touches canary credential files created under a temporary HOME.

Do not claim `one.one.one.one` is malicious.

Say instead:

> It is a neutral public test destination used to create observable egress.

Do not claim the broad replay triggers run real litellm or axios malware.

Say instead:

> These are safe simulations of the downstream host behavior seen in those incidents.

Do not claim divergence catches every vulnerability.

Say instead:

> Divergence catches behavior that violates declared intent. The vulnerability detector catches broad malicious behavior even without an intent model.

Do not over-explain internals on camera.

Say instead:

> EDAMAME sees the process, the files, the network, and the declared intent. That is enough for the product story.
