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

Keep EDAMAME on screen most of the time. The hero surface depends on which part of the story is on screen.

**Part 1 hero — the Brain Scan** (`AI Assistant` > `Agents` > `Easy`).

- Use it for the divergence story (prompt-injection / rogue `curl`) where there is a declared intent.
- Show it once on the calm baseline (tracking near 100%, all aligned, the orrery sweep rotating).
- Show it again after the runtime gap, with the tracking percentage dropping, `Outside` / `Forbidden` chips lighting up, and a new node appearing in the cursor sector.
- Drill into the rogue node so the side rail shows source, process, dimension, severity, evidence, and operator actions.
- Use the timeline river at the bottom to rewind to a clean tick, then jump back to live.
- Use **`AI Assistant` > `Agents` > `Advanced`** only as a short cutaway for the raw divergence verdict text (5–10 seconds, not the centerpiece).

**Part 2 hero — `AI Assistant` > `Security`**.

- Use it for the broad vulnerability replay (litellm-style, axios-style, future 2026 supply-chain behaviors).
- Part 2 has no per-trigger behavioral model, so there is no Brain Scan story for it. Stay out of the Brain Scan during this part.
- The headline finding count and severity color belong on `Security`. Open `History` to read the evidence card.

**Cross-cut surfaces** (used in both parts as supporting shots).

- **`AI Assistant` > `History`**: evidence cards and dismiss/restore controls.
- **`AI Assistant` > `Settings`**: notifications setup or output (only if Slack, Telegram, or Portal export is configured).
- **`Capture`** tab: one proof shot of the process/session at most, not as the main story.

Screen priority:

- EDAMAME app: 75%
  - Part 1 EDAMAME shots are mostly Brain Scan and `Security`/`History`.
  - Part 2 EDAMAME shots are mostly `Security` and `History`.
- Cursor: 12%
- Terminal / `edamame_cli`: 8%
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

## Scene 1: Open On EDAMAME, Land On The Brain Scan

Visual:

- EDAMAME app open on `AI Assistant` > `Security` for two seconds (clean state, headline finding count near zero).
- Switch to `AI Assistant` > `Agents` > `Easy` (the Brain Scan). This is where the camera should rest.
- The orrery is calm:
  - The animated sweep rotates over the central graph.
  - Source sectors are arranged around the orrery (one per paired agent: cursor, claude_code, etc.).
  - Process nodes orbit each source; forecast leaves sit around their owner process.
  - Header badge reads `Tracking ~100% of forecast` in green.
  - Category chips show high `Aligned`, near-zero `Outside`, `Forbidden`, `Silent`.
  - The river timeline at the bottom shows a steady run of green ticks.
- Terminal is ready but minimized.

Narration:

> AI agents are becoming part of the software supply chain. Provider guardrails are important, but they mostly see text and tool requests. EDAMAME sits on the endpoint and watches what actually runs: processes, network traffic, file access, and whether that behavior matches the agent's declared intent. The Brain Scan is how that intent looks live: each agent is a sector, each running process is a node, and each forecast leaf is a satellite around its process. Right now everything is aligned.

Key message:

> EDAMAME is the runtime security layer for AI agent workstations, and the Brain Scan is its live source-of-truth map.

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
- EDAMAME app `AI Assistant` > `Security`: the headline finding count ticks up; severity color shifts.
- EDAMAME app `AI Assistant` > `History`: open the newest vulnerability finding card and read the evidence.
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

Land on `Security` for the count, then `History` for the evidence card. Save the visual story for the next scene; the Brain Scan is where the divergence becomes obvious without reading any text.

## Scene 6: The Brain Scan Tells The Story

This is the centerpiece visual scene. Spend most of the time on the Brain Scan.

Visual sequence:

1. EDAMAME app `AI Assistant` > `Agents` > `Easy` (Brain Scan).
2. The orrery is no longer calm:
   - Header badge has dropped from `Tracking ~100%` (green) to a low value (warning or critical color).
   - Category chips: `Aligned` shrinks; `Outside` and `Forbidden` light up with non-zero counts.
   - In the cursor sector, a new node has appeared: this is the rogue `curl`. A deny-list forecast leaf in that branch lights up red.
3. Click (or tap) the rogue node.
4. The selection rail opens on the right with:
   - **Source**: the agent sector (e.g., `cursor`).
   - **Process**: `curl` and full path under `.../demo-bin/curl`.
   - Section: `WHY IT'S OUTSIDE THE FORECAST` — explains that the activity hit a deny-list leaf or has no matching forecast in this branch.
   - **Dimension** chip: `Traffic` (and `Files` for the canary access).
   - **Severity** chip: `High` or `Critical`.
   - **Session** id and a short evidence line (destination, port, file path).
   - Action buttons: `View session`, `View process`, `Mark process safe`, `Dismiss`.
5. Hover (do not click) the action buttons so the camera shows what the operator can do.
6. Use the river timeline at the bottom:
   - Tap an earlier (clean) bar in the timeline. The orrery redraws to that snapshot — calm, all aligned, the rogue node is gone.
   - Click `Jump to live`. The rogue node returns and the badge drops again.
7. (Optional, 5–10 seconds.) Cut to `AI Assistant` > `Agents` > `Advanced` to show the raw divergence verdict text:

```text
deterministic_verdict: Divergence
verdict: Divergence
parent_script_path: scripts/check_registry.js
process_name: curl
Traffic 'one.one.one.one:63169' matched forbidden pattern 'one.one.one.one'
```

Then return to `Easy` (Brain Scan) for the next scene.

Narration:

> Vulnerability detection said what this looks like. The Brain Scan says why it is rogue for this specific task. The declared intent was package metadata review — no credential reads, no unexpected egress, no poisoned `curl`. The orrery shows it. A new node appeared in the cursor sector, the deny-list leaf in that branch lit up, and the tracking percentage collapsed.
>
> Click the node and you see the source, the process, the dimension, the severity, the session, and the actions an operator can take.
>
> Rewind one snapshot. The map is calm again. Jump to live. The rogue node returns. That is the divergence story without reading any JSON.

Key messages:

> Vulnerability tells us what happened. The Brain Scan shows, visually, that it violates the agent's declared intent.
>
> Operators do not need to read a verdict string. They see it on the map and drill in.

Camera direction:

- Keep the camera on the Brain Scan.
- The Advanced cutaway exists only for the operator who wants to see the raw verdict. Do not dwell there.

## Scene 7: Broader Front-Line Coverage (Part 2 Begins)

Part 2 hero surface is `AI Assistant` > `Security`. Stay out of the Brain Scan for this part: the trigger script is not paired with a behavioral model, so divergence is not the story here. The broad vulnerability detector is.

Visual:

- EDAMAME app `AI Assistant` > `Security` is the main screen for this scene and the next.
  - Show the headline finding count, the severity color, and the active alertable count.
- Terminal beside it with the litellm-style trigger command.
- EDAMAME app `AI Assistant` > `History` for the new finding card with evidence.

Narration:

> This was one realistic package-review incident. But EDAMAME is not built around this one trick. The broader detector catches attack behaviors that already show up in real supply-chain incidents: broad credential harvesting, package beacons, suspicious child processes, file tampering, and secrets staged in unexpected places. For this part of the demo, the main screen is the AI Security tab — the headline finding count is what should grow on camera, and History is where we read the evidence.

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

> The named incident changes. The runtime behavior class remains detectable, and the AI Security tab is where the operator sees it first.

Camera direction:

Stay on `AI Assistant` > `Security` while the count rises, then open the new card in `History`. Do NOT cut to the Brain Scan in this part — there is no per-trigger behavioral model to make it meaningful. If a Slack, Telegram, or Portal notification is configured, show it here.

## Scene 8: Axios And The 2026 Attack Stream

Part 2 hero surface is still `AI Assistant` > `Security`.

Visual:

- EDAMAME app `AI Assistant` > `Security` stays as the main screen.
- Terminal or browser report showing the Part 2 handoff commands.
- Optional short run of the axios-style trigger.
- EDAMAME `AI Assistant` > `History` for the new card.

Narration:

> The same replay suite includes axios-style npm RAT beaconing, file-system tampering, temp-stage execution, token exfiltration, blacklist communication, and secrets staged outside normal sensitive paths. This is the point: AI agent security cannot wait for every new package name or CVE. The endpoint needs behavior-based coverage, and the AI Security tab is the single front-line view of that coverage.

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

Camera direction:

Same rule as Scene 7: stay on `AI Assistant` > `Security`, open `History` for the new card, no Brain Scan in Part 2.

## Scene 9: Notifications And Workflow

Visual:

- EDAMAME app `AI Assistant` > `History`: active findings, read/unread state, dismiss/restore controls.
- Show that the Brain Scan side rail and `History` share the same actions: dismissing on one updates the other; restoring brings the node back.
- EDAMAME app `AI Assistant` > `Settings`: Notifications section.
- If configured, show Slack, Telegram, or Portal notification output.

Narration:

> Front-line security is not just detection. The finding has to reach the operator with evidence. EDAMAME records the incident in Security History and can escalate through Slack, Telegram, or Portal export. The operator can inspect the evidence in either the Brain Scan side rail or History, dismiss a known test artifact, or restore it later. The state stays in sync.

Key message:

> Detection is useful only if it reaches the operator with evidence and workflow.

## Close

Narration:

> The point is not that agent providers are weak. Cursor did the right thing. The point is that AI agent security has to continue after the chat window. Scripts, tools, MCP calls, package hooks, and weaker runners can still execute. EDAMAME watches the host, ties behavior back to intent when intent exists, and catches broad runtime attack behavior when it does not.

Final on-screen line:

> EDAMAME: runtime security for the agentic endpoint.

## Recommended Final Edit

Part 1 (divergence story, Brain Scan-led):

1. **Cold open, 20 seconds:** EDAMAME `Security` for two seconds, then settle on the Brain Scan calm baseline (orrery, sweep, `Tracking ~100%`).
2. **Package review, 50 seconds:** Cursor catches the prompt injection.
3. **Runtime gap, 45 seconds:** verifier runs and poisoned `curl` executes.
4. **EDAMAME catch, 60 seconds:** `Security` finding count, then `History` finding card.
5. **Brain Scan reveal, 75 seconds:** `Agents > Easy` — tracking drops, Outside / Forbidden chips light up, drill into the rogue node, hover the action row, rewind the timeline to the clean snapshot, jump back to live. Optional 10-second cutaway to `Agents > Advanced` for the raw verdict text.

Part 2 (broad coverage, AI Security tab-led):

6. **Broad coverage, 75 seconds:** stay on `AI Assistant > Security` as the main screen; run litellm trigger live; open `History` for the new card; axios/full suite as additional proof points. No Brain Scan in this block.
7. **Workflow, 30 seconds:** History dismiss/restore on the Part 2 finding, optional notification output. Brain Scan side rail can mirror the Part 1 dismiss as a 5-second aside.
8. **Close, 15 seconds:** end on `AI Assistant > Security` — the front-line headline view — for the closing line.

## Simple Screen Timeline

Part 1 (Brain Scan-led):

- 0:00 EDAMAME `AI Assistant` > `Security`, then `Agents` > `Easy` (calm Brain Scan).
- 0:30 terminal starts `spectacular_demo.py`.
- 0:55 Cursor response shows prompt-injection refusal.
- 1:35 terminal shows `npm run verify-provenance`.
- 2:00 EDAMAME `AI Assistant` > `Security` (count ticks up), then `History` finding card.
- 2:50 EDAMAME `AI Assistant` > `Agents` > `Easy`: Brain Scan transition (tracking drops, rogue node appears).
- 3:10 drill into the rogue node, side rail with source / process / dimension / severity / evidence / actions.
- 3:30 timeline rewind to a clean snapshot, then `Jump to live`.
- 3:50 optional 10 seconds on `Agents` > `Advanced` for the raw verdict text.
- 4:05 optional browser incident report.

Part 2 (AI Security tab-led):

- 4:25 transition: back to `AI Assistant` > `Security`. This is the main screen for the rest of Part 2.
- 4:40 terminal runs `trigger_supply_chain_exfil.py`. Camera stays on `Security`; finding count rises.
- 5:25 EDAMAME `Security` shows the new severity, then `History` opens the litellm-style finding card.
- 5:55 optional axios command or montage of supported triggers; camera stays on `Security` while triggers run, with `History` cut-ins for the new cards.
- 6:20 EDAMAME `Settings` / notification output; dismiss/restore in `History`.
- 6:45 close on EDAMAME `AI Assistant` > `Security` — the front-line headline view, with the post-dismissal counts settled.

## Brain Scan Vocabulary (Use These Words On Camera)

Use these terms consistently so the narration matches what the viewer sees on screen.

- **Brain Scan**: the `AI Assistant` > `Agents` > `Easy` view as a whole.
- **Orrery**: the central animated radar-like graph with quadrants and the rotating sweep.
- **Source sector**: a quadrant on the orrery, one per paired agent (cursor, claude_code, etc.).
- **Process node**: a process orbiting its source sector.
- **Forecast leaf**: a satellite around a process — green for expected (allow), red for deny-list, purple for silent (unused forecast).
- **Tracking percentage**: the header badge showing how much of the forecast is being matched live.
- **Aligned / Outside / Forbidden / Silent**: the four category chips in the header strip.
- **Side rail**: the panel that opens when you click a node, showing source / process / dimension / severity / session / evidence / actions.
- **Timeline river**: the horizontal bar at the bottom; tap a bar to rewind, click `Jump to live` to return.
- **Drill down**: click the rogue node, read the side rail, and demo the action row (View session, View process, Mark process safe, Dismiss).

Avoid jargon like "verdict", "deterministic policy", "behavioral window" while on the Brain Scan; save those for the short Advanced cutaway.

The Brain Scan vocabulary belongs to Part 1 only. In Part 2, talk about findings, severity, and evidence on `AI Assistant > Security` and `History`. Do not narrate Brain Scan terms over Part 2 footage.

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

Do not claim the Brain Scan is the only place a finding lives.

Say instead:

> The Brain Scan is the live source-of-truth map. The same finding is also in `Security`, `History`, and on the CLI. Dismissing in one place updates the others.

Do not claim the Brain Scan invents a finding the detector did not produce.

Say instead:

> The Brain Scan is a visual rendering of the divergence engine and the vulnerability findings. It does not introduce new alerts; it makes the existing ones obvious.

Do not show the Brain Scan during Part 2 (the broad vulnerability replay).

Say instead:

> Part 2 is broad runtime coverage without an intent context for the trigger script. The main screen for Part 2 is `AI Assistant > Security`. The Brain Scan belongs to Part 1, where there is a declared intent and a divergence story.

Do not over-explain internals on camera.

Say instead:

> EDAMAME sees the process, the files, the network, and the declared intent. That is enough for the product story.
