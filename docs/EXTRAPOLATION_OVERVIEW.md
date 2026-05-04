# Extrapolation Architecture Overview

How EDAMAME's two-plane runtime security model reads agent intent across
OpenClaw, Cursor, and Claude Code -- and why each platform requires a
different trigger mechanism.

## The Extrapolation Problem

The two-plane model requires a **reasoning-plane producer** that periodically
reads agent session transcripts and forwards a compact behavioral prediction
to EDAMAME's system-plane observer. This is the extrapolator. Its output is a
`BehavioralWindow` slice containing expected traffic, processes, sensitive
file access, and LAN activity that the divergence engine correlates against
live host telemetry.

The challenge: each AI platform stores transcripts differently, exposes
different lifecycle APIs, and runs in different process models. The
extrapolation contract is the same; the trigger and transport vary.

## Platform Comparison

| Dimension | OpenClaw | Cursor | Claude Code |
|---|---|---|---|
| **Trigger** | System cron (`*/5 * * * *`) | MCP tool-call piggyback | MCP tool-call piggyback |
| **Transcript source** | Gateway API (`sessions_list` / `sessions_history`) | Local filesystem | Local filesystem |
| **Transcript location** | `~/.openclaw/agents/<id>/sessions/*.jsonl` | `~/.cursor/projects/.../agent-transcripts/*.jsonl` | `~/.claude/projects/<key>/*.jsonl`, `*.txt` |
| **Active window** | 15 min (`activeMinutes=15`) | 5 min (`transcriptActiveWindowMinutes`) | 5 min (`transcriptActiveWindowMinutes`) |
| **Min refresh interval** | Fixed cron period | 120 s (configurable) | 120 s (configurable) |
| **Idle behavior** | Cron fires regardless | No refresh when no tool calls | No refresh when no tool calls |
| **LLM cost per cycle** | Zero (compiled mode) or agent LLM tokens (fallback) | Zero (compiled heuristics) | Zero (compiled heuristics) |
| **Lifecycle hooks?** | None | 14+ hooks (session, tool, agent, compact) | 14+ hooks (session, tool, agent, compact) |
| **Background timer** | N/A (cron is primary) | Opt-in (`--background-refresh`) | Opt-in (`--background-refresh`) |
| **Repush on reconnect** | Not needed (cron handles) | Yes (detects app restart, re-upserts) | Yes (detects app restart, re-upserts) |
| **MCP host** | `edamame_posture` (Lima VM / server) | `edamame_app` (desktop) | `edamame_app` (desktop) |
| **Package repo** | `edamame_openclaw` | `edamame_cursor` | `edamame_claude_code` |
| **agent_type tag** | `openclaw` | `cursor` | `claude_code` |

## Trigger Mechanisms in Detail

### OpenClaw: Cron (Polling)

OpenClaw provides four session tools (`sessions_list`, `sessions_history`,
`sessions_send`, `sessions_spawn`) but they are **in-session tools** available
only to the running agent. There is no out-of-band HTTP API, no webhook/event
bus, and no lifecycle hook system. A feature request for `POST /api/sessions/spawn`
was explicitly closed as "not planned" (March 2026).

The only reliable way to periodically read transcripts is system cron:

```
# Production cadence
*/5 * * * *   openclaw agent --agent extrapolator

# Test/demo cadence
*/2 * * * *   openclaw agent --agent extrapolator
```

Each cron tick launches a short-lived agent session that calls
`extrapolator_run_cycle` (compiled mode, zero agent LLM tokens). This tool:

1. Reads recent sessions via the gateway API (`sessions_list` with `activeMinutes=15`)
2. Fetches transcripts for changed sessions (`sessions_history`)
3. Deterministically extracts behavioral signals (domains, ports, commands, files)
4. Forwards the structured payload to EDAMAME via `upsert_behavioral_model_from_raw_sessions`
5. Verifies the model was stored via `get_behavioral_model` read-back

If compiled mode fails (e.g., plugin not installed), the skill falls back to
Mode B where the agent LLM reads transcripts and builds the behavioral model
directly -- at the cost of agent tokens per cycle.

### Cursor: MCP Tool-Call Piggyback (Event-Driven)

Cursor provides lifecycle hooks (`sessionStart`, `sessionEnd`,
`afterAgentResponse`, `preToolUse`, `postToolUse`, `beforeMCPExecution`, etc.)
and runs the MCP server process for the full IDE session lifetime.

The `edamame_cursor` package uses `createCursorDrivenRefresh()` which
piggybacks on every MCP tool invocation. When the AI agent calls any EDAMAME
tool, the bridge opportunistically checks whether a new extrapolation cycle
is due:

1. **In-flight guard**: Skip if an extrapolation is already running
2. **Rate limit**: Skip if less than `minIntervalMs` (default 120 s) has elapsed
3. **Transcript change check**: Skip if no transcript file has been modified since last run
4. **Persisted state check**: Skip if last persisted run is recent enough and transcripts unchanged

If all gates pass, `runLatestExtrapolation()` reads `.jsonl` transcript files
from `~/.cursor/projects/.../agent-transcripts/`, builds a raw session
payload, and sends it to EDAMAME.

An opt-in `--background-refresh` flag activates `createBackgroundRefreshLoop()`,
a `setInterval`-based timer (default 120 s) that runs independently of tool calls.
This is not active by default.

### Claude Code: MCP Tool-Call Piggyback (Event-Driven)

Claude Code provides 14+ lifecycle hooks (`SessionStart`, `Stop`,
`PreToolUse`, `PostToolUse`, `TaskCompleted`, `SessionEnd`,
`PreCompact`/`PostCompact`, etc.) and supports command, HTTP, prompt, and
agent hook handlers.

The `edamame_claude_code` package uses `createClaudeCodeDrivenRefresh()` --
structurally identical to Cursor's approach:

1. Same in-flight, rate-limit, and transcript-change gating
2. Reads `.jsonl` and `.txt` transcripts from `~/.claude/projects/<workspace-key>/`
3. Sends raw session payload to EDAMAME via `upsert_behavioral_model_from_raw_sessions`

Claude Code's native hooks could theoretically trigger the extrapolator
directly (e.g., a `PostToolUse` command hook calling the extrapolator), but
the current implementation uses the MCP tool-call piggyback pattern for
consistency with Cursor and simpler deployment.

Same opt-in `--background-refresh` fallback is available but not active by
default.

## Why the Approaches Differ

The trigger mechanism is dictated by what each platform exposes:

**OpenClaw** runs agents as discrete sessions (main, cron, hook, group).
There is no persistent MCP server process that could poll -- the MCP plugin
(`extensions/edamame/index.ts`) only lives while an agent session is active.
Between sessions, nothing runs. Cron is the only mechanism that can
periodically wake up and read transcripts.

**Cursor and Claude Code** run the MCP server as a long-lived stdio child
process for the entire IDE/CLI session. Every AI tool call passes through
this process, creating natural trigger points. The MCP bridge can
opportunistically fire the extrapolator without any external scheduler.

Additionally, Cursor and Claude Code transcripts are local files on the
developer's machine, directly readable by the MCP bridge process. OpenClaw
transcripts are accessed through the gateway API, which requires an active
agent session context.

## Common Behavioral Model Contract

All three platforms produce the same output: a `BehavioralWindow` slice
pushed to EDAMAME via `upsert_behavioral_model_from_raw_sessions` (raw
transcript forwarding) or `upsert_behavioral_model` (prebuilt predictions).

Required fields on every slice:

- `agent_type`: `openclaw`, `cursor`, or `claude_code`
- `agent_instance_id`: stable per deployment/workstation/workspace
- `window_start` / `window_end`: ISO-8601 observation window
- `predictions[]`: expected traffic, processes, files, ports, protocols
- `contributors[]`: agent identity for multi-agent merge
- `version`: `"3.0"`

EDAMAME's divergence engine merges slices from multiple producers into one
canonical model, then correlates against live host telemetry to emit verdicts:
`CLEAN`, `DIVERGENCE`, `NO_MODEL`, or `STALE`.

## Recovery and Resilience

| Scenario | OpenClaw | Cursor / Claude Code |
|---|---|---|
| EDAMAME restart | Next cron tick re-upserts | Extrapolator detects empty/mismatched remote model, repushes |
| Agent idle | Cron fires regardless, sends heartbeat if no active sessions | No refresh until next tool call; heartbeat on stale transcript window |
| Network partition | Cron retries on next tick | Next tool call retries; failure classified and reported |
| Transcript format change | Gateway API abstraction insulates | Adapter's `walkFiles()` / parser must be updated |

## Key Source Files

| Component | OpenClaw | Cursor | Claude Code |
|---|---|---|---|
| MCP plugin / bridge | `edamame_openclaw/extensions/edamame/index.ts` | `edamame_cursor/bridge/cursor_edamame_mcp.mjs` | `edamame_claude_code/bridge/claude_code_edamame_mcp.mjs` |
| Extrapolator service | (in-session skill) | `edamame_cursor/service/cursor_extrapolator.mjs` | `edamame_claude_code/service/claude_code_extrapolator.mjs` |
| Transcript adapter | (gateway API, compiled in plugin) | `edamame_cursor/adapters/session_prediction_adapter.mjs` | `edamame_claude_code/adapters/session_prediction_adapter.mjs` |
| Skill contract | (compiled into `edamame_openclaw/extensions/edamame/index.ts`) | `edamame_cursor/skills/divergence-monitor/SKILL.md` | `edamame_claude_code/skills/divergence-monitor/SKILL.md` |
| Refresh trigger | System cron | `createCursorDrivenRefresh()` | `createClaudeCodeDrivenRefresh()` |

## Future Considerations

**OpenClaw event-driven path**: Would require OpenClaw to add one of:
- An HTTP webhook/callback when session content changes
- A `sessions_watch` streaming tool (like inotify for sessions)
- An out-of-band event bus for plugin subscriptions

Until then, cron remains the correct and only approach.

**Claude Code hooks as direct triggers**: Claude Code's `PostToolUse` or
`Stop` hooks could directly invoke the extrapolator via an HTTP hook handler,
removing the dependency on the agent calling EDAMAME tools. This would
provide more consistent coverage but adds deployment complexity (a local HTTP
endpoint for hook callbacks).

**Unified background timer**: Both Cursor and Claude Code support an opt-in
`--background-refresh` `setInterval` loop. Enabling this by default would
close the gap where the agent is active but not calling EDAMAME tools, at the
cost of a persistent timer in the MCP server process.
