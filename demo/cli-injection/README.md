These user-space injectors mirror the real payload shapes used by the executive demo harness in `scripts/demo_exec_scenario.sh`, but they run directly on the local workstation without the VM wrapper.

Files:

- `trigger_token_exfil.py`
  - Maps to `attack-token-exfil` and `attack-websocket-hijack`.
  - CVE anchor: `CVE-2026-25253` and `CVE-2025-52882`.
  - Keeps a fake SSH credential file open and, if present, also reads `~/.edamame_psk`, while generating repeated TLS egress to `1.0.0.1`.
  - Expected app behavior: `token_exfiltration` vulnerability finding, plus divergence if the active model forbids the traffic or file access.

- `trigger_tmp_lineage.sh`
  - Maps to `attack-lineage` and `attack-hook-rce`.
  - CVE anchor: `CVE-2026-24763` and `CVE-2025-59536`.
  - Launches a long-running payload from `/tmp` that repeatedly calls `curl` against `1.0.0.1`.
  - Expected app behavior: divergence on suspicious lineage or `/tmp` ancestry. Depending on platform L7 attribution, it can also surface `sandbox_exploitation`.

- `trigger_config_exfil.py`
  - Maps to `attack-config-exfil`.
  - CVE anchor: `CVE-2026-21852`.
  - Keeps `~/.claude/settings.json` and `~/.env_demo_sc8` open while generating repeated TLS POST requests.
  - Expected app behavior: divergence on `not_expected_open_files` and unexpected egress when the behavioral model forbids those accesses.

- `cleanup.sh`
  - Stops any injector started from this folder and removes only demo files that these scripts created themselves.

Usage:

```bash
cd demo/cli-injection

# CVE-2026-25253 / CVE-2025-52882 pattern
python3 trigger_token_exfil.py

# CVE-2026-24763 / CVE-2025-59536 pattern
bash trigger_tmp_lineage.sh

# CVE-2026-21852 pattern
python3 trigger_config_exfil.py

# Stop and clean up
bash cleanup.sh
```

Notes:

- All scripts are user-space only; no root is required.
- The network target defaults to `1.0.0.1:443` with SNI `one.one.one.one` to match the demo scenarios.
- The scripts never overwrite an existing `~/.edamame_psk` or `~/.claude/settings.json`.
- If a seed file already exists, the injector reads it in place instead of replacing it.
