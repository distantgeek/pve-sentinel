   ___ _   ______    _________  _____________  ________
  / _ \ | / / __/___/ __/ __/ |/ /_  __/  _/ |/ / __/ /
 / ___/ |/ / _//___/\ \/ _//    / / / _/ //    / _// /__
/_/   |___/___/   /___/___/_/|_/ /_/ /___/_/|_/___/____/

LLM-driven security advisory agent for Proxmox VE.

GLM-5.1 powered vulnerability monitoring, CVE tracking, and intelligent
infrastructure guidance — with human-in-the-loop permission gating.

## What Sentinel Does

| Capability | What It Means |
|------------|---------------|
| **CVE Intelligence** | Aggregates NVD, MITRE, and Proxmox PVE-SA advisories into a unified vulnerability feed with daily scans and weekly digests |
| **Package-Level Scanning** | Detects CVEs against installed packages on the Proxmox host and LXC containers — not just version matching, but PVE repo awareness |
| **Proxmox-Aware Remediation** | Correlates findings against Proxmox's curated package pipeline. Never suggests upstream version pinning that could break PVE |
| **LLM Advisory Chat** | GLM-5.1 provides contextual guidance, workarounds, and mitigation strategies — constrained by security framework guardrails |
| **System Health Monitoring** | Real-time CPU, RAM, storage, disk S.M.A.R.T., service status, and historical RRD metrics via Proxmox API |
| **Conversation Memory** | Chat history logged with topic extraction. System context (repos, health, services) cached and injected into every conversation |
| **Permission Gating** | Read operations auto-approved. Write operations require explicit confirmation. Destructive operations require a random token |
| **Management Mode** | Opt-in (`permissions.management_mode: true`) full API management — create/modify/delete VMs, LXCs, network, and storage with explicit per-operation confirmation |
| **Security Guardrails** | LLM responses constrained to NIST CSF AI Profile, CIS Ubuntu Level 1, CIS AI Controls Matrix, or general security-first |
| **Data Validation ("Soul")** | LLM cannot make claims it cannot verify. Prevents false positives and hallucinated commands. Cites data sources for every finding |
| **Database Management** | Tiered size warnings (50/75/100MB), VACUUM support, safe pruning with archive tables, conversation history with topic-based retrieval |
| **API-Efficient Design** | System context cached during scans. Zero extra API calls for chat. Lightweight `/refresh` for on-demand updates |
| **Scheduled Automation** | systemd timers for daily CVE scans and weekly digest reports. MOTD banner on SSH login with quick-start commands |

## Quick Start

```bash
# Clone and install
git clone https://github.com/distantgeek/pve-sentinel.git
cd pve-sentinel
uv sync

# Configure
cp config.yaml.example config.yaml
# Edit config.yaml with your Proxmox host details

# Create .env file
cat > .env << EOF
OPENCODE_GO_API_KEY=your-key-here
PROXMOX_TOKEN_VALUE=your-uuid-secret-here
# Optional: raises NVD API rate limit from 5 to 50 req/6s
# NVD_API_KEY=your-nvd-key-here
# Optional: only if you configure an OpenRouter free fallback
# OPENROUTER_API_KEY=sk-or-...
EOF

# Verify connectivity
uv run python -m src.setup verify

# Launch the CLI
uv run python cli.py
```

### On the LXC

SSH into the LXC and the MOTD displays quick-start commands:

```
  Launch CLI:    cd ~/advisory && uv run python -m cli
  Quick scan:    cd ~/advisory && uv run python -m src.scanner_cli
  Setup verify:  cd ~/advisory && uv run python -m src.setup verify
```

Key file locations on the LXC:

| Path | Purpose |
|------|---------|
| `~/advisory/config.yaml` | Main configuration |
| `~/advisory/.env` | API keys and tokens |
| `~/advisory/sentinel.db` | SQLite CVE database |
| `~/.config/systemd/user/cve-*.timer` | Scheduled scan timers |

## CLI Commands

```
/digest              Run full CVE scan and LLM summary (caches system context)
/cve check <pkg>     Deep-dive a specific package
/cve scan            Run host-only CVE scan
/status              Proxmox resource overview
/health [subcmd]     System health: full, rrd [timeframe], services
/refresh [type]      Update cached context: repos/health/services/all
/db [subcmd]         Database: status/vacuum/prune/history
/proxmox <action>    Proxmox API operation (write = confirm required)
/guardrails [preset] Show or switch security framework preset
/history             Recent scan history
/help                Command reference
/quit                Exit the shell
```

Free-text input is sent directly to the LLM for advisory chat. System context
(repos, health, services) is cached during `/digest` or `/refresh` and injected
into every chat message with timestamp attribution.

## Management Mode

By default the agent is read-heavy: it can query the API freely, perform basic
confirmed writes (start/stop VMs and LXCs, create VMs/LXCs/network/storage), but
critical endpoints (`stop`/`reboot`/`resize`/`migrate`/`move`/`firewall`/`acl`/
`user`/`group`/`permissions`) and **all DELETE operations are hard-blocked**.

Set `permissions.management_mode: true` in `config.yaml` to unlock full API
management. In management mode:

| Operation | Confirmation required |
|-----------|-----------------------|
| GET (read) | auto-approved |
| POST/PUT (create/modify) | type `y` |
| DELETE (remove VM/LXC/network/storage) | type `DELETE` |

Path-level destructive keywords (`destroy`/`delete`/`remove`/`unlink`/`purge`)
are **always** blocked, even in management mode. Every mutating operation is
logged to the audit trail (`tool_audit`) regardless of mode.

The LLM can request single calls or batches of up to 5 operations:

```
[TOOL:proxmox_api] POST /nodes/pve/qemu {"vmid": 200, "name": "web-02", "cores": 2, "memory": 4096}
```

## Setup Helper

```bash
uv run python -m src.setup cert      # Fetch Proxmox CA cert (user-level)
uv run python -m src.setup verify    # Test Proxmox API + LLM connectivity
```

The `cert` command fetches the Proxmox root CA certificate via `openssl s_client`
and saves it to `~/.local/share/ca-certificates/pve-root-ca.crt`.

**Note:** Do NOT set `SSL_CERT_FILE` to this file — it contains only the Proxmox
CA and will break external HTTPS (NVD, MITRE). For homelab environments, set
`verify_ssl: false` in `config.yaml` instead.

## Architecture

```
LXC: pve-sentinel (Debian 13, 4C/8GB/32GB, unprivileged)
├── OpenCode Go REST API → GLM-5.1 (direct HTTPS, no local server)
├── Python orchestrator  → CLI, CVE scanner, Proxmox tools
├── CVE sources          → NVD API, MITRE CVE, PVE-SA wiki feed
├── Proxmox API          → proxmoxer (API-only, no pvesh subprocess)
├── SQLite               → CVE database, package inventory, advisories, conversation log
├── .env                 → API keys, tokens (auto-loaded via dotenv)
├── systemd timers       → Daily scans (00:06), weekly digests (Mon 08:00)
└── MOTD                 → SSH login banner with quick-start commands
```

## Data Validation ("Soul")

All LLM responses are constrained by `VALIDATION_DIRECTIVE` — a single constant
in `src/guardrails.py` that enforces truthfulness:

- Never make claims about system state you cannot verify
- Rootless advisor with API-only access — no shell access to Proxmox host
- "Pending Verification" for inaccessible data, with timestamp-attributed cached context
- Do NOT suggest installing or running third-party tools unless explicitly asked
- Discuss and plan infrastructure changes before executing API operations
- Prioritize Proxmox-specific package management over generic Debian commands
- Don't recommend actions that are already configured
- Cite specific data sources for findings

This prevents false positives like "enable Proxmox repos" when repos are already enabled,
and stops hallucinated commands like `pveum audit cve-scan` (which doesn't exist).
The LLM receives real system data from cached snapshots and can make informed recommendations.

## Security Guardrails

Four named presets constrain the LLM's advisory perspective:

| Preset | Framework |
|--------|-----------|
| `general` | Pragmatic security-first advisory (default) |
| `cis-ubuntu-l1` | CIS Ubuntu Linux Benchmark Level 1 |
| `cis-ai` | CIS AI Controls Matrix |
| `nist-cyber-ai` | NIST CSF AI Profile (NIST IR 8596 iprd) |

Configure in `config.yaml`:

```yaml
guardrails:
  enabled: true
  preset: nist-cyber-ai
```

## Model Configuration

Default: GLM-5.1 via OpenCode Go (paid). OpenCode Zen (free tier, GLM-4) also supported:

```yaml
model:
  provider: opencode-go    # or opencode-zen for free tier
  model_id: glm-5.1        # glm-4 for zen
  # Alternatives: openai, anthropic, google, ollama, or custom OpenAI-compatible API
```

### Optional LLM Fallback

If the primary provider is rate-limited, out of credits, or errors, an optional
`model.fallback` list is tried in order. This is opt-in — paying users can leave
it empty and use the primary exclusively. A no-cost safety net example using
OpenRouter's `openrouter/free` meta-model (auto-routes to a currently-available
free model, so OpenRouter's weekly free-tier rotation never breaks the config):

```yaml
model:
  provider: opencode-go
  model_id: glm-5.1
  fallback:
    - provider: openrouter
      model_id: openrouter/free
      api_key_env: OPENROUTER_API_KEY
      api_base: https://openrouter.ai/api/v1
```

Set `OPENROUTER_API_KEY` in `.env`. Any non-2xx response (including a 404 for a
rotated-out model) moves to the next fallback entry.

## Tests

```bash
# Standard tests (fast, no API calls):
uv run pytest tests/ -v

# Conversation tests (live LLM, env-gated):
PVE_SENTINEL_TEST_LLM=1 uv run pytest tests/test_conversation.py -v
```

196 tests across 12 modules: cli, config, cve_scanner, database, db_maintenance,
guardrails, opencode_client, permission_gate, proxmox_tools, scanner_cli, setup,
snapshot.

Plus 13 conversation tests (env-gated) that verify LLM guardrail compliance:
no hallucinated commands, no unsolicited tool suggestions, correct verification
format, plan-before-execute behavior, and preset framing.

## Community Scripts Installer

A [Proxmox VE Helper-Scripts](https://community-scripts.org) installer is
staged at the repo root, mirroring the
[`community-scripts/ProxmoxVED`](https://github.com/community-scripts/ProxmoxVED)
layout for drop-in submission:

| File | Purpose |
|------|---------|
| [`ct/pve-sentinel.sh`](ct/pve-sentinel.sh) | Creates a Debian 13 unprivileged LXC on the PVE host |
| [`install/pve-sentinel-install.sh`](install/pve-sentinel-install.sh) | Runs inside the LXC: `setup_uv`, git clone, config, systemd timers |
| [`json/pve-sentinel.json`](json/pve-sentinel.json) | Website metadata + unattended `app_vars` |

**Test on a Proxmox host** (the engine needs the scripts base — our repo):

```bash
COMMUNITY_SCRIPTS_URL=https://raw.githubusercontent.com/distantgeek/pve-sentinel/main \
bash -c "$(wget -qLO - https://raw.githubusercontent.com/distantgeek/pve-sentinel/main/ct/pve-sentinel.sh)"
```

Unattended (values are exported and carried into the LXC):

```bash
bash ct/pve-sentinel.sh mode=unattended \
  var_proxmox_host=192.168.x.x \
  var_proxmox_user=sentinel@pve \
  var_proxmox_token_name=sentinel \
  var_proxmox_token_value=<uuid> \
  var_opencode_api_key=<key>
```

### Submission checklist

- [x] Bare-metal install (no Docker) — Python via `setup_uv`
- [x] `$STD` before apt/git/uv commands, `msg_info`/`msg_ok` for custom code
- [x] Required `app_vars` exported from CT script and declared in JSON
- [x] Update function present (`git pull` + `uv sync` + restart)
- [x] Footer `motd_ssh`, `customize`, `cleanup_lxc`
- [x] `apt` (not `apt-get`); no core packages listed as deps
- [x] JSON metadata with `install_methods`, `app_vars`, `notes`

Known deviations to resolve before submitting a PR: cut a tagged GitHub release
and switch the scripts to `fetch_and_deploy_gh_release`/`check_for_gh_release`;
add a selfhst `pve-sentinel` logo; leave `architectures` unset until arm64 is
verified.

## License

MIT — see [LICENSE](LICENSE)
