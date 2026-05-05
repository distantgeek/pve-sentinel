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

## Tests

```bash
# Standard tests (fast, no API calls):
uv run pytest tests/ -v

# Conversation tests (live LLM, env-gated):
PVE_SENTINEL_TEST_LLM=1 uv run pytest tests/test_conversation.py -v
```

97 standard tests across 10 modules: config, cve_scanner, database, db_maintenance,
guardrails, opencode_client, permission_gate, proxmox_tools, setup, snapshot.

Plus 13 conversation tests (env-gated) that verify LLM guardrail compliance:
no hallucinated commands, no unsolicited tool suggestions, correct verification
format, plan-before-execute behavior, and preset framing.

## License

MIT — see [LICENSE](LICENSE)
