   ___ _   ______    _________  _____________  ________
  / _ \ | / / __/___/ __/ __/ |/ /_  __/  _/ |/ / __/ /
 / ___/ |/ / _//___/\ \/ _//    / / / _/ //    / _// /__
/_/   |___/___/   /___/___/_/|_/ /_/ /___/_/|_/___/____/

LLM-driven security advisory agent for Proxmox VE.

GLM-5.1 driven vulnerability monitoring, CVE tracking, and intelligent
infrastructure guidance — with human-in-the-loop permission gating.

## Features

- **Interactive CLI** — prompt_toolkit REPL with tab completion, command history,
  and rich output formatting (tables, panels, markdown)
- **CVE Monitoring** — Multi-source vulnerability intelligence (NVD, MITRE, PVE-SA)
  with daily scheduled scans and weekly digest reports
- **Host + LXC Scanning** — Package-level vulnerability detection on both the
  Proxmox host and all LXC containers via native `pct exec` and local `dpkg-query`
- **Proxmox-Aware Remediation** — Correlates CVEs against Proxmox's curated
  package repos, never suggests upstream version pinning that could break PVE
- **LLM Advisory Chat** — GLM-5.1 provides contextual guidance, workarounds,
  and mitigation strategies with security framework guardrails
- **Permission Gating** — Read operations auto-approved; write operations
  require explicit confirmation; destructive operations require a random token
- **Security Guardrails** — LLM responses constrained to NIST CSF AI Profile,
  CIS Ubuntu Level 1, or CIS AI Controls Matrix frameworks
- **Setup Helper** — CA cert fetch and connectivity verification
- **SSH MOTD** — Login banner with quick-start commands and file locations
- **systemd Timers** — Daily CVE scans + weekly digest reports (user-level)
- **Guest VM Scanning** *(opt-in)* — Vulnerabilities inside VMs via QEMU
  Guest Agent, with multi-method package discovery (dpkg/rpm/apk/flatpak/npm/
  pip/containers)

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
/digest              Run full CVE scan and LLM summary
/cve check <pkg>     Deep-dive a specific package
/cve scan            Run host-only CVE scan
/status              Proxmox resource overview
/proxmox <action>    Proxmox API operation (write = confirm required)
/guardrails [preset] Show or switch security framework preset
/history             Recent scan history
/help                Command reference
/quit                Exit the shell
```

Free-text input is sent directly to the LLM for advisory chat.

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
├── SQLite               → CVE database, package inventory, advisories (12 tables)
├── .env                 → API keys, tokens (auto-loaded via dotenv)
├── systemd timers       → Daily scans (00:06), weekly digests (Mon 08:00)
└── MOTD                 → SSH login banner with quick-start commands
```

## Data Validation ("Soul")

All LLM responses are constrained by `VALIDATION_DIRECTIVE` — a single constant
in `src/guardrails.py` that enforces truthfulness:

- Never make claims about system state you cannot verify
- Use "Pending Verification" for inaccessible data
- Don't recommend actions that are already configured
- Cite specific data sources for findings

This prevents false positives like "enable Proxmox repos" when repos are already enabled.
The LLM receives real repo status from the Proxmox API and can make informed recommendations.

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

Default: GLM-5.1 via OpenCode Go. Configurable via `config.yaml`:

```yaml
model:
  provider: opencode-go
  model_id: glm-5.1
  # Alternatives: openai, anthropic, google, ollama, or custom OpenAI-compatible API
```

## Tests

```bash
uv run pytest tests/ -v
```

68 tests across 8 modules: config, cve_scanner, database, guardrails,
opencode_client, permission_gate, proxmox_tools, setup.

## License

MIT — see [LICENSE](LICENSE)
