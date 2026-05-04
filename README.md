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
- **CVE Monitoring** — Multi-source vulnerability intelligence (NVD, MITRE)
  with daily scheduled scans and on-demand digests
- **Host + LXC Scanning** — Package-level vulnerability detection on both the
  Proxmox host and all LXC containers via native `pct exec`
- **Proxmox-Aware Remediation** — Correlates CVEs against Proxmox's curated
  package repos, never suggests upstream version pinning that could break PVE
- **LLM Advisory Chat** — GLM-5.1 provides contextual guidance, workarounds,
  and mitigation strategies with security framework guardrails
- **Permission Gating** — Read operations auto-approved; write operations
  require explicit confirmation; destructive operations require a random token
- **Security Guardrails** — LLM responses constrained to NIST CSF AI Profile,
  CIS Ubuntu Level 1, or CIS AI Controls Matrix frameworks
- **Setup Helper** — One-command CA cert installation and connectivity verification
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
EOF

# Install Proxmox CA certificate (for SSL verification)
uv run python -m src.setup cert

# Launch the CLI
uv run python cli.py
```

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
uv run python -m src.setup cert      # Install Proxmox CA cert to trust store
uv run python -m src.setup verify    # Test Proxmox API + LLM connectivity
```

The `cert` command fetches the Proxmox root CA certificate via the TLS handshake
on port 8006 and installs it to the system trust store. If run as a non-root user,
it displays the exact sudo command needed.

## Architecture

```
LXC: pve-sentinel (Debian 13, 4C/8GB/32GB, unprivileged)
├── OpenCode Go REST API → GLM-5.1 (direct HTTPS, no local server)
├── Python orchestrator  → CLI, CVE scanner, Proxmox tools
├── SQLite               → CVE database, package inventory (12 tables)
├── .env                 → API keys, tokens (auto-loaded via dotenv)
└── systemd timers       → Daily scans, weekly digests
```

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

62 tests across 7 modules: config, cve_scanner, database, guardrails,
opencode_client, permission_gate, proxmox_tools.

## License

MIT — see [LICENSE](LICENSE)
