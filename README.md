   ___ _   ______    _________  _____________  ________
  / _ \ | / / __/___/ __/ __/ |/ /_  __/  _/ |/ / __/ /
 / ___/ |/ / _//___/\ \/ _//    / / / _/ //    / _// /__
/_/   |___/___/   /___/___/_/|_/ /_/ /___/_/|_/___/____/

LLM-driven security advisory agent for Proxmox VE.

GLM-5.1 driven vulnerability monitoring, CVE tracking, and intelligent
infrastructure guidance — with human-in-the-loop permission gating.

## Features

- **CVE Monitoring** — Multi-source vulnerability intelligence (NVD, MITRE,
  Exploit-DB, Proxmox PVE-SA) with daily scheduled scans and on-demand digests
- **Host + LXC Scanning** — Package-level vulnerability detection on both the
  Proxmox host and all LXC containers via native `pct exec`
- **Proxmox-Aware Remediation** — Correlates CVEs against Proxmox's curated
  package repos, never suggests upstream version pinning that could break PVE
- **Public Exploit Detection** — Cross-references Exploit-DB to escalate
  severity when working PoCs exist
- **Intelligent Advisory** — GLM-5.1 provides contextual guidance,
  workarounds, and mitigation strategies
- **Permission Gating** — Read operations auto-approved; write operations
  require explicit confirmation; destructive operations require a random token
- **Guest VM Scanning** *(opt-in)* — Vulnerabilities inside VMs via QEMU
  Guest Agent, with multi-method package discovery (dpkg/rpm/apk/flatpak/npm/
  pip/containers)
- **Open WebUI Ready** — OpenAI-compatible API endpoint for integration with
  Open WebUI or any chat frontend

## Quick Start

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/community-scripts/ProxmoxVED/main/ct/pve-sentinel.sh)"
```

After installation, SSH into the LXC:

```bash
ssh sentinel@<lxc-ip>
```

## CLI Commands

```
/digest              Run full CVE scan (host + LXCs)
/cve check <pkg>     Deep-dive a specific package
/cve scan            Run host-only CVE scan
/scan guests         Scan all running VMs with QEMU agent
/scan full           Host + LXCs + VMs
/proxmox <action>    Proxmox API operation (write = confirm required)
/status              Proxmox resource overview
/history             Recent conversation
/help                Command reference
```

## Architecture

```
LXC: pve-sentinel (Debian 12, 4C/8GB/32GB)
  ├── opencode serve       → GLM-5.1 via OpenCode Go
  ├── Python orchestrator  → CLI, CVE scanner, Proxmox tools
  ├── SQLite               → CVE database, package inventory
  └── systemd timers       → Daily scans, weekly digests
```

## Model Configuration

Default: GLM-5.1 via OpenCode Go. Configurable via `config.yaml`:

```yaml
model:
  provider: opencode-go
  model_id: glm-5.1
  # Alternatives: deepseek-v4-pro, qwen3-coder, or any OpenAI-compatible API
```

## License

MIT — see [LICENSE](LICENSE)
