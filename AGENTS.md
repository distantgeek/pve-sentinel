# pve-sentinel

> LLM-driven security advisory agent for Proxmox VE.
> GLM-5.1 powered vulnerability monitoring, CVE tracking, and infrastructure guidance.

## Architecture

```
LXC (Debian 12, 4C/8GB/32GB)
├── opencode serve (port 4096) → GLM-5.1 via OpenCode Go
├── Python orchestrator (uv venv, 3.12+)
│   ├── CLI (rich + prompt_toolkit)  ← SSH entry
│   ├── CVE scanner (NVD + MITRE + ExploitDB + PVE-SA)
│   ├── Proxmox tools (proxmoxer + pct exec)
│   └── Permission gate (read auto / write confirm / destroy token)
├── SQLite → sentinel.db (12 tables)
└── systemd timers → daily scans + weekly digests
```

## Phase Plan

| # | Phase | Status |
|---|-------|--------|
| 1 | Provision LXC + base tooling | pending |
| 2 | OpenCode serve + GLM-5.1 integration | pending |
| 3 | Core CLI + Proxmox read queries | pending |
| 4 | Permission gates for write ops | pending |
| 5 | Host + LXC CVE monitoring | pending |
| 6 | OpenAI-compatible API → Open WebUI | deferred |
| 7 | Guest VM scanning (QEMU agent) | deferred |
| 8 | Community Scripts shell installer | deferred |

## Key Files

- `cli.py` — SSH entry point, pyfiglet banner
- `src/config.py` — YAML config loader, env var resolution
- `src/database.py` — Full SQLite schema + CRUD
- `src/cve_scanner.py` — Multi-source CVE pipeline
- `src/permission_gate.py` — Read/write/destructive gating
- `src/proxmox_tools.py` — proxmoxer wrapper, pct exec, qm guest exec
- `src/opencode_client.py` — HTTP → opencode serve REST API
- `config.yaml.example` — Anonymized template
- `systemd/` — opencode-server, cve-scanner, cve-digest units

## Commands

```
/digest              Full CVE scan (host + LXCs)
/cve check <pkg>     Deep-dive a specific package
/cve scan            Host-only CVE scan
/scan guests         All running VMs (QEMU agent required)
/scan full           Host + LXCs + VMs
/proxmox <action>    API operation (write = confirm required)
/status              Proxmox resource overview
/history             Recent conversation
/help                Command reference
```

## Test Commands

```bash
uv run python -m pytest tests/ -v    # Run all tests
uv run python cli.py                 # Run CLI
```

## CVE Data Pipeline

```
NVD API → MITRE CVE → Exploit-DB → Proxmox PVE-SA
         (enrich)     (escalate)    (patch status)
```

## Security Model

- Proxmox token: `claude@pam!claudeToken` (ClaudeDevbox role)
- Read operations: auto-approved
- Write operations: type "confirm"
- Destructive operations: type "CONFIRM-XXXX" (random token)
- No SSH keys shared with guests
- No guest modifications ever (reporting + advisory only)

## LXC Target

- IP: 192.168.2.5
- Proxmox host: 192.168.2.146
- Storage pool: SSD (to be determined during provisioning)
- Node: auto-detected
