# pve-sentinel

> LLM-driven security advisory agent for Proxmox VE.
> GLM-5.1 powered vulnerability monitoring, CVE tracking, and infrastructure guidance.

## Quick Reference

| Item | Value |
|------|-------|
| LXC | 101, Debian 13, 192.168.2.5, 4C/8GB/32GB |
| Proxmox host | kevbot-pve, 192.168.2.146 |
| SSH | `ssh -i ~/.ssh/id_ed25519_proxmox root@192.168.2.5` |
| LLM | GLM-5.1 via OpenCode Go REST API |
| API endpoint | `https://opencode.ai/zen/go/v1/chat/completions` |
| API key env var | `OPENCODE_GO_API_KEY` (set on LXC in kevbot's .bashrc) |
| Tests | `uv run pytest tests/` — 36 passing |
| Python venv | `/home/kevbot/advisory/.venv` (uv-managed) |
| Proxmox API | `claude@pam!claudeToken` (ClaudeDevbox role) |
| Proxmox token env | `PROXMOX_TOKEN_VALUE` (devbox env, not yet on LXC) |

## Architecture

```
LXC 101: pve-sentinel (Debian 13, unprivileged)
┌─────────────────────────────────────────────┐
│ OpenCode Go REST API (direct HTTPS)          │
│   https://opencode.ai/zen/go/v1              │
│   Model: glm-5.1                             │
├─────────────────────────────────────────────┤
│ Python orchestrator (uv + Python 3.14)      │
│   cli.py             Entry point             │
│   src/config.py       YAML config loader     │
│   src/database.py     SQLite schema + CRUD   │
│   src/opencode_client.py   Direct API client │
│   src/guardrails.py  Security framework presets│
│   src/cve_scanner.py  NVD+MITRE+ExploitDB    │
│   src/proxmox_tools.py  proxmoxer + pct exec │
│   src/permission_gate.py Read/write/destroy  │
│   src/framework_data/  NIST CSF AI reference │
├─────────────────────────────────────────────┤
│ SQLite: sentinel.db (12 tables, 9 indexes)  │
│ systemd timers: cve-scanner + cve-digest    │
└─────────────────────────────────────────────┘
```

## Phase Plan

| # | Phase | Status |
|---|-------|--------|
| 1 | Provision LXC + base tooling | ✅ complete |
| 2 | OpenCode Go direct API integration | ✅ complete |
| 2.5 | Security guardrails + NIST reference data | ✅ complete |
| 3 | Core CLI (interactive shell) | 🔜 next |
| 4 | Permission gates (confirm/CONFIRM-XXXX) | pending |
| 5 | Host + LXC CVE monitoring | pending |
| 6 | OpenAI-compatible API → Open WebUI | deferred |
| 7 | Guest VM scanning (QEMU agent) | deferred |
| 8 | Community Scripts installer | deferred |

## Security Guardrails

Four named presets selectable via config.yaml:

```yaml
guardrails:
  enabled: true
  preset: nist-cyber-ai  # cis-ubuntu-l1 | cis-ai | general | custom
```

Each preset injects a system prompt constraining the LLM to the chosen framework:
- **general**: Pragmatic security-first advisory (default)
- **cis-ubuntu-l1**: CIS Ubuntu Linux Benchmark Level 1 perspective
- **cis-ai**: CIS AI Controls Matrix perspective
- **nist-cyber-ai**: NIST CSF AI Profile with authoritative control IDs from NIST IR 8596 iprd

Reference data at `src/framework_data/nist_csf_ai.yaml` (full CSF 2.0 structure with AI considerations).

## Key Design Decisions

1. **Direct API, no opencode serve** — Simpler, more reliable. One less moving part.
2. **SQLite, no PostgreSQL** — Zero-maintenance, portable, full SQL for CVE queries.
3. **Permission gate in Python layer** — Proxmox token never exposed to LLM.
4. **Read-by-default, confirm-for-write** — Human-in-the-loop for all mutating operations.
5. **Framework guardrails as system prompt** — Constrains LLM thinking, not command execution.

## Provisioning (for reference)

LXC was created via Proxmox API with Debian 13 template. SSH key injection worked on the raw API call (not proxmoxer). The key insight: the `+` characters in SSH keys cause URL-encoding issues with proxmoxer but not with `requests.post(data=...)`.

LXC network: bridge vmbr0, static IP 192.168.2.5/24, gw 192.168.2.1, DNS 192.168.2.1 + 1.1.1.1.

## Test Commands

```bash
# On devbox:
cd /var/home/kevbot/pve-sentinel
uv run pytest tests/ -v

# On LXC:
ssh root@192.168.2.5 -i ~/.ssh/id_ed25519_proxmox
cd /home/kevbot/advisory
/usr/local/bin/uv run pytest tests/ -v
```

## Files Not Yet Synced to LXC

After local changes, sync with:
```bash
cd /var/home/kevbot/pve-sentinel
tar czf /tmp/pve-sentinel-update.tar.gz --exclude='.git' --exclude='.venv' --exclude='__pycache__' --exclude='.pytest_cache' src/ tests/ config.yaml.example pyproject.toml cli.py framework_data/ 2>/dev/null
cat /tmp/pve-sentinel-update.tar.gz | ssh -i ~/.ssh/id_ed25519_proxmox root@192.168.2.5 'cd /home/kevbot/advisory && tar xzf - && chown -R kevbot:kevbot .'
```

## Environment Variables Needed on LXC

- `OPENCODE_GO_API_KEY` — Set on LXC in `/home/kevbot/.bashrc` ✅ (user confirmed)
- `PROXMOX_TOKEN_VALUE` — NOT YET SET on LXC (needed for Phase 3+)
