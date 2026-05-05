# pve-sentinel

> LLM-driven security advisory agent for Proxmox VE.
> GLM-5.1 powered vulnerability monitoring, CVE tracking, and infrastructure guidance.

## Quick Reference

| Item | Value |
|------|-------|
| LXC | 101, Debian 13, 192.168.2.5, 4C/8GB/32GB |
| Proxmox host | kevbot-pve, 192.168.2.146 |
| SSH | `ssh -i ~/.ssh/id_ed25519_proxmox kevbot@192.168.2.5` |
| LLM | GLM-5.1 via OpenCode Go REST API |
| API endpoint | `https://opencode.ai/zen/go/v1/chat/completions` |
| API key env var | `OPENCODE_GO_API_KEY` (set in `.env` on LXC) |
| Tests | `uv run pytest tests/` — 62 passing |
| Python venv | `/home/kevbot/advisory/.venv` (uv-managed) |
| Proxmox API | `claude@pam!claudeToken` (ClaudeDevbox role) |
| Proxmox token env | `PROXMOX_TOKEN_VALUE` (set in `.env` on LXC) |
| Version | 0.2.0 |

## Architecture

```
LXC 101: pve-sentinel (Debian 13, unprivileged)
┌─────────────────────────────────────────────────────────┐
│ OpenCode Go REST API (direct HTTPS)                      │
│   https://opencode.ai/zen/go/v1                           │
│   Model: glm-5.1                                          │
├─────────────────────────────────────────────────────────┤
│ Python orchestrator (uv + Python 3.12/3.14)              │
│   cli.py              Interactive REPL (prompt_toolkit)  │
│   src/config.py        YAML config + dotenv + env resolve│
│   src/database.py      SQLite schema + CRUD (12 tables)  │
│   src/opencode_client.py  Direct API client (httpx)     │
│   src/guardrails.py    Security framework presets        │
│   src/cve_scanner.py   NVD+MITRE pipeline (httpx)        │
│   src/proxmox_tools.py proxmoxer + pvesh wrapper         │
│   src/permission_gate.py Read/write/destroy + secrets    │
│   src/setup.py         Setup helper (cert, verify)       │
│   src/scanner_cli.py   systemd timer entry point         │
│   src/framework_data/  NIST CSF AI reference data        │
├─────────────────────────────────────────────────────────┤
│ SQLite: sentinel.db (12 tables, 9 indexes, mode=0o700)  │
│ .env file: API keys, tokens (auto-loaded via dotenv)    │
│ systemd timers: cve-scanner + cve-digest                │
└─────────────────────────────────────────────────────────┘
```

## Phase Plan

| # | Phase | Status |
|---|-------|--------|
| 0 | Code audit + cleanup + hardening | ✅ complete |
| 1 | Provision LXC + base tooling | ✅ complete |
| 2 | OpenCode Go direct API integration | ✅ complete |
| 2.5 | Security guardrails + NIST reference data | ✅ complete |
| 3 | Core CLI (interactive shell) | ✅ complete |
| 4 | Permission gates (confirm/CONFIRM-XXXXXX) | ✅ complete |
| 4.5 | Dotenv support + SSL error handling + setup helper | ✅ complete |
| 5 | Host + LXC CVE monitoring | 🔜 next |
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

## CLI Commands

| Command | Description |
|---------|-------------|
| `/digest` | Run full CVE scan and LLM summary |
| `/cve check <pkg>` | Deep-dive a specific package's CVEs |
| `/cve scan` | Run host-only CVE scan |
| `/status` | Proxmox resource overview (VMs, LXCs, storage) |
| `/proxmox <action>` | Proxmox API operation (write = confirm required) |
| `/guardrails [preset]` | Show or switch security framework preset |
| `/history` | Recent scan history from SQLite |
| `/help` | Command reference |
| `/quit` | Exit the shell |

Free-text input is sent directly to the LLM for advisory chat.

## Setup Helper

```bash
uv run python -m src.setup cert      # Install Proxmox CA cert to trust store
uv run python -m src.setup verify    # Test Proxmox API + LLM connectivity
uv run python -m src.setup wizard    # Interactive setup (future)
```

The `cert` command fetches the Proxmox CA cert via `openssl s_client` and installs it to the user-level trust store.
extracts the root CA cert from the chain, and installs it via `update-ca-certificates`.
If run as non-root, it displays the exact sudo command needed.

## Key Design Decisions

1. **Direct API, no opencode serve** — Simpler, more reliable. One less moving part.
2. **SQLite, no PostgreSQL** — Zero-maintenance, portable, full SQL for CVE queries.
3. **Permission gate in Python layer** — Proxmox token never exposed to LLM.
4. **Read-by-default, confirm-for-write** — Human-in-the-loop for all mutating operations.
5. **Framework guardrails as system prompt** — Constrains LLM thinking, not command execution.
6. **httpx only** — Single HTTP library (removed requests dependency).
7. **CIS L1 alignment** — verify_ssl=True, secrets module for tokens, restricted DB dir (0o700), least-privilege deny_always.
8. **python-dotenv** — `.env` file auto-loaded regardless of shell context.
9. **SSL Option B as default** — Install Proxmox CA cert instead of disabling verification.

## Security Hardening (Phase 0)

| Issue | Fix |
|-------|-----|
| `DENY_ALWAYS` was empty | Populated with destructive actions |
| `random` for confirm tokens | Replaced with `secrets.choice`, 6-char tokens |
| `verify_ssl=False` default | Changed to `True` (CIS L1) |
| Arbitrary `run_command` execution | Gated by read-only allowlist + method check |
| Dead `opencode serve` code | Removed systemd unit + config loader code |
| Exploit-DB HTML scraping | Removed (unreliable), placeholder for future API |
| DB connection leak | Fixed with context managers |
| DB dir permissions | Set to `0o700` (CIS L1) |
| Empty API key silent failure | Raises `ValueError` at init |
| Empty Proxmox token silent failure | Raises `ValueError` at config load |

## Environment Variables

Loaded automatically via `python-dotenv` from `.env` in the project directory:

```bash
OPENCODE_GO_API_KEY=sk-...
PROXMOX_TOKEN_VALUE=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

No `.bashrc` or `.profile` sourcing needed — dotenv handles it at import time.

## Provisioning (for reference)

LXC was created via Proxmox API with Debian 13 template. SSH key injection worked on the raw API call (not proxmoxer). The key insight: the `+` characters in SSH keys cause URL-encoding issues with proxmoxer but not with `requests.post(data=...)`.

LXC network: bridge vmbr0, static IP 192.168.2.5/24, gw 192.168.2.1, DNS 192.168.2.1 + 1.1.1.1.

## Test Commands

```bash
# On devbox:
cd /var/home/kevbot/pve-sentinel
uv run pytest tests/ -v

# On LXC:
ssh -i ~/.ssh/id_ed25519_proxmox kevbot@192.168.2.5
cd advisory
uv run pytest tests/ -v
```

## Sync to LXC

```bash
cd /var/home/kevbot/pve-sentinel
tar czf /tmp/pve-sentinel-update.tar.gz \
  --exclude='.git' --exclude='.venv' --exclude='__pycache__' \
  --exclude='.pytest_cache' --exclude='sentinel.db' \
  . 2>/dev/null
cat /tmp/pve-sentinel-update.tar.gz | \
  ssh -i ~/.ssh/id_ed25519_proxmox root@192.168.2.5 \
  'cd /home/kevbot/advisory && tar xzf - && chown -R kevbot:kevbot .'
```

## File Inventory

| File | Purpose | Status |
|------|---------|--------|
| `cli.py` | Interactive REPL with prompt_toolkit + rich | ✅ Phase 3 complete |
| `src/config.py` | YAML config loader, dotenv, env var resolution, token validation | ✅ Hardened |
| `src/database.py` | SQLite 12-table schema, CRUD, WAL mode, 0o700 dir | ✅ Hardened |
| `src/opencode_client.py` | Direct REST API client, context manager, cached guardrails | ✅ Hardened |
| `src/guardrails.py` | 4 presets + custom, system prompt injection | ✅ Complete |
| `src/cve_scanner.py` | NVD+MITRE pipeline, httpx, priority matrix | ✅ Hardened |
| `src/proxmox_tools.py` | proxmoxer wrapper, pvesh, path gating, verify_ssl=True | ✅ Hardened |
| `src/permission_gate.py` | READ/WRITE/DESTRUCTIVE, secrets.choice, DENY_ALWAYS | ✅ Hardened |
| `src/setup.py` | Setup helper: cert install, connectivity verify | ✅ New (Phase 4.5) |
| `src/scanner_cli.py` | systemd timer entry point | ✅ Complete |
| `src/framework_data/nist_csf_ai.yaml` | NIST CSF 2.0 + AI considerations | ✅ Complete |
| `config.yaml.example` | Anonymized configuration template | ✅ Updated |
| `systemd/cve-scanner.service` | Timer service (proper script entry point) | ✅ Fixed |
| `systemd/cve-scanner.timer` | Daily scan timer | ✅ Fixed |
| `systemd/cve-digest.timer` | Weekly digest timer | ✅ Fixed |
| `tests/` | 62 tests across 7 modules | ✅ Complete |

## SSL Verification Note

Proxmox VE's default self-signed CA certificate (`/etc/pve/pve-root-ca.pem`) does not
include the `keyUsage` X.509 extension required by modern Python/OpenSSL (3.12+).
This causes `CERTIFICATE_VERIFY_FAILED` even when the correct CA cert is installed.

**Workaround:** Set `verify_ssl: false` in `config.yaml` (acceptable for homelab
environments on trusted networks). The `src/setup.py cert` command is provided for
environments where the Proxmox CA has been replaced with a standards-compliant cert.
