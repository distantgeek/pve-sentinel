# pve-sentinel

> LLM-driven security advisory agent for Proxmox VE.
> GLM-5.1 powered vulnerability monitoring, CVE tracking, and infrastructure guidance.

## Quick Reference

| Item | Value |
|------|-------|
| LXC | 101, Debian 13, 192.168.2.5, 4C/8GB/32GB |
| Proxmox host | kevbot-pve, 192.168.2.146 |
| SSH | `ssh -i ~/.ssh/id_ed25519_pve-sentinel kevbot@192.168.2.5` |
| LLM | GLM-5.1 via OpenCode Go REST API (Zen: glm-4 free tier) |
| API endpoint | `https://opencode.ai/zen/go/v1/chat/completions` |
| API key env var | `OPENCODE_GO_API_KEY` (set in `.env` on LXC) |
| Tests | `uv run pytest tests/` — 138 passing (+13 env-gated conversation tests) |
| Python venv | `/home/kevbot/advisory/.venv` (uv-managed) |
| Proxmox API | `claude@pam!claudeToken` (ClaudeDevbox role) |
| Proxmox token env | `PROXMOX_TOKEN_VALUE` (set in `.env` on LXC) |
| Version | 0.6.0 |

## Architecture

```
LXC 101: pve-sentinel (Debian 13, unprivileged)
┌─────────────────────────────────────────────────────────┐
│ OpenCode Go REST API (direct HTTPS)                      │
│   https://opencode.ai/zen/go/v1                           │
│   Model: glm-5.1                                          │
├─────────────────────────────────────────────────────────┤
│ Python orchestrator (uv + Python 3.13)                   │
│   cli.py              Interactive REPL (prompt_toolkit)  │
│   src/config.py        YAML config + dotenv + env resolve│
│   src/database.py      SQLite schema + CRUD (12 tables)  │
│   src/opencode_client.py  Direct API client (httpx)     │
│   src/guardrails.py    VALIDATION_DIRECTIVE + presets    │
│   src/cve_scanner.py   NVD+MITRE+PVE-SA pipeline (httpx) │
│   src/proxmox_tools.py proxmoxer (API-only, no pvesh)   │
│   src/permission_gate.py Read/write/destroy + secrets    │
│   src/setup.py         Setup helper (cert, verify)       │
│   src/scanner_cli.py   systemd timer entry point         │
│   src/framework_data/  NIST CSF AI reference data        │
├─────────────────────────────────────────────────────────┤
│ SQLite: sentinel.db (12 tables, 9 indexes, mode=0o700)  │
│ .env file: API keys, tokens (auto-loaded via dotenv)    │
│ systemd timers: cve-scanner (daily) + cve-digest (weekly│
│ MOTD: /etc/update-motd.d/50-sentinel (SSH login banner) │
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
| 5 | Host + LXC CVE monitoring | ✅ complete |
| 6 | OpenAI-compatible API → Open WebUI | deferred |
| 7 | Guest VM scanning (QEMU agent) | deferred |
| 8 | Community Scripts installer | deferred |

## Security Guardrails

### VALIDATION_DIRECTIVE ("Soul")

A single master constant (`src/guardrails.py:VALIDATION_DIRECTIVE`) is prepended to
every guardrail preset (named and custom). It enforces data validation and truthfulness:

- Never make definitive claims about system state you cannot verify
- Rootless advisor with API-only access — no shell access to Proxmox host
- "Pending Verification — I cannot access [X] via the available API" for inaccessible data
- Suggest verification via Proxmox web GUI or API endpoints, not CLI commands
- Do NOT suggest installing/running third-party tools unless explicitly asked
- Discuss and plan infrastructure changes before executing API operations
- Don't recommend actions that are already configured
- Cite specific data sources for findings
- Distinguish verified findings from general best practices
- Summary output: concise finding + source reference
- Deep-dive reports: full verbose details, raw data, complete analysis
- **Focus on topic** — when user asks about a specific topic, respond only on that topic. Do NOT re-list all findings or re-assess the entire system unless explicitly asked
- **Infer intent** — when user gives short responses like "yes", "go ahead", infer intent from the immediately preceding exchange in conversation history

**Single update point** — change `VALIDATION_DIRECTIVE` once, affects all presets.
**Model-agnostic** — applies to any LLM plugged in via the OpenAI-compatible API.

### Framework Presets

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
| `/digest` | Run full CVE scan and LLM summary (uses 24h cache; `force` bypasses) |
| `/cve check <pkg>` | Deep-dive a specific package's CVEs |
| `/cve scan` | Run host-only CVE scan |
| `/health` | Full hypervisor health dashboard |
| `/health rrd [period]` | Historical metrics (hour/day/week/month/year) |
| `/health services` | Proxmox service status |
| `/status` | Proxmox resource overview (VMs, LXCs, storage) |
| `/refresh [type]` | Update cached system context (repos/health/services/all) |
| `/db status` | Database size, row counts, maintenance level |
| `/db vacuum` | Run VACUUM to reclaim space |
| `/db prune [days]` | Archive and remove old unmatched CVEs (default 365) |
| `/db history [n]` | Show recent conversation history (default 10) |
| `/proxmox <action>` | Proxmox API operation (write = confirm required) |
| `/guardrails [preset]` | Show or switch security framework preset |
| `/history` | Recent scan history from SQLite |
| `/help` | Command reference |
| `/quit` | Exit the shell |

Free-text input is sent directly to the LLM for advisory chat. Each prompt includes:
1. **Recent conversation history** (last 10 messages, configurable) for continuity
2. **User message** (the current prompt)
3. **System context** (repos, health, services — reference only, at end of prompt)

Conversation history is logged to SQLite with topic extraction for retrieval.
The LLM is instructed to stay focused on the user's topic and not re-list all findings.

## Setup Helper

```bash
uv run python -m src.setup cert      # Fetch Proxmox CA cert (user-level)
uv run python -m src.setup verify    # Test Proxmox API + LLM connectivity
uv run python -m src.setup wizard    # Interactive setup (future)
```

The `cert` command fetches the Proxmox CA cert via `openssl s_client` and saves it
to `~/.local/share/ca-certificates/pve-root-ca.crt`. Note: this does NOT set
`SSL_CERT_FILE` — doing so would break external HTTPS (NVD, MITRE). For homelab
use, set `verify_ssl: false` in `config.yaml` instead.

## SSH Login MOTD

On SSH login to the LXC, a MOTD banner displays quick-start commands and file locations:

```
  Launch CLI:    cd ~/advisory && uv run python -m cli
  Quick scan:    cd ~/advisory && uv run python -m src.scanner_cli
  Setup verify:  cd ~/advisory && uv run python -m src.setup verify

  Key files:
    Config:      ~/advisory/config.yaml
    Secrets:     ~/advisory/.env
    Database:    ~/advisory/sentinel.db
    Timers:      ~/.config/systemd/user/cve-*.timer
```

MOTD source: `/etc/update-motd.d/50-sentinel` (requires root to edit).
Profile.d fallback: `/etc/profile.d/pve-sentinel.sh`.

## Key Design Decisions

1. **Direct API, no opencode serve** — Simpler, more reliable. One less moving part.
2. **SQLite, no PostgreSQL** — Zero-maintenance, portable, full SQL for CVE queries.
3. **Permission gate in Python layer** — Proxmox token never exposed to LLM.
4. **Read-by-default, confirm-for-write** — Human-in-the-loop for all mutating operations.
5. **Framework guardrails as system prompt** — Constrains LLM thinking, not command execution.
6. **httpx only** — Single HTTP library (removed requests dependency).
7. **CIS L1 alignment** — verify_ssl=True, secrets module for tokens, restricted DB dir (0o700), least-privilege deny_always.
8. **python-dotenv** — `.env` file auto-loaded regardless of shell context.
9. **No SSL_CERT_FILE override** — Setting it to Proxmox-only CA breaks external HTTPS (NVD, MITRE). Use `verify_ssl: false` for Proxmox instead.
10. **SSH key separation** — `id_ed25519_pve-sentinel` for LXC access, `id_ed25519_proxmox` for Proxmox host.
11. **API-only Proxmox access** — `proxmox_tools.py` uses `proxmoxer` API exclusively. No `pvesh` subprocess calls for host packages, repos, or run_command. Least-privilege: no root needed on Proxmox host.
12. **VALIDATION_DIRECTIVE as "Soul"** — Single constant for core LLM truthfulness principles. One update point, affects all guardrails. Prevents false positives by requiring data verification before making claims.
13. **Conversation history injection** — Last 10 messages (configurable) injected into each LLM prompt for multi-turn continuity. 500-char truncation per message to control token costs.
14. **24-hour scan cache** — `/digest` uses cached results (CVE data + LLM summary) within 24h TTL. `/digest force` bypasses cache. Avoids redundant API calls and LLM token costs.
15. **System context at end of prompt** — Cached repos/health/services placed after user message, labeled "reference data only" to prevent LLM from re-assessing everything on each turn.

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
# Standard tests (fast, no API calls):
cd /var/home/kevbot/pve-sentinel
uv run pytest tests/ -v

# Conversation tests (live LLM, env-gated):
PVE_SENTINEL_TEST_LLM=1 uv run pytest tests/test_conversation.py -v

# On LXC:
ssh -i ~/.ssh/id_ed25519_pve-sentinel kevbot@192.168.2.5
cd advisory
uv run pytest tests/ -v
```

## Database Maintenance

SQLite does not require periodic re-indexing like MSSQL. However, after heavy
DELETE operations, `VACUUM` reclaims free space in the database file.

| DB Size | Level | Behavior |
|---------|-------|----------|
| < 50MB | OK | Silent |
| 50-74MB | Info | Dim info on startup |
| 75-99MB | Warning | Yellow warning on startup |
| 100MB+ | Critical | Red nag on every startup |

**100MB is not critical for SQLite** (handles up to 281TB). The threshold is
about operational hygiene: backup speed, disk usage predictability, and data
lifecycle management. For homelab/SMB, 100MB+ is totally manageable.

```bash
/db status          # Show size, row counts, maintenance level
/db vacuum          # Reclaim space (1-3s, locks DB during operation)
/db prune [days]    # Archive unmatched CVEs older than N days (default 365)
/db history [n]     # Show recent conversation history
```

Pruned CVEs are archived to `cve_archive` table before deletion — reversible.
Does not affect future CVE detection (NVD fetch is independent of DB contents).

## Sync to LXC

```bash
cd /var/home/kevbot/pve-sentinel
tar czf /tmp/pve-sentinel-update.tar.gz \
  --exclude='.git' --exclude='.venv' --exclude='__pycache__' \
  --exclude='.pytest_cache' --exclude='sentinel.db' \
  . 2>/dev/null
cat /tmp/pve-sentinel-update.tar.gz | \
  ssh -i ~/.ssh/id_ed25519_pve-sentinel kevbot@192.168.2.5 \
  'cd advisory && tar xzf -'
```

## File Inventory

| File | Purpose | Status |
|------|---------|--------|
| `cli.py` | Interactive REPL with prompt_toolkit + rich, repo context in digest | ✅ Phase 3+ |
| `src/config.py` | YAML config loader, dotenv, env var resolution, token validation | ✅ Hardened |
| `src/database.py` | SQLite 12-table schema, CRUD, WAL mode, 0o700 dir, dedup | ✅ Hardened |
| `src/opencode_client.py` | Direct REST API client, context manager, cached guardrails | ✅ Hardened |
| `src/guardrails.py` | VALIDATION_DIRECTIVE + 4 presets + custom, system prompt injection | ✅ Phase 6 |
| `src/cve_scanner.py` | NVD+MITRE+PVE-SA pipeline, httpx, priority matrix, local pkg scan | ✅ Phase 5 |
| `src/proxmox_tools.py` | proxmoxer API-only (no pvesh), get_host_repos, dynamic traversal | ✅ Phase 6 |
| `src/permission_gate.py` | READ/WRITE/DESTRUCTIVE, secrets.choice, DENY_ALWAYS | ✅ Hardened |
| `src/setup.py` | Setup helper: cert fetch, connectivity verify | ✅ Phase 4.5 |
| `src/scanner_cli.py` | systemd timer entry point, host + local LXC scan | ✅ Phase 5 |
| `src/framework_data/nist_csf_ai.yaml` | NIST CSF 2.0 + AI considerations | ✅ Complete |
| `config.yaml.example` | Anonymized configuration template | ✅ Updated |
| `systemd/cve-scanner.service` | Daily scan service (EnvironmentFile=.env) | ✅ Phase 5 |
| `systemd/cve-scanner.timer` | Daily scan timer (00:06 UTC) | ✅ Phase 5 |
| `systemd/cve-digest.service` | Weekly digest service | ✅ Phase 5 |
| `systemd/cve-digest.timer` | Weekly digest timer (Mon 08:00 UTC) | ✅ Phase 5 |
| `tests/` | 138 tests across 11 modules | ✅ Complete |

## On-LXC File Locations

| Path | Purpose |
|------|---------|
| `~/advisory/config.yaml` | Main configuration (edit for Proxmox host, guardrails, CVE sources) |
| `~/advisory/.env` | Secrets: `OPENCODE_GO_API_KEY`, `PROXMOX_TOKEN_VALUE`, optional `NVD_API_KEY` |
| `~/advisory/sentinel.db` | SQLite database (CVEs, scans, advisories, matches) |
| `~/advisory/.venv/` | uv-managed Python virtual environment |
| `~/.config/systemd/user/cve-*.timer` | systemd user timers (scan + digest) |
| `~/.local/share/pve-sentinel/` | CLI history, logs |
| `/etc/update-motd.d/50-sentinel` | SSH login MOTD banner (root to edit) |
| `/etc/profile.d/pve-sentinel.sh` | Interactive shell quick-reference (root to edit) |

## SSL Verification Note

Proxmox VE's default self-signed CA certificate (`/etc/pve/pve-root-ca.pem`) does not
include the `keyUsage` X.509 extension required by modern Python/OpenSSL (3.12+).
This causes `CERTIFICATE_VERIFY_FAILED` even when the correct CA cert is installed.

**Workaround:** Set `verify_ssl: false` in `config.yaml` (acceptable for homelab
environments on trusted networks). The `src/setup.py cert` command is provided for
environments where the Proxmox CA has been replaced with a standards-compliant cert.

## Security Compliance

pve-sentinel adheres to three security frameworks:

| Framework | Status | Document |
|-----------|--------|----------|
| OWASP Secure Coding Practices | ✅ Compliant | `SECURITY.md` |
| CIS Secure Coding Standard (Python) | ✅ Compliant | `SECURITY.md` |
| NIST SSDF (SP 800-218) | ✅ Aligned | `SECURITY.md` |

### Coding Standards

- **No `eval()` or `exec()`** — Never used, never allowed
- **No `shell=True` in subprocess** — Always use list arguments
- **Parameterized SQL only** — All queries use `?` placeholders
- **`secrets` module for tokens** — Never `random` for security-sensitive values
- **`yaml.safe_load()` only** — Never `yaml.load()`
- **No hardcoded credentials** — All secrets via environment variables
- **Input validation** — All user input validated before use
- **File permissions** — `0o700` for directories, `0o600` for secret files
- **Resource cleanup** — Context managers and `finally` blocks for all connections

### LLM-Assisted Coding Policy

1. All LLM-generated code is reviewed before merge
2. All code passes `bandit` security scanning
3. New features include corresponding tests
4. All code must comply with OWASP and CIS standards
5. LLM-assisted commits are documented in commit messages

### Security Scanning

```bash
# Run bandit security scanner
uv run bandit src/ -r --severity-level medium

# Run full test suite
uv run pytest tests/ -v
```
