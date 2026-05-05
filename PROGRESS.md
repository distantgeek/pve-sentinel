# PROGRESS.md — Session History

## 2026-05-04: Full Build Session (DeepSeek + Qwen)

### Phase 0 — Code Audit & Cleanup ✅ Complete

#### Audit Findings (9 critical/high issues identified and fixed)

| # | Issue | File | Severity | Fix Applied |
|---|-------|------|----------|-------------|
| 1 | Arbitrary pvesh execution via `run_command()` | `proxmox_tools.py:188` | CRITICAL | Gated by read-only allowlist + method check. Destructive paths blocked entirely. |
| 2 | `DENY_ALWAYS` was empty set | `permission_gate.py:32` | HIGH | Populated with `{"destroy", "remove", "delete", "unlink", "purge"}` |
| 3 | Non-crypto RNG for confirm tokens | `permission_gate.py:98` | HIGH | Replaced `random.choices` with `secrets.choice`, increased to 6 chars (36^6 = 2.1B) |
| 4 | Dead `opencode serve` code in config loader | `config.py:56-59` | HIGH | Removed entire opencode password resolution block |
| 5 | Silent empty API key | `opencode_client.py:24` | HIGH | Raises `ValueError` at init time |
| 6 | `verify_ssl=False` default | `proxmox_tools.py:31` | HIGH | Changed default to `True` (CIS L1) |
| 7 | Exploit-DB HTML scraping | `cve_scanner.py:193` | HIGH | Removed fragile scraping, conservative placeholder for future API |
| 8 | Stale `opencode-server.service` systemd unit | `systemd/` | HIGH | Deleted entirely |
| 9 | DB connection leak in `scan_lxc` | `cve_scanner.py:381` | HIGH | Fixed with proper context managers |

#### Additional Cleanup

- Removed `requests` dependency, migrated all HTTP to `httpx`
- Removed dead `_env_or()` function from config.py
- Added `encoding="utf-8"` to all `open()` calls
- Added `ValueError` on empty Proxmox token in config loader
- Fixed DB directory permissions to `0o700` (CIS L1)
- Added `__repr__` with credential redaction to ProxmoxTools
- Fixed `run_command()` to block non-GET methods without permission gate
- Replaced substring matching in permission gate with exact set membership
- Added empty action validation in permission gate
- Pinned dependency versions in pyproject.toml
- Added `[project.scripts]` entry point for `pve-sentinel` CLI
- Rewrote systemd units: `Requires=` → `After=`, inline Python → proper `scanner_cli.py`
- Updated `config.yaml.example`: `verify_ssl: true`, removed dead opencode section

#### Test Coverage Added

- `test_opencode_client.py` — 11 tests (init validation, health check, ask, error handling, context manager)
- `test_proxmox_tools.py` — 9 tests (init defaults, repr redaction, node detection, status, command gating)
- Updated `test_config.py` — 5 tests (added empty token validation, empty file rejection)
- Updated `test_permission_gate.py` — 10 tests (added deny_always, empty action, exact match)

**Total: 62 tests passing** (was 36)

### Phase 3 — Core CLI ✅ Complete

#### Interactive REPL (`cli.py`)

Built full interactive shell with:

- **prompt_toolkit** REPL with tab completion, command history (file-backed), custom styling
- **rich** output formatting: tables for `/status` and `/history`, panels for scan results, markdown rendering for LLM responses
- **Command router** with 9 slash commands
- **LLM advisory chat** — free-text input sent to GLM-5.1 with guardrail system prompt
- **Permission gate wiring** — `/proxmox` commands flow through `PermissionGate.request_confirmation()`
- **Guardrail switching** — `/guardrails <preset>` updates config and reinitializes client
- **Graceful degradation** — LLM and Proxmox features unavailable if not configured, shell still works for local commands
- **Startup status table** — shows LLM, Proxmox, Database, Guardrails status on launch

#### Commands Implemented

| Command | Implementation |
|---------|---------------|
| `/help` | Rich table of all commands |
| `/status` | ProxmoxTools.get_status() → rich tables for VMs/LXCs |
| `/history` | SQLite scan_log query → rich table |
| `/digest` | CVEScanner.scan_host() → panel + LLM summary |
| `/cve check <pkg>` | DB query → rich table + LLM analysis |
| `/cve scan` | Alias for /digest |
| `/guardrails` | Show current + available presets, switch on argument |
| `/proxmox <action>` | PermissionGate → ProxmoxTools (start/stop/status/generic) |
| `/quit` | Clean exit with client close |

### Phase 4.5 — Dotenv, SSL, Setup Helper ✅ Complete

#### python-dotenv Integration

- Added `python-dotenv>=1,<2` to dependencies
- `src/config.py` auto-loads `.env` from project directory or `~/.config/pve-sentinel/.env`
- No `.bashrc` or `.profile` sourcing needed — works in any shell context
- `.env` file owned by `kevbot:kevbot`, covered by `.gitignore`

#### SSL Certificate Handling

- Changed `verify_ssl` default to `True` (CIS L1)
- Added graceful SSL error handling to all CLI commands — shows fix options instead of raw traceback
- Created `src/setup.py` with `cert` command:
  - Uses `openssl s_client` to observe TLS handshake on Proxmox port 8006
  - Extracts root CA cert from chain (last cert in chain)
  - Installs to `/usr/local/share/ca-certificates/pve-root-ca.crt`
  - Runs `update-ca-certificates`
  - If non-root, displays exact sudo command needed

#### Setup Helper Module (`src/setup.py`)

```bash
uv run python -m src.setup cert      # Install Proxmox CA cert
uv run python -m src.setup verify    # Test Proxmox API + LLM connectivity
uv run python -m src.setup wizard    # Interactive setup (placeholder)
```

#### LXC Environment Fix

- Discovered `.bashrc` non-interactive guard (`case $- in *i*) ;; *) return;; esac`) prevented `.env` sourcing via `su - kevbot -c`
- Moved `.env` sourcing to `.profile` (always runs for login shells)
- Added dotenv as fallback so `.env` works regardless of shell context

### Files Changed in This Session

| File | Change |
|------|--------|
| `cli.py` | Complete rewrite: banner-only stub → full interactive REPL (~350 lines). Added SSL error handling to all command handlers. |
| `src/config.py` | Removed dead opencode code, added dotenv, added encoding, token validation |
| `src/database.py` | Added mode=0o700 for DB dir, id validation on insert |
| `src/opencode_client.py` | API key validation, context manager, cached guardrails, better errors |
| `src/guardrails.py` | No changes (already clean) |
| `src/cve_scanner.py` | httpx migration, connection leak fix, removed Exploit-DB scraping |
| `src/proxmox_tools.py` | verify_ssl=True, __repr__ redaction, run_command gating, _user attr |
| `src/permission_gate.py` | DENY_ALWAYS populated, secrets.choice, 6-char tokens, exact matching |
| `src/setup.py` | New: setup helper with cert, verify, wizard commands |
| `src/scanner_cli.py` | New: systemd timer entry point |
| `pyproject.toml` | v0.2.0, removed requests, added entry point, pinned versions, added pyfiglet, python-dotenv |
| `config.yaml.example` | verify_ssl=true, removed opencode section, added Option B docs, Google provider noted |
| `systemd/opencode-server.service` | Deleted (dead code) |
| `systemd/cve-scanner.service` | Rewritten: proper WorkingDirectory, script entry point |
| `systemd/cve-scanner.timer` | Requires= → After= |
| `systemd/cve-digest.timer` | Requires= → After= |
| `tests/test_config.py` | Added empty token and empty file tests |
| `tests/test_permission_gate.py` | Added deny_always, empty action, exact match tests |
| `tests/test_opencode_client.py` | New: 11 tests |
| `tests/test_proxmox_tools.py` | New: 9 tests |
| `AGENTS.md` | Full rewrite with Phase 0/3/4.5 status, security hardening table, file inventory |
| `PROGRESS.md` | This file |
| `README.md` | Updated with CLI commands, new architecture, guardrails table |

### Next: Phase 5 — Host + LXC CVE Monitoring

What needs to be built:
1. **NVD API key support** — Currently rate-limited to 5 req/6s without key. Add `NVD_API_KEY` env var support.
2. **Exploit-DB proper integration** — Replace placeholder with local database or proper API.
3. **PVE-SA feed parser** — Parse Proxmox security advisories from https://pve.proxmox.com/wiki/Security_Advisories
4. **LXC package scanning** — Wire `ProxmoxTools.get_lxc_packages()` into `CVEScanner.scan_lxc()`
5. **systemd timer activation** — Enable and start cve-scanner.timer and cve-digest.timer on LXC
6. **Digest generation** — Weekly digest output to `digests/` directory with markdown reports

### Architecture Decisions for Phase 5

- **Cluster support**: `ProxmoxTools` should iterate all nodes, not assume single node.
- **Local model path**: Already architected in config (provider: ollama, api_base, etc.).
- **Multi-method package discovery**: For guest scanning (Phase 7), dpkg/rpm/apk/flatpak/npm/pip/containers.

### Known Limitations

1. Exploit-DB check is a conservative placeholder (always returns no exploit)
2. NVD API rate-limited without API key
3. PVE-SA database is empty (no advisory feed parser yet)
4. LXC scanning requires manual package population (no automated pct exec pipeline yet)
5. No conversation history persistence (only scan history in SQLite)
6. **SSL verification with Proxmox default CA**: Proxmox VE's default self-signed CA
   certificate lacks the `keyUsage` X.509 extension required by modern Python/OpenSSL
   (3.12+). `verify_ssl: false` in `config.yaml` is required for homelab environments.
   The `src/setup.py cert` command is provided for environments where the Proxmox CA
   has been replaced with a standards-compliant cert.

### 2026-05-05: SSH Key Separation + SSL Investigation

- Generated sentinel-specific SSH key pair (`id_ed25519_pve-sentinel`) for kevbot-only LXC access
- Updated `src/setup.py cert` for user-level CA trust store (`~/.local/share/ca-certificates/`)
- Updated `.env` template with `SSL_CERT_FILE` and `REQUESTS_CA_BUNDLE`
- Updated `config.yaml.example` with user-level CA documentation
- Injected new SSH key into LXC kevbot `authorized_keys` (no root, no `chown`)
- Tested LXC access with new key — works perfectly, zero root needed
- **SSL root cause identified**: Proxmox default CA cert missing `keyUsage` extension
  — confirmed via `openssl x509 -text`. Env var ordering irrelevant; cert itself is
  invalid by modern X.509 standards. `verify_ssl: false` is the practical workaround.
- Updated `AGENTS.md`, `PROGRESS.md` with SSL limitation documentation

### 2026-05-05: Phase 5 — Host + LXC CVE Monitoring ✅ Complete

- **NVD API key support**: `NVD_API_KEY` env var, raises rate limit from 5 to 50 req/6s
- **PVE-SA feed parser**: `fetch_pve_advisories()` scrapes Proxmox wiki, `sync_pve_advisories()` populates local DB
- **Local LXC package scanning**: `scan_local_packages()` auto-detects via `dpkg-query`, cross-references 90-day CVE DB
- **systemd timers**: `cve-scanner.timer` (daily 00:06 UTC), `cve-digest.timer` (weekly Mon 08:00 UTC)
- **MOTD banner**: `/etc/update-motd.d/50-sentinel` shows CLI commands + file locations on SSH login
- **Profile.d fallback**: `/etc/profile.d/pve-sentinel.sh` for interactive shells
- **SSL fix**: Removed `SSL_CERT_FILE` from `.env` — it was breaking external HTTPS
- Scanner runs: 213 CVEs fetched, 285 local packages checked, 0 matches (clean LXC)
- Version bumped to 0.3.0

### 2026-05-05: API Migration + VALIDATION_DIRECTIVE ✅ Complete

**VALIDATION_DIRECTIVE ("Soul")**
- Added `VALIDATION_DIRECTIVE` constant to `src/guardrails.py` — single update point
- Prepended to ALL guardrail presets (named and custom) via `get_system_prompt()`
- Core principles: no unverified claims, "Pending Verification" for inaccessible data,
  cite data sources, distinguish verified vs general, summary concise / deep-dive verbose
- 5 new tests: directive nonempty, prepended to default/preset/custom, contains key principles

**API Migration — `proxmox_tools.py`**
- `get_host_packages()`: replaced `pvesh` subprocess with `apt/versions` API endpoint
- `get_host_repos()`: new method using `apt/repositories` API — returns structured repo status
  (enabled/disabled repos, warnings, errors) for LLM context injection
- `run_command()`: replaced `pvesh` subprocess with dynamic API traversal (`_api_traverse()`)
- Removed `subprocess` import from module-level (kept in `get_lxc_packages()` for Phase 7)
- `get_lxc_packages()` kept as subprocess — requires root on Proxmox host, Phase 7 API migration
- 2 new tests: `test_returns_installed_packages`, `test_returns_repo_summary`

**CLI — `/digest` with repo context**
- Removed `FileNotFoundError` catch (no longer needed — no subprocess)
- Fetch repo status via `get_host_repos()` and include in LLM prompt
- Scan results panel shows: host CVEs, LXC matches, enabled repos, duration
- LLM now correctly references repo data instead of producing false positives

**Database fix**
- `update_host_packages()` deduplicates by (name, version) to handle API returning duplicates
- Fixed `UNIQUE constraint failed: host_packages.name, host_packages.version`

**Results**
- LLM correctly says "Pending Verification" for data it can't access (source file contents)
- No more false "enable Proxmox repos" recommendations — LLM sees No-Subscription is enabled
- Scan results: 30 CVEs across 59 host packages, 0 matches across 285 LXC packages
- Version bumped to 0.4.0
- Tests: 68 passing (was 62)
