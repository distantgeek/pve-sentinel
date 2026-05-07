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

### 2026-05-05: Phase 6 — `/health` Command + OpenCode Zen + Known API Gaps ✅ Complete

**`/health` Command**
- New `/health` command with subcommands: `full`, `rrd [timeframe]`, `services`
- `full`: CPU, RAM, RootFS, storage pools, S.M.A.R.T. disk health, VM/LXC counts
- `rrd [timeframe]`: Historical CPU/RAM metrics from Proxmox RRD (default `day`, supports `hour`/`week`/`month`/`year`)
- `services`: Proxmox systemd service status (pveproxy, pvedaemon, corosync, etc.)
- Health context bolted into `/digest` LLM prompt for holistic advisory summaries

**OpenCode Zen Provider**
- Added `opencode-zen` provider support in `opencode_client.py`
- `PROVIDER_BASE_URLS` dict maps provider to API endpoint
- Zen defaults to `glm-4` (free tier), opencode-go defaults to `glm-5.1`
- `config.yaml.example` updated with provider selection docs
- 6 new tests: zen base URL, default model, custom model, default provider, DEFAULT_MODELS dict, zen ask

**Known API Gaps (documented in AGENTS.md)**
- Temperature sensors: 501 Not Implemented in Proxmox API (requires `lm-sensors` + community patch)
- LXC package scanning: No API endpoint for guest package lists (requires LXC exec, Phase 7)
- S.M.A.R.T. detailed data: Limited to health status via API (full details require host-side tools)

**proxmox_tools.py additions**
- `get_health()`: Aggregated health dict (CPU%, RAM%, RootFS%, storage, disks, VMs, LXCs)
- `get_rrd_metrics(timeframe)`: Historical RRD data points with normalized timestamps
- `get_service_status()`: List of Proxmox services with running/dead state

**Results**
- Tests: 77 passing (was 68)
- Version: 0.4.0 (unchanged — additive feature)

### 2026-05-05: VALIDATION_DIRECTIVE Hardening + Conversation Tests ✅ Complete

**Problem: LLM hallucinated commands and suggested unsolicited tools**
- `pveum audit cve-scan --verbose` — completely fictional command
- Suggested `lynis`, `nmap`, `fail2ban` without being asked
- Forced to suggest CLI commands it had no shell access to run
- No awareness of its own API-only, rootless constraints

**VALIDATION_DIRECTIVE Rewrite (`src/guardrails.py`)**
- Removed `"Verify with: [command]"` pattern that forced hallucination
- Added explicit role definition: rootless advisor, API-only access
- Changed verification format: "Pending Verification — I cannot access [X] via the available API"
- Added suppression of unsolicited third-party tool recommendations
- Added plan-before-execute principle for infrastructure changes
- Model-agnostic — applies to any LLM via OpenAI-compatible API

**Conversation Tests (`tests/test_conversation.py`)**
- 13 live LLM tests gated behind `PVE_SENTINEL_TEST_LLM=1` env var
- Tests: no hallucinated commands, no unsolicited tools, pending verification format,
  no false claims, plan-before-execute, preset framing
- Skipped by default (costs tokens, slow), opt-in for verification runs
- Pattern-based assertions against response content

**Updated guardrail tests (`tests/test_guardrails.py`)**
- Added assertions for new directive principles: rootless advisor, API-only,
  no third-party tools, plan-before-execute

**Results**
- Standard tests: 77 passing
- Conversation tests: 13 (env-gated, run with `PVE_SENTINEL_TEST_LLM=1`)
- Total: 90 tests available (77 standard + 13 conversation)

### 2026-05-05: System Context Caching + /refresh Command ✅ Complete

**Problem: LLM had no awareness of system state between API calls**
- During free-text chat, LLM couldn't reference repo config, health, or services
- LLM hallucinated that it had no API access at all (it does — via Python layer)
- LLM suggested manual curl commands instead of using built-in capabilities
- Every chat message had zero system context

**System Snapshot Caching (`src/database.py`)**
- New `system_snapshot` table: stores JSON payloads keyed by type (repos/health/services)
- `cache_snapshot()`, `get_snapshot()`, `get_all_snapshots()`, `clear_snapshots()` CRUD
- During `/digest`, all API-fetched data is cached — zero extra API calls
- Snapshots include `updated_at` timestamp for freshness awareness

**Chat Context Injection (`cli.py`)**
- `_build_chat_context()` pulls all cached snapshots before every LLM chat message
- Context includes: repos (enabled/disabled), health (CPU/RAM/RootFS), services (running/dead)
- Each section includes cache timestamp for LLM to reference ("Based on snapshot from...")
- ~2ms SQLite read per chat message, zero API overhead

**`/refresh` Command**
- `/refresh repos` — fetch repo config, update cache
- `/refresh health` — fetch health metrics, update cache
- `/refresh services` — fetch service status, update cache
- `/refresh all` — fetch everything (default)
- Lightweight alternative to full `/digest` when you just need fresh context

**VALIDATION_DIRECTIVE Update**
- Added cached context awareness: "System context is cached in your conversation context"
- Added timestamp attribution: "Always note the snapshot timestamp when referencing data"
- LLM now knows to say "Based on the snapshot from 2026-05-05T14:32:00Z"

**Tests (`tests/test_snapshot.py`)**
- 7 new tests: cache/retrieve, missing returns None, overwrite, get_all, clear, complex data, timestamp freshness

**Results**
- Standard tests: 84 passing (was 77)
- API cost-conscious design: cache once, reference many times

### 2026-05-05: DB Maintenance + Conversation Log + /db Command ✅ Complete

**Database Maintenance (`src/database.py`)**
- New `get_size_mb()`, `get_maintenance_status()` with tiered levels (ok/info/warning/critical)
- `vacuum()` — reclaims space after DELETE operations
- `prune_old_cves(days)` — archives unmatched CVEs to `cve_archive` before deletion
- Tiered warnings: 50MB (info), 75MB (warning), 100MB+ (nag on every startup)
- 100MB is not critical for SQLite (handles 281TB) — threshold is operational hygiene

**Conversation Log (`src/database.py`)**
- New `conversation_log` table with role/content/timestamp/topic columns
- `log_conversation()` — auto-extracts topic from user input via keyword matching
- `get_recent_conversations(limit)` — returns last N messages in order
- `get_conversations_by_topic(topic, limit)` — topic-based retrieval
- `prune_conversations(days)` — archives to `conversation_archive` before deletion
- Topics: repositories, cves, guests, health, network, security, general

**`/db` Command (`cli.py`)**
- `/db status` — size, row counts, maintenance level
- `/db vacuum` — run VACUUM, show before/after size
- `/db prune [days]` — archive unmatched CVEs (default 365 days)
- `/db history [n]` — show recent conversation history (default 10)

**Startup DB Size Check**
- Info at 50MB: dim message, growing normally
- Warning at 75MB: yellow, suggests /db prune
- Critical at 100MB+: red nag every startup, explains why

**Health Integration**
- `/health` now shows DB status: size, level, CVE count, match count

**Conversation Logging**
- Every chat message logged to SQLite with topic extraction
- Deterministic keyword matching (no LLM overhead)
- Archived before pruning for safety

**`config.yaml.example`**
- Added `auto_vacuum: false` (user preference, not default)
- Added `db_size_threshold_mb: 100` (warning threshold)
- Documented pros/cons of auto-vacuum

**Tests (`tests/test_db_maintenance.py`)**
- 13 new tests: size monitoring, maintenance levels, vacuum, CVE pruning,
  conversation log, topic extraction, conversation pruning with archiving

**Results**
- Standard tests: 97 passing (was 84)
- Zero API overhead for all DB operations
- SQLite does NOT require periodic re-indexing like MSSQL

### 2026-05-06: CLI Syntax Fix + Test Suite

**Bug: `cli.py` had unclosed `try` block and `table` print outside `if` block**
- `SyntaxError: expected 'except' or 'finally' block` at `cli.py:572`
- `_cmd_digest` try block was never closed — no `except` handler
- `self.console.print(table)` was outside the `if lxc_result.get("matched_cves"):` block
- Also found dead code in `_cmd_refresh` referencing `_cmd_digest` variables

**Bug: `_handle_command("")` crashed with `IndexError`**
- Empty string input caused `parts[0].lower()` to fail
- Added `if not parts: return` guard

**Created `tests/test_cli.py` — 27 tests**
- Syntax/import checks (AST-based unclosed block detection)
- Constants validation (banner, commands dict, slash commands)
- SSL error panel rendering
- Shell initialization (minimal config, full config, history dir permissions)
- Command routing (all 12 slash commands)
- Chat context builder (empty snapshots, repos, health, services, combined)

**Results**
- Total tests: 124 passing (97 + 27 new)
- Caught the exact syntax error that was preventing CLI from loading

### 2026-05-06: 24-Hour Scan Cache with LLM Summary Caching

**Problem: `/digest` runs expensive scan + LLM summary every time, even if nothing changed**
- NVD/MITRE/PVE-SA API calls are rate-limited and network-bound
- LLM summary generation costs tokens
- CVE data and system state don't change meaningfully within a day

**Solution: Cache full scan results for 24 hours**
- `_cmd_digest` checks `scan_results` snapshot before running
- If within TTL: displays cached results + LLM summary with age indicator
- If stale or `/digest force`: runs fresh scan, updates cache
- Cache payload: host results, LXC results, LLM summary, repo summary
- Configurable via `scan_cache_ttl_hours` in config.yaml (default 24)

**UX: Clear cache status messaging**
- Fresh cache: "Using cached scan from [timestamp] (6 hours old)"
- Cached summary includes "Cached summary — ask a follow-up question for fresh analysis"
- `/digest force` or `/digest --force` bypasses cache

**Refactored `_cmd_digest` into two methods**
- `_cmd_digest()`: cache check + routing
- `_display_cached_digest()`: display cached results
- `_run_fresh_digest()`: full scan + cache update
- Removed dead code from `_cmd_refresh` (referenced `_cmd_digest` variables)

**Tests (`tests/test_cli.py`)**
- 6 new tests: cache hit within TTL, cache miss, force bypass (2 variants), summary note, matched CVEs

**Results**
- Total tests: 130 passing (was 124)

### 2026-05-06: Timezone-Aware Scan Cache Fix

**Bug: `TypeError: can't subtract offset-naive and offset-aware datetimes`**
- Cached timestamps from older versions lacked timezone info
- `datetime.fromisoformat()` returned naive datetime
- Could not subtract from `datetime.now(timezone.utc)`

**Fix**
- Attach UTC tzinfo to naive timestamps: `cached_ts.replace(tzinfo=timezone.utc)`
- Added `TypeError` to except clause for any comparison failures

**Tests**
- 2 new tests: naive timestamp handled gracefully, malformed timestamp falls through

**Results**
- Total tests: 132 passing (was 130)

### 2026-05-06: Conversation History Injection + Focus Guardrails

**Problem: LLM re-lists all findings on every message, loses context on "yes" responses**
- System context (repos/health/services) was the FIRST thing in every prompt
- LLM treated it as "here's what to talk about" each time
- No conversation history passed — LLM had zero memory of prior exchanges
- VALIDATION_DIRECTIVE had no "stay focused" principle

**Solution: Three-part fix**

**1. Conversation history injection**
- `_get_conversation_history()` fetches last N messages from `conversation_log`
- Default 10 messages (configurable via `conversation_history_depth`, 0 to disable)
- Each message truncated to 500 chars to control token costs
- Format: "Recent conversation: User: ... / Assistant: ..."

**2. System context repositioned**
- Moved to END of prompt (after user message + history)
- Label changed to "Available system context — reference data only. Do NOT re-list findings unless asked."
- No longer the dominant signal that triggers reassessment

**3. VALIDATION_DIRECTIVE focus principles**
- "When the user asks about a specific topic, focus your response on that topic only"
- "Do NOT re-list all findings or re-assess the entire system unless explicitly asked"
- "When the user gives short responses like 'yes', 'go ahead', infer intent from the immediately preceding exchange"

**Prompt assembly order (new)**
```
Recent conversation:
  User: Are you able to clean up the stale repos?
  Assistant: Yes — the Proxmox API provides endpoints...

User: yes please

Available system context — reference data only. Do NOT re-list findings unless asked.
  Repositories (cached ...): ...
  Health (cached ...): ...
  Services (cached ...): ...
```

**Tests**
- 8 new tests: history injection, empty history, depth=0, truncation, config depth,
  system context label, focus principles in guardrails (4 assertions)

**Results**
- Total tests: 138 passing (was 132)
- Token cost: ~1000-2000 extra tokens per message (acceptable for GLM-5.1)
- Configurable for cost-conscious users and lighter local model loads

## 2026-05-07: Quality Control Tooling

### ruff + mypy + bandit setup ✅ Complete

**Added to dev dependencies**
- `ruff>=0.9,<1` — Fast Python linter and formatter
- `mypy>=1.15,<2` — Static type checker
- `types-PyYAML>=6.0,<7` — Type stubs for PyYAML

**ruff configuration** (`pyproject.toml`)
- Target: Python 3.12
- Rules: E, F, W, I, N, UP, B, SIM, RUF
- Line length: 100
- Auto-fixable: 45 of 60 issues fixed automatically

**mypy configuration** (`pyproject.toml`)
- Python version: 3.12
- `ignore_missing_imports = true` (for untyped third-party libs)
- `check_untyped_defs = true`
- `warn_return_any = true`
- `strict_optional = true`

**Issues fixed**
- 45 auto-fixed by ruff (unused imports, import sorting, f-string cleanup, UTC alias)
- 15 manual fixes:
  - Unused loop variables renamed to `_i`, `_k`
  - `zip()` given `strict=True` parameter
  - Ternary operators for simple if-else blocks
  - Unused variable `current_advisory` removed
  - `ClassVar` annotation for `CONVERSATION_TOPICS`
  - List unpacking instead of concatenation
  - `# noqa: E402` for intentional post-sys.path imports
  - Implicit `Optional` → explicit `T | None`
  - `Callable[[str], bool]` → `Callable[[str, str], bool]` (type fix)
  - Keyword args → positional args for mypy compatibility
  - `# type: ignore[import-untyped]` for proxmoxer

**Results**
- ruff: All checks passed (0 errors)
- mypy: No errors (0 issues)
- bandit: 0 medium/high issues (14 low — intentional patterns)
- pytest: 165 passed (unchanged)

**Updated documentation**
- `AGENTS.md`: Added ruff/mypy commands to Security Scanning section
- `AGENTS.md`: Updated LLM-Assisted Coding Policy to include ruff + mypy
