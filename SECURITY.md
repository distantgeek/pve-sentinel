# Security Compliance — pve-sentinel

> This document maps pve-sentinel against the OWASP Secure Coding Practices
> Quick Reference Guide, CIS Secure Coding Standard (Python), and NIST
> Secure Software Development Framework (SSDF, SP 800-218).

## Compliance Summary

| Framework | Status | Coverage |
|-----------|--------|----------|
| **OWASP Secure Coding Practices** | ✅ Compliant (with documented exceptions) | 13/15 categories fully covered, 2 partially |
| **CIS Secure Coding Standard (Python)** | ✅ Compliant | All applicable rules covered |
| **NIST SSDF (SP 800-218)** | ✅ Aligned | All 4 practice groups addressed |

---

## OWASP Secure Coding Practices

### 1. Input Validation — ✅ Covered

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Validate all input from untrusted sources | ✅ | `src/permission_gate.py:52-53` — empty action validation |
| Validate type and range of numeric input | ✅ | `cli.py:750-755` — VMID validated with try/except |
| Validate against whitelist of allowed values | ✅ | `cli.py:579-583` — `/refresh` type whitelist |
| Validate file paths against traversal | ✅ | `src/config.py:84-91` — db_path path traversal protection |

### 2. Parameterized Queries — ✅ Covered

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Use parameterized queries for all SQL | ✅ | `src/database.py` — all queries use `?` placeholders |
| No string concatenation in SQL | ✅ | Verified across all database operations |

### 3. Encoding and Escaping — ✅ Covered

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Encode output for target interpreter | ✅ | `cli.py:1094` — newline sanitization for table display |
| JSON-serialize data before storage | ✅ | `src/database.py:400-406` — `json.dumps()` for snapshots |

### 4. Authentication — ✅ Covered

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Use strong authentication mechanisms | ✅ | Proxmox token-based auth, OpenCode API key |
| Never hardcode credentials | ✅ | `src/config.py:62-72` — env var resolution |
| Validate credentials at startup | ✅ | `src/opencode_client.py:48-52`, `src/config.py:67-71` |

### 5. Session Management — ✅ Covered (with documented design choice)

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Close resources on session end | ✅ | `cli.py:356-358` — client close on quit |
| Context manager for resource cleanup | ✅ | `src/opencode_client.py:69-74` — `__enter__`/`__exit__` |

**Design note:** This is a local CLI tool. No authentication is required for REPL access — filesystem permissions on the LXC enforce access control. This is an intentional design choice, not a gap.

### 6. Access Control — ✅ Covered

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Enforce least privilege | ✅ | `src/permission_gate.py` — READ/WRITE/DESTRUCTIVE levels |
| Deny by default for destructive operations | ✅ | `src/permission_gate.py:32-34` — `DENY_ALWAYS` |
| Use cryptographic random for tokens | ✅ | `src/permission_gate.py:7` — `secrets` module |
| Defense in depth for API operations | ✅ | `src/proxmox_tools.py:355-387` — multiple validation layers |

### 7. Cryptography — ✅ Covered

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Use established crypto libraries | ✅ | `secrets` module for tokens, HTTPS for all connections |
| Verify TLS certificates | ✅ | `src/proxmox_tools.py:28` — `verify_ssl=True` by default |
| Use HTTPS for all external connections | ✅ | `src/opencode_client.py`, `src/cve_scanner.py` |

### 8. Error Handling and Logging — ⚠️ Partial

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Handle errors without exposing sensitive data | ✅ | `cli.py:275-276` — LLM errors caught, no stack traces |
| Graceful degradation on failure | ✅ | `src/cve_scanner.py:196-197` — MITRE enrichment fails gracefully |
| Structured logging | ⚠️ | Console output via `rich` — no structured log file yet |

**Gap:** No structured logging module. All output goes to stdout/stderr. Planned for future enhancement.

### 9. Data Protection — ✅ Covered

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Restrict file permissions | ✅ | `src/database.py:186` — DB dir `0o700` |
| Redact secrets in representations | ✅ | `src/proxmox_tools.py:43-46`, `src/opencode_client.py:78` |
| Gitignore sensitive files | ✅ | `.gitignore` covers `.env`, `*.key`, `*.pem`, etc. |

### 10. Communication Security — ✅ Covered

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Use TLS for all network communication | ✅ | HTTPS for all external APIs |
| Configure timeouts on connections | ✅ | `src/opencode_client.py:66`, `src/cve_scanner.py:46` |
| Rate limit API requests | ✅ | `src/cve_scanner.py:114-115` — NVD rate limiting |

### 11. System Configuration — ✅ Covered

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Use safe YAML parsing | ✅ | `src/config.py:57` — `yaml.safe_load()` |
| Validate configuration at load time | ✅ | `src/config.py:59-71` — empty config and token validation |
| Separate config from secrets | ✅ | `config.yaml.example` + `.env` pattern |

### 12. Database Security — ✅ Covered

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Enable foreign key constraints | ✅ | `src/database.py:198` — `PRAGMA foreign_keys=ON` |
| Use WAL mode for crash recovery | ✅ | `src/database.py:197` — `PRAGMA journal_mode=WAL` |
| Archive before deletion | ✅ | `src/database.py:486-515` — CVE archive table |

### 13. File Management — ✅ Covered

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Restrict file permissions on creation | ✅ | `cli.py:99` — history dir `0o700`, `src/setup.py:112` — CA dir `0o700` |
| Use secure file creation for secrets | ✅ | `src/setup.py:114-116` — `os.open` with `0o600` |
| Explicit encoding for file I/O | ✅ | All `open()` calls use `encoding="utf-8"` |

### 14. Memory Management — ✅ Covered

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Close resources explicitly | ✅ | `src/opencode_client.py:147-149`, `src/cve_scanner.py:48-50` |
| Use context managers for cleanup | ✅ | `src/opencode_client.py:69-74`, `src/database.py:194-200` |
| Ensure cleanup on error | ✅ | `src/scanner_cli.py:70-71` — `finally` block |

### 15. General Coding Practices — ✅ Covered

| Requirement | Status | Evidence |
|-------------|--------|----------|
| No `eval()` or `exec()` | ✅ | Verified — not used anywhere |
| No `shell=True` in subprocess | ✅ | `src/cve_scanner.py:454-457` — list arguments |
| Use `secrets` not `random` for security | ✅ | `src/permission_gate.py:7` |
| No hardcoded credentials | ✅ | Env var pattern throughout |
| LLM output validation | ✅ | `src/guardrails.py:VALIDATION_DIRECTIVE` |

---

## CIS Secure Coding Standard (Python)

| CIS Rule | Status | Evidence |
|----------|--------|----------|
| 2.1 Never use `eval()` or `exec()` | ✅ | Not used anywhere |
| 2.2 Never use `shell=True` in subprocess | ✅ | List arguments used |
| 2.3 Use `yaml.safe_load()` | ✅ | `src/config.py:57` |
| 2.4 Use parameterized SQL queries | ✅ | All queries use `?` placeholders |
| 2.5 Validate all input | ✅ | See OWASP Input Validation above |
| 2.6 Use `secrets` module for tokens | ✅ | `src/permission_gate.py:7` |
| 2.7 Never hardcode credentials | ✅ | Env var pattern |
| 2.8 Restrict file permissions | ✅ | `0o700` on DB dir, `0o600` on CA cert |
| 2.9 Use type hints | ⚠️ | Partial — most functions have type hints |
| 2.10 No dead code | ✅ | Removed unreachable code in `cve_scanner.py` |

---

## NIST SSDF (SP 800-218) Alignment

### PO — Prepare the Organization

| Practice | Status | Evidence |
|----------|--------|----------|
| PO 1.1 Define security requirements | ✅ | OWASP + CIS frameworks adopted |
| PO 2.1 Define secure coding standards | ✅ | `SECURITY.md` + `AGENTS.md` coding standards |
| PO 3.1 Configure development toolchain | ✅ | `bandit` for static analysis, `pytest` for testing |

### PS — Protect the Software

| Practice | Status | Evidence |
|----------|--------|----------|
| PS 1.1 Document software provenance | ✅ | Git history, `pyproject.toml` dependencies |
| PS 2.1 Secure the development environment | ✅ | LXC isolation, SSH key separation, `.gitignore` |
| PS 3.1 Manage third-party components | ✅ | Pinned versions in `pyproject.toml`, `bandit` for scanning |

### PW — Produce Well-Secured Software

| Practice | Status | Evidence |
|----------|--------|----------|
| PW 1.1 Follow secure coding practices | ✅ | OWASP + CIS compliance (see above) |
| PW 2.1 Review AI-generated code | ✅ | All LLM-assisted code reviewed before merge |
| PW 4.1 Conduct security testing | ✅ | `pytest` test suite (97 tests), `bandit` static analysis |
| PW 5.1 Use static analysis tools | ✅ | `bandit` in dev dependencies |

### RV — Respond to Vulnerabilities

| Practice | Status | Evidence |
|----------|--------|----------|
| RV 1.1 Establish vulnerability response process | ✅ | `/db prune` for CVE lifecycle, `bandit` for code scanning |
| RV 2.1 Analyze and remediate vulnerabilities | ✅ | CVE scanner identifies and tracks vulnerabilities |

---

## LLM-Assisted Coding Policy

All code generated or assisted by LLM tools follows these requirements:

1. **Human review required** — No LLM-generated code is merged without human review
2. **Static analysis** — All code passes `bandit` security scanning before merge
3. **Test coverage** — New features include corresponding tests
4. **Framework alignment** — All code must comply with OWASP and CIS standards
5. **Provenance tracking** — LLM-assisted commits are documented in commit messages

---

## Automated Security Scanning

```bash
# Run bandit security scanner (dev dependency)
uv run bandit src/ -r --severity-level medium

# Run full test suite
uv run pytest tests/ -v

# Run conversation tests (requires API key)
PVE_SENTINEL_TEST_LLM=1 uv run pytest tests/test_conversation.py -v
```

---

## Documented Exceptions

| Exception | Reason | Risk Level |
|-----------|--------|------------|
| No SQLite encryption at rest | Filesystem permissions (`0o700`) provide adequate protection for local tool | Low |
| No structured logging | Console output sufficient for local CLI tool | Low |
| No REPL authentication | Local tool — filesystem permissions enforce access | Low |
| `verify_ssl: false` option | Homelab convenience for self-signed Proxmox certs | Medium (documented warning) |
