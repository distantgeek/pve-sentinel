# PROGRESS.md — Session History

## 2026-05-04: Initial Build (DeepSeek session)

### Completed

#### Phase 1 — LXC Provisioning
- **LXC 101 created**: Debian 13 (Trixie), unprivileged, 4C/8GB/32GB on kevbot-pve
- IP: 192.168.2.5/24, bridge vmbr0, gw 192.168.2.1
- SSH: key-only auth (id_ed25519_proxmox), UseDNS=no for fast connects
- Users: root + kevbot (sudo NOPASSWD), both with proxmox SSH key
- **SSH key injection bug found**: proxmoxer has issues with `+` in SSH keys due to URL encoding. Raw `requests.post(data=...)` works because `urllib.parse.urlencode` correctly encodes `+` as `%2B`.
- **Password injection also fails** via API — both `password` and `ssh-public-keys` parameters accepted but silently dropped by Debian 13 template.
- **Tried VM with cloud-init**: blocked by missing `Sys.Modify` permission. `Datastore.AllocateTemplate` was granted but `download-url` endpoint still requires `Sys.Modify`.
- **Resolution**: Created LXC via raw HTTP API with properly URL-encoded SSH key. SSH works on first boot.

#### Phase 2 — OpenCode Go Integration
- **Architecture simplified**: Found OpenCode Go has a direct REST API (`https://opencode.ai/zen/go/v1/chat/completions`). No `opencode serve` needed.
- `src/opencode_client.py` rewritten to use direct API with Bearer token auth.
- GLM-5.1 confirmed working: "Proxmox VE is an open-source, enterprise-grade bare-metal hypervisor..."
- API key stored in `OPENCODE_GO_API_KEY` env var on LXC (set in kevbot's .bashrc).
- **openCode CLI not installed on LXC** — not needed since we use direct API.

#### Phase 2.5 — Security Guardrails
- `src/guardrails.py` created with 4 named presets: general, cis-ubuntu-l1, cis-ai, nist-cyber-ai.
- Config-driven via `config.yaml` → `guardrails.enabled` and `guardrails.preset`.
- System prompts injected automatically by `src/opencode_client.py` on every LLM call.
- **NIST CSF AI Profile reference data** extracted from NIST IR 8596 iprd (Dec 2025):
  - Full CSF 2.0 structure: 6 functions, 22 categories, ~90 subcategories
  - AI-specific considerations per subcategory
  - Three Focus Areas: Secure, Defend, Thwart
  - Informative references (NIST SP 800-53, OWASP LLM Top 10, MITRE ATLAS, etc.)
  - Stored at `src/framework_data/nist_csf_ai.yaml`
- Guardrail preset `nist-cyber-ai` updated to reference real control IDs.
- **Lynis integration considered then rejected** — community edition lacks CIS control labels.
- 36 tests passing (28 original + 8 guardrails).

#### DevOps
- Git repo: `/var/home/kevbot/pve-sentinel` on devbox
- Project structure: src/, tests/, systemd/, docs/, misc/, framework_data/
- No remote configured yet (needs `git remote add origin` and push)
- LXC syncs: via tarball pipe over SSH

### Tools Installed on LXC
- Node.js 22.22.2 (nodesource)
- uv 0.11.8 (standalone installer, copied to /usr/local/bin for kevbot access)
- Python 3.14.4 (via uv venv)
- Dependencies: httpx, proxmoxer, rich, prompt-toolkit, pyyaml, requests, pymupdf
- Dev deps: pytest, pytest-asyncio, pytest-cov

### Systemd Timers (deployed, logic pending)
- `cve-scanner.timer` — daily scan
- `cve-digest.timer` — weekly Mon 08:00
- Service files reference `/usr/local/bin/uv` and user `kevbot`

### Key Files Status

| File | Status | Notes |
|------|--------|-------|
| `src/database.py` | ✅ complete | 12 tables, full CRUD, tested |
| `src/config.py` | ✅ complete | YAML loader, env var resolution |
| `src/opencode_client.py` | ✅ complete | Direct API, system prompt injection |
| `src/guardrails.py` | ✅ complete | 4 presets, 8 tests |
| `src/cve_scanner.py` | ✅ structure | Pipeline defined, needs Phase 5 wiring |
| `src/proxmox_tools.py` | ✅ structure | proxmoxer wrapper, needs Phase 3+4 wiring |
| `src/permission_gate.py` | ✅ complete | READ/WRITE/DESTROY classification, tested |
| `cli.py` | ⚠️ skeleton | Banner works, needs Phase 3 CLI loop |
| `config.yaml.example` | ✅ complete | All sections documented |
| `config.yaml` | ✅ on LXC | Has actual IP/token values |
| Systemd units | ✅ deployed | Timer logic needs Phase 5 |

### Next: Phase 3 — Core CLI

What needs to be built:
1. **Interactive CLI loop** in `cli.py` using `rich` + `prompt_toolkit`
2. **OpenCode client integration**: CLI asks → OpenCodeClient.ask() → display response
3. **Proxmox status query**: `/status` command calls ProxmoxTools.get_status()
4. **CVE commands**: `/cve check <pkg>` and `/digest` calling CVEScanner
5. **Permission gate integration**: `/proxmox <action>` flows through PermissionGate
6. **Model routing**: Cloud (GLM-5.1) for research, configurable local endpoint
7. **Guardrail injection**: System prompt loaded from config and injected automatically

Prerequisites for Phase 3:
- `PROXMOX_TOKEN_VALUE` env var must be set on LXC
- `OPENCODE_GO_API_KEY` is already set ✅

### Architecture Decisions for Phase 3+

- **Cluster support**: `ProxmoxTools` should iterate all nodes, not assume single node. The `get_status()` method needs a `get_nodes()` call first, then aggregate across nodes.
- **Local model path**: Already architected in config (provider: ollama, api_base, etc.). OpenCodeClient can be extended with an OpenAI-compatible client class.
- **Multi-method package discovery**: For guest scanning (Phase 7), dpkg/rpm/apk/flatpak/npm/pip/containers. LXC scanning (Phase 5) only needs dpkg/rpm/apk via `pct exec`.
