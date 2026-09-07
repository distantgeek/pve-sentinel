# Community Scripts Installer (ProxmoxVED / ProxmoxVE)

Staging area for the pve-sentinel submission to
[community-scripts](https://github.com/community-scripts/ProxmoxVED)
(development repo — new submissions land here first).

The layout mirrors the community-scripts repository so the files can be copied
straight into a fork of `ProxmoxVED`:

| File | Destination in ProxmoxVED | Purpose |
|------|---------------------------|---------|
| `ct/pve-sentinel.sh` | `ct/pve-sentinel.sh` | Creates the Debian 13 unprivileged LXC on the PVE host |
| `install/pve-sentinel-install.sh` | `install/pve-sentinel-install.sh` | Runs inside the LXC: `setup_uv`, git clone, config, systemd timers |
| `json/pve-sentinel.json` | `json/pve-sentinel.json` | Website metadata + unattended `app_vars` |

## Test it locally

Once the repo is on GitHub, run the CT script directly on a Proxmox host
(it sources the community-scripts engine from `community-scripts/core`):

```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/distantgeek/pve-sentinel/main/community-scripts/ct/pve-sentinel.sh)"
```

Unattended (values are exported and carried into the LXC):

```bash
bash ct/pve-sentinel.sh mode=unattended \
  var_proxmox_host=192.168.x.x \
  var_proxmox_user=sentinel@pve \
  var_proxmox_token_name=sentinel \
  var_proxmox_token_value=<uuid> \
  var_opencode_api_key=<key>
```

## Submission checklist

Per the ProxmoxVED `AGENTS.md` contribution rules:

- [x] Bare-metal install (no Docker) — Python via `setup_uv`
- [x] `$STD` before apt/git/uv commands, `msg_info`/`msg_ok` for custom code
- [x] Required `app_vars` exported from CT script and declared in JSON
- [x] Update function present (`git pull` + `uv sync` + restart)
- [x] Footer `motd_ssh`, `customize`, `cleanup_lxc`
- [x] `apt` (not `apt-get`); no core packages listed as deps
- [x] JSON metadata with `install_methods`, `app_vars`, `notes`

### Known deviations to resolve before submission

1. **No GitHub releases yet.** The installer uses `git clone` / `git pull`
   instead of `fetch_and_deploy_gh_release` / `check_for_gh_release`. Cut tagged
   releases (e.g. `v0.6.0`) and switch the install/update scripts to the release
   helpers to fully satisfy the checklist.
2. **Logo.** `json/pve-sentinel.json` points at a selfhst-icons webp that does
   not exist yet. Add a `pve-sentinel` icon to
   [selfhst/icons](https://github.com/selfhst/icons) (or otherwise update the
   `logo` field) before submitting.
3. **arm64.** Untested — the `architectures` field is omitted (site defaults to
   amd64). Set `var_arm64` and add `architectures` only after arm64 is verified.
