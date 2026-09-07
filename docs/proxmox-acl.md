# Proxmox API Token Privileges — pve-sentinel

Least-privilege ACL setup for the `pve-sentinel` API token. Privileges and
permissions below are taken from the Proxmox VE user-management documentation and
the API schema (`api-viewer`), PVE 8.x/9.x.

> Containers (LXC) use the same `VM.*` privileges and `/vms/...` paths as VMs —
> there is no separate container privilege set.

## Principle

- Use the **`pve`** authentication realm (no host PAM account required).
- Keep **Privilege Separation enabled** (the default). A separated token's
  effective permissions are the *intersection* of the user ACL and the token ACL,
  so the role must be granted to **both** the user and the token.
- Set an **expiry** on the token so abandoned automation cannot keep working
  silently.

## Role: `SentinelAdmin`

Create one custom role with the full management privilege set. (`PVE*` role
prefixes are reserved for built-in roles, so a custom name is required.)

| Area | Privileges |
|------|-----------|
| VMs/CTs — create/remove | `VM.Allocate` |
| VMs/CTs — view | `VM.Audit` |
| VMs/CTs — power | `VM.PowerMgmt` |
| VMs/CTs — config | `VM.Config.CDROM`, `VM.Config.CPU`, `VM.Config.Cloudinit`, `VM.Config.Disk`, `VM.Config.HWType`, `VM.Config.Memory`, `VM.Config.Network`, `VM.Config.Options` |
| VMs/CTs — lifecycle | `VM.Backup`, `VM.Clone`, `VM.Migrate`, `VM.Snapshot`, `VM.Snapshot.Rollback` |
| Storage | `Datastore.Allocate`, `Datastore.AllocateSpace`, `Datastore.AllocateTemplate`, `Datastore.Audit` |
| Pools | `Pool.Allocate`, `Pool.Audit` |
| SDN / vnets | `SDN.Allocate`, `SDN.Audit`, `SDN.Use` |
| Node/system (network, firewall, apt, logs) | `Sys.Audit`, `Sys.Modify`, `Sys.PowerMgmt`, `Sys.Syslog` |
| Users/groups | `User.Modify`, `Group.Allocate`, `Realm.AllocateUser` |
| **Optional — only if the agent should edit ACLs** | `Permissions.Modify` |

Not included (not needed, or unavailable to tokens):

- `VM.Console` / `Sys.Console` — console endpoints cannot be used by API tokens.
- `VM.Replicate`, `VM.GuestAgent.*`, `Realm.Allocate`, `Mapping.*` — only add if
  you use replication, guest-agent automation, or resource mappings.
- `Permissions.Modify` — only add if you want pve-sentinel to modify Proxmox ACLs
  itself. This and `Sys.Modify` are the two privileges the PVE docs single out as
  "dangerous or sensitive".

## Path scoping (least privilege)

| Privilege group | ACL path |
|-----------------|----------|
| all `VM.*` | `/vms` |
| all `Datastore.*` | `/storage` |
| `Sys.*` | `/nodes` |
| `Pool.*` | `/pool` |
| `SDN.*` | `/sdn` |
| `User.Modify`, `Group.Allocate`, `Permissions.Modify` | `/access` |
| `Realm.AllocateUser` | `/access/realm/pve` |

For a single-node homelab, assigning the role at `/` (root) is equivalent and
simpler; use the scoped paths above for least privilege.

## Setup commands

```bash
# 1. Create the role
pveum role add SentinelAdmin -privs "VM.Allocate VM.Audit VM.Backup VM.Clone \
  VM.Config.CDROM VM.Config.CPU VM.Config.Cloudinit VM.Config.Disk VM.Config.HWType \
  VM.Config.Memory VM.Config.Network VM.Config.Options VM.Migrate VM.PowerMgmt \
  VM.Snapshot VM.Snapshot.Rollback Datastore.Allocate Datastore.AllocateSpace \
  Datastore.AllocateTemplate Datastore.Audit Pool.Allocate Pool.Audit \
  SDN.Allocate SDN.Audit SDN.Use Sys.Audit Sys.Modify Sys.PowerMgmt Sys.Syslog \
  User.Modify Group.Allocate Realm.AllocateUser"

# 2. Dedicated user (pve realm — no host account)
pveum user add sentinel@pve --comment "pve-sentinel LXC agent"

# 3. User ACL
pveum acl modify / --roles SentinelAdmin --users sentinel@pve

# 4. API token (privilege separation ON, set an expiry)
pveum user token add sentinel@pve sentinel --privsep 1 --comment "pve-sentinel"

# 5. Token ACL (required under privsep — effective = user ∩ token)
pveum acl modify / --roles SentinelAdmin --users sentinel@pve!sentinel
```

To add the optional `Permissions.Modify`:

```bash
pveum role add SentinelAdmin -privs "Permissions.Modify"   # appends to the role
```

## Wiring into pve-sentinel

`pveum user token add` prints the secret exactly once, in the form:

```
PVEAPIToken=sentinel@pve!sentinel=<UUID>
```

Map it to `config.yaml` + `.env`:

```yaml
# config.yaml
proxmox:
  host: "<host-ip>"
  user: "sentinel@pve"
  token_name: "sentinel"
  token_value_env: PROXMOX_TOKEN_VALUE
```

```bash
# .env — the UUID part only (after the last '=')
PROXMOX_TOKEN_VALUE=<UUID>
```

## Troubleshooting

| Symptom | Cause |
|---------|-------|
| Writes return `403` while reads work | Token has the role but the user does not (or vice versa) — grant both (steps 3 and 5) |
| Console/noVNC access fails | Inherent PVE limitation — console endpoints never work via API tokens |
| `Sys.Modify`/`Permissions.Modify` not effective | These are cluster-config privileges; verify they were not omitted from the role |
