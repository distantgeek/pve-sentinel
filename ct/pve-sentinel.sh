#!/usr/bin/env bash
# pve-sentinel LXC installer (simplified standalone version)
# Creates a Debian 13 LXC container and runs the install script inside it.
# This version does NOT depend on the community-scripts engine — it uses
# pct directly so it works from any repo without URL resolution tricks.
#
# Usage (on Proxmox host):
#   bash -c "$(wget -qLO - https://raw.githubusercontent.com/distantgeek/pve-sentinel/main/ct/pve-sentinel.sh)"
#
# Optional env vars:
#   var_proxmox_host       Proxmox host IP/FQDN (required)
#   var_proxmox_user       API user (default: sentinel@pve)
#   var_proxmox_token_name API token name (default: sentinel)
#   var_proxmox_token_value API token value UUID (required)
#   var_opencode_api_key   OpenCode API key (optional)
#   var_nvd_api_key        NVD API key (optional)
#   var_management_mode    yes/no (default: no)
#   CTID                   Container ID (default: auto)
#   STORAGE                Storage for rootfs (default: local-lvm)
#   TEMPLATE_STORAGE       Storage for template (default: local)

set -euo pipefail

APP="pve-sentinel"
CTID="${CTID:-}"
STORAGE="${STORAGE:-local-lvm}"
TEMPLATE_STORAGE="${TEMPLATE_STORAGE:-local}"
BRIDGE="${BRIDGE:-vmbr0}"
CPU="${CPU:-2}"
RAM="${RAM:-2048}"
DISK="${DISK:-8}"
OS="debian"
VERSION="13"
UNPRIVILEGED="${UNPRIVILEGED:-1}"

# Application settings passed to the install script.
# Accepts both var_proxmox_* and PROXMOX_* naming conventions so the
# token file can be sourced directly (e.g. . /path/to/pve-sentinel.token).
export var_proxmox_host="${var_proxmox_host:-${PROXMOX_HOST:-}}"
export var_proxmox_user="${var_proxmox_user:-${PROXMOX_USER:-sentinel@pve}}"
export var_proxmox_token_name="${var_proxmox_token_name:-${PROXMOX_TOKEN_NAME:-sentinel}}"
export var_proxmox_token_value="${var_proxmox_token_value:-${PROXMOX_TOKEN_VALUE:-}}"
export var_opencode_api_key="${var_opencode_api_key:-${OPENCODE_GO_API_KEY:-}}"
export var_nvd_api_key="${var_nvd_api_key:-${NVD_API_KEY:-}}"
export var_management_mode="${var_management_mode:-no}"

# Fail fast on required values
if [[ -z "${var_proxmox_host:-}" ]]; then
  echo "ERROR: var_proxmox_host is required (Proxmox host IP/FQDN)"
  echo "Usage: var_proxmox_host=192.168.1.10 var_proxmox_token_value=UUID bash -c \"\$(wget -qLO - <url>)\""
  exit 1
fi
if [[ -z "${var_proxmox_token_value:-}" ]]; then
  echo "ERROR: var_proxmox_token_value is required (Proxmox API token UUID)"
  exit 1
fi

# Check we're on a Proxmox host
if ! command -v pct >/dev/null 2>&1; then
  echo "ERROR: This script must run on a Proxmox VE host (pct not found)"
  exit 1
fi

# Pick a container ID
if [[ -z "$CTID" ]]; then
  CTID=$(pvesh get /cluster/nextid)
fi
echo "Using container ID: $CTID"

# Find or download the Debian template (filename includes patch version, e.g. 13.6-1)
TEMPLATE_PATTERN="${OS}-${VERSION}-standard"
TEMPLATE=$(pveam list "$TEMPLATE_STORAGE" 2>/dev/null | grep "$TEMPLATE_PATTERN" | awk '{print $1}' | sed 's|.*/||' | tail -1)
if [[ -z "$TEMPLATE" ]]; then
  echo "Downloading Debian $VERSION template..."
  AVAIL=$(pveam available --section system 2>/dev/null | grep "$TEMPLATE_PATTERN" | tail -1 | awk '{print $2}')
  if [[ -z "$AVAIL" ]]; then
    echo "ERROR: No Debian $VERSION template available"
    exit 1
  fi
  pveam download "$TEMPLATE_STORAGE" "$AVAIL"
  TEMPLATE="$AVAIL"
fi
echo "Using template: $TEMPLATE"

# Destroy existing container if present
if pct status "$CTID" >/dev/null 2>&1; then
  echo "Container $CTID already exists — destroying it"
  pct stop "$CTID" 2>/dev/null || true
  pct destroy "$CTID" 2>/dev/null || true
fi

# Create the container
echo "Creating container $CTID..."
pct create "$CTID" "$TEMPLATE_STORAGE:vztmpl/$TEMPLATE" \
  --hostname "$APP" \
  --cores "$CPU" \
  --memory "$RAM" \
  --swap 512 \
  --rootfs "$STORAGE:$DISK" \
  --net0 "name=eth0,bridge=$BRIDGE,ip=dhcp" \
  --ostype "$OS" \
  --unprivileged "$UNPRIVILEGED" \
  --features "nesting=1,keyctl=1" \
  --onboot 1 \
  --tags "proxmox;security;cve"

# Start the container
echo "Starting container $CTID..."
pct start "$CTID"

# Wait for container to be ready AND have network (DHCP must assign an IP)
echo "Waiting for container to boot..."
for i in $(seq 1 60); do
  if pct exec "$CTID" -- bash -c 'ip -4 addr show eth0 2>/dev/null | grep -q "inet " && getent hosts raw.githubusercontent.com >/dev/null 2>&1' 2>/dev/null; then
    break
  fi
  sleep 2
done

# Fetch and run the install script inside the container.
# Download to a file and verify it is non-empty so a failed fetch cannot
# silently run an empty script (bash <(wget ...) exits 0 on empty input).
echo "Running install script inside container..."
INSTALL_URL="https://raw.githubusercontent.com/distantgeek/pve-sentinel/main/install/pve-sentinel-install.sh"
pct exec "$CTID" -- bash -c "
  export var_proxmox_host='${var_proxmox_host}'
  export var_proxmox_user='${var_proxmox_user}'
  export var_proxmox_token_name='${var_proxmox_token_name}'
  export var_proxmox_token_value='${var_proxmox_token_value}'
  export var_opencode_api_key='${var_opencode_api_key}'
  export var_nvd_api_key='${var_nvd_api_key}'
  export var_management_mode='${var_management_mode}'
  wget -qO /tmp/pve-sentinel-install.sh '${INSTALL_URL}' || { echo 'ERROR: failed to download install script'; exit 1; }
  test -s /tmp/pve-sentinel-install.sh || { echo 'ERROR: install script is empty'; exit 1; }
  bash /tmp/pve-sentinel-install.sh
"

echo ""
echo "=============================================="
echo "pve-sentinel setup completed successfully!"
echo "Container ID: $CTID"
echo "Attach: pct enter $CTID"
echo "Then run: pve-sentinel"
echo "=============================================="
