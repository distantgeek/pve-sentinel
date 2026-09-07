#!/usr/bin/env bash
# Engine comes from community-scripts/core; this repo only ships the scripts.
# A local core checkout wins (COMMUNITY_SCRIPTS_CORE_DIR, else a sibling ../core),
# so a fork or branch of core can be tested without editing this file.
_cs_boot="${COMMUNITY_SCRIPTS_CORE_DIR:-$(dirname "${BASH_SOURCE[0]}")/../../core}/core/build.func"
source "$_cs_boot" 2>/dev/null || source <(curl -fsSL "${COMMUNITY_SCRIPTS_CORE_URL:-https://raw.githubusercontent.com/community-scripts/core/main}/core/build.func")
# Copyright (c) 2021-2026 community-scripts ORG
# Author: Kevbot (distantgeek)
# License: MIT | https://github.com/community-scripts/ProxmoxVED/raw/main/LICENSE
# Source: https://github.com/distantgeek/pve-sentinel

APP="pve-sentinel"
var_tags="${var_tags:-proxmox;security;cve}"
var_cpu="${var_cpu:-2}"
var_ram="${var_ram:-2048}"
var_disk="${var_disk:-8}"
var_os="${var_os:-debian}"
var_version="${var_version:-13}"
var_unprivileged="${var_unprivileged:-1}"

# Application settings the install script accepts up front (see JSON app_vars).
# Without the export they never reach the container.
export var_proxmox_host="${var_proxmox_host:-}"
export var_proxmox_user="${var_proxmox_user:-sentinel@pve}"
export var_proxmox_token_name="${var_proxmox_token_name:-sentinel}"
export var_proxmox_token_value="${var_proxmox_token_value:-}"
export var_opencode_api_key="${var_opencode_api_key:-}"
export var_nvd_api_key="${var_nvd_api_key:-}"
export var_management_mode="${var_management_mode:-no}"

# Fail fast on values the install script cannot prompt for unattended.
if [[ -n "${mode:-}" ]]; then
  if [[ -z "${var_proxmox_host:-}" ]]; then
    msg_error "var_proxmox_host is required for unattended installs."
    exit 1
  fi
  if [[ -z "${var_proxmox_token_value:-}" ]]; then
    msg_error "var_proxmox_token_value is required for unattended installs."
    exit 1
  fi
fi

header_info "$APP"
variables
color
catch_errors

function update_script() {
  header_info
  check_container_storage
  check_container_resources

  if [[ ! -d /opt/pve-sentinel ]]; then
    msg_error "No ${APP} Installation Found!"
    exit
  fi

  msg_info "Updating ${APP}"
  cd /opt/pve-sentinel
  $STD git pull origin main
  $STD uv sync
  systemctl restart pve-sentinel-scanner
  msg_ok "Updated ${APP}"
  exit
}

start
build_container
description

msg_ok "Completed Successfully!\n"
echo -e "${CREATING}${GN}${APP} setup has been successfully initialized!${CL}"
echo -e "${INFO}${YW}Attach to the container and run the following to start the CLI:${CL}"
echo -e "${TAB}${BGN}pve-sentinel${CL}"
