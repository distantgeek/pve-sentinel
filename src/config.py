"""Configuration loader for pve-sentinel."""

import os
from pathlib import Path
from typing import Any

import yaml


def _env_or(value: Any, env_var: str) -> Any:
    """Return environment variable if set, otherwise the config value."""
    return os.environ.get(env_var, value)


def load_config(path: str | Path | None = None) -> dict:
    """Load configuration from YAML file, resolving environment variable references.

    Searches in order:
        1. Explicit path argument
        2. SENTINEL_CONFIG environment variable
        3. ./config.yaml (current directory)
        4. ~/.config/pve-sentinel/config.yaml
    """
    if path is None:
        env_config = os.environ.get("SENTINEL_CONFIG")
        if env_config:
            path = env_config
        else:
            candidates = [
                Path("config.yaml"),
                Path.home() / ".config" / "pve-sentinel" / "config.yaml",
            ]
            for candidate in candidates:
                if candidate.exists():
                    path = candidate
                    break
            else:
                raise FileNotFoundError(
                    "No config found. Copy config.yaml.example to config.yaml "
                    "or set SENTINEL_CONFIG environment variable."
                )

    with open(path) as f:
        config = yaml.safe_load(f)

    if config is None:
        raise ValueError(f"Empty or invalid config file: {path}")

    # Resolve environment variable references in proxmox section
    if "proxmox" in config:
        pmx = config["proxmox"]
        token_env = pmx.get("token_value_env", "PROXMOX_TOKEN_VALUE")
        pmx["token_value"] = os.environ.get(token_env, "")

    # Resolve opencode password
    if "opencode" in config:
        oc = config["opencode"]
        pass_env = oc.get("password_env", "SENTINEL_OPENCODE_PASSWORD")
        oc["password"] = os.environ.get(pass_env, "")

    return config
