"""Configuration loader for pve-sentinel."""

import os
from pathlib import Path

import yaml
from dotenv import load_dotenv


def load_config(path: str | Path | None = None) -> dict:
    """Load configuration from YAML file, resolving environment variable references.

    Searches in order:
        1. Explicit path argument
        2. SENTINEL_CONFIG environment variable
        3. ./config.yaml (current directory)
        4. ~/.config/pve-sentinel/config.yaml

    Before loading, attempts to load .env from:
        1. ./ .env (current directory)
        2. ~/.config/pve-sentinel/.env

    Raises:
        FileNotFoundError: If no config file is found.
        ValueError: If config is empty, invalid, or required secrets are missing.
    """
    # Load .env file if present (python-dotenv)
    candidates = [
        Path(".env"),
        Path.home() / ".config" / "pve-sentinel" / ".env",
    ]
    for candidate in candidates:
        if candidate.exists():
            load_dotenv(dotenv_path=candidate)
            break

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

    with open(path, encoding="utf-8") as f:
        config = yaml.safe_load(f)

    if config is None:
        raise ValueError(f"Empty or invalid config file: {path}")

    # Resolve environment variable references in proxmox section
    if "proxmox" in config:
        pmx = config["proxmox"]
        token_env = pmx.get("token_value_env", "PROXMOX_TOKEN_VALUE")
        token_value = os.environ.get(token_env, "")
        if not token_value:
            raise ValueError(
                f"Proxmox token value is empty. Set the '{token_env}' "
                "environment variable before running pve-sentinel."
            )
        pmx["token_value"] = token_value

    return config
