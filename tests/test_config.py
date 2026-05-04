"""Tests for pve-sentinel config loader."""

import os
import tempfile

import pytest

from src.config import load_config


SAMPLE_CONFIG = """
model:
  provider: opencode-go
  model_id: glm-5.1

proxmox:
  host: "192.168.1.100"
  user: "testuser@pam"
  token_name: "testToken"
  token_value_env: PROXMOX_TOKEN_VALUE
  node: ""
  verify_ssl: true

cve:
  nvd_api_enabled: true
  mitre_api_enabled: false
  exploitdb_enabled: false
  pve_security_enabled: false

storage:
  db_path: "./test.db"
  digest_dir: "./digests"
  log_dir: "./logs"
"""


class TestConfig:
    def test_load_config_basic(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(SAMPLE_CONFIG)
            config_path = f.name

        try:
            os.environ["PROXMOX_TOKEN_VALUE"] = "test-token"
            config = load_config(config_path)
            assert config["model"]["provider"] == "opencode-go"
            assert config["model"]["model_id"] == "glm-5.1"
            assert config["proxmox"]["host"] == "192.168.1.100"
            assert config["cve"]["nvd_api_enabled"] is True
            assert config["storage"]["db_path"] == "./test.db"
            assert config["proxmox"]["token_value"] == "test-token"
        finally:
            os.unlink(config_path)
            del os.environ["PROXMOX_TOKEN_VALUE"]

    def test_load_config_resolves_token_env(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(SAMPLE_CONFIG)
            config_path = f.name

        try:
            os.environ["PROXMOX_TOKEN_VALUE"] = "test-secret-token"
            config = load_config(config_path)
            assert config["proxmox"]["token_value"] == "test-secret-token"
        finally:
            os.unlink(config_path)
            del os.environ["PROXMOX_TOKEN_VALUE"]

    def test_load_config_raises_on_empty_token(self):
        """Config must reject empty Proxmox token values."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(SAMPLE_CONFIG)
            config_path = f.name

        try:
            os.environ["PROXMOX_TOKEN_VALUE"] = ""
            with pytest.raises(ValueError, match="token value is empty"):
                load_config(config_path)
        finally:
            os.unlink(config_path)
            del os.environ["PROXMOX_TOKEN_VALUE"]

    def test_load_config_missing_file(self):
        with pytest.raises(FileNotFoundError):
            load_config("/nonexistent/config.yaml")

    def test_load_config_empty_file(self):
        """Config must reject empty YAML files."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("")
            config_path = f.name

        try:
            with pytest.raises(ValueError, match="Empty or invalid"):
                load_config(config_path)
        finally:
            os.unlink(config_path)
