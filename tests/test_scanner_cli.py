"""Tests for the scheduled scan entry point (src/scanner_cli.py)."""

from unittest.mock import MagicMock, patch

from src.scanner_cli import _get_host_packages


def _proxmox_cfg(**overrides: object) -> dict:
    cfg: dict[str, object] = {
        "host": "192.168.1.1",
        "user": "user@pam",
        "token_name": "token",
        "token_value": "secret",
        "node": "",
        "verify_ssl": True,
    }
    cfg.update(overrides)
    return {"proxmox": cfg}


class TestGetHostPackages:
    def test_returns_packages_from_api(self):
        """Host packages are fetched from the Proxmox API and returned."""
        mock_tools = MagicMock()
        mock_tools.get_host_packages.return_value = [
            {"name": "pve-manager", "version": "9.1.6", "architecture": "all"},
            {"name": "qemu-server", "version": "9.1.4", "architecture": "amd64"},
        ]

        with patch("src.scanner_cli.ProxmoxTools", return_value=mock_tools) as mock_cls:
            result = _get_host_packages(_proxmox_cfg())

        assert result == mock_tools.get_host_packages.return_value
        mock_cls.assert_called_once_with(
            host="192.168.1.1",
            user="user@pam",
            token_name="token",
            token_value="secret",
            node="",
            verify_ssl=True,
        )

    def test_returns_empty_when_proxmox_not_configured(self):
        """Missing host/token falls back to an empty package list."""
        assert _get_host_packages({"proxmox": {}}) == []
        assert _get_host_packages({"proxmox": {"host": "192.168.1.1"}}) == []

    def test_returns_empty_on_api_error(self):
        """Proxmox API failures degrade gracefully to an empty list."""
        mock_tools = MagicMock()
        mock_tools.get_host_packages.side_effect = ConnectionError("boom")

        with patch("src.scanner_cli.ProxmoxTools", return_value=mock_tools):
            result = _get_host_packages(_proxmox_cfg())

        assert result == []

    def test_returns_empty_when_no_packages(self):
        """An empty host inventory is returned as-is."""
        mock_tools = MagicMock()
        mock_tools.get_host_packages.return_value = []

        with patch("src.scanner_cli.ProxmoxTools", return_value=mock_tools):
            result = _get_host_packages(_proxmox_cfg())

        assert result == []
