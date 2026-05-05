"""Tests for Proxmox API wrapper."""

from unittest.mock import MagicMock, patch

import pytest

from src.proxmox_tools import ProxmoxTools


class TestProxmoxToolsInit:
    @patch("src.proxmox_tools.ProxmoxAPI")
    def test_init_with_defaults(self, mock_api):
        """ProxmoxTools initializes with verify_ssl=True by default."""
        tools = ProxmoxTools(
            host="192.168.1.1",
            user="test@pam",
            token_name="token",
            token_value="secret",
        )
        mock_api.assert_called_once_with(
            "192.168.1.1",
            user="test@pam",
            token_name="token",
            token_value="secret",
            verify_ssl=True,
        )

    @patch("src.proxmox_tools.ProxmoxAPI")
    def test_repr_redacts_token(self, mock_api):
        """__repr__ does not expose token value."""
        tools = ProxmoxTools(
            host="192.168.1.1",
            user="test@pam",
            token_name="token",
            token_value="secret",
        )
        repr_str = repr(tools)
        assert "secret" not in repr_str
        assert "192.168.1.1" in repr_str


class TestProxmoxToolsGetNode:
    @patch("src.proxmox_tools.ProxmoxAPI")
    def test_uses_configured_node(self, mock_api):
        """Returns configured node without API call."""
        tools = ProxmoxTools(
            host="h", user="u", token_name="t", token_value="v", node="pve1"
        )
        assert tools._get_node() == "pve1"

    @patch("src.proxmox_tools.ProxmoxAPI")
    def test_auto_detects_node(self, mock_api):
        """Auto-detects node from API when not configured."""
        mock_instance = MagicMock()
        mock_instance.nodes.get.return_value = [{"node": "pve-node-01"}]
        mock_api.return_value = mock_instance

        tools = ProxmoxTools(
            host="h", user="u", token_name="t", token_value="v"
        )
        assert tools._get_node() == "pve-node-01"

    @patch("src.proxmox_tools.ProxmoxAPI")
    def test_raises_on_no_nodes(self, mock_api):
        """Raises RuntimeError when no nodes found."""
        mock_instance = MagicMock()
        mock_instance.nodes.get.return_value = []
        mock_api.return_value = mock_instance

        tools = ProxmoxTools(
            host="h", user="u", token_name="t", token_value="v"
        )
        with pytest.raises(RuntimeError, match="No Proxmox nodes found"):
            tools._get_node()


class TestProxmoxToolsGetStatus:
    @patch("src.proxmox_tools.ProxmoxAPI")
    def test_returns_status_dict(self, mock_api):
        """get_status returns structured status dict."""
        mock_instance = MagicMock()
        mock_instance.nodes.get.return_value = [{"node": "pve1"}]
        mock_instance.nodes.return_value.status.get.return_value = {
            "cpu": 0.25, "memory": {"used": 4096, "total": 8192}
        }
        mock_instance.nodes.return_value.qemu.get.return_value = [
            {"vmid": 100, "name": "web", "status": "running", "cpus": 2,
             "maxmem": 4294967296, "uptime": 86400}
        ]
        mock_instance.nodes.return_value.lxc.get.return_value = [
            {"vmid": 101, "name": "sentinel", "status": "running", "cpus": 4,
             "maxmem": 8589934592, "uptime": 3600}
        ]
        mock_instance.nodes.return_value.storage.get.return_value = []
        mock_api.return_value = mock_instance

        tools = ProxmoxTools(
            host="h", user="u", token_name="t", token_value="v"
        )
        status = tools.get_status()

        assert status["node"] == "pve1"
        assert len(status["vms"]) == 1
        assert status["vms"][0]["vmid"] == 100
        assert len(status["lxcs"]) == 1
        assert status["lxcs"][0]["vmid"] == 101


class TestProxmoxToolsRunCommand:
    @patch("src.proxmox_tools.ProxmoxAPI")
    def test_read_only_path_allowed(self, mock_api):
        """Read-only API paths are allowed without permission gate."""
        mock_instance = MagicMock()
        mock_instance.nodes.pve1.status.get.return_value = {"data": "ok"}
        mock_api.return_value = mock_instance

        tools = ProxmoxTools(
            host="h", user="u", token_name="t", token_value="v", node="pve1"
        )
        result = tools.run_command("/nodes/pve1/status", method="get")
        assert result == {"data": "ok"}

    @patch("src.proxmox_tools.ProxmoxAPI")
    def test_destructive_path_blocked(self, mock_api):
        """Destructive paths are blocked with PermissionError."""
        mock_api.return_value = MagicMock()

        tools = ProxmoxTools(
            host="h", user="u", token_name="t", token_value="v", node="pve1"
        )

        with pytest.raises(PermissionError, match="Destructive operation blocked"):
            tools.run_command("/nodes/pve1/qemu/100/destroy", method="post")

    @patch("src.proxmox_tools.ProxmoxAPI")
    def test_write_path_requires_gate(self, mock_api):
        """Write paths raise PermissionError directing to CLI gate."""
        mock_api.return_value = MagicMock()

        tools = ProxmoxTools(
            host="h", user="u", token_name="t", token_value="v", node="pve1"
        )

        with pytest.raises(PermissionError, match="requires permission gate"):
            tools.run_command("/nodes/pve1/qemu/100/status/start", method="post")


class TestProxmoxToolsGetHostPackages:
    @patch("src.proxmox_tools.ProxmoxAPI")
    def test_returns_installed_packages(self, mock_api):
        """get_host_packages returns installed packages from apt/versions."""
        mock_instance = MagicMock()
        mock_instance.nodes.get.return_value = [{"node": "pve1"}]
        mock_instance.nodes.return_value.apt.versions.get.return_value = [
            {"Package": "pve-manager", "OldVersion": "9.1.6", "Arch": "all",
             "CurrentState": "Installed"},
            {"Package": "qemu-server", "OldVersion": "9.1.4", "Arch": "amd64",
             "CurrentState": "Installed"},
            {"Package": "old-kernel", "OldVersion": "6.8.0", "Arch": "amd64",
             "CurrentState": "NotInstalled"},
        ]
        mock_api.return_value = mock_instance

        tools = ProxmoxTools(
            host="h", user="u", token_name="t", token_value="v"
        )
        packages = tools.get_host_packages()

        assert len(packages) == 2
        assert packages[0]["name"] == "pve-manager"
        assert packages[0]["version"] == "9.1.6"
        assert packages[1]["name"] == "qemu-server"


class TestProxmoxToolsGetHostRepos:
    @patch("src.proxmox_tools.ProxmoxAPI")
    def test_returns_repo_summary(self, mock_api):
        """get_host_repos returns structured repo status."""
        mock_instance = MagicMock()
        mock_instance.nodes.get.return_value = [{"node": "pve1"}]
        mock_instance.nodes.return_value.apt.repositories.get.return_value = {
            "standard-repos": [
                {"name": "Enterprise", "handle": "enterprise", "status": 0},
                {"name": "No-Subscription", "handle": "no-subscription", "status": 1},
            ],
            "infos": [
                {"kind": "warning", "message": "old suite configured"},
                {"kind": "origin", "message": "Debian"},
            ],
            "errors": [],
        }
        mock_api.return_value = mock_instance

        tools = ProxmoxTools(
            host="h", user="u", token_name="t", token_value="v"
        )
        repos = tools.get_host_repos()

        assert len(repos["standard_repos"]) == 2
        assert repos["standard_repos"][0]["enabled"] is False
        assert repos["standard_repos"][1]["enabled"] is True
        assert len(repos["warnings"]) == 1
        assert repos["warnings"][0] == "old suite configured"
        assert repos["errors"] == []
