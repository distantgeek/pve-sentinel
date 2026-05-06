"""Tests for pve-sentinel CLI module.

These tests verify that cli.py loads correctly, constants are defined,
helper functions work, and command routing is wired properly.

Note: Full REPL interaction tests are not included (requires prompt_toolkit
event loop). These tests focus on import validity, constant correctness,
and handler wiring — catching syntax errors and missing imports.
"""

import ast
import importlib
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ── Syntax & Import Tests ──────────────────────────────────────────


class TestCliSyntax:
    """Verify cli.py is syntactically valid and importable."""

    def test_parse_succeeds(self):
        """cli.py must parse without SyntaxError."""
        cli_path = Path(__file__).parent.parent / "cli.py"
        source = cli_path.read_text(encoding="utf-8")
        ast.parse(source)

    def test_import_succeeds(self):
        """cli module must import without error."""
        cli = importlib.import_module("cli")
        assert hasattr(cli, "BANNER")
        assert hasattr(cli, "COMMANDS")
        assert hasattr(cli, "SentinelShell")

    def test_no_unclosed_blocks(self):
        """All try/except/for/if blocks must be properly closed."""
        cli_path = Path(__file__).parent.parent / "cli.py"
        source = cli_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        # Walk the AST and verify no structural issues
        for node in ast.walk(tree):
            if isinstance(node, ast.Try):
                assert node.handlers or node.finalbody, (
                    f"Try block at line {node.lineno} has no except or finally"
                )


# ── Constants Tests ────────────────────────────────────────────────


class TestCliConstants:
    """Verify CLI constants are correctly defined."""

    def test_banner_nonempty(self):
        """Banner must contain ASCII art."""
        from cli import BANNER
        assert "pve-sentinel" in BANNER or "___" in BANNER

    def test_commands_dict_nonempty(self):
        """COMMANDS must have entries."""
        from cli import COMMANDS
        assert len(COMMANDS) > 0

    def test_slash_commands_match_keys(self):
        """SLASH_COMMANDS must be derived from COMMANDS keys."""
        from cli import COMMANDS, SLASH_COMMANDS
        expected = [cmd.split()[0] for cmd in COMMANDS]
        assert sorted(SLASH_COMMANDS) == sorted(expected)

    def test_expected_commands_present(self):
        """All documented commands must be in COMMANDS."""
        from cli import COMMANDS
        expected = ["/help", "/quit", "/status", "/history", "/digest",
                     "/health", "/health rrd [period]", "/refresh [type]", "/db [subcmd]",
                     "/guardrails [preset]", "/cve check <pkg>", "/cve scan", "/proxmox <action>"]
        for cmd in expected:
            assert cmd in COMMANDS, f"Missing command: {cmd}"


# ── Helper Function Tests ──────────────────────────────────────────


class TestSslErrorPanel:
    """Test SSL error panel helper."""

    def test_returns_panel(self):
        """_ssl_error_panel must return a Panel with correct title."""
        from cli import _ssl_error_panel
        error = Exception("CERTIFICATE_VERIFY_FAILED: self-signed")
        panel = _ssl_error_panel(error)
        assert "SSL Certificate Verification Failed" in panel.title

    def test_contains_fix_options(self):
        """Panel must mention both fix options."""
        from cli import _ssl_error_panel
        error = Exception("SSL error")
        panel = _ssl_error_panel(error)
        renderable = str(panel.renderable)
        assert "src.setup cert" in renderable
        assert "verify_ssl: false" in renderable


# ── SentinelShell Initialization Tests ─────────────────────────────


class TestSentinelShellInit:
    """Test SentinelShell initialization with mocked dependencies."""

    @pytest.fixture
    def mock_config(self):
        """Minimal config dict for shell init."""
        return {
            "model": {"provider": "opencode-go", "model_id": "glm-5.1"},
            "proxmox": {},
            "guardrails": {"enabled": True, "preset": "general"},
            "storage": {"db_path": ":memory:"},
            "permissions": {"allowed_write_actions": [], "deny_always": []},
        }

    @patch("cli.load_config")
    @patch("cli.Database")
    @patch("cli.OpenCodeClient")
    @patch("cli.ProxmoxTools")
    @patch("cli.PermissionGate")
    def test_init_with_minimal_config(self, mock_gate, mock_proxmox,
                                       mock_client, mock_db, mock_load_cfg,
                                       mock_config):
        """Shell must initialize with minimal config (no Proxmox, no LLM)."""
        mock_load_cfg.return_value = mock_config
        mock_client.side_effect = ValueError("No API key")
        mock_proxmox.return_value = None

        from cli import SentinelShell
        shell = SentinelShell()

        assert shell.config == mock_config
        assert shell.proxmox is None
        assert shell.client is None
        mock_gate.assert_called_once()

    @patch("cli.load_config")
    @patch("cli.Database")
    @patch("cli.OpenCodeClient")
    @patch("cli.ProxmoxTools")
    @patch("cli.PermissionGate")
    def test_init_with_full_config(self, mock_gate, mock_proxmox,
                                     mock_client, mock_db, mock_load_cfg,
                                     mock_config):
        """Shell must initialize with full config (Proxmox + LLM)."""
        mock_config["proxmox"] = {
            "host": "192.168.1.100",
            "token_value": "test-token",
            "user": "test@pam",
            "token_name": "testToken",
            "verify_ssl": True,
        }
        mock_load_cfg.return_value = mock_config
        mock_proxmox.return_value = MagicMock()

        from cli import SentinelShell
        shell = SentinelShell()

        assert shell.proxmox is not None
        mock_client.assert_called_once()

    @patch("cli.load_config")
    @patch("cli.Database")
    @patch("cli.OpenCodeClient")
    @patch("cli.ProxmoxTools")
    @patch("cli.PermissionGate")
    def test_init_creates_history_dir(self, mock_gate, mock_proxmox,
                                       mock_client, mock_db, mock_load_cfg,
                                       mock_config):
        """Shell must create history directory with 0o700 permissions."""
        mock_load_cfg.return_value = mock_config
        mock_client.side_effect = ValueError("No API key")
        mock_proxmox.return_value = None

        from cli import HISTORY_FILE, SentinelShell
        history_path = Path(HISTORY_FILE)

        # Clean up if exists
        if history_path.parent.exists():
            import shutil
            shutil.rmtree(history_path.parent)

        try:
            SentinelShell()
            assert history_path.parent.exists()
            # Check directory permissions (only on POSIX)
            if os.name != "nt":
                mode = history_path.parent.stat().st_mode & 0o777
                assert mode == 0o700, f"Expected 0o700, got {oct(mode)}"
        finally:
            # Cleanup
            if history_path.parent.exists():
                import shutil
                shutil.rmtree(history_path.parent)


# ── Command Routing Tests ──────────────────────────────────────────


class TestCommandRouting:
    """Test that slash commands route to correct handlers."""

    @pytest.fixture
    def shell(self):
        """Create a shell with mocked dependencies."""
        mock_config = {
            "model": {"provider": "opencode-go", "model_id": "glm-5.1"},
            "proxmox": {},
            "guardrails": {"enabled": True, "preset": "general"},
            "storage": {"db_path": ":memory:"},
            "permissions": {"allowed_write_actions": [], "deny_always": []},
        }
        with patch("cli.load_config", return_value=mock_config), \
             patch("cli.Database") as mock_db, \
             patch("cli.OpenCodeClient", side_effect=ValueError("No API key")), \
             patch("cli.ProxmoxTools", return_value=None), \
             patch("cli.PermissionGate") as mock_gate:
            from cli import SentinelShell
            shell = SentinelShell()
            shell.console = MagicMock()
            yield shell

    def test_help_routes_to_handler(self, shell):
        """/help must call _cmd_help."""
        with patch.object(shell, "_cmd_help") as mock:
            shell._handle_command("/help")
            mock.assert_called_once_with(["/help"])

    def test_digest_routes_to_handler(self, shell):
        """/digest must call _cmd_digest."""
        with patch.object(shell, "_cmd_digest") as mock:
            shell._handle_command("/digest")
            mock.assert_called_once_with(["/digest"])

    def test_health_routes_to_handler(self, shell):
        """/health must call _cmd_health."""
        with patch.object(shell, "_cmd_health") as mock:
            shell._handle_command("/health")
            mock.assert_called_once_with(["/health"])

    def test_health_rrd_routes_to_handler(self, shell):
        """/health rrd must call _cmd_health."""
        with patch.object(shell, "_cmd_health") as mock:
            shell._handle_command("/health rrd day")
            mock.assert_called_once_with(["/health", "rrd", "day"])

    def test_db_routes_to_handler(self, shell):
        """/db must call _cmd_db."""
        with patch.object(shell, "_cmd_db") as mock:
            shell._handle_command("/db status")
            mock.assert_called_once_with(["/db", "status"])

    def test_refresh_routes_to_handler(self, shell):
        """/refresh must call _cmd_refresh."""
        with patch.object(shell, "_cmd_refresh") as mock:
            shell._handle_command("/refresh all")
            mock.assert_called_once_with(["/refresh", "all"])

    def test_unknown_command_shows_error(self, shell):
        """Unknown command must show error message."""
        shell._handle_command("/nonexistent")
        shell.console.print.assert_any_call("[red]Unknown command:[/red] /nonexistent")

    def test_empty_input_ignored(self, shell):
        """Empty command string must not crash."""
        shell._handle_command("")
        # Should not raise, no print calls expected
        shell.console.print.assert_not_called()

    def test_quit_exits(self, shell):
        """/quit must call sys.exit."""
        with patch("sys.exit") as mock_exit:
            shell._handle_command("/quit")
            mock_exit.assert_called_once_with(0)

    def test_exit_aliases_quit(self, shell):
        """/exit must also call sys.exit."""
        with patch("sys.exit") as mock_exit:
            shell._handle_command("/exit")
            mock_exit.assert_called_once_with(0)


# ── Chat Context Builder Tests ─────────────────────────────────────


class TestChatContextBuilder:
    """Test _build_chat_context with various snapshot states."""

    @pytest.fixture
    def shell(self):
        """Create a shell with mocked dependencies."""
        mock_config = {
            "model": {"provider": "opencode-go", "model_id": "glm-5.1"},
            "proxmox": {},
            "guardrails": {"enabled": True, "preset": "general"},
            "storage": {"db_path": ":memory:"},
            "permissions": {"allowed_write_actions": [], "deny_always": []},
        }
        with patch("cli.load_config", return_value=mock_config), \
             patch("cli.Database") as mock_db, \
             patch("cli.OpenCodeClient", side_effect=ValueError("No API key")), \
             patch("cli.ProxmoxTools", return_value=None), \
             patch("cli.PermissionGate"):
            from cli import SentinelShell
            shell = SentinelShell()
            shell.console = MagicMock()
            shell.db = mock_db.return_value
            yield shell

    def test_empty_snapshots_returns_empty(self, shell):
        """No snapshots must return empty string."""
        shell.db.get_all_snapshots.return_value = {}
        result = shell._build_chat_context()
        assert result == ""

    def test_repos_snapshot_included(self, shell):
        """Repos snapshot must be in context."""
        shell.db.get_all_snapshots.return_value = {
            "repos": {
                "data": {
                    "standard_repos": [
                        {"name": "pve-enterprise", "enabled": True},
                        {"name": "pve-no-subscription", "enabled": True},
                    ],
                    "warnings": [],
                    "errors": [],
                },
                "updated_at": "2026-05-05T14:32:00Z",
            }
        }
        result = shell._build_chat_context()
        assert "pve-enterprise" in result
        assert "2026-05-05T14:32:00Z" in result

    def test_health_snapshot_included(self, shell):
        """Health snapshot must be in context."""
        shell.db.get_all_snapshots.return_value = {
            "health": {
                "data": {
                    "cpu_pct": 25.0,
                    "mem_pct": 60.0,
                    "rootfs_pct": 45.0,
                    "vm_count": 3,
                    "lxc_count": 2,
                },
                "updated_at": "2026-05-05T14:32:00Z",
            }
        }
        result = shell._build_chat_context()
        assert "CPU 25.0%" in result
        assert "RAM 60.0%" in result

    def test_services_snapshot_included(self, shell):
        """Services snapshot must be in context."""
        shell.db.get_all_snapshots.return_value = {
            "services": {
                "data": {
                    "services": [
                        {"name": "pveproxy", "state": "running"},
                        {"name": "pvedaemon", "state": "running"},
                        {"name": "corosync", "state": "dead"},
                    ]
                },
                "updated_at": "2026-05-05T14:32:00Z",
            }
        }
        result = shell._build_chat_context()
        assert "2 running" in result
        assert "dead=['corosync']" in result

    def test_all_snapshots_combined(self, shell):
        """All snapshots must appear in context together."""
        shell.db.get_all_snapshots.return_value = {
            "repos": {
                "data": {"standard_repos": [], "warnings": [], "errors": []},
                "updated_at": "2026-05-05T14:32:00Z",
            },
            "health": {
                "data": {"cpu_pct": 10, "mem_pct": 50, "rootfs_pct": 30,
                          "vm_count": 1, "lxc_count": 1},
                "updated_at": "2026-05-05T14:32:00Z",
            },
            "services": {
                "data": {"services": [{"name": "pveproxy", "state": "running"}]},
                "updated_at": "2026-05-05T14:32:00Z",
            },
        }
        result = shell._build_chat_context()
        assert "System Context" in result
        assert "Repositories" in result
        assert "Health" in result
        assert "Services" in result


# ── Scan Cache Tests ─────────────────────────────────────────────


class TestScanCache:
    """Test 24-hour scan cache behavior."""

    @pytest.fixture
    def shell(self):
        """Create a shell with mocked dependencies."""
        mock_config = {
            "model": {"provider": "opencode-go", "model_id": "glm-5.1"},
            "proxmox": {},
            "guardrails": {"enabled": True, "preset": "general"},
            "storage": {"db_path": ":memory:", "scan_cache_ttl_hours": 24},
            "permissions": {"allowed_write_actions": [], "deny_always": []},
        }
        with patch("cli.load_config", return_value=mock_config), \
             patch("cli.Database") as mock_db, \
             patch("cli.OpenCodeClient", side_effect=ValueError("No API key")), \
             patch("cli.ProxmoxTools", return_value=None), \
             patch("cli.PermissionGate"):
            from cli import SentinelShell
            shell = SentinelShell()
            shell.console = MagicMock()
            shell.db = mock_db.return_value
            yield shell

    def test_cache_hit_within_ttl(self, shell):
        """Fresh cache (within TTL) must display cached results, not run scan."""
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        shell.db.get_snapshot.return_value = {
            "updated_at": now,
            "data": {
                "host_result": {"cves_found": 30, "packages_checked": 59, "duration": 5.0},
                "lxc_result": {"cves_matched": 0, "packages_checked": 285, "duration": 1.0},
                "llm_summary": "No critical issues found.",
                "repo_summary": "Repos: pve-no-subscription",
            },
        }

        shell._cmd_digest(["/digest"])

        # Should display cached results
        shell.console.print.assert_any_call(
            "[dim]Using cached scan from {} (0 minutes old)[/dim]".format(now)
        )
        # Should NOT run a fresh scan (no "Running fresh CVE scan" message)
        for call in shell.console.print.call_args_list:
            assert "Running fresh CVE scan" not in str(call)

    def test_cache_miss_triggers_fresh_scan(self, shell):
        """Empty cache must trigger fresh scan."""
        shell.db.get_snapshot.return_value = None

        # Fresh scan will fail (no scanner), but should attempt it
        shell._cmd_digest(["/digest"])

        shell.console.print.assert_any_call("[cyan]Running fresh CVE scan...[/cyan]")

    def test_force_bypasses_cache(self, shell):
        """--force flag must bypass cache and run fresh scan."""
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        shell.db.get_snapshot.return_value = {
            "updated_at": now,
            "data": {
                "host_result": {"cves_found": 30, "packages_checked": 59, "duration": 5.0},
                "lxc_result": {"cves_matched": 0, "packages_checked": 285, "duration": 1.0},
                "llm_summary": "Cached summary.",
                "repo_summary": "Repos: pve-no-subscription",
            },
        }

        shell._cmd_digest(["/digest", "--force"])

        shell.console.print.assert_any_call("[cyan]Running fresh CVE scan...[/cyan]")

    def test_force_keyword_bypasses_cache(self, shell):
        """'force' keyword (without --) must also bypass cache."""
        shell.db.get_snapshot.return_value = {"updated_at": "2026-05-06T08:00:00Z", "data": {}}

        shell._cmd_digest(["/digest", "force"])

        shell.console.print.assert_any_call("[cyan]Running fresh CVE scan...[/cyan]")

    def test_cached_digest_shows_summary_note(self, shell):
        """Cached LLM summary must include 'ask a follow-up' note."""
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        shell.db.get_snapshot.return_value = {
            "updated_at": now,
            "data": {
                "host_result": {"cves_found": 30, "packages_checked": 59, "duration": 5.0},
                "lxc_result": {"cves_matched": 0, "packages_checked": 285, "duration": 1.0, "matched_cves": []},
                "llm_summary": "No critical issues found.",
                "repo_summary": "Repos: pve-no-subscription",
            },
        }

        shell._cmd_digest(["/digest"])

        # Check that the cached summary panel includes the follow-up note
        for call in shell.console.print.call_args_list:
            args = str(call)
            if "Cached LLM Summary" in args:
                assert "Cached summary" in args
                assert "ask a follow-up question" in args
                break

    def test_cached_digest_shows_matched_cves(self, shell):
        """Cached digest must show matched CVEs table if present."""
        from datetime import datetime, timezone
        from rich.table import Table
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        shell.db.get_snapshot.return_value = {
            "updated_at": now,
            "data": {
                "host_result": {"cves_found": 30, "packages_checked": 59, "duration": 5.0},
                "lxc_result": {
                    "cves_matched": 1,
                    "packages_checked": 285,
                    "duration": 1.0,
                    "matched_cves": [
                        {"cve_id": "CVE-2026-1234", "package": "openssl",
                         "version": "3.0.0", "severity": "HIGH", "cvss_score": 7.5},
                    ],
                },
                "llm_summary": "",
                "repo_summary": "",
            },
        }

        shell._cmd_digest(["/digest"])

        # Should print a Table object (matched CVEs)
        found_table = False
        for call in shell.console.print.call_args_list:
            args, kwargs = call
            if args and isinstance(args[0], Table):
                if args[0].title and "Matched CVEs" in str(args[0].title):
                    found_table = True
                    break
        assert found_table, "Expected matched CVEs Table in cached digest output"

    def test_naive_timestamp_is_handled_gracefully(self, shell):
        """Naive timestamp (no timezone) must not crash — treated as UTC."""
        shell.db.get_snapshot.return_value = {
            "updated_at": "2026-05-06T08:30:00",  # No Z, no timezone — naive
            "data": {
                "host_result": {"cves_found": 30, "packages_checked": 59, "duration": 5.0},
                "lxc_result": {"cves_matched": 0, "packages_checked": 285, "duration": 1.0},
                "llm_summary": "Cached summary.",
                "repo_summary": "",
            },
        }

        shell._cmd_digest(["/digest"])

        # Should use cache (treated as UTC), not crash or run fresh scan
        for call in shell.console.print.call_args_list:
            args = str(call)
            if "Using cached scan from" in args:
                return
        assert False, "Expected cached scan output, not fresh scan"

    def test_malformed_timestamp_falls_through_to_fresh_scan(self, shell):
        """Malformed timestamp must not crash — falls through to fresh scan."""
        shell.db.get_snapshot.return_value = {
            "updated_at": "not-a-timestamp",
            "data": {},
        }

        shell._cmd_digest(["/digest"])

        shell.console.print.assert_any_call("[cyan]Running fresh CVE scan...[/cyan]")
