"""Tests for pve-sentinel CLI module.

These tests verify that cli.py loads correctly, constants are defined,
helper functions work, and command routing is wired properly.

Note: Full REPL interaction tests are not included (requires prompt_toolkit
event loop). These tests focus on import validity, constant correctness,
and handler wiring — catching syntax errors and missing imports.
"""

import ast
import importlib
import json
import os
import re
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
                    "node": "kevbot-pve",
                    "pveversion": "pve-manager/8.4.1",
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
        assert "Node: kevbot-pve" in result
        assert "Proxmox: pve-manager/8.4.1" in result
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
                "data": {"node": "test-node", "pveversion": "pve-manager/8.4",
                          "cpu_pct": 10, "mem_pct": 50, "rootfs_pct": 30,
                          "vm_count": 1, "lxc_count": 1},
                "updated_at": "2026-05-05T14:32:00Z",
            },
            "services": {
                "data": {"services": [{"name": "pveproxy", "state": "running"}]},
                "updated_at": "2026-05-05T14:32:00Z",
            },
        }
        result = shell._build_chat_context()
        assert "Available system context" in result
        assert "reference data only" in result
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


# ── Conversation History Tests ─────────────────────────────────────


class TestConversationHistory:
    """Test conversation history injection for LLM context."""

    @pytest.fixture
    def shell(self):
        """Create a shell with mocked dependencies."""
        mock_config = {
            "model": {"provider": "opencode-go", "model_id": "glm-5.1"},
            "proxmox": {},
            "guardrails": {"enabled": True, "preset": "general"},
            "storage": {"db_path": ":memory:", "conversation_history_depth": 10},
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

    def test_history_injected_when_available(self, shell):
        """Recent messages must appear in prompt."""
        shell.db.get_recent_conversations.return_value = [
            {"role": "user", "content": "What about repos?"},
            {"role": "assistant", "content": "The repo config shows..."},
        ]
        result = shell._get_conversation_history()
        assert "Recent conversation:" in result
        assert "What about repos?" in result
        assert "The repo config shows..." in result

    def test_empty_history_returns_empty(self, shell):
        """No history must return empty string."""
        shell.db.get_recent_conversations.return_value = []
        assert shell._get_conversation_history() == ""

    def test_depth_zero_disables_history(self, shell):
        """depth=0 must disable history."""
        shell.config["storage"]["conversation_history_depth"] = 0
        shell.db.get_recent_conversations.return_value = [
            {"role": "user", "content": "test"},
        ]
        assert shell._get_conversation_history() == ""

    def test_long_messages_truncated(self, shell):
        """Messages over 500 chars must be truncated."""
        long_msg = "x" * 600
        shell.db.get_recent_conversations.return_value = [
            {"role": "user", "content": long_msg},
        ]
        result = shell._get_conversation_history()
        assert "[truncated]" in result
        # Should not contain the full 600 chars
        assert "x" * 501 not in result

    def test_default_depth_from_config(self, shell):
        """Default depth must come from config."""
        shell.config["storage"]["conversation_history_depth"] = 3
        shell.db.get_recent_conversations.return_value = [
            {"role": "user", "content": "msg1"},
            {"role": "assistant", "content": "msg2"},
            {"role": "user", "content": "msg3"},
            {"role": "assistant", "content": "msg4"},
        ]
        shell._get_conversation_history()
        shell.db.get_recent_conversations.assert_called_with(3)

    def test_system_context_label_is_reference_only(self, shell):
        """System context must use reference-only label."""
        shell.db.get_all_snapshots.return_value = {
            "repos": {
                "data": {"standard_repos": [], "warnings": [], "errors": []},
                "updated_at": "2026-05-06T08:00:00Z",
            },
        }
        result = shell._build_chat_context()
        assert "Available system context" in result
        assert "reference data only" in result
        assert "Do NOT re-list findings" in result
        assert "System Context (cached" not in result


# ── Tool-Use Tests ─────────────────────────────────────────────


class TestToolUse:
    """Test tool-use pattern with PermissionGate."""

    @pytest.fixture
    def shell(self):
        """Create a shell with mocked dependencies."""
        mock_config = {
            "model": {"provider": "opencode-go", "model_id": "glm-5.1"},
            "proxmox": {},
            "guardrails": {"enabled": True, "preset": "general"},
            "storage": {"db_path": ":memory:", "conversation_history_depth": 10},
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

    def test_tool_request_pattern_detected(self):
        """LLM tool request pattern must be detected by regex."""
        import re
        response = "[TOOL:proxmox_api] GET /nodes/kevbot-pve/apt/repositories"
        match = re.match(r'\[TOOL:(\w+)\]\s+(.*)', response)
        assert match is not None
        assert match.group(1) == "proxmox_api"
        assert match.group(2) == "GET /nodes/kevbot-pve/apt/repositories"

    def test_read_operation_auto_approved(self, shell):
        """GET requests must be auto-approved."""
        assert shell._check_tool_permission("proxmox_api", "GET /nodes/test/path") is True

    def test_write_operation_blocked(self, shell):
        """POST requests must be blocked."""
        assert shell._check_tool_permission("proxmox_api", "POST /nodes/test/path") is False

    def test_delete_operation_blocked(self, shell):
        """DELETE requests must be blocked."""
        assert shell._check_tool_permission("proxmox_api", "DELETE /nodes/test/path") is False

    def test_unknown_tool_denied(self, shell):
        """Unknown tool names must be denied."""
        assert shell._check_tool_permission("unknown_tool", "args") is False

    def test_tool_registry_has_proxmox_api(self):
        """Tool registry must include proxmox_api."""
        from src.tools import TOOL_REGISTRY
        assert "proxmox_api" in TOOL_REGISTRY
        assert "purpose" in TOOL_REGISTRY["proxmox_api"]
        assert "access" in TOOL_REGISTRY["proxmox_api"]
        assert "format" in TOOL_REGISTRY["proxmox_api"]

    def test_get_tool_info_returns_string(self):
        """get_tool_info must return non-empty string."""
        from src.tools import get_tool_info
        info = get_tool_info()
        assert isinstance(info, str)
        assert len(info) > 50
        assert "proxmox_api" in info

    def test_tools_command_displays_table(self, shell):
        """/tools must display tool table."""
        shell._cmd_tools(["/tools"])
        # Should have printed at least once (the table)
        assert shell.console.print.call_count >= 1


# ── Batch Operation Tests ─────────────────────────────────────


class TestBatchOperations:
    """Test batch operation pattern with PermissionGate."""

    @pytest.fixture
    def shell(self):
        """Create a shell with mocked dependencies."""
        mock_config = {
            "model": {"provider": "opencode-go", "model_id": "glm-5.1"},
            "proxmox": {},
            "guardrails": {"enabled": True, "preset": "general"},
            "storage": {"db_path": ":memory:", "conversation_history_depth": 10},
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

    def test_batch_pattern_detected(self):
        """Batch tool request pattern must be detected."""
        response = '[TOOL:proxmox_api] BATCH [{"method": "POST", "path": "/nodes/test/qemu", "body": {"vmid": 100}}]'
        match = re.match(r'\[TOOL:(\w+)\]\s+BATCH\s+(.*)', response, re.DOTALL)
        assert match is not None
        assert match.group(1) == "proxmox_api"
        operations = json.loads(match.group(2))
        assert len(operations) == 1

    def test_batch_max_operations(self):
        """Batch exceeding max operations must be rejected."""
        from src.tools import validate_batch, BATCH_OPERATIONS_MAX
        ops = [{"method": "GET", "path": "/nodes/test/status"}] * (BATCH_OPERATIONS_MAX + 1)
        valid, error = validate_batch(ops)
        assert not valid
        assert "exceeds maximum" in error

    def test_batch_empty_rejected(self):
        """Empty batch must be rejected."""
        from src.tools import validate_batch
        valid, error = validate_batch([])
        assert not valid
        assert "at least one" in error

    def test_batch_not_list_rejected(self):
        """Non-list batch must be rejected."""
        from src.tools import validate_batch
        valid, error = validate_batch({"method": "GET", "path": "/test"})
        assert not valid
        assert "JSON array" in error

    def test_blacklist_rejection(self):
        """Blacklisted paths must be rejected."""
        from src.tools import validate_batch
        ops = [{"method": "POST", "path": "/nodes/test/stop"}]
        valid, error = validate_batch(ops)
        assert not valid
        assert "blacklist" in error.lower()

    def test_firewall_blacklisted(self):
        """Firewall paths must be blacklisted."""
        from src.tools import is_path_blacklisted
        assert is_path_blacklisted("/nodes/test/firewall") is True

    def test_stop_blacklisted(self):
        """Stop paths must be blacklisted."""
        from src.tools import is_path_blacklisted
        assert is_path_blacklisted("/nodes/test/stop") is True

    def test_shutdown_blacklisted(self):
        """Shutdown paths must be blacklisted."""
        from src.tools import is_path_blacklisted
        assert is_path_blacklisted("/nodes/test/shutdown") is True

    def test_migrate_blacklisted(self):
        """Migrate paths must be blacklisted."""
        from src.tools import is_path_blacklisted
        assert is_path_blacklisted("/nodes/test/migrate") is True

    def test_permissions_blacklisted(self):
        """Permissions paths must be blacklisted."""
        from src.tools import is_path_blacklisted
        assert is_path_blacklisted("/nodes/test/permissions") is True

    def test_destructive_operation_flagged(self):
        """DELETE operations must be flagged as destructive."""
        from src.tools import describe_api_operation
        desc = describe_api_operation("DELETE", "/nodes/test/qemu/100")
        assert "DESTRUCTIVE" in desc

    def test_vm_create_description(self):
        """VM create operation must have readable description."""
        from src.tools import describe_api_operation
        desc = describe_api_operation("POST", "/nodes/test/qemu", {"vmid": 100, "name": "web-01", "cores": 4, "memory": 8192})
        assert "web-01" in desc
        assert "100" in desc
        assert "4C" in desc

    def test_lxc_create_description(self):
        """LXC create operation must have readable description."""
        from src.tools import describe_api_operation
        desc = describe_api_operation("POST", "/nodes/test/lxc", {"vmid": 200, "hostname": "app-01", "cores": 2, "memory": 4096})
        assert "app-01" in desc
        assert "200" in desc

    def test_network_create_description(self):
        """Network create operation must have readable description."""
        from src.tools import describe_api_operation
        desc = describe_api_operation("POST", "/nodes/test/network", {"iface": "vmbr1"})
        assert "vmbr1" in desc

    def test_valid_batch_passes(self):
        """Valid batch with mixed operations must pass validation."""
        from src.tools import validate_batch
        ops = [
            {"method": "POST", "path": "/nodes/test/network", "body": {"iface": "vmbr1"}},
            {"method": "POST", "path": "/nodes/test/qemu", "body": {"vmid": 100, "name": "web-01"}},
            {"method": "GET", "path": "/nodes/test/status"},
        ]
        valid, error = validate_batch(ops)
        assert valid
        assert error == ""

    def test_user_blacklist_add_remove(self):
        """User blacklist add and remove must work."""
        import tempfile
        import os
        from src.tools import (
            USER_BLACKLIST_PATH, add_to_user_blacklist,
            remove_from_user_blacklist, get_full_blacklist,
            BUILTIN_BLACKLIST, _load_user_blacklist, _save_user_blacklist,
        )
        # Use a temp file for testing
        original_path = USER_BLACKLIST_PATH
        test_path = Path(tempfile.gettempdir()) / "test-blacklist.yaml"
        import src.tools
        src.tools.USER_BLACKLIST_PATH = test_path

        try:
            # Clean up any existing test file
            if test_path.exists():
                test_path.unlink()

            # Add a path
            success, msg = add_to_user_blacklist("/custom/blocked")
            assert success
            assert "Added" in msg

            # Verify it's in the full blacklist
            full = get_full_blacklist()
            assert "/custom/blocked" in full

            # Duplicate add must fail
            success, msg = add_to_user_blacklist("/custom/blocked")
            assert not success
            assert "already blacklisted" in msg.lower()

            # Remove it
            success, msg = remove_from_user_blacklist("/custom/blocked")
            assert success
            assert "Removed" in msg

            # Verify it's gone
            full = get_full_blacklist()
            assert "/custom/blocked" not in full

            # Remove built-in must fail
            success, msg = remove_from_user_blacklist("/stop")
            assert not success
            assert "built-in" in msg.lower()

            # Remove non-existent must fail
            success, msg = remove_from_user_blacklist("/nonexistent")
            assert not success
            assert "not in the user blacklist" in msg.lower()
        finally:
            # Restore original path
            src.tools.USER_BLACKLIST_PATH = original_path
            if test_path.exists():
                test_path.unlink()

    def test_blacklist_list_command(self, shell):
        """/blacklist list must display all paths."""
        shell._cmd_blacklist(["/blacklist", "list"])
        assert shell.console.print.call_count >= 1

    def test_blacklist_add_command(self, shell):
        """/blacklist add must add a path."""
        shell._cmd_blacklist(["/blacklist", "add", "/test/path"])
        # Should have printed success or duplicate message
        assert shell.console.print.call_count >= 1
        # Clean up
        from src.tools import remove_from_user_blacklist
        remove_from_user_blacklist("/test/path")

    def test_blacklist_remove_command(self, shell):
        """/blacklist remove must remove a path."""
        from src.tools import add_to_user_blacklist, remove_from_user_blacklist
        add_to_user_blacklist("/test/remove-me")
        shell._cmd_blacklist(["/blacklist", "remove", "/test/remove-me"])
        assert shell.console.print.call_count >= 1
