"""Tests for pve-sentinel permission gate."""

import pytest

from src.permission_gate import (
    ActionLevel,
    DENY_ALWAYS,
    DESTRUCTIVE_ACTIONS,
    PermissionGate,
)


class TestPermissionGate:
    @pytest.fixture
    def gate(self):
        return PermissionGate()

    def test_classify_read(self, gate):
        assert gate.classify("get status") == ActionLevel.READ
        assert gate.classify("status") == ActionLevel.READ
        assert gate.classify("list") == ActionLevel.READ

    def test_classify_write(self, gate):
        assert gate.classify("start") == ActionLevel.WRITE
        assert gate.classify("stop") == ActionLevel.WRITE
        assert gate.classify("shutdown") == ActionLevel.WRITE

    def test_classify_destructive(self, gate):
        assert gate.classify("destroy") == ActionLevel.DESTRUCTIVE
        assert gate.classify("delete") == ActionLevel.DESTRUCTIVE
        assert gate.classify("remove") == ActionLevel.DESTRUCTIVE

    def test_classify_empty_raises(self, gate):
        """Empty action string raises ValueError."""
        with pytest.raises(ValueError, match="cannot be empty"):
            gate.classify("")

    def test_read_auto_approved(self, gate):
        """Read operations should auto-approve without user input."""
        assert gate.request_confirmation("get status") is True
        assert gate.request_confirmation("list vms") is True

    def test_write_requires_confirm(self, gate):
        """Write operations should call the confirm callback."""

        def mock_confirm(prompt, expected=None):
            return True

        gate = PermissionGate(confirm_callback=mock_confirm)
        assert gate.request_confirmation("start", "VM 100") is True

    def test_destructive_random_token(self, gate):
        """Destructive operations should generate a random CONFIRM-XXXXXX token."""
        tokens_seen = []

        def mock_confirm(prompt, expected=None):
            tokens_seen.append({"prompt": prompt, "expected": expected})
            return False

        gate = PermissionGate(confirm_callback=mock_confirm)
        result = gate.request_confirmation("destroy", "VM 100")
        assert result is False
        assert len(tokens_seen) == 1
        assert tokens_seen[0]["expected"].startswith("CONFIRM-")
        # Token is 6 chars: CONFIRM-XXXXXX = 14 total
        assert len(tokens_seen[0]["expected"]) == len("CONFIRM-XXXXXX")

    def test_deny_always_populated(self):
        """DENY_ALWAYS must contain destructive actions (CIS L1 least privilege)."""
        assert len(DENY_ALWAYS) > 0
        assert "destroy" in DENY_ALWAYS
        assert "delete" in DENY_ALWAYS
        assert "remove" in DENY_ALWAYS

    def test_deny_always_enforced(self):
        """Actions in DENY_ALWAYS are always classified as DESTRUCTIVE."""
        gate = PermissionGate()
        for action in DENY_ALWAYS:
            assert gate.classify(action) == ActionLevel.DESTRUCTIVE

    def test_exact_match_no_substring(self, gate):
        """Classification uses exact set membership, not substring matching."""
        # "get_destroy_log" should NOT match "destroy" via substring
        assert gate.classify("get_destroy_log") == ActionLevel.READ
        # "undestroy" should NOT match "destroy"
        assert gate.classify("undestroy") == ActionLevel.WRITE
