"""Tests for pve-sentinel permission gate."""

import pytest

from src.permission_gate import ActionLevel, PermissionGate


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

    def test_read_auto_approved(self, gate):
        """Read operations should auto-approve without user input."""
        assert gate.request_confirmation("get status") is True
        assert gate.request_confirmation("list vms") is True

    def test_write_requires_confirm(self, gate):
        """Write operations should call the confirm callback."""

        def mock_confirm(prompt, expected=None):
            # Return expected string
            return True

        gate = PermissionGate(confirm_callback=mock_confirm)
        assert gate.request_confirmation("start", "VM 100") is True

    def test_destructive_random_token(self, gate):
        """Destructive operations should generate a random CONFIRM-XXXX token."""
        tokens_seen = []

        def mock_confirm(prompt, expected=None):
            tokens_seen.append({"prompt": prompt, "expected": expected})
            return False  # User denies to keep test predictable

        gate = PermissionGate(confirm_callback=mock_confirm)
        result = gate.request_confirmation("destroy", "VM 100")
        assert result is False  # User denied
        assert len(tokens_seen) == 1
        assert tokens_seen[0]["expected"].startswith("CONFIRM-")
        assert len(tokens_seen[0]["expected"]) == len("CONFIRM-XXXX")
