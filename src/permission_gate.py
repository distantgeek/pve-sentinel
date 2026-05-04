"""Permission gate for pve-sentinel.

Enforces human-in-the-loop confirmation for all Proxmox write operations.
Read operations are auto-approved. Destructive operations require a random token.
"""

import secrets
import string
from enum import Enum
from typing import Callable


class ActionLevel(Enum):
    """Classification for Proxmox API actions."""
    READ = "read"
    WRITE = "write"
    DESTRUCTIVE = "destructive"


# Actions that require "confirm" (single-word approval)
WRITE_ACTIONS = frozenset({
    "start", "stop", "reset", "shutdown", "reboot",
    "suspend", "resume", "create", "clone", "migrate",
})

# Actions that require "CONFIRM-XXXXXX" (random 6-char token)
DESTRUCTIVE_ACTIONS = frozenset({
    "destroy", "remove", "delete", "unlink", "purge",
})

# Always denied — no confirmation can override (CIS L1 least privilege)
DENY_ALWAYS = frozenset({
    "destroy", "remove", "delete", "unlink", "purge",
})


class PermissionGate:
    """Permission enforcement for Proxmox API operations."""

    def __init__(
        self,
        allowed_write: set[str] | None = None,
        deny_always: set[str] | None = None,
        confirm_callback: Callable[[str], bool] | None = None,
    ):
        self.allowed_write = allowed_write or set(WRITE_ACTIONS)
        self.deny_always = deny_always or set(DENY_ALWAYS)
        self._confirm_callback = confirm_callback or self._default_confirm

    def classify(self, action: str) -> ActionLevel:
        """Classify an API action into read, write, or destructive."""
        if not action or not action.strip():
            raise ValueError("Action string cannot be empty")

        action_lower = action.lower().strip()

        if action_lower in self.deny_always:
            return ActionLevel.DESTRUCTIVE

        # Exact set membership — no substring matching
        if action_lower in DESTRUCTIVE_ACTIONS:
            return ActionLevel.DESTRUCTIVE

        if action_lower in self.allowed_write:
            return ActionLevel.WRITE

        if action_lower.startswith(("get", "list")) or action_lower in {"status", "config"}:
            return ActionLevel.READ

        return ActionLevel.WRITE

    def request_confirmation(
        self,
        action: str,
        detail: str = "",
    ) -> bool:
        """Request user confirmation for an action.

        Returns True if confirmed, False if denied.
        """
        level = self.classify(action)

        if level == ActionLevel.READ:
            return True  # Auto-approved

        if level == ActionLevel.DESTRUCTIVE:
            token = self._generate_token()
            prompt = (
                f"\n  DESTRUCTIVE OPERATION: {action}\n"
                f"  {detail}\n\n"
                f"  Type CONFIRM-{token} to proceed: "
            )
            return self._confirm_callback(prompt, expected=f"CONFIRM-{token}")

        prompt = (
            f"\n  Write operation: {action}\n"
            f"  {detail}\n\n"
            f"  Type 'confirm' to proceed: "
        )
        return self._confirm_callback(prompt, expected="confirm")

    def _generate_token(self, length: int = 6) -> str:
        """Generate a cryptographically secure confirmation token."""
        chars = string.ascii_uppercase + string.digits
        return "".join(secrets.choice(chars) for _ in range(length))

    @staticmethod
    def _default_confirm(prompt: str, expected: str) -> bool:
        """Default confirmation handler using stdin."""
        user_input = input(prompt).strip()
        return user_input == expected
