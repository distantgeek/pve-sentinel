"""OpenCode Go client — direct REST API (OpenAI-compatible).

Calls https://opencode.ai/zen/go/v1/chat/completions directly.
No opencode serve or CLI needed.
"""

import os
from typing import Optional

import httpx

OPENCODE_GO_BASE = "https://opencode.ai/zen/go/v1"


class OpenCodeClient:
    """Direct client for OpenCode Go REST API."""

    def __init__(
        self,
        api_key: str = "",
        model: str = "glm-5.1",
        timeout: float = 120.0,
    ):
        self.api_key = api_key or os.environ.get("OPENCODE_GO_API_KEY", "")
        self.model = model
        self._client = httpx.Client(
            base_url=OPENCODE_GO_BASE,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            timeout=httpx.Timeout(timeout),
        )

    def ask(self, prompt: str, system: str = "") -> str:
        """Send a prompt to the model and return the response text.

        If a guardrail system prompt is configured (via config.yaml),
        it is automatically prepended. Explicit system parameter overrides.
        """
        from .guardrails import get_system_prompt
        import yaml
        from pathlib import Path

        # Auto-inject security guardrail if configured
        if not system:
            config_path = Path("config.yaml")
            if config_path.exists():
                cfg = yaml.safe_load(config_path.read_text()) or {}
                guard = cfg.get("guardrails", {})
                if guard.get("enabled", True):
                    preset = guard.get("preset")
                    custom = guard.get("custom")
                    system = get_system_prompt(preset=preset, custom=custom)
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        resp = self._client.post(
            "/chat/completions",
            json={
                "model": self.model,
                "messages": messages,
            },
        )
        resp.raise_for_status()
        data = resp.json()
        choices = data.get("choices", [])
        if choices:
            return choices[0].get("message", {}).get("content", "")
        return ""

    def health_check(self) -> bool:
        """Check if the OpenCode Go API is reachable."""
        try:
            resp = self._client.get("/models")
            return resp.status_code == 200
        except httpx.RequestError:
            return False

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()
