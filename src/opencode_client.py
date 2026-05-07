"""OpenCode Go client — direct REST API (OpenAI-compatible).

Calls https://opencode.ai/zen/go/v1/chat/completions directly.
No opencode serve or CLI needed.
"""

import os

import httpx

from .config import load_config
from .guardrails import get_system_prompt

OPENCODE_GO_BASE = os.environ.get("OPENCODE_GO_BASE", "https://opencode.ai/zen/go/v1")

# Base URLs per provider
PROVIDER_BASE_URLS = {
    "opencode-go": "https://opencode.ai/zen/go/v1",
    "opencode-zen": "https://zen.opencode.ai/v1",
}

# Default models per provider
DEFAULT_MODELS = {
    "opencode-go": "glm-5.1",
    "opencode-zen": "glm-4",
}


class OpenCodeClient:
    """Direct client for OpenCode Go REST API.

    Usage:
        with OpenCodeClient() as client:
            response = client.ask("What is the status of my Proxmox cluster?")
    """

    def __init__(
        self,
        api_key: str = "",
        model: str = "",
        provider: str = "opencode-go",
        timeout: float = 120.0,
        guardrail_preset: str | None = None,
        guardrail_custom: str | None = None,
    ):
        self.api_key = api_key or os.environ.get("OPENCODE_GO_API_KEY", "")
        if not self.api_key:
            raise ValueError(
                "OpenCode Go API key is empty. Set the OPENCODE_GO_API_KEY "
                "environment variable before running pve-sentinel."
            )
        self.provider = provider
        self.model = model or DEFAULT_MODELS.get(provider, "glm-5.1")
        self._guardrail_preset = guardrail_preset
        self._guardrail_custom = guardrail_custom
        self._system_prompt: str | None = None
        base_url = os.environ.get("OPENCODE_GO_BASE", PROVIDER_BASE_URLS.get(provider, OPENCODE_GO_BASE))
        self._client = httpx.Client(
            base_url=base_url,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            timeout=httpx.Timeout(timeout),
        )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def __repr__(self) -> str:
        return f"OpenCodeClient(provider={self.provider!r}, model={self.model!r}, api_key='***')"

    def _load_guardrail(self) -> str:
        """Load guardrail system prompt from config (cached after first call)."""
        if self._guardrail_custom:
            return self._guardrail_custom

        if self._guardrail_preset:
            return get_system_prompt(preset=self._guardrail_preset)

        # Fall back to config.yaml
        try:
            cfg = load_config()
            guard = cfg.get("guardrails", {})
            if guard.get("enabled", True):
                preset = guard.get("preset")
                custom = guard.get("custom")
                if custom:
                    return custom
                if preset:
                    return get_system_prompt(preset=preset)
        except (FileNotFoundError, ValueError):
            pass

        return get_system_prompt()  # default: general

    def ask(self, prompt: str, system: str = "") -> str:
        """Send a prompt to the model and return the response text.

        If a guardrail system prompt is configured (via config.yaml),
        it is automatically prepended. Explicit system parameter overrides.
        """
        if not system:
            if self._system_prompt is None:
                self._system_prompt = self._load_guardrail()
            system = self._system_prompt

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        try:
            resp = self._client.post(
                "/chat/completions",
                json={
                    "model": self.model,
                    "messages": messages,
                },
            )
            resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            body = e.response.text[:500] if e.response else ""
            raise RuntimeError(
                f"OpenCode Go API error ({e.response.status_code}): {body}"
            ) from e
        except httpx.RequestError as e:
            raise RuntimeError(f"OpenCode Go API request failed: {e}") from e

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
