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
    "opencode-zen": "https://opencode.ai/zen/v1",
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
        fallback: list[dict] | None = None,
    ):
        self.api_key = api_key or os.environ.get("OPENCODE_GO_API_KEY", "")
        if not self.api_key:
            raise ValueError(
                "OpenCode Go API key is empty. Set the OPENCODE_GO_API_KEY "
                "environment variable before running pve-sentinel."
            )
        self.provider = provider
        self.model = model or DEFAULT_MODELS.get(provider, "glm-5.1")
        self.fallback = fallback or []
        self._guardrail_preset = guardrail_preset
        self._guardrail_custom = guardrail_custom
        self._system_prompt: str | None = None
        self._timeout = timeout
        base_url = os.environ.get(
            "OPENCODE_GO_BASE", PROVIDER_BASE_URLS.get(provider, OPENCODE_GO_BASE)
        )
        self._client = self._make_client(base_url, self.api_key, timeout)

    def _make_client(self, base_url: str, api_key: str, timeout: float) -> httpx.Client:
        """Build an httpx client for a given base URL and API key."""
        return httpx.Client(
            base_url=base_url,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            timeout=httpx.Timeout(timeout),
        )

    def _build_fallback_client(self, fb: dict) -> httpx.Client:
        """Build a client for a fallback provider entry from config."""
        provider = fb.get("provider", "opencode-zen")
        base_url = fb.get("api_base") or PROVIDER_BASE_URLS.get(provider, OPENCODE_GO_BASE)
        api_key = self.api_key
        key_env = fb.get("api_key_env")
        if key_env:
            api_key = os.environ.get(key_env, self.api_key)
        return self._make_client(base_url, api_key, self._timeout)

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

        If the primary provider fails (rate limit, auth error, or server
        error), configured fallback providers are tried in order.
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
            return self._chat(messages, self._client, self.model, self.provider)
        except RuntimeError as primary_err:
            last_error = primary_err
            if not self.fallback:
                raise

        for fb in self.fallback:
            try:
                fb_provider = fb.get("provider", "opencode-zen")
                fb_model = fb.get("model_id") or DEFAULT_MODELS.get(fb_provider, self.model)
                fb_client = self._build_fallback_client(fb)
                return self._chat(messages, fb_client, fb_model, fb_provider)
            except RuntimeError as e:
                last_error = e
                continue

        raise RuntimeError(f"All LLM providers failed. Last error: {last_error}") from last_error

    def _chat(self, messages: list[dict], client: httpx.Client, model: str, provider: str) -> str:
        """POST a chat completion and return the response text."""
        try:
            resp = client.post(
                "/chat/completions",
                json={
                    "model": model,
                    "messages": messages,
                },
            )
            resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            body = e.response.text[:500] if e.response else ""
            raise RuntimeError(f"{provider} API error ({e.response.status_code}): {body}") from e
        except httpx.RequestError as e:
            raise RuntimeError(f"{provider} API request failed: {e}") from e

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
