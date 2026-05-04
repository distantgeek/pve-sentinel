"""HTTP client for OpenCode server (GLM-5.1 API gateway).

Calls the OpenCode serve REST API to send prompts and receive responses.
OpenCode handles provider routing (Go → Z.AI → GLM-5.1).
"""

from typing import Optional

import httpx


class OpenCodeClient:
    """Client for the OpenCode server REST API."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 4096,
        password: str = "",
        timeout: float = 120.0,
    ):
        self.base_url = f"http://{host}:{port}"
        self.password = password
        self.timeout = timeout
        self._session_id: Optional[str] = None
        self._client = httpx.Client(
            timeout=httpx.Timeout(timeout),
            auth=("opencode", password) if password else None,
        )

    def _ensure_session(self) -> str:
        """Create a session if one doesn't exist."""
        if self._session_id is None:
            resp = self._client.post(
                f"{self.base_url}/session",
                json={"title": "pve-sentinel"},
            )
            resp.raise_for_status()
            self._session_id = resp.json()["id"]
        return self._session_id

    def ask(self, prompt: str, model_id: str = "glm-5.1") -> str:
        """Send a prompt to GLM-5.1 and return the response text.

        Args:
            prompt: The user's query.
            model_id: Model to use (default: glm-5.1).

        Returns:
            The model's text response.

        Raises:
            httpx.HTTPError: On API communication failure.
        """
        session_id = self._ensure_session()

        resp = self._client.post(
            f"{self.base_url}/session/{session_id}/message",
            json={
                "parts": [{"type": "text", "text": prompt}],
                "model": {
                    "providerID": "opencode-go",
                    "modelID": model_id,
                },
            },
        )
        resp.raise_for_status()
        data = resp.json()

        # Extract text from response parts
        parts = data.get("parts", [])
        text_parts = [p["text"] for p in parts if p.get("type") == "text"]
        return "\n".join(text_parts) if text_parts else str(data)

    def health_check(self) -> bool:
        """Check if the OpenCode server is reachable."""
        try:
            resp = self._client.get(f"{self.base_url}/global/health")
            return resp.status_code == 200
        except httpx.RequestError:
            return False

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()
