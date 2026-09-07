"""Tests for OpenCode Go REST API client."""

import os
from unittest.mock import MagicMock, patch

import httpx
import pytest

from src.opencode_client import DEFAULT_MODELS, OPENCODE_GO_BASE, OpenCodeClient


class TestOpenCodeClientInit:
    def test_raises_on_empty_api_key(self):
        """Client must reject empty API keys at init time."""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("OPENCODE_GO_API_KEY", None)
            with pytest.raises(ValueError, match="API key is empty"):
                OpenCodeClient(api_key="")

    def test_accepts_api_key_from_env(self):
        """Client reads API key from environment variable."""
        with patch.dict(os.environ, {"OPENCODE_GO_API_KEY": "test-key-123"}):
            client = OpenCodeClient()
            assert client.api_key == "test-key-123"

    def test_accepts_api_key_from_argument(self):
        """Client accepts API key as constructor argument."""
        client = OpenCodeClient(api_key="explicit-key")
        assert client.api_key == "explicit-key"

    def test_argument_overrides_env(self):
        """Constructor argument takes precedence over environment variable."""
        with patch.dict(os.environ, {"OPENCODE_GO_API_KEY": "env-key"}):
            client = OpenCodeClient(api_key="arg-key")
            assert client.api_key == "arg-key"

    def test_custom_model(self):
        """Client accepts custom model name."""
        with patch.dict(os.environ, {"OPENCODE_GO_API_KEY": "k"}):
            client = OpenCodeClient(model="custom-model")
            assert client.model == "custom-model"


class TestOpenCodeClientHealthCheck:
    @patch("src.opencode_client.httpx.Client")
    def test_health_check_returns_true_on_200(self, mock_client_cls):
        """Health check returns True when /models responds 200."""
        mock_client = MagicMock()
        mock_client.get.return_value = MagicMock(status_code=200)
        mock_client_cls.return_value = mock_client

        with patch.dict(os.environ, {"OPENCODE_GO_API_KEY": "k"}):
            client = OpenCodeClient()
            assert client.health_check() is True

    @patch("src.opencode_client.httpx.Client")
    def test_health_check_returns_false_on_error(self, mock_client_cls):
        """Health check returns False on request error."""
        mock_client = MagicMock()
        mock_client.get.side_effect = httpx.RequestError("connection refused")
        mock_client_cls.return_value = mock_client

        with patch.dict(os.environ, {"OPENCODE_GO_API_KEY": "k"}):
            client = OpenCodeClient()
            assert client.health_check() is False


class TestOpenCodeClientAsk:
    @patch("src.opencode_client.httpx.Client")
    def test_ask_returns_response_text(self, mock_client_cls):
        """Ask returns the model's response content."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"choices": [{"message": {"content": "Hello, world!"}}]}
        mock_response.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.post.return_value = mock_response
        mock_client_cls.return_value = mock_client

        with patch.dict(os.environ, {"OPENCODE_GO_API_KEY": "k"}):
            client = OpenCodeClient()
            result = client.ask("Say hello", system="")
            assert result == "Hello, world!"

    @patch("src.opencode_client.httpx.Client")
    def test_ask_includes_system_message(self, mock_client_cls):
        """Ask includes system message when provided."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"choices": [{"message": {"content": "ok"}}]}
        mock_response.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.post.return_value = mock_response
        mock_client_cls.return_value = mock_client

        with patch.dict(os.environ, {"OPENCODE_GO_API_KEY": "k"}):
            client = OpenCodeClient()
            client.ask("test", system="You are a security advisor")

            call_args = mock_client.post.call_args
            messages = call_args[1]["json"]["messages"]
            assert messages[0]["role"] == "system"
            assert messages[0]["content"] == "You are a security advisor"

    @patch("src.opencode_client.httpx.Client")
    def test_ask_raises_on_http_error(self, mock_client_cls):
        """Ask raises RuntimeError on HTTP error with response body."""
        error_response = MagicMock()
        error_response.text = "Rate limit exceeded"
        error_response.status_code = 429
        http_error = httpx.HTTPStatusError(
            "Rate limited", request=MagicMock(), response=error_response
        )
        mock_client = MagicMock()
        mock_client.post.side_effect = http_error
        mock_client_cls.return_value = mock_client

        with patch.dict(os.environ, {"OPENCODE_GO_API_KEY": "k"}):
            client = OpenCodeClient()
            with pytest.raises(RuntimeError, match="429"):
                client.ask("test")

    @patch("src.opencode_client.httpx.Client")
    def test_ask_returns_empty_on_no_choices(self, mock_client_cls):
        """Ask returns empty string when response has no choices."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"choices": []}
        mock_response.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.post.return_value = mock_response
        mock_client_cls.return_value = mock_client

        with patch.dict(os.environ, {"OPENCODE_GO_API_KEY": "k"}):
            client = OpenCodeClient()
            assert client.ask("test") == ""


class TestOpenCodeClientFallback:
    def _http_error(self, status: int = 429) -> httpx.HTTPStatusError:
        error_response = MagicMock()
        error_response.text = "Rate limit exceeded"
        error_response.status_code = status
        return httpx.HTTPStatusError("Rate limited", request=MagicMock(), response=error_response)

    @patch("src.opencode_client.httpx.Client")
    def test_fallback_used_when_primary_fails(self, mock_client_cls):
        """Fallback provider is tried when the primary returns an error."""
        primary = MagicMock()
        primary.post.side_effect = self._http_error(429)
        fallback = MagicMock()
        fallback_response = MagicMock()
        fallback_response.json.return_value = {
            "choices": [{"message": {"content": "Fallback response"}}]
        }
        fallback_response.raise_for_status = MagicMock()
        fallback.post.return_value = fallback_response
        mock_client_cls.side_effect = [primary, fallback]

        with patch.dict(os.environ, {"OPENCODE_GO_API_KEY": "k"}):
            client = OpenCodeClient(
                fallback=[{"provider": "opencode-zen", "model_id": "mimo-v2.5-free"}]
            )
            result = client.ask("test")
            assert result == "Fallback response"

        # Fallback client must use the Zen base URL and mimo-v2.5-free model
        fb_call = fallback.post.call_args
        assert fb_call[1]["json"]["model"] == "mimo-v2.5-free"
        fb_client_kwargs = mock_client_cls.call_args_list[1].kwargs
        assert str(fb_client_kwargs["base_url"]).rstrip("/") == "https://opencode.ai/zen/v1"

    @patch("src.opencode_client.httpx.Client")
    def test_fallback_not_tried_on_success(self, mock_client_cls):
        """Fallback is not contacted when the primary succeeds."""
        primary = MagicMock()
        primary_response = MagicMock()
        primary_response.json.return_value = {
            "choices": [{"message": {"content": "Primary response"}}]
        }
        primary_response.raise_for_status = MagicMock()
        primary.post.return_value = primary_response
        mock_client_cls.return_value = primary

        with patch.dict(os.environ, {"OPENCODE_GO_API_KEY": "k"}):
            client = OpenCodeClient(
                fallback=[{"provider": "opencode-zen", "model_id": "mimo-v2.5-free"}]
            )
            assert client.ask("test") == "Primary response"
            assert mock_client_cls.call_count == 1

    @patch("src.opencode_client.httpx.Client")
    def test_all_fail_raises_combined_error(self, mock_client_cls):
        """Raises a combined error when primary and all fallbacks fail."""
        primary = MagicMock()
        primary.post.side_effect = self._http_error(429)
        fallback = MagicMock()
        fallback.post.side_effect = self._http_error(500)
        mock_client_cls.side_effect = [primary, fallback]

        with patch.dict(os.environ, {"OPENCODE_GO_API_KEY": "k"}):
            client = OpenCodeClient(
                fallback=[{"provider": "opencode-zen", "model_id": "mimo-v2.5-free"}]
            )
            with pytest.raises(RuntimeError, match="All LLM providers failed"):
                client.ask("test")

    @patch("src.opencode_client.httpx.Client")
    def test_fallback_uses_separate_api_key_env(self, mock_client_cls):
        """Fallback uses api_key_env override when configured."""
        primary = MagicMock()
        primary.post.side_effect = self._http_error(429)
        fallback = MagicMock()
        fallback_response = MagicMock()
        fallback_response.json.return_value = {"choices": [{"message": {"content": "ok"}}]}
        fallback_response.raise_for_status = MagicMock()
        fallback.post.return_value = fallback_response
        mock_client_cls.side_effect = [primary, fallback]

        with patch.dict(
            os.environ,
            {"OPENCODE_GO_API_KEY": "k", "OPENCODE_ZEN_API_KEY": "zen-key"},
        ):
            client = OpenCodeClient(
                fallback=[
                    {
                        "provider": "opencode-zen",
                        "model_id": "mimo-v2.5-free",
                        "api_key_env": "OPENCODE_ZEN_API_KEY",
                    }
                ]
            )
            assert client.ask("test") == "ok"
            # Fallback client must be built with the Zen key
            fb_client_kwargs = mock_client_cls.call_args_list[1].kwargs
            assert fb_client_kwargs["headers"]["Authorization"] == "Bearer zen-key"

    @patch("src.opencode_client.httpx.Client")
    def test_fallback_uses_primary_key_by_default(self, mock_client_cls):
        """Fallback reuses the primary API key when api_key_env is omitted."""
        primary = MagicMock()
        primary.post.side_effect = self._http_error(429)
        fallback = MagicMock()
        fallback_response = MagicMock()
        fallback_response.json.return_value = {"choices": [{"message": {"content": "ok"}}]}
        fallback_response.raise_for_status = MagicMock()
        fallback.post.return_value = fallback_response
        mock_client_cls.side_effect = [primary, fallback]

        with patch.dict(os.environ, {"OPENCODE_GO_API_KEY": "k"}):
            client = OpenCodeClient(
                fallback=[{"provider": "opencode-zen", "model_id": "mimo-v2.5-free"}]
            )
            assert client.ask("test") == "ok"
            fb_client_kwargs = mock_client_cls.call_args_list[1].kwargs
            assert fb_client_kwargs["headers"]["Authorization"] == "Bearer k"

    @patch("src.opencode_client.httpx.Client")
    def test_fallback_openrouter_free(self, mock_client_cls):
        """OpenRouter free fallback uses api_base + api_key_env + openrouter/free."""
        primary = MagicMock()
        primary.post.side_effect = self._http_error(429)
        fallback = MagicMock()
        fallback_response = MagicMock()
        fallback_response.json.return_value = {"choices": [{"message": {"content": "ok"}}]}
        fallback_response.raise_for_status = MagicMock()
        fallback.post.return_value = fallback_response
        mock_client_cls.side_effect = [primary, fallback]

        with patch.dict(
            os.environ,
            {"OPENCODE_GO_API_KEY": "k", "OPENROUTER_API_KEY": "or-key"},
        ):
            client = OpenCodeClient(
                fallback=[
                    {
                        "provider": "openrouter",
                        "model_id": "openrouter/free",
                        "api_key_env": "OPENROUTER_API_KEY",
                        "api_base": "https://openrouter.ai/api/v1",
                    }
                ]
            )
            assert client.ask("test") == "ok"

        # Fallback client must use the OpenRouter base URL and key
        fb_client_kwargs = mock_client_cls.call_args_list[1].kwargs
        assert str(fb_client_kwargs["base_url"]).rstrip("/") == "https://openrouter.ai/api/v1"
        assert fb_client_kwargs["headers"]["Authorization"] == "Bearer or-key"
        # Model sent must be the meta-model
        fb_call = fallback.post.call_args
        assert fb_call[1]["json"]["model"] == "openrouter/free"


class TestOpenCodeClientContextManager:
    @patch("src.opencode_client.httpx.Client")
    def test_context_manager_closes_client(self, mock_client_cls):
        """Context manager properly closes HTTP client on exit."""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        with patch.dict(os.environ, {"OPENCODE_GO_API_KEY": "k"}):
            with OpenCodeClient() as client:
                pass
            mock_client.close.assert_called_once()


class TestOpenCodeClientZenProvider:
    def test_zen_provider_sets_correct_base_url(self):
        """Zen provider uses the free tier base URL."""
        with patch.dict(os.environ, {"OPENCODE_GO_API_KEY": "k"}):
            client = OpenCodeClient(provider="opencode-zen")
            assert str(client._client.base_url).rstrip("/") == "https://opencode.ai/zen/v1"

    def test_zen_provider_default_model(self):
        """Zen provider defaults to glm-4."""
        with patch.dict(os.environ, {"OPENCODE_GO_API_KEY": "k"}):
            client = OpenCodeClient(provider="opencode-zen")
            assert client.model == "glm-4"

    def test_zen_provider_custom_model(self):
        """Zen provider accepts custom model override."""
        with patch.dict(os.environ, {"OPENCODE_GO_API_KEY": "k"}):
            client = OpenCodeClient(provider="opencode-zen", model="qwen3-235b")
            assert client.model == "qwen3-235b"

    def test_default_provider_is_opencode_go(self):
        """Default provider is opencode-go with glm-5.1."""
        with patch.dict(os.environ, {"OPENCODE_GO_API_KEY": "k"}):
            client = OpenCodeClient()
            assert client.provider == "opencode-go"
            assert client.model == "glm-5.1"
            assert str(client._client.base_url).rstrip("/") == OPENCODE_GO_BASE

    def test_default_models_dict(self):
        """DEFAULT_MODELS contains expected provider defaults."""
        assert DEFAULT_MODELS["opencode-go"] == "glm-5.1"
        assert DEFAULT_MODELS["opencode-zen"] == "glm-4"

    @patch("src.opencode_client.httpx.Client")
    def test_zen_provider_ask_works(self, mock_client_cls):
        """Zen provider ask endpoint works identically."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"choices": [{"message": {"content": "Zen response"}}]}
        mock_response.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.post.return_value = mock_response
        mock_client_cls.return_value = mock_client

        with patch.dict(os.environ, {"OPENCODE_GO_API_KEY": "k"}):
            client = OpenCodeClient(provider="opencode-zen")
            result = client.ask("test")
            assert result == "Zen response"
            call_args = mock_client.post.call_args
            assert call_args[1]["json"]["model"] == "glm-4"
