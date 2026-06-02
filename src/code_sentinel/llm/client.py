"""
Unified LLM Client.

Provides an OpenAI-compatible chat-completions interface over ``httpx``,
with streaming support and automatic retry / exponential back-off.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, AsyncIterator, Optional

import httpx

from code_sentinel.config import Config

logger = logging.getLogger(__name__)


class LLMClientError(Exception):
    """Raised when the LLM client encounters an unrecoverable error."""


class LLMClient:
    """Async LLM client wrapping the OpenAI-compatible ``/chat/completions`` API.

    Parameters
    ----------
    config : Config
        Application configuration (provides api_key, base_url, etc.).
    timeout : float
        HTTP timeout in seconds (default 120).
    max_retries : int
        Maximum retry attempts on transient failures (default 3).
    """

    def __init__(
        self,
        config: Config,
        timeout: float | None = None,
        max_retries: int | None = None,
    ) -> None:
        self._config = config
        self._timeout = timeout or config.timeout
        self._max_retries = max_retries if max_retries is not None else config.max_retries
        self._base_url = (config.base_url or "").rstrip("/")
        self._headers = config.headers
        self._client: Optional[httpx.AsyncClient] = None

    # ── Lifecycle ────────────────────────────────────────────────────

    async def _get_client(self) -> httpx.AsyncClient:
        """Lazily create the shared ``httpx.AsyncClient``."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self._timeout, connect=30.0),
                limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
            )
        return self._client

    async def close(self) -> None:
        """Shut down the underlying HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> "LLMClient":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    # ── Public API ───────────────────────────────────────────────────

    async def chat(
        self,
        messages: list[dict[str, str]],
        model: str | None = None,
        temperature: float = 0.3,
        max_tokens: int = 4096,
        response_format: dict | None = None,
        **kwargs: Any,
    ) -> str:
        """Send a chat-completion request and return the assistant content.

        Parameters
        ----------
        messages : list[dict]
            OpenAI-style message list (role/content dicts).
        model : str, optional
            Model override; falls back to ``config.model``.
        temperature : float
            Sampling temperature.
        max_tokens : int
            Maximum tokens in the response.
        response_format : dict, optional
            e.g. ``{"type": "json_object"}``.
        **kwargs
            Extra fields merged into the request body.

        Returns
        -------
        str
            The assistant's reply text.

        Raises
        ------
        LLMClientError
            If all retries are exhausted.
        """
        body = self._build_body(
            messages=messages,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format=response_format,
            stream=False,
            **kwargs,
        )
        data = await self._request_with_retry(body)
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as exc:
            raise LLMClientError(f"Unexpected response structure: {exc}") from exc

    async def chat_stream(
        self,
        messages: list[dict[str, str]],
        model: str | None = None,
        temperature: float = 0.3,
        max_tokens: int = 4096,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Stream a chat-completion response, yielding content deltas.

        Yields
        ------
        str
            Incremental content chunks.
        """
        body = self._build_body(
            messages=messages,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            stream=True,
            **kwargs,
        )
        url = f"{self._base_url}/chat/completions"
        client = await self._get_client()

        for attempt in range(1, self._max_retries + 1):
            try:
                async with client.stream(
                    "POST", url, headers=self._headers, json=body
                ) as resp:
                    resp.raise_for_status()
                    async for line in resp.aiter_lines():
                        if not line.startswith("data: "):
                            continue
                        payload = line[len("data: "):]
                        if payload.strip() == "[DONE]":
                            return
                        try:
                            chunk = json.loads(payload)
                            delta = chunk["choices"][0].get("delta", {})
                            content = delta.get("content")
                            if content:
                                yield content
                        except (json.JSONDecodeError, KeyError, IndexError):
                            continue
                    return
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code in (429, 500, 502, 503, 504):
                    wait = 2 ** attempt
                    logger.warning(
                        "Stream attempt %d/%d got %d, retrying in %ds",
                        attempt, self._max_retries, exc.response.status_code, wait,
                    )
                    await asyncio.sleep(wait)
                    continue
                raise LLMClientError(
                    f"HTTP {exc.response.status_code}: {exc.response.text}"
                ) from exc
            except httpx.RequestError as exc:
                if attempt < self._max_retries:
                    wait = 2 ** attempt
                    logger.warning(
                        "Stream attempt %d/%d error: %s, retrying in %ds",
                        attempt, self._max_retries, exc, wait,
                    )
                    await asyncio.sleep(wait)
                    continue
                raise LLMClientError(f"Request failed after {self._max_retries} retries: {exc}") from exc

        raise LLMClientError(f"All {self._max_retries} stream attempts failed.")

    # ── Internal helpers ─────────────────────────────────────────────

    def _build_body(
        self,
        messages: list[dict[str, str]],
        model: str | None,
        temperature: float,
        max_tokens: int,
        stream: bool = False,
        response_format: dict | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Assemble the request payload."""
        body: dict[str, Any] = {
            "model": model or self._config.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": stream,
        }
        if response_format is not None:
            body["response_format"] = response_format
        body.update(kwargs)
        return body

    async def _request_with_retry(self, body: dict[str, Any]) -> dict[str, Any]:
        """POST to ``/chat/completions`` with exponential back-off.

        Retries on 429 / 5xx and network errors up to ``max_retries`` times.
        """
        url = f"{self._base_url}/chat/completions"
        client = await self._get_client()

        last_exc: Exception | None = None
        for attempt in range(1, self._max_retries + 1):
            try:
                resp = await client.post(
                    url, headers=self._headers, json=body
                )
                resp.raise_for_status()
                return resp.json()

            except httpx.HTTPStatusError as exc:
                last_exc = exc
                status = exc.response.status_code
                if status in (429, 500, 502, 503, 504):
                    wait = 2 ** attempt
                    logger.warning(
                        "Attempt %d/%d got HTTP %d, retrying in %ds …",
                        attempt, self._max_retries, status, wait,
                    )
                    await asyncio.sleep(wait)
                    continue
                # Non-retryable HTTP error
                raise LLMClientError(
                    f"HTTP {status}: {exc.response.text}"
                ) from exc

            except httpx.RequestError as exc:
                last_exc = exc
                if attempt < self._max_retries:
                    wait = 2 ** attempt
                    logger.warning(
                        "Attempt %d/%d network error: %s, retrying in %ds …",
                        attempt, self._max_retries, exc, wait,
                    )
                    await asyncio.sleep(wait)
                    continue

        raise LLMClientError(
            f"All {self._max_retries} attempts failed. Last error: {last_exc}"
        )
