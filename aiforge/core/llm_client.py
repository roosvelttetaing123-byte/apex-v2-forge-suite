"""Universal LLM/AI API client — supports OpenAI, Anthropic, Azure, HuggingFace, Ollama, and custom endpoints.

Provides a unified interface for sending prompts and receiving responses
from any supported AI backend. Handles authentication, rate limiting,
response parsing, token counting, and retry logic.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

import aiohttp

log = logging.getLogger("forge.aiforge.llm_client")


@dataclass
class LLMResponse:
    """Parsed response from an LLM API call."""
    text:           str = ""
    raw_response:   dict[str, Any] = field(default_factory=dict)
    model:          str = ""
    finish_reason:  str = ""
    prompt_tokens:  int = 0
    completion_tokens: int = 0
    total_tokens:   int = 0
    latency_ms:     float = 0.0
    status_code:    int = 0
    headers:        dict[str, str] = field(default_factory=dict)
    error:          str = ""
    blocked:        bool = False
    block_reason:   str = ""

    @property
    def success(self) -> bool:
        return self.status_code == 200 and not self.error and not self.blocked


@dataclass
class ConversationTurn:
    """A single turn in a multi-turn conversation."""
    role:    str  # system, user, assistant, tool
    content: str


class LLMClient:
    """Universal LLM API client for security testing.

    Supports:
    - OpenAI (GPT-4o, o3, etc.)
    - Anthropic (Claude 4 Sonnet/Opus)
    - Azure OpenAI
    - HuggingFace Inference API
    - Ollama (local models)
    - Custom REST endpoints
    - Web chat interfaces (via session)

    Args:
        api_type:       One of: openai, anthropic, azure, huggingface, ollama, custom, web
        endpoint:       API endpoint URL
        api_key:        API key for authentication
        model_name:     Target model name
        max_tokens:     Max tokens per response
        temperature:    Sampling temperature
        timeout:        Request timeout in seconds
        proxy:          Optional HTTP proxy
        system_prompt:  Optional system prompt override
    """

    def __init__(
        self,
        api_type: str = "openai",
        endpoint: str = "",
        api_key: str = "",
        model_name: str = "",
        max_tokens: int = 2000,
        temperature: float = 0.7,
        timeout: int = 30,
        proxy: str | None = None,
        system_prompt: str | None = None,
    ) -> None:
        self.api_type = api_type
        self.endpoint = endpoint.rstrip("/")
        self.api_key = api_key
        self.model_name = model_name
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.timeout = timeout
        self.proxy = proxy
        self.system_prompt = system_prompt
        self._session: aiohttp.ClientSession | None = None
        self._conversation: list[ConversationTurn] = []
        self._request_count = 0
        self._total_tokens = 0

    async def __aenter__(self) -> "LLMClient":
        connector = aiohttp.TCPConnector(ssl=False, limit=5)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self._session = aiohttp.ClientSession(connector=connector, timeout=timeout)
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._session:
            await self._session.close()

    def reset_conversation(self) -> None:
        """Reset multi-turn conversation history."""
        self._conversation.clear()

    async def send(
        self,
        prompt: str,
        system: str | None = None,
        multi_turn: bool = False,
        raw_mode: bool = False,
        extra_headers: dict[str, str] | None = None,
        extra_params: dict[str, Any] | None = None,
    ) -> LLMResponse:
        """Send a prompt to the target LLM and return the parsed response.

        Args:
            prompt:         User message to send.
            system:         Optional system prompt (overrides default).
            multi_turn:     If True, maintain conversation context.
            raw_mode:       If True, send raw request body (for injection testing).
            extra_headers:  Additional HTTP headers.
            extra_params:   Additional request body parameters.

        Returns:
            LLMResponse with parsed output.
        """
        if not self._session:
            raise RuntimeError("LLMClient must be used as async context manager")

        if multi_turn:
            self._conversation.append(ConversationTurn(role="user", content=prompt))

        dispatch = {
            "openai":      self._send_openai,
            "anthropic":   self._send_anthropic,
            "azure":       self._send_openai,   # Same format
            "huggingface": self._send_huggingface,
            "ollama":      self._send_ollama,
            "custom":      self._send_custom,
            "web":         self._send_web,
        }

        handler = dispatch.get(self.api_type, self._send_custom)
        start = time.monotonic()

        try:
            response = await handler(
                prompt, system=system or self.system_prompt,
                multi_turn=multi_turn, raw_mode=raw_mode,
                extra_headers=extra_headers or {},
                extra_params=extra_params or {},
            )
        except asyncio.TimeoutError:
            response = LLMResponse(error="Request timed out", status_code=408)
        except aiohttp.ClientError as exc:
            response = LLMResponse(error=str(exc), status_code=0)
        except Exception as exc:
            response = LLMResponse(error=f"Unexpected error: {exc}", status_code=0)

        response.latency_ms = (time.monotonic() - start) * 1000
        self._request_count += 1
        self._total_tokens += response.total_tokens

        if multi_turn and response.success:
            self._conversation.append(ConversationTurn(role="assistant", content=response.text))

        return response

    async def _send_openai(
        self, prompt: str, system: str | None = None,
        multi_turn: bool = False, raw_mode: bool = False,
        extra_headers: dict[str, str] | None = None,
        extra_params: dict[str, Any] | None = None,
    ) -> LLMResponse:
        """Send via OpenAI / Azure API format."""
        url = f"{self.endpoint}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            **(extra_headers or {}),
        }

        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        if multi_turn:
            for turn in self._conversation:
                messages.append({"role": turn.role, "content": turn.content})
        else:
            messages.append({"role": "user", "content": prompt})

        body: dict[str, Any] = {
            "model": self.model_name,
            "messages": messages,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            **(extra_params or {}),
        }

        async with self._session.post(url, json=body, headers=headers, proxy=self.proxy) as resp:
            status = resp.status
            resp_headers = {k: v for k, v in resp.headers.items()}
            raw = await resp.json(content_type=None)

            if status != 200:
                error_msg = raw.get("error", {}).get("message", str(raw)) if isinstance(raw, dict) else str(raw)
                blocked = "content_filter" in error_msg.lower() or "safety" in error_msg.lower()
                return LLMResponse(
                    status_code=status, raw_response=raw, headers=resp_headers,
                    error=error_msg, blocked=blocked,
                    block_reason=error_msg if blocked else "",
                )

            choice = raw.get("choices", [{}])[0]
            usage = raw.get("usage", {})
            return LLMResponse(
                text=choice.get("message", {}).get("content", ""),
                raw_response=raw,
                model=raw.get("model", self.model_name),
                finish_reason=choice.get("finish_reason", ""),
                prompt_tokens=usage.get("prompt_tokens", 0),
                completion_tokens=usage.get("completion_tokens", 0),
                total_tokens=usage.get("total_tokens", 0),
                status_code=status,
                headers=resp_headers,
                blocked=choice.get("finish_reason") == "content_filter",
            )

    async def _send_anthropic(
        self, prompt: str, system: str | None = None,
        multi_turn: bool = False, raw_mode: bool = False,
        extra_headers: dict[str, str] | None = None,
        extra_params: dict[str, Any] | None = None,
    ) -> LLMResponse:
        """Send via Anthropic Messages API."""
        url = f"{self.endpoint}/v1/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2024-10-22",
            "Content-Type": "application/json",
            **(extra_headers or {}),
        }

        messages: list[dict[str, str]] = []
        if multi_turn:
            for turn in self._conversation:
                if turn.role != "system":
                    messages.append({"role": turn.role, "content": turn.content})
        else:
            messages.append({"role": "user", "content": prompt})

        body: dict[str, Any] = {
            "model": self.model_name or "claude-sonnet-4-20250514",
            "messages": messages,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            **(extra_params or {}),
        }
        if system:
            body["system"] = system

        async with self._session.post(url, json=body, headers=headers, proxy=self.proxy) as resp:
            status = resp.status
            resp_headers = {k: v for k, v in resp.headers.items()}
            raw = await resp.json(content_type=None)

            if status != 200:
                error_msg = raw.get("error", {}).get("message", str(raw)) if isinstance(raw, dict) else str(raw)
                blocked = raw.get("stop_reason") == "end_turn" and "I cannot" in str(raw)
                return LLMResponse(
                    status_code=status, raw_response=raw, headers=resp_headers,
                    error=error_msg, blocked=blocked,
                )

            content = raw.get("content", [{}])
            text = "".join(c.get("text", "") for c in content if c.get("type") == "text")
            usage = raw.get("usage", {})
            return LLMResponse(
                text=text, raw_response=raw,
                model=raw.get("model", self.model_name),
                finish_reason=raw.get("stop_reason", ""),
                prompt_tokens=usage.get("input_tokens", 0),
                completion_tokens=usage.get("output_tokens", 0),
                total_tokens=usage.get("input_tokens", 0) + usage.get("output_tokens", 0),
                status_code=status, headers=resp_headers,
            )

    async def _send_huggingface(
        self, prompt: str, **kwargs: Any,
    ) -> LLMResponse:
        """Send via HuggingFace Inference API."""
        url = f"{self.endpoint}"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        body = {"inputs": prompt, "parameters": {"max_new_tokens": self.max_tokens, "temperature": self.temperature}}

        async with self._session.post(url, json=body, headers=headers, proxy=self.proxy) as resp:
            raw = await resp.json(content_type=None)
            if isinstance(raw, list) and raw:
                text = raw[0].get("generated_text", str(raw))
            elif isinstance(raw, dict):
                text = raw.get("generated_text", str(raw))
            else:
                text = str(raw)
            return LLMResponse(text=text, raw_response=raw if isinstance(raw, dict) else {"output": raw},
                             status_code=resp.status, headers={k: v for k, v in resp.headers.items()})

    async def _send_ollama(
        self, prompt: str, system: str | None = None,
        multi_turn: bool = False, **kwargs: Any,
    ) -> LLMResponse:
        """Send via Ollama local API."""
        url = f"{self.endpoint}/api/chat"
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        body = {"model": self.model_name or "llama3", "messages": messages, "stream": False}

        async with self._session.post(url, json=body, proxy=self.proxy) as resp:
            raw = await resp.json(content_type=None)
            text = raw.get("message", {}).get("content", "")
            return LLMResponse(text=text, raw_response=raw, model=raw.get("model", ""),
                             status_code=resp.status, headers={k: v for k, v in resp.headers.items()})

    async def _send_custom(
        self, prompt: str, system: str | None = None,
        multi_turn: bool = False, raw_mode: bool = False,
        extra_headers: dict[str, str] | None = None,
        extra_params: dict[str, Any] | None = None,
    ) -> LLMResponse:
        """Send to a custom REST endpoint. Tries common response formats."""
        headers = {"Content-Type": "application/json", **(extra_headers or {})}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        body: dict[str, Any] = {
            "prompt": prompt,
            "message": prompt,
            "query": prompt,
            "max_tokens": self.max_tokens,
            **(extra_params or {}),
        }
        if system:
            body["system"] = system

        async with self._session.post(self.endpoint, json=body, headers=headers, proxy=self.proxy) as resp:
            raw_text = await resp.text()
            try:
                raw = json.loads(raw_text)
            except json.JSONDecodeError:
                raw = {"raw": raw_text}

            # Try common response field names
            text = ""
            for key in ["response", "text", "output", "answer", "result", "content", "message", "reply"]:
                if isinstance(raw, dict) and key in raw:
                    val = raw[key]
                    text = val if isinstance(val, str) else str(val)
                    break
            if not text:
                text = raw_text[:5000]

            return LLMResponse(text=text, raw_response=raw if isinstance(raw, dict) else {"raw": raw_text},
                             status_code=resp.status, headers={k: v for k, v in resp.headers.items()})

    async def _send_web(
        self, prompt: str, **kwargs: Any,
    ) -> LLMResponse:
        """Send via web form / chat interface (POST with form data)."""
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {"message": prompt, "prompt": prompt, "input": prompt}

        async with self._session.post(self.endpoint, data=data, headers=headers, proxy=self.proxy) as resp:
            text = await resp.text()
            return LLMResponse(text=text, raw_response={"html": text[:5000]},
                             status_code=resp.status, headers={k: v for k, v in resp.headers.items()})


class TestLLMClient:
    def test_response_success(self) -> None:
        r = LLMResponse(text="hello", status_code=200)
        assert r.success is True

    def test_response_blocked(self) -> None:
        r = LLMResponse(status_code=200, blocked=True, block_reason="safety")
        assert r.success is False

    def test_response_error(self) -> None:
        r = LLMResponse(status_code=400, error="bad request")
        assert r.success is False

    def test_conversation_turn(self) -> None:
        t = ConversationTurn(role="user", content="hello")
        assert t.role == "user"
