"""
Caching wrapper around OpenAI client (compatible with OpenRouter).

Usage:
    client = CachingLLMClient(api_key=..., base_url=...)
    response, meta = client.chat(agent="log_monitor", model="gpt-4o", messages=[...])
    print(meta.cache_hit, meta.latency_ms, meta.input_tokens)
"""

import os
import time
from dataclasses import dataclass

from openai import OpenAI

from llm_cache import CacheEntry, LLMCache, get_default_cache
from eval_tracker import EvalTracker


@dataclass
class CallMeta:
    """Token, latency, and cache metadata returned from ``CachingLLMClient.chat``."""

    input_tokens: int
    output_tokens: int
    latency_ms: float
    cache_hit: bool


class CachingLLMClient:
    """
    Wraps OpenAI (or OpenRouter) with an in-memory cache.
    Pass cache=None to disable caching entirely (useful for uncached eval runs).
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        cache: LLMCache | None = None,
        tracker: EvalTracker | None = None,
        run_label: str = "",
    ):
        """Configure OpenAI client, optional cache, and eval tracker."""
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self._base_url = base_url
        self._client: OpenAI | None = None
        self._cache = cache  # None → caching disabled for this client
        self._tracker = tracker
        self.run_label = run_label

    def _openai_client(self) -> OpenAI:
        """Create the OpenAI client lazily so the app can start without an API key."""
        if self._client is None:
            self._client = OpenAI(
                api_key=self._api_key,
                base_url=self._base_url,
            )
        return self._client

    def chat(
        self,
        agent: str,
        model: str,
        messages: list[dict],
        temperature: float = 0.0,
        max_tokens: int | None = None,
    ) -> tuple[dict, CallMeta]:
        """
        Send a chat request, returning (response_dict, CallMeta).
        If the cache is enabled and a match exists, returns the cached response
        with near-zero latency.
        """
        # Try cache first
        if self._cache is not None:
            entry = self._cache.get(model, messages)
            if entry is not None:
                meta = CallMeta(
                    input_tokens=entry.input_tokens,
                    output_tokens=entry.output_tokens,
                    latency_ms=1.0,   # negligible lookup time reported as 1 ms
                    cache_hit=True,
                )
                if self._tracker:
                    self._tracker.record(
                        agent=agent,
                        model=model,
                        input_tokens=entry.input_tokens,
                        output_tokens=entry.output_tokens,
                        latency_ms=meta.latency_ms,
                        cache_hit=True,
                        run_label=self.run_label,
                    )
                return entry.response, meta

        # Cache miss → real API call
        kwargs: dict = {"model": model, "messages": messages, "temperature": temperature}
        if max_tokens:
            kwargs["max_tokens"] = max_tokens

        t0 = time.perf_counter()
        raw = self._openai_client().chat.completions.create(**kwargs)
        latency_ms = (time.perf_counter() - t0) * 1000

        response = raw.model_dump()
        in_tok = raw.usage.prompt_tokens
        out_tok = raw.usage.completion_tokens

        meta = CallMeta(
            input_tokens=in_tok,
            output_tokens=out_tok,
            latency_ms=latency_ms,
            cache_hit=False,
        )

        # Store in cache
        if self._cache is not None:
            self._cache.set(
                model, messages,
                CacheEntry(
                    response=response,
                    input_tokens=in_tok,
                    output_tokens=out_tok,
                    latency_ms=latency_ms,
                ),
            )

        if self._tracker:
            self._tracker.record(
                agent=agent,
                model=model,
                input_tokens=in_tok,
                output_tokens=out_tok,
                latency_ms=latency_ms,
                cache_hit=False,
                run_label=self.run_label,
            )

        return response, meta

    def extract_text(self, response: dict) -> str:
        """Pull the assistant text out of a cached or live response dict."""
        try:
            return response["choices"][0]["message"]["content"]
        except (KeyError, IndexError):
            return ""
