"""
Per-session eval metrics for dashboard analysis runs.

Tracks latency, tokens, cost, and cache behavior for each agent in a pipeline run.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from eval_tracker import compute_cost
from llm_cache import get_default_cache

AGENT_LABELS = {
    "log_monitor": "Log Monitor",
    "threat_intel": "Threat Intel",
    "vuln_scanner": "Vuln Scanner",
    "incident_response": "Incident Response",
    "policy_checker": "Policy Checker",
    "slack_notifier": "Slack Notifier",
}

AGENT_TYPES = {
    "log_monitor": "deterministic",
    "threat_intel": "external_api",
    "vuln_scanner": "deterministic",
    "incident_response": "llm",
    "policy_checker": "deterministic",
    "slack_notifier": "external_api",
}

AGENT_CACHE_INFO = {
    "log_monitor": {
        "strategy": "none",
        "reason": "Regex-based log parsing — no LLM calls",
    },
    "threat_intel": {
        "strategy": "none",
        "reason": "NVD + AbuseIPDB HTTP calls (future: TTL response cache)",
    },
    "vuln_scanner": {
        "strategy": "none",
        "reason": "OWASP pattern matching — no LLM calls",
    },
    "incident_response": {
        "strategy": "lru_memory",
        "reason": "In-memory LRU cache keyed on SHA-256(model + messages)",
    },
    "policy_checker": {
        "strategy": "none",
        "reason": "NIST/SOC2 rule mapping — no LLM calls",
    },
    "slack_notifier": {
        "strategy": "none",
        "reason": "Slack incoming webhook POST when user provides URL",
    },
}


@dataclass
class LlmCallRecord:
    """Single LLM invocation metrics stored for one agent in a session."""

    model: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    cost_if_uncached_usd: float
    latency_ms: float
    cache_hit: bool
    cache_strategy: str = "lru_memory"


@dataclass
class AgentEvalRecord:
    """Aggregated eval data for one pipeline agent in a session."""

    agent: str
    latency_ms: float = 0.0
    llm_calls: list[LlmCallRecord] = field(default_factory=list)
    error: bool = False


@dataclass
class SessionEvalRecord:
    """Top-level eval record for one analysis run."""

    session_id: str
    log_source: str
    line_count: int = 0
    used_fallback: bool = False
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    completed_at: str | None = None
    agents: dict[str, AgentEvalRecord] = field(default_factory=dict)

    def agent_record(self, agent: str) -> AgentEvalRecord:
        """Get or create the eval record for a named agent."""
        if agent not in self.agents:
            self.agents[agent] = AgentEvalRecord(agent=agent)
        return self.agents[agent]


_store: dict[str, SessionEvalRecord] = {}
_run_order: list[str] = []


def begin_session(
    session_id: str,
    log_source: str,
    line_count: int = 0,
    used_fallback: bool = False,
) -> SessionEvalRecord:
    """Register a new session for eval tracking."""
    record = SessionEvalRecord(
        session_id=session_id,
        log_source=log_source,
        line_count=line_count,
        used_fallback=used_fallback,
    )
    _store[session_id] = record
    _run_order.append(session_id)
    return record


def get_session(session_id: str) -> SessionEvalRecord | None:
    """Return the eval record for a session, if registered."""
    return _store.get(session_id)


def record_agent_latency(session_id: str, agent: str, latency_ms: float) -> None:
    """Store wall-clock latency for an agent node execution."""
    rec = _store.get(session_id)
    if not rec:
        return
    entry = rec.agent_record(agent)
    entry.latency_ms = latency_ms


def record_agent_error(session_id: str, agent: str) -> None:
    """Mark an agent as failed for eval reporting."""
    rec = _store.get(session_id)
    if not rec:
        return
    entry = rec.agent_record(agent)
    entry.error = True


def record_llm_call(
    session_id: str,
    agent: str,
    model: str,
    input_tokens: int,
    output_tokens: int,
    latency_ms: float,
    cache_hit: bool,
) -> None:
    """Append LLM call metrics to the session eval record."""
    rec = _store.get(session_id)
    if not rec:
        return
    uncached_cost = compute_cost(_normalize_model(model), input_tokens, output_tokens)
    cost = 0.0 if cache_hit else uncached_cost
    call = LlmCallRecord(
        model=model,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cost_usd=cost,
        cost_if_uncached_usd=uncached_cost,
        latency_ms=latency_ms,
        cache_hit=cache_hit,
    )
    rec.agent_record(agent).llm_calls.append(call)


def finish_session(session_id: str) -> None:
    """Set completion timestamp on a session eval record."""
    rec = _store.get(session_id)
    if rec:
        rec.completed_at = datetime.now(timezone.utc).isoformat()


def _normalize_model(model: str) -> str:
    """Strip OpenRouter provider prefix for pricing lookup."""
    if model.startswith("openai/"):
        return model.split("/", 1)[1]
    return model


def _agent_to_dict(agent: str, entry: AgentEvalRecord) -> dict[str, Any]:
    """Serialize one agent's eval record for the API response."""
    agent_type = AGENT_TYPES.get(agent, "deterministic")
    cache_info = dict(AGENT_CACHE_INFO.get(agent, {"strategy": "none", "reason": ""}))

    total_in = sum(c.input_tokens for c in entry.llm_calls)
    total_out = sum(c.output_tokens for c in entry.llm_calls)
    total_cost = sum(c.cost_usd for c in entry.llm_calls)
    uncached_cost = sum(c.cost_if_uncached_usd for c in entry.llm_calls)
    hits = sum(1 for c in entry.llm_calls if c.cache_hit)
    misses = len(entry.llm_calls) - hits

    if entry.llm_calls:
        last = entry.llm_calls[-1]
        cache_info["hit"] = last.cache_hit
        cache_info["hits"] = hits
        cache_info["misses"] = misses
        if entry.llm_calls:
            cache_info["hit_rate"] = hits / len(entry.llm_calls)

    return {
        "agent": agent,
        "label": AGENT_LABELS.get(agent, agent),
        "type": agent_type,
        "latency_ms": round(entry.latency_ms, 1),
        "error": entry.error,
        "cache": cache_info,
        "tokens": {"input": total_in, "output": total_out, "total": total_in + total_out},
        "cost_usd": round(total_cost, 6),
        "cost_if_uncached_usd": round(uncached_cost, 6),
        "cost_saved_usd": round(uncached_cost - total_cost, 6),
        "model": entry.llm_calls[-1].model if entry.llm_calls else None,
        "calls": [
            {
                "model": c.model,
                "input_tokens": c.input_tokens,
                "output_tokens": c.output_tokens,
                "total_tokens": c.input_tokens + c.output_tokens,
                "cost_usd": round(c.cost_usd, 6),
                "cost_if_uncached_usd": round(c.cost_if_uncached_usd, 6),
                "cost_saved_usd": round(c.cost_if_uncached_usd - c.cost_usd, 6),
                "latency_ms": round(c.latency_ms, 1),
                "cache_hit": c.cache_hit,
                "cache_strategy": c.cache_strategy,
            }
            for c in entry.llm_calls
        ],
    }


def _build_summary(record: SessionEvalRecord) -> dict[str, Any]:
    """Compute session-level token, cost, latency, and cache summaries."""
    agents_data = []
    for agent in AGENT_TYPES:
        if agent in record.agents:
            agents_data.append(_agent_to_dict(agent, record.agents[agent]))

    total_in = sum(a["tokens"]["input"] for a in agents_data)
    total_out = sum(a["tokens"]["output"] for a in agents_data)
    total_cost = sum(a["cost_usd"] for a in agents_data)
    uncached_cost = sum(a["cost_if_uncached_usd"] for a in agents_data)
    total_latency = sum(a["latency_ms"] for a in agents_data)
    llm_hits = sum(
        1 for a in agents_data for c in a["calls"] if c["cache_hit"]
    )
    llm_misses = sum(
        1 for a in agents_data for c in a["calls"] if not c["cache_hit"]
    )
    llm_calls = llm_hits + llm_misses

    global_cache = get_default_cache()
    cache_layers = [
        {
            "name": "In-Memory LRU (LLM)",
            "type": "lru_memory",
            "scope": "incident_response agent",
            "hits": llm_hits,
            "misses": llm_misses,
            "hit_rate": llm_hits / llm_calls if llm_calls else 0.0,
            "global_hits": global_cache.hits,
            "global_misses": global_cache.misses,
            "global_hit_rate": global_cache.hit_rate,
            "global_size": global_cache.size,
        },
        {
            "name": "Deterministic (no LLM)",
            "type": "deterministic",
            "scope": "log_monitor, vuln_scanner, policy_checker",
            "agents": 3,
            "cost_usd": 0.0,
        },
        {
            "name": "External HTTP APIs",
            "type": "external_api",
            "scope": "threat_intel (NVD, AbuseIPDB)",
            "note": "No LLM tokens; HTTP response cache planned",
        },
    ]

    return {
        "total_cost_usd": round(total_cost, 6),
        "cost_if_uncached_usd": round(uncached_cost, 6),
        "cost_saved_usd": round(uncached_cost - total_cost, 6),
        "total_input_tokens": total_in,
        "total_output_tokens": total_out,
        "total_tokens": total_in + total_out,
        "total_latency_ms": round(total_latency, 1),
        "llm_cache_hits": llm_hits,
        "llm_cache_misses": llm_misses,
        "llm_cache_hit_rate": llm_hits / llm_calls if llm_calls else 0.0,
        "cache_layers": cache_layers,
    }


def session_to_dict(session_id: str) -> dict[str, Any] | None:
    """Return full eval payload for a session, or ``None`` if unknown."""
    record = _store.get(session_id)
    if not record:
        return None

    agents_data = []
    for agent in AGENT_TYPES:
        if agent in record.agents:
            agents_data.append(_agent_to_dict(agent, record.agents[agent]))
        else:
            agents_data.append(
                {
                    "agent": agent,
                    "label": AGENT_LABELS.get(agent, agent),
                    "type": AGENT_TYPES.get(agent, "deterministic"),
                    "latency_ms": 0,
                    "error": False,
                    "cache": AGENT_CACHE_INFO.get(agent, {}),
                    "tokens": {"input": 0, "output": 0, "total": 0},
                    "cost_usd": 0,
                    "cost_if_uncached_usd": 0,
                    "cost_saved_usd": 0,
                    "model": None,
                    "calls": [],
                }
            )

    summary = _build_summary(record)
    return {
        "session_id": record.session_id,
        "started_at": record.started_at,
        "completed_at": record.completed_at,
        "log_source": record.log_source,
        "line_count": record.line_count,
        "used_fallback": record.used_fallback,
        "summary": summary,
        "agents": agents_data,
    }


def list_all_evals() -> dict[str, Any]:
    """Return all session evals with an overall aggregate summary."""
    runs = []
    total_cost = 0.0
    total_saved = 0.0
    total_tokens = 0
    total_hits = 0
    total_misses = 0

    for session_id in reversed(_run_order):
        detail = session_to_dict(session_id)
        if not detail:
            continue
        s = detail["summary"]
        runs.append(
            {
                "session_id": session_id,
                "started_at": detail["started_at"],
                "completed_at": detail["completed_at"],
                "log_source": detail["log_source"],
                "line_count": detail["line_count"],
                "summary": s,
            }
        )
        total_cost += s["total_cost_usd"]
        total_saved += s["cost_saved_usd"]
        total_tokens += s["total_tokens"]
        total_hits += s["llm_cache_hits"]
        total_misses += s["llm_cache_misses"]

    llm_total = total_hits + total_misses
    global_cache = get_default_cache()

    return {
        "overall": {
            "total_runs": len(runs),
            "total_cost_usd": round(total_cost, 6),
            "total_cost_saved_usd": round(total_saved, 6),
            "total_tokens": total_tokens,
            "llm_cache_hits": total_hits,
            "llm_cache_misses": total_misses,
            "llm_cache_hit_rate": total_hits / llm_total if llm_total else 0.0,
            "global_cache_hit_rate": global_cache.hit_rate,
            "global_cache_size": global_cache.size,
        },
        "runs": runs,
    }
