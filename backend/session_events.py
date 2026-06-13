"""Per-session SSE event queues for live agent progress streaming."""

import queue
from datetime import datetime, timezone

_queues: dict[str, queue.Queue] = {}
_status: dict[str, dict[str, str]] = {}


def create_session(session_id: str) -> queue.Queue:
    """Initialize SSE queue and agent status map for a new analysis session.

    Args:
        session_id: Unique session identifier.

    Returns:
        Thread-safe queue that SSE consumers read from.
    """
    q: queue.Queue = queue.Queue()
    _queues[session_id] = q
    _status[session_id] = {
        "log_monitor": "pending",
        "threat_intel": "pending",
        "vuln_scanner": "pending",
        "incident_response": "pending",
        "policy_checker": "pending",
        "slack_notifier": "pending",
    }
    return q


def get_queue(session_id: str) -> queue.Queue | None:
    """Return the SSE queue for a session, if it exists."""
    return _queues.get(session_id)


def get_agent_status(session_id: str) -> dict[str, str]:
    """Return the latest status string for each agent in a session."""
    return _status.get(session_id, {})


def emit_sync(
    session_id: str, agent: str, status: str, findings: list | None = None
) -> None:
    """Publish an agent status event to the session SSE queue.

    Args:
        session_id: Target session.
        agent: Agent name or ``pipeline`` for terminal events.
        status: One of ``running``, ``done``, or ``error``.
        findings: Optional payload attached to the event (usually empty).
    """
    q = _queues.get(session_id)
    if not q:
        return
    if agent in _status.get(session_id, {}):
        _status[session_id][agent] = status
    q.put(
        {
            "agent": agent,
            "status": status,
            "findings": findings or [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


def close_session(session_id: str) -> None:
    """Signal SSE consumers to stop by enqueueing a ``None`` sentinel."""
    q = _queues.get(session_id)
    if q:
        q.put(None)
