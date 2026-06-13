"""LangGraph orchestration for the six-agent security analysis pipeline."""

from langgraph.graph import END, StateGraph
import time

from agents.incident_response import run_incident_response
from agents.log_monitor import run_log_monitor
from agents.policy_checker import run_policy_checker
from agents.slack_notifier import run_slack_notifier
from agents.threat_intel import run_threat_intel
from agents.vuln_scanner import run_vuln_scanner
from session_events import emit_sync
from session_evals import record_agent_error, record_agent_latency
from state import SecurityState, make_initial_state

AGENTS = [
    ("log_monitor", run_log_monitor),
    ("threat_intel", run_threat_intel),
    ("vuln_scanner", run_vuln_scanner),
    ("incident_response", run_incident_response),
    ("policy_checker", run_policy_checker),
    ("slack_notifier", run_slack_notifier),
]


def _wrap(agent_name: str, fn):
    """Wrap an agent node with SSE events, latency tracking, and error handling.

    Args:
        agent_name: SSE identifier emitted to the dashboard.
        fn: Agent function accepting and returning ``SecurityState``.

    Returns:
        LangGraph-compatible node callable.
    """

    def node(state: SecurityState) -> SecurityState:
        session_id = state["session_id"]
        emit_sync(session_id, agent_name, "running")
        t0 = time.perf_counter()
        try:
            result = fn(state)
            latency_ms = (time.perf_counter() - t0) * 1000
            record_agent_latency(session_id, agent_name, latency_ms)
            emit_sync(session_id, agent_name, "done")
            return result
        except Exception:
            record_agent_error(session_id, agent_name)
            emit_sync(session_id, agent_name, "error")
            raise

    return node


def build_graph():
    """Compile the linear LangGraph pipeline for all security agents.

    Returns:
        Compiled LangGraph application invokable with ``SecurityState``.
    """
    graph = StateGraph(SecurityState)
    for name, fn in AGENTS:
        graph.add_node(name, _wrap(name, fn))
    graph.set_entry_point("log_monitor")
    graph.add_edge("log_monitor", "threat_intel")
    graph.add_edge("threat_intel", "vuln_scanner")
    graph.add_edge("vuln_scanner", "incident_response")
    graph.add_edge("incident_response", "policy_checker")
    graph.add_edge("policy_checker", "slack_notifier")
    graph.add_edge("slack_notifier", END)
    return graph.compile()


def run_analysis(
    logs: list[str],
    log_source: str,
    session_id: str,
    github_repo: str = "",
    slack_webhook_url: str = "",
) -> SecurityState:
    """Execute the full agent pipeline synchronously.

    Args:
        logs: Raw log lines (empty for GitHub-only scans).
        log_source: Source label stored in state and session metadata.
        session_id: UUID for SSE and eval tracking.
        github_repo: Optional ``owner/repo`` to scan via the Vuln Scanner.
        slack_webhook_url: Optional Slack incoming webhook for alerts.

    Returns:
        Final ``SecurityState`` after all agents complete.
    """
    app = build_graph()
    initial = make_initial_state(
        raw_logs=logs,
        log_source=log_source,
        session_id=session_id,
        github_repo=github_repo,
        slack_webhook_url=slack_webhook_url,
    )
    return app.invoke(initial)
