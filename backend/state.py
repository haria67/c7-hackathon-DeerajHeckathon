"""Shared pipeline state definitions for the LangGraph security agents."""

from typing import TypedDict


class SecurityState(TypedDict):
    """Accumulated inputs and outputs for a single analysis session.

    Each agent reads from and returns an updated ``SecurityState`` as it runs
    through the LangGraph pipeline.
    """

    raw_logs: list[str]
    log_source: str
    session_id: str
    anomalies: list[dict]
    severity_map: dict[str, str]
    cve_matches: list[dict]
    threat_score: int
    vulnerabilities: list[dict]
    risk_level: str
    action_plan: list[str]
    runbook_md: str
    compliance_gaps: list[dict]
    compliance_score: int
    github_repo: str
    repo_languages: dict[str, float]
    primary_language: str
    files_scanned: int
    code_findings: list[dict]
    scan_error: str
    slack_webhook_url: str
    slack_sent: bool
    slack_error: str
    slack_skipped: bool


def make_initial_state(
    raw_logs: list[str],
    log_source: str,
    session_id: str,
    github_repo: str = "",
    slack_webhook_url: str = "",
) -> SecurityState:
    """Create a fresh ``SecurityState`` with empty agent output fields.

    Args:
        raw_logs: Log lines to analyze (may be empty for code-only GitHub scans).
        log_source: One of ``synthetic``, ``system``, ``upload``, or ``github``.
        session_id: UUID for this analysis run.
        github_repo: Optional ``owner/repo`` when scanning a GitHub repository.
        slack_webhook_url: Optional Slack incoming webhook for incident alerts.

    Returns:
        Initial state ready for the Log Monitor entry point.
    """
    return SecurityState(
        raw_logs=raw_logs,
        log_source=log_source,
        session_id=session_id,
        anomalies=[],
        severity_map={},
        cve_matches=[],
        threat_score=0,
        vulnerabilities=[],
        risk_level="low",
        action_plan=[],
        runbook_md="",
        compliance_gaps=[],
        compliance_score=0,
        github_repo=github_repo,
        repo_languages={},
        primary_language="",
        files_scanned=0,
        code_findings=[],
        scan_error="",
        slack_webhook_url=slack_webhook_url,
        slack_sent=False,
        slack_error="",
        slack_skipped=True,
    )
