"""Slack Notifier agent — posts incident summary and resolution to user webhook."""

from state import SecurityState
from tools.slack_notifier import build_incident_message, is_valid_slack_webhook, send_slack_message


def run_slack_notifier(state: SecurityState) -> SecurityState:
    """Send findings and action plan to the user's Slack webhook when configured.

    Skips silently when no webhook URL is provided. Invalid URLs or delivery
    failures are recorded in ``slack_error`` without failing the pipeline.

    Args:
        state: Pipeline state after Policy Checker.

    Returns:
        Updated state with ``slack_sent``, ``slack_error``, and ``slack_skipped``.
    """
    webhook = (state.get("slack_webhook_url") or "").strip()

    if not webhook:
        return {
            **state,
            "slack_sent": False,
            "slack_error": "",
            "slack_skipped": True,
        }

    if not is_valid_slack_webhook(webhook):
        return {
            **state,
            "slack_sent": False,
            "slack_error": "Invalid Slack webhook URL format",
            "slack_skipped": False,
        }

    payload = build_incident_message(state)
    result = send_slack_message(webhook, payload)

    if result.get("ok"):
        return {
            **state,
            "slack_sent": True,
            "slack_error": "",
            "slack_skipped": False,
        }

    return {
        **state,
        "slack_sent": False,
        "slack_error": result.get("error", "Slack delivery failed"),
        "slack_skipped": False,
    }
