"""Tests for Slack webhook formatting and delivery."""

from unittest.mock import patch

from agents.slack_notifier import run_slack_notifier
from state import make_initial_state
from tools.slack_notifier import (
    build_incident_message,
    is_valid_slack_webhook,
    send_slack_message,
)

WEBHOOK = "https://hooks.slack.com/services/T00/B00/XXXXXXXX"


def test_is_valid_slack_webhook():
    assert is_valid_slack_webhook(WEBHOOK)
    assert not is_valid_slack_webhook("https://example.com/hook")
    assert not is_valid_slack_webhook("")


def test_build_incident_message_includes_incidents_and_plan():
    state = make_initial_state([], "synthetic", "sess-1")
    state["anomalies"] = [
        {
            "type": "brute_force",
            "title": "SSH Brute Force Attack",
            "severity": "CRITICAL",
            "source_ip": "1.2.3.4",
            "recommendation": "Block the IP",
        }
    ]
    state["action_plan"] = ["Block IP at firewall", "Enable MFA"]
    state["threat_score"] = 72
    state["risk_level"] = "high"

    payload = build_incident_message(state)
    text_blob = str(payload)

    assert "SSH Brute Force Attack" in text_blob
    assert "Block IP at firewall" in text_blob
    assert "72/100" in text_blob
    assert payload["blocks"]


def test_run_slack_notifier_skips_without_webhook():
    state = make_initial_state([], "synthetic", "sess-2")
    result = run_slack_notifier(state)
    assert result["slack_skipped"] is True
    assert result["slack_sent"] is False


@patch("tools.slack_notifier.httpx.post")
def test_send_slack_message_success(mock_post):
    mock_post.return_value.status_code = 200
    mock_post.return_value.text = "ok"
    result = send_slack_message(WEBHOOK, {"text": "hello"})
    assert result["ok"] is True


@patch("agents.slack_notifier.send_slack_message", return_value={"ok": True})
def test_run_slack_notifier_sends_when_webhook_set(mock_send):
    state = make_initial_state([], "synthetic", "sess-3", slack_webhook_url=WEBHOOK)
    state["action_plan"] = ["Step one"]
    result = run_slack_notifier(state)
    assert result["slack_sent"] is True
    assert result["slack_skipped"] is False
    mock_send.assert_called_once()
