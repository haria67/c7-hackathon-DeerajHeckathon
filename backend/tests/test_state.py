"""Tests for ``SecurityState`` initialization."""

from state import make_initial_state


def test_make_initial_state_sets_required_fields():
    state = make_initial_state(
        raw_logs=["log line 1"], log_source="synthetic", session_id="abc123"
    )
    assert state["raw_logs"] == ["log line 1"]
    assert state["log_source"] == "synthetic"
    assert state["session_id"] == "abc123"
    assert state["anomalies"] == []
    assert state["cve_matches"] == []
    assert state["vulnerabilities"] == []
    assert state["action_plan"] == []
    assert state["compliance_gaps"] == []
    assert state["threat_score"] == 0
    assert state["compliance_score"] == 0
    assert state["github_repo"] == ""
    assert state["code_findings"] == []
    assert state["slack_webhook_url"] == ""
    assert state["slack_skipped"] is True
