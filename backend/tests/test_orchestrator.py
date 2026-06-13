"""Tests for the LangGraph orchestrator end-to-end pipeline."""

import json
from unittest.mock import patch

from orchestrator import run_analysis

MOCK_PLAN = "1. Block IP\n2. Rotate SSH keys\n3. Enable 2FA\n4. Update nginx\n5. Add headers"


def test_run_analysis_populates_all_state_fields():
    with open("data/synthetic_logs.json") as f:
        logs = json.load(f)

    with patch("agents.threat_intel.search_nvd_cve", return_value=[]):
        with patch(
            "agents.threat_intel.check_ip_reputation",
            return_value={"score": 0, "flagged": False},
        ):
            with patch("agents.incident_response.call_openai", return_value=MOCK_PLAN):
                state = run_analysis(
                    logs=logs, log_source="synthetic", session_id="orch-test"
                )

    assert len(state["anomalies"]) > 0
    assert len(state["compliance_gaps"]) > 0
    assert len(state["action_plan"]) > 0
    assert 0 <= state["compliance_score"] <= 100
    assert state["risk_level"] in ("low", "medium", "high", "critical")
    assert state["session_id"] == "orch-test"
    assert state["slack_skipped"] is True
