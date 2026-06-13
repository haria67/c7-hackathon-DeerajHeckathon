"""Tests for eval API endpoints."""

from unittest.mock import patch

from fastapi.testclient import TestClient

from main import app
from session_evals import begin_session, finish_session, record_agent_latency, record_llm_call

client = TestClient(app)


def test_evals_endpoint_returns_run_after_analysis():
    begin_session("eval-test-1", "synthetic", line_count=10)
    record_agent_latency("eval-test-1", "log_monitor", 5.0)
    record_llm_call(
        "eval-test-1",
        "incident_response",
        "openai/gpt-4o",
        input_tokens=100,
        output_tokens=50,
        latency_ms=1.0,
        cache_hit=True,
    )
    finish_session("eval-test-1")

    all_evals = client.get("/evals")
    assert all_evals.status_code == 200
    body = all_evals.json()
    assert body["overall"]["total_runs"] >= 1

    detail = client.get("/evals/eval-test-1")
    assert detail.status_code == 200
    data = detail.json()
    assert data["log_source"] == "synthetic"
    assert len(data["agents"]) == 6
    ir = next(a for a in data["agents"] if a["agent"] == "incident_response")
    assert ir["calls"][0]["cache_hit"] is True
    assert ir["cost_saved_usd"] > 0


def test_evals_session_not_found():
    response = client.get("/evals/does-not-exist")
    assert response.status_code == 404
