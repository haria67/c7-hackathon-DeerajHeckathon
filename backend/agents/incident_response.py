"""Incident Response agent — LLM action plans with deterministic fallback."""

import os
import time

from llm_cache import get_default_cache
from llm_client import CachingLLMClient
from session_evals import record_llm_call
from state import SecurityState

_llm: CachingLLMClient | None = None


def _get_llm() -> CachingLLMClient:
    """Return a shared LLM client, created on first use."""
    global _llm
    if _llm is None:
        _llm = CachingLLMClient(
            api_key=os.getenv("OPENROUTER_API_KEY"),
            base_url="https://openrouter.ai/api/v1",
            cache=get_default_cache(),
        )
    return _llm


def call_openai(prompt: str, session_id: str | None = None) -> str:
    """Send the incident prompt to OpenRouter via the caching LLM client.

    Args:
        prompt: User message built from pipeline findings.
        session_id: Optional session id for eval metric recording.

    Returns:
        Assistant response text from the LLM.
    """
    messages = [
        {
            "role": "system",
            "content": "You are a senior security incident responder. Be concise and actionable.",
        },
        {"role": "user", "content": prompt},
    ]
    response, meta = _get_llm().chat(
        agent="incident_response",
        model="openai/gpt-4o",
        messages=messages,
        temperature=0.2,
    )
    if session_id:
        record_llm_call(
            session_id=session_id,
            agent="incident_response",
            model="openai/gpt-4o",
            input_tokens=meta.input_tokens,
            output_tokens=meta.output_tokens,
            latency_ms=meta.latency_ms,
            cache_hit=meta.cache_hit,
        )
    return _get_llm().extract_text(response)


def build_prompt(state: SecurityState) -> str:
    """Format pipeline findings into a structured LLM prompt.

    Args:
        state: Full pipeline state with anomalies, CVEs, vulns, and code findings.

    Returns:
        Multi-section prompt string for the incident response LLM.
    """
    anomaly_lines = "\n".join(
        f"- {a['type']} from {a.get('source_ip', '?')} ({a['severity']})"
        for a in state["anomalies"]
    )
    cve_lines = "\n".join(
        f"- {c['id']} CVSS:{c['cvss_score']} — {c['description'][:80]}"
        for c in state["cve_matches"]
    )
    vuln_lines = "\n".join(
        f"- {v.get('category', '?')} {v.get('name', '?')} ({v['severity']})"
        for v in state["vulnerabilities"]
    )
    code_lines = "\n".join(
        f"- {f.get('name')} in {f.get('file')}:{f.get('line')} [{f.get('language')}]"
        for f in state.get("code_findings", [])[:10]
    )
    lang_lines = ", ".join(
        f"{lang} ({pct}%)" for lang, pct in state.get("repo_languages", {}).items()
    )
    return f"""Security incident analysis:

ANOMALIES DETECTED:
{anomaly_lines or 'None'}

CVE MATCHES:
{cve_lines or 'None'}

VULNERABILITIES:
{vuln_lines or 'None'}

GITHUB REPO: {state.get('github_repo') or 'None'}
PRIMARY LANGUAGE: {state.get('primary_language') or 'N/A'}
LANGUAGES: {lang_lines or 'N/A'}
FILES SCANNED: {state.get('files_scanned', 0)}

CODE FINDINGS:
{code_lines or 'None'}

THREAT SCORE: {state['threat_score']}/100

Provide a numbered action plan (5-7 steps) to remediate these issues immediately. Be specific and actionable."""


def _fallback_action_plan(state: SecurityState) -> list[str]:
    """Deterministic remediation steps when LLM is unavailable or returns empty."""
    steps: list[str] = []
    seen: set[str] = set()

    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    anomalies = sorted(
        state.get("anomalies", []),
        key=lambda a: severity_rank.get(a.get("severity", "LOW"), 9),
    )
    for anomaly in anomalies:
        key = f"anomaly:{anomaly.get('type')}:{anomaly.get('source_ip')}"
        if key in seen:
            continue
        seen.add(key)
        title = anomaly.get("title") or anomaly.get("type", "Threat").replace("_", " ")
        source = anomaly.get("source_ip", "unknown")
        detail = anomaly.get("detail") or ""
        context = f" from {source}" if source != "unknown" else ""
        if anomaly.get("attempt_count"):
            context += f" ({anomaly['attempt_count']} attempts)"
        if detail:
            context += f" — {detail}"
        rec = anomaly.get(
            "recommendation",
            "Investigate and contain the incident following your runbook",
        )
        steps.append(f"Respond to {title}{context}: {rec}")
        if len(steps) >= 7:
            break

    for finding in state.get("code_findings", []):
        key = f"{finding.get('file')}:{finding.get('name')}"
        if key in seen:
            continue
        seen.add(key)
        steps.append(
            f"Fix {finding['name']} in {finding['file']}:{finding['line']} — "
            f"{finding['recommendation']}"
        )
        if len(steps) >= 7:
            break

    if len(steps) < 7:
        for vuln in state.get("vulnerabilities", []):
            if vuln.get("source") == "github_code_scan":
                continue
            name = vuln.get("name") or vuln.get("header") or vuln.get("category", "Issue")
            key = f"vuln:{name}:{vuln.get('linked_anomaly', '')}"
            if key in seen:
                continue
            seen.add(key)
            rec = vuln.get("recommendation", "Review and remediate manually")
            loc = f" ({vuln['file']}:{vuln['line']})" if vuln.get("file") else ""
            steps.append(f"Address {name}{loc}: {rec}")
            if len(steps) >= 7:
                break

    if len(steps) < 7:
        for cve in state.get("cve_matches", [])[:3]:
            key = f"cve:{cve.get('id')}"
            if key in seen:
                continue
            seen.add(key)
            steps.append(
                f"Patch or mitigate {cve.get('id')} (CVSS {cve.get('cvss_score', '?')}): "
                f"{cve.get('description', 'Apply vendor security updates')[:120]}"
            )
            if len(steps) >= 7:
                break

    if not steps and state.get("github_repo"):
        steps.append(
            f"Review all {state.get('files_scanned', 0)} scanned files in "
            f"{state['github_repo']} against AWS and Terraform security best practices."
        )

    return steps or ["No automated remediation steps generated — review scan output manually."]


def run_incident_response(state: SecurityState) -> SecurityState:
    """Generate an action plan and markdown runbook from all pipeline findings.

    Uses the LLM when available; falls back to deterministic steps otherwise.

    Args:
        state: Pipeline state after Threat Intel and Vuln Scanner.

    Returns:
        Updated state with ``action_plan`` and ``runbook_md``.
    """
    prompt = build_prompt(state)
    action_plan: list[str] = []
    try:
        raw = call_openai(prompt, session_id=state["session_id"])
        lines = [
            l.strip()
            for l in raw.strip().split("\n")
            if l.strip() and l.strip()[0].isdigit()
        ]
        action_plan = [l.split(". ", 1)[-1] if ". " in l else l for l in lines]
    except Exception:
        action_plan = []

    if not action_plan:
        action_plan = _fallback_action_plan(state)
    runbook_md = (
        "# Incident Response Runbook\n\n## Action Plan\n\n"
        + "\n".join(f"{i + 1}. {step}" for i, step in enumerate(action_plan))
    )
    return {**state, "action_plan": action_plan, "runbook_md": runbook_md}
