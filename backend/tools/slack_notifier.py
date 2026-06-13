"""Slack incoming webhook client for incident notifications."""

import re

import httpx

SLACK_WEBHOOK_RE = re.compile(
    r"^https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+$"
)


def is_valid_slack_webhook(url: str) -> bool:
    """Return True when ``url`` looks like a Slack incoming webhook."""
    return bool(SLACK_WEBHOOK_RE.match(url.strip()))


def build_incident_message(state: dict) -> dict:
    """Build a Slack Block Kit payload summarizing incidents and remediation.

    Args:
        state: Final pipeline ``SecurityState`` dict.

    Returns:
        JSON body suitable for a Slack incoming webhook POST.
    """
    session_id = state.get("session_id", "unknown")
    threat_score = state.get("threat_score", 0)
    risk_level = str(state.get("risk_level", "low")).upper()
    compliance_score = state.get("compliance_score", 0)
    log_source = state.get("log_source", "unknown")
    github_repo = state.get("github_repo", "")

    header = (
        f"🛡️ CyberSentinel incident report — {log_source}"
        if not github_repo
        else f"🛡️ CyberSentinel report — {github_repo}"
    )

    summary_lines = [
        f"*Threat score:* {threat_score}/100",
        f"*Risk level:* {risk_level}",
        f"*Compliance score:* {compliance_score}%",
        f"*Session:* `{session_id}`",
    ]

    blocks: list[dict] = [
        {"type": "header", "text": {"type": "plain_text", "text": header[:150], "emoji": True}},
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": "\n".join(summary_lines)},
        },
    ]

    anomalies = state.get("anomalies", [])
    if anomalies:
        lines = []
        for a in anomalies[:8]:
            title = a.get("title") or a.get("type", "Incident").replace("_", " ").title()
            sev = a.get("severity", "?")
            ip = a.get("source_ip")
            ip_part = f" from `{ip}`" if ip and ip != "unknown" else ""
            rec = a.get("recommendation", "")
            line = f"• *[{sev}]* {title}{ip_part}"
            if rec:
                line += f"\n  _Fix:_ {rec}"
            lines.append(line)
        blocks.append({"type": "divider"})
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Detected incidents*\n" + "\n".join(lines),
                },
            }
        )

    code_findings = state.get("code_findings", [])
    if code_findings:
        lines = []
        for f in code_findings[:8]:
            lines.append(
                f"• *[{f.get('severity', '?')}]* {f.get('name')} "
                f"in `{f.get('file')}:{f.get('line')}`\n"
                f"  _Fix:_ {f.get('recommendation', 'Review manually')}"
            )
        blocks.append({"type": "divider"})
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Code security findings*\n" + "\n".join(lines),
                },
            }
        )

    action_plan = state.get("action_plan", [])
    if action_plan:
        plan_lines = [f"{i + 1}. {step}" for i, step in enumerate(action_plan[:7])]
        blocks.append({"type": "divider"})
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Resolution action plan*\n" + "\n".join(plan_lines),
                },
            }
        )

    fallback = (
        "CyberSentinel completed analysis. Review the dashboard for full details."
    )
    return {"text": fallback, "blocks": blocks}


def send_slack_message(webhook_url: str, payload: dict) -> dict:
    """POST an incident summary to a Slack incoming webhook.

    Args:
        webhook_url: Slack incoming webhook URL from the user.
        payload: Block Kit message body from :func:`build_incident_message`.

    Returns:
        Dict with ``ok`` bool and optional ``error`` message.
    """
    url = webhook_url.strip()
    if not is_valid_slack_webhook(url):
        return {"ok": False, "error": "Invalid Slack webhook URL"}

    try:
        resp = httpx.post(url, json=payload, timeout=15)
        if resp.status_code == 200 and resp.text.strip().lower() == "ok":
            return {"ok": True}
        return {
            "ok": False,
            "error": f"Slack returned {resp.status_code}: {resp.text[:200]}",
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
