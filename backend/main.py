"""FastAPI application — analysis endpoints, SSE streaming, and eval API."""

import asyncio
import json
import platform
import uuid
from pathlib import Path
from typing import AsyncGenerator

from dotenv import load_dotenv

load_dotenv()

from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from orchestrator import run_analysis
from session_events import close_session, create_session, emit_sync, get_agent_status, get_queue
from session_evals import begin_session, finish_session, list_all_evals, session_to_dict

app = FastAPI(title="CyberSentinel AI")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)

_sessions: dict[str, dict] = {}
_session_meta: dict[str, dict] = {}
_running: set[str] = set()

SYNTHETIC_LOGS_PATH = Path(__file__).parent / "data" / "synthetic_logs.json"


class AnalyzeRequest(BaseModel):
    """Request body for ``POST /analyze``."""

    source: str
    slack_webhook_url: str = ""


def _load_synthetic_logs() -> list[str]:
    """Load bundled synthetic log lines from ``data/synthetic_logs.json``."""
    return json.loads(SYNTHETIC_LOGS_PATH.read_text())


SYSTEM_LOG_PATHS = [
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/system.log",
    "/var/log/secure.log",
]


def _load_system_logs() -> tuple[list[str], dict]:
    """Read recent lines from OS log files, falling back to synthetic logs.

    Returns:
        Tuple of log lines and metadata describing what was loaded.
    """
    logs: list[str] = []
    loaded_from: list[str] = []

    for path in SYSTEM_LOG_PATHS:
        try:
            with open(path) as f:
                lines = [line.strip() for line in f.readlines()[-200:] if line.strip()]
                if lines:
                    logs.extend(lines)
                    loaded_from.append(path)
        except OSError:
            continue

    if logs:
        return logs, {
            "used_fallback": False,
            "paths": loaded_from,
            "line_count": len(logs),
        }

    synthetic = _load_synthetic_logs()
    return synthetic, {
        "used_fallback": True,
        "paths": [],
        "line_count": len(synthetic),
        "fallback_reason": (
            "No readable system log files found "
            f"({platform.system()}); using bundled synthetic logs"
        ),
    }


def _load_logs_for_source(source: str) -> tuple[list[str], dict]:
    """Resolve log lines for ``synthetic`` or ``system`` sources.

    Raises:
        HTTPException: When ``source`` is not supported (use upload endpoint).
    """
    if source == "synthetic":
        logs = _load_synthetic_logs()
        return logs, {
            "used_fallback": False,
            "paths": [str(SYNTHETIC_LOGS_PATH)],
            "line_count": len(logs),
        }
    if source == "system":
        return _load_system_logs()
    raise HTTPException(status_code=400, detail="Use /analyze/upload for file uploads")


async def _run_analysis_background(
    logs: list[str],
    log_source: str,
    session_id: str,
    github_repo: str = "",
    slack_webhook_url: str = "",
) -> None:
    """Run the LangGraph pipeline in a thread and emit completion events."""
    _running.add(session_id)
    try:
        state = await asyncio.to_thread(
            run_analysis,
            logs,
            log_source,
            session_id,
            github_repo,
            slack_webhook_url,
        )
        _sessions[session_id] = state
        finish_session(session_id)
        emit_sync(session_id, "pipeline", "done")
    finally:
        close_session(session_id)
        _running.discard(session_id)


def _start_analysis(
    logs: list[str],
    log_source: str,
    background_tasks: BackgroundTasks,
    log_meta: dict | None = None,
    github_repo: str = "",
    slack_webhook_url: str = "",
) -> tuple[str, dict]:
    """Create a session, register eval tracking, and queue background analysis.

    Returns:
        ``(session_id, metadata)`` for the API response.
    """
    session_id = str(uuid.uuid4())
    create_session(session_id)
    begin_session(
        session_id,
        log_source=log_source,
        line_count=log_meta.get("line_count", len(logs)) if log_meta else len(logs),
        used_fallback=log_meta.get("used_fallback", False) if log_meta else False,
    )
    background_tasks.add_task(
        _run_analysis_background,
        logs,
        log_source,
        session_id,
        github_repo,
        slack_webhook_url,
    )
    meta = {"log_source": log_source, **(log_meta or {})}
    if github_repo:
        meta["github_repo"] = github_repo
    if slack_webhook_url:
        meta["slack_notify"] = True
    _session_meta[session_id] = meta
    return session_id, meta


class GitHubAnalyzeRequest(BaseModel):
    """Request body for ``POST /analyze/github``."""

    repo_url: str
    include_logs: bool = False
    log_source: str = "synthetic"
    slack_webhook_url: str = ""


@app.post("/analyze")
async def analyze(request: AnalyzeRequest, background_tasks: BackgroundTasks):
    """Start log analysis from synthetic or system log sources."""
    logs, log_meta = _load_logs_for_source(request.source)
    session_id, meta = _start_analysis(
        logs, request.source, background_tasks, log_meta,
        slack_webhook_url=request.slack_webhook_url.strip(),
    )
    return {"session_id": session_id, **meta}


@app.post("/analyze/upload")
async def analyze_upload(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    slack_webhook_url: str = Form(""),
):
    """Start analysis from an uploaded ``.log`` or ``.txt`` file (max 10 MB)."""
    content = await file.read()
    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File too large (max 10MB)")
    if not (file.filename or "").endswith((".log", ".txt")):
        raise HTTPException(status_code=400, detail="Only .log and .txt files accepted")
    logs = content.decode("utf-8", errors="ignore").splitlines()
    log_meta = {
        "used_fallback": False,
        "paths": [file.filename or "upload"],
        "line_count": len(logs),
    }
    session_id, meta = _start_analysis(
        logs,
        "upload",
        background_tasks,
        log_meta,
        slack_webhook_url=slack_webhook_url.strip(),
    )
    return {"session_id": session_id, **meta}


@app.post("/analyze/github")
async def analyze_github(
    request: GitHubAnalyzeRequest, background_tasks: BackgroundTasks
):
    """Start GitHub repository static analysis, optionally combined with logs."""
    from tools.github_scanner import parse_github_url

    try:
        owner, repo = parse_github_url(request.repo_url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    github_repo = f"{owner}/{repo}"

    if request.include_logs:
        logs, log_meta = _load_logs_for_source(request.log_source)
    else:
        logs = []
        log_meta = {"line_count": 0, "used_fallback": False, "paths": []}

    log_meta = {
        **log_meta,
        "github_repo": github_repo,
        "repo_url": f"https://github.com/{github_repo}",
        "scan_mode": "code_only" if not request.include_logs else "code_and_logs",
    }

    session_id, meta = _start_analysis(
        logs,
        "github",
        background_tasks,
        log_meta,
        github_repo=github_repo,
        slack_webhook_url=request.slack_webhook_url.strip(),
    )
    return {"session_id": session_id, **meta}


@app.get("/stream/{session_id}")
async def stream(session_id: str):
    """Server-sent events stream of agent progress for a session."""
    q = get_queue(session_id)
    if not q:
        raise HTTPException(status_code=404, detail="Session not found")

    async def event_generator() -> AsyncGenerator[dict, None]:
        while True:
            event = await asyncio.to_thread(q.get)
            if event is None:
                break
            yield {"data": json.dumps(event)}

    return EventSourceResponse(event_generator())


@app.get("/report/{session_id}")
async def get_report(session_id: str):
    """Return the final pipeline state and session metadata."""
    state = _sessions.get(session_id)
    if not state:
        raise HTTPException(status_code=404, detail="Session not found or still running")
    meta = _session_meta.get(session_id, {})
    return {**state, **meta}


@app.get("/agents/status/{session_id}")
async def agents_status(session_id: str):
    """Return per-agent status strings for dashboard polling."""
    status = get_agent_status(session_id)
    if not status:
        raise HTTPException(status_code=404, detail="Session not found")
    return status


@app.get("/evals")
async def get_all_evals():
    """List eval metrics for all completed analysis sessions."""
    return list_all_evals()


@app.get("/evals/{session_id}")
async def get_session_evals(session_id: str):
    """Return detailed eval metrics for a single session."""
    detail = session_to_dict(session_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Eval data not found for session")
    return detail
