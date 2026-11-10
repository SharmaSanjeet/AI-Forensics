"""FastAPI + HTMX case workbench.

Bind to localhost. Every page reads the masked case database; the LLM is only
called when the analyst clicks an explanation button.
"""

from __future__ import annotations

import json
import math
import os
import re
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

from ai_forensics.analyze import (
    LLMConfig,
    explain_anomalies,
    explain_case,
    probe,
    rank_anomalies,
)
from ai_forensics.collect.collector import cases_root, collect, list_cases, open_case
from ai_forensics.detect.anomalies import detect_and_store
from ai_forensics.ledger import TRIAGE_DISPOSITIONS, CollectionHost
from ai_forensics.model import CREATOR_NAME, CREATOR_URL, SEVERITIES
from ai_forensics.report import report_html, report_markdown
from ai_forensics.reporting import (
    anomalies_csv_chunks,
    case_manifest,
    case_zip,
    collected_hashes,
    rows_csv_chunks,
    verify_hashes,
)
from ai_forensics.watch import (
    WATCH_MAX_INTERVAL,
    WATCH_MIN_INTERVAL,
    CaseWatcher,
)

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

FILTER_KEYS = (
    "q",
    "tool",
    "role",
    "recordType",
    "invokedTool",
    "workspace",
    "user",
    "host",
    "sessionId",
    "start",
    "end",
)


def _human_ts(value: object) -> str:
    text = str(value or "")
    if not text:
        return "—"
    return text.replace("T", " ").replace("Z", "")


def _pct(value: float, maximum: float) -> float:
    if maximum <= 0:
        return 0.0
    return round(min(100.0, value / maximum * 100.0), 1)


templates.env.filters["ts"] = _human_ts
templates.env.globals["pct"] = _pct
templates.env.globals["severities"] = SEVERITIES


class CaseManager:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.host: CollectionHost | None = None
        self.case_dir: Path | None = None
        self._llm_cache: tuple[float, dict] | None = None
        self._watcher: CaseWatcher | None = None

    def peek(self) -> CollectionHost | None:
        with self._lock:
            return self.host

    def current(self) -> CollectionHost:
        with self._lock:
            if self.host is None:
                raise HTTPException(409, "No case is loaded. Collect or open a case first.")
            return self.host

    def load(self, case_dir: Path) -> CollectionHost:
        self._stop_watcher()
        host = open_case(case_dir)
        if host.row_count and not host.get_meta().get("detected_at"):
            detect_and_store(host)
            explain_anomalies(host, config=LLMConfig(provider="none"))
        with self._lock:
            previous = self.host
            self.host = host
            self.case_dir = Path(case_dir)
            self._llm_cache = None
        if previous is not None:
            previous.close()
        return host

    def close(self) -> None:
        self._stop_watcher()
        with self._lock:
            if self.host is not None:
                self.host.close()
                self.host = None

    def _stop_watcher(self) -> None:
        with self._lock:
            watcher = self._watcher
            self._watcher = None
        if watcher is not None:
            watcher.stop()

    def watch_status(self) -> dict:
        with self._lock:
            host = self.host
            case_dir = self.case_dir
            watcher = self._watcher
        if host is None or case_dir is None:
            return {"loaded": False, "running": False, "state": "no case"}
        meta = host.get_meta()
        try:
            rows = int(meta.get("rows", "0") or 0)
        except ValueError:
            rows = 0
        if rows > host.row_count:
            with self._lock:
                host.row_count = rows
        try:
            recent = json.loads(meta.get("watch_recent_leads", "[]") or "[]")
        except ValueError:
            recent = []
        running = bool(watcher is not None and watcher.is_alive())
        state = "running" if running else (meta.get("watch_state") or "stopped")

        def number(key: str) -> int:
            try:
                return int(meta.get(key, "0") or 0)
            except ValueError:
                return 0

        return {
            "loaded": True,
            "running": running,
            "state": state,
            "caseId": meta.get("case_id") or case_dir.name,
            "interval": number("watch_interval"),
            "explain": meta.get("watch_explain", "1") == "1",
            "scans": number("watch_scans"),
            "lastScan": meta.get("watch_last_scan", ""),
            "lastDurationMs": number("watch_last_duration_ms"),
            "newRows": number("watch_last_new_rows"),
            "newLeads": number("watch_last_new_leads"),
            "totalRows": number("watch_total_new_rows"),
            "totalLeads": number("watch_total_new_leads"),
            "filesCount": number("watch_files_count"),
            "parseErrors": number("watch_last_parse_errors"),
            "truncations": number("watch_last_truncations"),
            "lastError": meta.get("watch_last_error", ""),
            "startedAt": meta.get("watch_started_at", ""),
            "stoppedAt": meta.get("watch_stopped_at", ""),
            "recent": recent if isinstance(recent, list) else [],
        }

    def start_watch(self, interval: int = 30, explain: bool = True) -> dict:
        if interval < WATCH_MIN_INTERVAL or interval > WATCH_MAX_INTERVAL:
            raise HTTPException(
                400,
                f"interval must be between {WATCH_MIN_INTERVAL} and {WATCH_MAX_INTERVAL} seconds",
            )
        with self._lock:
            host = self.host
            case_dir = self.case_dir
            watcher = self._watcher
        if host is None or case_dir is None:
            raise HTTPException(409, "No case is loaded. Collect or open a case first.")
        if watcher is not None and watcher.is_alive():
            return self.watch_status()
        watcher = CaseWatcher(case_dir, interval=interval, explain=explain)
        host.set_meta(
            {
                "watch_state": "starting",
                "watch_interval": str(interval),
                "watch_explain": "1" if explain else "0",
                "watch_last_error": "",
            }
        )
        with self._lock:
            self._watcher = watcher
        watcher.start()
        return self.watch_status()

    def stop_watch(self) -> dict:
        with self._lock:
            watcher = self._watcher
            host = self.host
            self._watcher = None
        if watcher is not None:
            watcher.stop()
        if host is not None:
            host.set_meta(
                {
                    "watch_state": "stopped",
                    "watch_stopped_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                }
            )
        return self.watch_status()

    def llm_status(self) -> dict:
        now = time.monotonic()
        with self._lock:
            cached = self._llm_cache
        if cached and now - cached[0] < 20:
            return cached[1]
        status = probe(LLMConfig.from_env())
        with self._lock:
            self._llm_cache = (now, status)
        return status


def _startup_case() -> Path | None:
    configured = (os.environ.get("AIF_CASE") or "").strip()
    if configured:
        path = Path(configured).expanduser()
        if (path / "ledger.sqlite").is_file():
            return path
    found = list_cases()
    return Path(found[0]["path"]) if found else None


@asynccontextmanager
async def lifespan(app: FastAPI):
    manager = CaseManager()
    app.state.manager = manager
    target = _startup_case()
    if target is not None:
        try:
            await run_in_threadpool(manager.load, target)
        except Exception as error:  # keep the UI reachable even with a bad case
            app.state.startup_error = f"{type(error).__name__}: {error}"
    yield
    manager.close()


app = FastAPI(title="Assistant Session Ledger", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


@app.exception_handler(HTTPException)
async def http_error(request: Request, exc: HTTPException):
    if "text/html" in request.headers.get("accept", ""):
        ctx = _page_context(request, active="", error=str(exc.detail))
        return templates.TemplateResponse(
            request=request, name="error.html", context=ctx, status_code=exc.status_code
        )
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


def _page_context(request: Request, *, active: str, **extra) -> dict:
    manager: CaseManager = request.app.state.manager
    host = manager.peek()
    current = None
    if host is not None and manager.case_dir is not None:
        meta = host.get_meta()
        current = {
            "id": meta.get("case_id") or manager.case_dir.name,
            "path": str(manager.case_dir),
            "rows": host.row_count,
            "user": meta.get("user", ""),
            "host": meta.get("host", ""),
            "mode": meta.get("mode", ""),
        }
    context = {
        "request": request,
        "active": active,
        "current": current,
        "cases": list_cases(),
        "llm_config": LLMConfig.from_env().public(),
        "startup_error": getattr(request.app.state, "startup_error", ""),
        "creator": {"name": CREATOR_NAME, "url": CREATOR_URL},
        "watch": manager.watch_status() if host is not None else None,
    }
    context.update(extra)
    return context


def _filters(request: Request) -> dict[str, str]:
    found = {}
    for key in FILTER_KEYS:
        value = (request.query_params.get(key) or "").strip()
        if value:
            found[key] = value
    if found.get("end", "").count("-") == 2 and len(found["end"]) == 10:
        found["end"] = found["end"] + "T23:59:59Z"
    return found


def _base_qs(filters: dict[str, str]) -> str:
    return urlencode({key: value for key, value in filters.items() if value})


def _severity_counts(items: list[dict]) -> list[dict]:
    counts = {severity: 0 for severity in SEVERITIES}
    for item in items:
        counts[item["severity"]] = counts.get(item["severity"], 0) + 1
    return [{"label": severity, "count": counts[severity]} for severity in SEVERITIES]


def _review_all(request: Request) -> bool:
    return (request.query_params.get("review") or "").strip() == "all"


def _group_mode(request: Request) -> bool:
    return (request.query_params.get("group") or "").strip() == "session"


def _group_leads(items: list[dict]) -> list[dict]:
    buckets: dict[str, list[dict]] = {}
    for item in items:
        key = str(item.get("sessionId") or "") or (
            f"nosession|{item.get('tool', '')}|{item.get('workspace', '')}"
        )
        buckets.setdefault(key, []).append(item)
    groups = []
    for leads in buckets.values():
        present = {lead["severity"] for lead in leads}
        times = [lead["timestamp"] for lead in leads if lead.get("timestamp")]
        groups.append(
            {
                "sessionId": str(leads[0].get("sessionId") or ""),
                "tool": leads[0].get("tool", ""),
                "workspace": leads[0].get("workspace", ""),
                "count": len(leads),
                "severity": next(
                    (severity for severity in SEVERITIES if severity in present), leads[0]["severity"]
                ),
                "first": min(times) if times else "",
                "last": max(times) if times else "",
                "leads": leads,
            }
        )
    return groups


def _reviewer() -> str:
    return (os.environ.get("USERNAME") or os.environ.get("USER") or "analyst").strip()


def _anomaly_context(
    host: CollectionHost,
    *,
    severity: str,
    review_all: bool,
    grouped: bool = False,
    report: dict | None = None,
    rank: dict | None = None,
) -> dict:
    visible = host.query_anomalies(
        "", exclude_suppressed=not review_all, exclude_reviewed=not review_all
    )
    items = [item for item in visible if not severity or item["severity"] == severity]
    unfiltered = host.query_anomalies(severity)
    return {
        "items": items,
        "groups": _group_leads(items) if grouped else [],
        "grouped": grouped,
        "severity": severity,
        "review_all": review_all,
        "hidden_count": len(unfiltered) - len(items),
        "severity_counts": _severity_counts(visible),
        "suppressions": host.list_suppressions(),
        "report": report,
        "rank": rank,
        "llm_config": LLMConfig.from_env().public(),
    }


def _stored_brief(host: CollectionHost) -> dict | None:
    raw = host.get_meta().get("case_brief", "")
    if not raw:
        return None
    try:
        value = json.loads(raw)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def _find_case(case_id: str) -> Path | None:
    wanted = (case_id or "").strip()
    if not wanted:
        return None
    for item in list_cases():
        if item["id"] == wanted:
            return Path(item["path"])
    return None


def _safe_name(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-") or "case"


@app.get("/", response_class=HTMLResponse)
def overview(request: Request):
    manager: CaseManager = request.app.state.manager
    host = manager.peek()
    if host is None:
        return templates.TemplateResponse(
            request=request, name="index.html", context=_page_context(request, active="overview")
        )
    stats = host.stats()
    tools = stats.get("by_tool") or []
    max_tool = max((int(item["count"]) for item in tools), default=1)
    hourly = stats.get("hourly") or []
    max_hour = max((int(item["count"]) for item in hourly), default=1)
    coverage = {item["label"]: int(item["count"]) for item in (stats.get("by_coverage") or [])}
    visible = host.query_anomalies(exclude_suppressed=True, exclude_reviewed=True)
    context = _page_context(
        request,
        active="overview",
        stats=stats,
        tools=tools,
        max_tool=max_tool,
        hourly=hourly,
        max_hour=max_hour,
        coverage=coverage,
        severity_counts=_severity_counts(visible),
        recent=visible[:5],
        brief=_stored_brief(host),
    )
    return templates.TemplateResponse(request=request, name="index.html", context=context)


@app.get("/timeline", response_class=HTMLResponse)
def timeline(request: Request):
    manager: CaseManager = request.app.state.manager
    host = manager.current()
    filters = _filters(request)
    try:
        page = max(1, int(request.query_params.get("page") or 1))
    except ValueError:
        page = 1
    limit = 100
    total = host.count(filters)
    pages = max(1, math.ceil(total / limit))
    page = min(page, pages)
    rows = host.query_rows(filters, offset=(page - 1) * limit, limit=limit)
    context = _page_context(
        request,
        active="timeline",
        filters=filters,
        base_qs=_base_qs(filters),
        rows=rows,
        total=total,
        page=page,
        pages=pages,
        facets=host.facets(),
    )
    return templates.TemplateResponse(request=request, name="timeline.html", context=context)


@app.get("/rows/{row_id}", response_class=HTMLResponse)
def row_detail(request: Request, row_id: str):
    host = request.app.state.manager.current()
    row = host.get_row(row_id)
    if row is None:
        raise HTTPException(404, f"Row {row_id} not found")
    return templates.TemplateResponse(
        request=request, name="partials/row_drawer.html", context={"request": request, "row": row}
    )


@app.get("/anomalies", response_class=HTMLResponse)
def anomalies(request: Request):
    manager: CaseManager = request.app.state.manager
    host = manager.current()
    severity = (request.query_params.get("severity") or "").strip()
    context = _page_context(
        request,
        active="anomalies",
        **_anomaly_context(
            host,
            severity=severity,
            review_all=_review_all(request),
            grouped=_group_mode(request),
        ),
    )
    return templates.TemplateResponse(request=request, name="anomalies.html", context=context)


@app.post("/anomalies/explain", response_class=HTMLResponse)
def explain_all(
    request: Request, severity: str = Form(""), review: str = Form(""), group: str = Form("")
):
    host = request.app.state.manager.current()
    review_all = review == "all"
    visible = host.query_anomalies(
        "", exclude_suppressed=not review_all, exclude_reviewed=not review_all
    )
    wanted = [item["id"] for item in visible if not severity or item["severity"] == severity]
    report = explain_anomalies(host, config=LLMConfig.from_env(), anomaly_ids=wanted)
    context = {
        "request": request,
        **_anomaly_context(
            host,
            severity=severity,
            review_all=review_all,
            grouped=group == "session",
            report=report.as_dict(),
        ),
    }
    return templates.TemplateResponse(
        request=request, name="partials/anomaly_shell.html", context=context
    )


@app.post("/anomalies/rank", response_class=HTMLResponse)
def rank_leads(
    request: Request, severity: str = Form(""), review: str = Form(""), group: str = Form("")
):
    host = request.app.state.manager.current()
    rank = rank_anomalies(host, config=LLMConfig.from_env())
    context = {
        "request": request,
        **_anomaly_context(
            host,
            severity=severity,
            review_all=review == "all",
            grouped=group == "session",
            rank=rank.as_dict(),
        ),
    }
    return templates.TemplateResponse(
        request=request, name="partials/anomaly_shell.html", context=context
    )


@app.post("/anomalies/{anomaly_id}/explain", response_class=HTMLResponse)
def explain_one(
    request: Request, anomaly_id: str, severity: str = Form(""), review: str = Form("")
):
    from ai_forensics.analyze.explain import explain_anomaly

    manager: CaseManager = request.app.state.manager
    host = manager.current()
    item = host.get_anomaly(anomaly_id)
    if item is None:
        raise HTTPException(404, f"Anomaly {anomaly_id} not found")
    config = LLMConfig.from_env()
    explained = explain_anomaly(host, item, config=config, force=True)
    merged = {**item, **explained}
    return templates.TemplateResponse(
        request=request,
        name="partials/anomaly_card.html",
        context={
            "request": request,
            "a": merged,
            "llm_config": config.public(),
            "severity": severity,
            "review_all": review == "all",
        },
    )


@app.post("/anomalies/{anomaly_id}/triage", response_class=HTMLResponse)
def triage_anomaly(
    request: Request,
    anomaly_id: str,
    disposition: str = Form(...),
    note: str = Form(""),
    suppress: str = Form(""),
    severity: str = Form(""),
    review: str = Form(""),
    group: str = Form(""),
):
    host = request.app.state.manager.current()
    item = host.get_anomaly(anomaly_id)
    if item is None:
        raise HTTPException(404, f"Anomaly {anomaly_id} not found")
    if disposition not in TRIAGE_DISPOSITIONS:
        raise HTTPException(400, f"Unknown disposition: {disposition}")
    reviewer = _reviewer()
    host.set_triage(anomaly_id, disposition=disposition, note=note.strip(), reviewer=reviewer)
    if suppress and disposition != "open":
        host.add_suppression(
            rule=str(item.get("rule") or ""),
            workspace=str(item.get("workspace") or ""),
            command_hash=host.suppression_fingerprint(item),
            note=note.strip(),
            created_by=reviewer,
        )
    context = {
        "request": request,
        **_anomaly_context(
            host, severity=severity, review_all=review == "all", grouped=group == "session"
        ),
    }
    return templates.TemplateResponse(
        request=request, name="partials/anomaly_shell.html", context=context
    )


@app.post("/anomalies/bulk", response_class=HTMLResponse)
def bulk_triage(
    request: Request,
    session: str = Form(""),
    disposition: str = Form(...),
    severity: str = Form(""),
    review: str = Form(""),
    group: str = Form("session"),
):
    host = request.app.state.manager.current()
    if disposition not in TRIAGE_DISPOSITIONS:
        raise HTTPException(400, f"Unknown disposition: {disposition}")
    wanted = session.strip()
    if not wanted:
        raise HTTPException(400, "A session id is required for bulk review")
    reviewer = _reviewer()
    notes = host.triage_map()
    targets = [item for item in host.query_anomalies() if item.get("sessionId") == wanted]
    for item in targets:
        host.set_triage(
            item["id"],
            disposition=disposition,
            note=notes.get(item["id"], {}).get("note", ""),
            reviewer=reviewer,
        )
    context = {
        "request": request,
        **_anomaly_context(
            host, severity=severity, review_all=review == "all", grouped=group == "session"
        ),
    }
    return templates.TemplateResponse(
        request=request, name="partials/anomaly_shell.html", context=context
    )


@app.post("/suppressions/{suppression_id}/remove", response_class=HTMLResponse)
def remove_suppression(
    request: Request,
    suppression_id: str,
    severity: str = Form(""),
    review: str = Form(""),
    group: str = Form(""),
):
    host = request.app.state.manager.current()
    host.remove_suppression(suppression_id)
    context = {
        "request": request,
        **_anomaly_context(
            host, severity=severity, review_all=review == "all", grouped=group == "session"
        ),
    }
    return templates.TemplateResponse(
        request=request, name="partials/anomaly_shell.html", context=context
    )


@app.post("/detect", response_class=HTMLResponse)
def redetect(
    request: Request, severity: str = Form(""), review: str = Form(""), group: str = Form("")
):
    host = request.app.state.manager.current()
    detect_and_store(host)
    fresh = [item for item in host.query_anomalies() if not item.get("whatHappened")]
    if fresh:
        explain_anomalies(
            host, config=LLMConfig(provider="none"), anomaly_ids=[item["id"] for item in fresh]
        )
    context = {
        "request": request,
        **_anomaly_context(
            host,
            severity=severity,
            review_all=review == "all",
            grouped=group == "session",
            report={
                "provider": "deterministic",
                "generated": 0,
                "cached": 0,
                "fallback": len(fresh),
                "errors": [],
            },
        ),
    }
    return templates.TemplateResponse(
        request=request, name="partials/anomaly_shell.html", context=context
    )


@app.get("/secrets", response_class=HTMLResponse)
def secrets_view(request: Request):
    host = request.app.state.manager.current()
    context = _page_context(request, active="secrets", rows=host.secret_rows(500))
    return templates.TemplateResponse(request=request, name="secrets.html", context=context)


@app.get("/coverage", response_class=HTMLResponse)
def coverage_view(request: Request):
    host = request.app.state.manager.current()
    files, source, omitted = collected_hashes(host)
    meta = host.get_meta()
    context = _page_context(
        request,
        active="coverage",
        entries=host.coverage_public(),
        stats=host.stats(),
        files=files,
        hash_source=source,
        hash_omitted=omitted,
        parse_errors=meta.get("parse_errors", "0"),
        truncations=meta.get("truncations", "0"),
    )
    return templates.TemplateResponse(request=request, name="coverage.html", context=context)


@app.post("/coverage/verify", response_class=HTMLResponse)
def coverage_verify(request: Request):
    host = request.app.state.manager.current()
    result = verify_hashes(host)
    return templates.TemplateResponse(
        request=request,
        name="partials/hash_check.html",
        context={"request": request, "result": result},
    )


@app.post("/brief", response_class=HTMLResponse)
def brief_view(request: Request):
    host = request.app.state.manager.current()
    brief = explain_case(host, config=LLMConfig.from_env())
    return templates.TemplateResponse(
        request=request,
        name="partials/brief.html",
        context={"request": request, "brief": brief, "llm_config": LLMConfig.from_env().public()},
    )


@app.get("/llm/status", response_class=HTMLResponse)
def llm_status(request: Request):
    manager: CaseManager = request.app.state.manager
    status = manager.llm_status()
    return templates.TemplateResponse(
        request=request, name="partials/llm_chip.html", context={"request": request, "status": status}
    )


def _watch_panel(request: Request):
    manager: CaseManager = request.app.state.manager
    return templates.TemplateResponse(
        request=request,
        name="partials/watch_panel.html",
        context={"request": request, "watch": manager.watch_status()},
    )


@app.get("/watch/status", response_class=HTMLResponse)
def watch_status_view(request: Request):
    return _watch_panel(request)


@app.post("/watch/start", response_class=HTMLResponse)
def watch_start(
    request: Request,
    interval: str = Form("30"),
    explain: str = Form(""),
):
    manager: CaseManager = request.app.state.manager
    try:
        seconds = int(interval)
    except ValueError as error:
        raise HTTPException(400, "interval must be a whole number of seconds") from error
    manager.start_watch(seconds, explain.lower() in {"1", "on", "true", "yes"})
    return _watch_panel(request)


@app.post("/watch/stop", response_class=HTMLResponse)
def watch_stop(request: Request):
    manager: CaseManager = request.app.state.manager
    manager.stop_watch()
    return _watch_panel(request)


@app.get("/cases", response_class=HTMLResponse)
def cases_view(request: Request):
    context = _page_context(
        request,
        active="cases",
        active_cases=list_cases(),
        cases_root=str(cases_root()),
    )
    return templates.TemplateResponse(request=request, name="cases.html", context=context)


@app.post("/cases/open")
def case_open(request: Request, case_id: str = Form(...)):
    manager: CaseManager = request.app.state.manager
    target = _find_case(case_id)
    if target is None:
        raise HTTPException(404, "Case not found")
    manager.load(target)
    return RedirectResponse("/", status_code=303)


@app.post("/cases/collect")
def case_collect(
    request: Request,
    mode: str = Form("machine"),
    path: str = Form(""),
    include_subagents: str = Form(""),
):
    manager: CaseManager = request.app.state.manager
    include = include_subagents.lower() in {"1", "on", "true", "yes"}
    if mode not in {"machine", "folder"}:
        raise HTTPException(400, "mode must be machine or folder")
    try:
        host, report = collect(
            mode=mode,
            path=path.strip() or None,
            include_subagents=include,
            reset=True,
        )
    except (ValueError, FileNotFoundError, OSError) as error:
        raise HTTPException(400, f"Collection failed: {error}") from error
    host.close()
    manager.load(Path(report.case_dir))
    return RedirectResponse("/", status_code=303)


@app.get("/export", response_class=HTMLResponse)
def export_view(request: Request):
    host = request.app.state.manager.current()
    manifest = case_manifest(host)
    context = _page_context(request, active="export", manifest=manifest)
    return templates.TemplateResponse(request=request, name="export.html", context=context)


def _attachment(name: str) -> dict[str, str]:
    return {"Content-Disposition": f'attachment; filename="{_safe_name(name)}"'}


@app.get("/export/rows.csv")
def export_rows(request: Request):
    host = request.app.state.manager.current()
    filters = _filters(request)
    filename = f"{_safe_name(str(host.get_meta().get('case_id') or 'case'))}-rows.csv"
    return StreamingResponse(
        rows_csv_chunks(host, filters),
        media_type="text/csv; charset=utf-8",
        headers=_attachment(filename),
    )


@app.get("/export/anomalies.csv")
def export_anomalies(request: Request):
    host = request.app.state.manager.current()
    severity = (request.query_params.get("severity") or "").strip()
    filename = f"{_safe_name(str(host.get_meta().get('case_id') or 'case'))}-anomalies.csv"
    return StreamingResponse(
        anomalies_csv_chunks(host, severity),
        media_type="text/csv; charset=utf-8",
        headers=_attachment(filename),
    )


@app.get("/export/manifest.json")
def export_manifest(request: Request):
    host = request.app.state.manager.current()
    body = json.dumps(case_manifest(host), indent=2, ensure_ascii=False).encode("utf-8")
    filename = f"{_safe_name(str(host.get_meta().get('case_id') or 'case'))}-manifest.json"
    return Response(content=body, media_type="application/json", headers=_attachment(filename))


@app.get("/export/report.html")
def export_report_html(request: Request):
    host = request.app.state.manager.current()
    body = report_html(host).encode("utf-8")
    filename = f"{_safe_name(str(host.get_meta().get('case_id') or 'case'))}-report.html"
    return Response(
        content=body, media_type="text/html; charset=utf-8", headers=_attachment(filename)
    )


@app.get("/export/report.md")
def export_report_markdown(request: Request):
    host = request.app.state.manager.current()
    body = report_markdown(host).encode("utf-8")
    filename = f"{_safe_name(str(host.get_meta().get('case_id') or 'case'))}-report.md"
    return Response(
        content=body, media_type="text/markdown; charset=utf-8", headers=_attachment(filename)
    )


@app.get("/export/case.zip")
def export_zip(request: Request):
    host = request.app.state.manager.current()
    body = case_zip(host)
    filename = f"{_safe_name(str(host.get_meta().get('case_id') or 'case'))}.zip"
    return Response(content=body, media_type="application/zip", headers=_attachment(filename))


def main() -> None:
    import uvicorn

    uvicorn.run(
        "ai_forensics.web.app:app",
        host=os.environ.get("AIF_HOST", "127.0.0.1"),
        port=int(os.environ.get("AIF_PORT", "8000")),
        reload=False,
    )
