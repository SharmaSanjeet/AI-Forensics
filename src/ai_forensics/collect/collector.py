"""Collect AI-assistant artifacts into one case database."""

from __future__ import annotations

import json
import os
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ai_forensics.collect.parsers.claude import parse_claude_code, parse_claude_desktop
from ai_forensics.collect.parsers.codex import parse_codex
from ai_forensics.collect.parsers.copilot import parse_copilot, parse_vscode_chats
from ai_forensics.collect.parsers.cursor import parse_cursor
from ai_forensics.collect.parsers.gemini import parse_gemini
from ai_forensics.discover import discover_roots, this_machine_discovery
from ai_forensics.ledger import CollectionHost
from ai_forensics.model import (
    CREATOR_NAME,
    CREATOR_URL,
    FULLTEXT_BYTES,
    ROW_CAP,
)

HANDLERS = {
    "claude_code": parse_claude_code,
    "claude_config": parse_claude_code,
    "claude_desktop": parse_claude_desktop,
    "codex": parse_codex,
    "cursor_home": parse_cursor,
    "cursor_app": parse_cursor,
    "cursor_search": parse_cursor,
    "gemini": parse_gemini,
    "copilot": parse_copilot,
    "vscode": parse_vscode_chats,
    "vscode_chats": parse_vscode_chats,
}

UNHANDLED = {
    "chatgpt": ("inventory-only", "ChatGPT Desktop/Atlas stores inventoried; LevelDB/bundle decoding not in MVP"),
    "grok": ("inventory-only", "Grok Build sessions inventoried; decoded parsing not in MVP"),
    "grokbot": ("inventory-only", "Grok Bot stores inventoried; decoded parsing not in MVP"),
    "grokbot_app": ("inventory-only", "Grok Bot app stores inventoried; decoded parsing not in MVP"),
    "computer_history": ("unsupported", "Computer History 54-column schema not implemented"),
    "gemini_desktop": ("unsupported", "Gemini desktop app is not parsed; collect Gemini CLI instead"),
    "windsurf": ("inventory-only", "Windsurf chat stores inventoried; Cascade protobuf not decoded"),
    "continue": ("inventory-only", "Continue session JSON inventoried; parser not in MVP"),
    "browser": ("inventory-only", "Browser profile detected; collect the browser separately for web-only AI usage"),
}

_TOOL_HINTS = (
    ("claude", "Claude Code"),
    ("codex", "OpenAI Codex"),
    ("chatgpt", "ChatGPT Desktop"),
    ("grokbot", "Grok Bot"),
    ("grok", "Grok Build"),
    ("cursor", "Cursor"),
    ("gemini", "Gemini CLI"),
    ("copilot", "GitHub Copilot"),
    ("windsurf", "Windsurf"),
    ("continue", "Continue"),
)


@dataclass
class CollectReport:
    case_id: str
    case_dir: str
    mode: str
    roots: list[str] = field(default_factory=list)
    stores: int = 0
    rows: int = 0
    files_read: int = 0
    parse_errors: int = 0
    truncations: int = 0
    cap_hit: bool = False
    cancelled: bool = False
    coverage: dict[str, int] = field(default_factory=dict)
    activity: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "caseId": self.case_id,
            "caseDir": self.case_dir,
            "mode": self.mode,
            "roots": self.roots,
            "stores": self.stores,
            "rows": self.rows,
            "filesRead": self.files_read,
            "parseErrors": self.parse_errors,
            "truncations": self.truncations,
            "capHit": self.cap_hit,
            "cancelled": self.cancelled,
            "coverage": self.coverage,
        }


def cases_root() -> Path:
    configured = os.environ.get("AIF_CASES_DIR")
    return Path(configured) if configured else Path.cwd() / "cases"


def new_case_dir(label: str = "") -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    slug = re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")[:40]
    base = cases_root()
    base.mkdir(parents=True, exist_ok=True)
    candidate = base / f"{stamp}-{slug or 'case'}"
    counter = 2
    while candidate.exists():
        candidate = base / f"{stamp}-{slug or 'case'}-{counter}"
        counter += 1
    return candidate


def list_cases() -> list[dict]:
    base = cases_root()
    if not base.is_dir():
        return []
    found = []
    for folder in sorted(base.iterdir(), reverse=True):
        db = folder / "ledger.sqlite"
        if not db.is_file():
            continue
        found.append(
            {
                "id": folder.name,
                "path": str(folder),
                "modified": datetime.fromtimestamp(
                    db.stat().st_mtime, timezone.utc
                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        )
    return found


def open_case(case_dir: Path) -> CollectionHost:
    meta_path = Path(case_dir) / "case.json"
    roots: list[Path] = [Path(case_dir)]
    if meta_path.is_file():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            roots = [Path(item) for item in meta.get("roots", [])] or roots
        except (OSError, ValueError):
            pass
    ledger = CollectionHost(roots, include_subagents=True, row_cap=ROW_CAP, fulltext_bytes=FULLTEXT_BYTES)
    ledger.open_db(Path(case_dir))
    stored = ledger.get_meta()
    if stored.get("roots"):
        try:
            roots = [Path(item) for item in json.loads(stored["roots"])]
            ledger.roots = [path.resolve() for path in roots]
        except (ValueError, OSError):
            pass
    ledger.user = stored.get("user", "")
    ledger.host_name = stored.get("host", "")
    ledger.include_subagents = stored.get("include_subagents", "0") == "1"
    return ledger


def _tool_for_path(path: str) -> str:
    lowered = path.lower()
    for hint, tool in _TOOL_HINTS:
        if hint in lowered:
            return tool
    return "Unknown"


def _write_case_json(target: Path, ledger: CollectionHost, report: CollectReport) -> None:
    meta = ledger.get_meta()
    payload = {
        "case_id": report.case_id,
        "mode": report.mode,
        "creator": {"name": CREATOR_NAME, "linkedin": CREATOR_URL},
        "roots": report.roots,
        "user": meta.get("user", ""),
        "host": meta.get("host", ""),
        "created_at": meta.get("created_at", ledger.created_at),
        "finished_at": meta.get("finished_at", ""),
        "rows": report.rows,
        "stores": report.stores,
        "files_read": report.files_read,
        "parse_errors": report.parse_errors,
        "truncations": report.truncations,
        "coverage": report.coverage,
    }
    try:
        (target / "case.json").write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    except OSError as error:
        ledger.log(f"case.json not written: {type(error).__name__}")


def collect(
    *,
    mode: str = "machine",
    path: str | None = None,
    case_dir: Path | None = None,
    include_subagents: bool = False,
    reset: bool = True,
    cancel: threading.Event | None = None,
    progress=None,
) -> tuple[CollectionHost, CollectReport]:
    if mode == "folder":
        if not path:
            raise ValueError("folder mode requires a path")
        root = Path(path).expanduser()
        if not root.exists():
            raise FileNotFoundError(path)
        target = case_dir or new_case_dir(root.name)
        roots = [root]
        discovery = discover_roots(
            roots, default_user="", default_host="", cancel=cancel, log=progress
        )
    else:
        target = case_dir or new_case_dir("this-machine")
        roots = []
        discovery = this_machine_discovery(cancel=cancel, log=progress)

    all_roots: list[Path] = list(roots)
    all_roots.extend(Path(store.path) for store in discovery.stores)
    seen: set[str] = set()
    deduped: list[Path] = []
    for item in all_roots:
        try:
            key = str(item.resolve()).lower()
        except OSError:
            key = str(item).lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)

    ledger = CollectionHost(
        deduped or [target],
        include_subagents=include_subagents,
        row_cap=ROW_CAP,
        fulltext_bytes=FULLTEXT_BYTES,
    )
    if cancel is not None:
        ledger.cancel = cancel
    ledger.open_db(target, reset=reset)
    ledger.roots = [item.resolve() for item in deduped]
    ledger.user = os.environ.get("USERNAME") or os.environ.get("USER") or ""
    ledger.host_name = os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME") or ""
    ledger.set_meta(
        {
            "case_id": target.name,
            "mode": mode,
            "roots": json.dumps([str(item) for item in deduped]),
            "include_subagents": "1" if include_subagents else "0",
            "user": ledger.user,
            "host": ledger.host_name,
            "created_at": ledger.created_at,
        }
    )
    ledger.log(f"case {target.name} started in {mode} mode")

    for path_text, exists, note in discovery.checked:
        if not exists:
            ledger.cover(
                path_text,
                _tool_for_path(path_text),
                "unavailable",
                notes=note or "not present",
            )

    for user in discovery.user_trees_empty:
        ledger.cover(
            f"user:{user}",
            "Unknown",
            "unavailable",
            notes="profile discovered but no AI stores found",
        )

    for store in discovery.stores:
        if cancel is not None and cancel.is_set():
            ledger.cancelled = True
            break
        handler = HANDLERS.get(store.kind)
        try:
            if handler is not None:
                handler(ledger, store)
            else:
                status, note = UNHANDLED.get(
                    store.kind, ("inventory-only", "store detected; parser not implemented")
                )
                ledger.cover(str(store.path), _tool_for_path(str(store.path)), status, notes=note)
        except Exception as error:  # a broken parser must not abandon the whole case
            ledger.error()
            ledger.cover(
                str(store.path),
                _tool_for_path(str(store.path)),
                "malformed",
                notes=f"parser exception: {type(error).__name__}: {error}",
            )

    if not discovery.stores:
        ledger.cover(
            str(roots[0]) if roots else "this machine",
            "Unknown",
            "empty",
            notes="no AI-assistant stores discovered",
        )

    ledger.link_prompts()
    hashes, hashes_omitted = ledger.file_hashes()
    ledger.set_meta(
        {
            "file_hashes": json.dumps(hashes, separators=(",", ":")),
            "file_hashes_omitted": str(hashes_omitted),
        }
    )
    coverage = ledger.coverage_public()
    counts: dict[str, int] = {}
    for entry in coverage:
        status = str(entry["status"])
        counts[status] = counts.get(status, 0) + 1
    ledger.set_meta(
        {
            "finished_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "rows": ledger.row_count,
            "parse_errors": ledger.parse_errors,
            "truncations": ledger.truncations,
            "cap_hit": "1" if ledger.hit_cap else "0",
            "cancelled": "1" if ledger.cancelled else "0",
        }
    )
    report = CollectReport(
        case_id=target.name,
        case_dir=str(target),
        mode=mode,
        roots=[str(item) for item in deduped],
        stores=len(discovery.stores),
        rows=ledger.row_count,
        files_read=sum(int(entry["filesRead"]) for entry in coverage),
        parse_errors=ledger.parse_errors,
        truncations=ledger.truncations,
        cap_hit=ledger.hit_cap,
        cancelled=ledger.cancelled,
        coverage=counts,
    )
    _write_case_json(target, ledger, report)
    ledger.log(
        f"case finished: {report.rows} rows, {report.files_read} files, "
        f"{report.parse_errors} parse errors"
    )
    return ledger, report


__all__ = ["collect", "list_cases", "new_case_dir", "open_case", "cases_root", "CollectReport"]
