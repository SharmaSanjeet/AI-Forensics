"""Shared parsing helpers.

Parsers never invent artifact text: every emitted value comes from the file
being read. Timestamps fall back to file mtime only when the artifact itself
carries no time, and that fallback is recorded in coverage notes.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ai_forensics.ledger import CollectionHost
from ai_forensics.model import LINE_BYTES, RawRecord
from ai_forensics.textutil import (
    command_from_input,
    pick_time,
    role_name,
    text_from_content,
)

_SKIP_DIRS = {
    "node_modules",
    ".git",
    "extensions",
    "dist",
    "build",
    "__pycache__",
    ".venv",
    "canvases",
    "assets",
    "cache",
    "cacheddata",
    "gpucache",
}

_TIMESTAMP_TAG = re.compile(r"<timestamp>([^<]+)</timestamp>")
_TIMESTAMP_BODY = re.compile(
    r"\w+,\s+(\w{3})\s+(\d{1,2}),\s+(\d{4}),\s+(\d{1,2}):(\d{2})\s+(AM|PM)"
    r"(?:\s+\(UTC([+-]\d{1,2})(?::?(\d{2}))?\))?"
)

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def iter_jsonl(path: Path, ledger: CollectionHost):
    """Yield (object, byte_offset) for each JSON line. Malformed lines are counted."""
    try:
        handle = path.open("rb")
    except OSError:
        ledger.error()
        return
    with handle:
        offset = 0
        while True:
            raw = handle.readline()
            if not raw:
                break
            start = offset
            offset += len(raw)
            if len(raw) > LINE_BYTES:
                ledger.error()
                continue
            if not raw.strip():
                continue
            try:
                value = json.loads(raw.decode("utf-8", "replace"))
            except (ValueError, UnicodeDecodeError):
                ledger.error()
                continue
            yield value, start


def read_text(path: Path, ledger: CollectionHost, *, limit: int = 8 * 1024 * 1024) -> str:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)
    except OSError:
        ledger.error()
        return ""


def read_json(path: Path, ledger: CollectionHost) -> object | None:
    text = read_text(path, ledger)
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        ledger.error()
        return None


def mtime_iso(path: Path) -> str:
    try:
        stamp = path.stat().st_mtime
    except OSError:
        return ""
    return datetime.fromtimestamp(stamp, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def walk_files(
    root: Path,
    *,
    suffixes: set[str] | None = None,
    names: set[str] | None = None,
    skip: set[str] | None = None,
):
    skip_dirs = _SKIP_DIRS | (skip or set())
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [
            name for name in dirs
            if name.lower() not in skip_dirs and not (Path(current) / name).is_symlink()
        ]
        for name in files:
            path = Path(current) / name
            if path.is_symlink():
                continue
            if suffixes is not None and path.suffix.lower() not in suffixes:
                continue
            if names is not None and name.lower() not in names:
                continue
            yield path


def walk_named(root: Path, pattern: str, *, skip: set[str] | None = None):
    skip_dirs = _SKIP_DIRS | (skip or set())
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [
            name for name in dirs
            if name.lower() not in skip_dirs and not (Path(current) / name).is_symlink()
        ]
        for name in files:
            if re.search(pattern, name, re.IGNORECASE):
                yield Path(current) / name


def emit(
    ledger: CollectionHost,
    *,
    tool: str,
    role: str,
    text: str = "",
    timestamp: str = "",
    record_type: str = "message",
    invoked_tool: str = "",
    tool_command: str = "",
    tool_input: object | None = None,
    tool_description: str = "",
    session_id: str = "",
    workspace: str = "",
    source_file: Path | str | None = None,
    source_offset: int = 0,
    model: str = "",
    is_subagent: bool = False,
) -> bool:
    record = RawRecord(
        tool=tool,
        role=role if role in {"user", "assistant", "tool", "system", "metadata"} else "metadata",
        text=text or "",
        timestamp=timestamp or "",
        record_type=record_type or "message",
        invoked_tool=invoked_tool or "",
        tool_command=tool_command or "",
        tool_input=tool_input,
        tool_description=tool_description or "",
        session_id=session_id or "",
        workspace=workspace or "",
        source_file=str(source_file) if source_file else "",
        source_offset=int(source_offset or 0),
        model=model or "",
        is_subagent=is_subagent,
    )
    return ledger.emit(record)


def timestamp_tag(text: str) -> str:
    """Parse Cursor's `<timestamp>Saturday, Jul 11, 2026, 5:52 PM (UTC+5:30)</timestamp>`."""
    match = _TIMESTAMP_TAG.search(text or "")
    if not match:
        return ""
    body = _TIMESTAMP_BODY.search(match.group(1))
    if not body:
        return ""
    month, day, year, hour, minute, meridiem, offset_hour, offset_minute = body.groups()
    if month not in _MONTHS:
        return ""
    hour = int(hour) % 12
    if meridiem.upper() == "PM":
        hour += 12
    offset = timezone.utc
    if offset_hour:
        sign = -1 if offset_hour.startswith("-") else 1
        offset = timezone(sign * timedelta(hours=abs(int(offset_hour)), minutes=int(offset_minute or 0)))
    try:
        parsed = datetime(
            int(year), _MONTHS[month], int(day), hour, int(minute),
            tzinfo=offset,
        )
    except ValueError:
        return ""
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def text_of(value: object) -> str:
    return text_from_content(value)


def role_of(value: object) -> str:
    return role_name(value)


def time_of(obj: object, fallback: str = "") -> str:
    return pick_time(obj) or fallback


def command_of(value: object) -> str:
    return command_from_input(value)


def source_rel(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def folder_from_uri(value: str) -> str:
    """Decode a workspace folder URI, keeping Windows drive paths intact."""
    from urllib.parse import unquote

    text = str(value or "").strip()
    if text.startswith("file://"):
        text = unquote(text[7:])
    if re.match(r"^/[A-Za-z]:[\\/]", text):
        text = text[1:]
    return text.rstrip("/\\")
