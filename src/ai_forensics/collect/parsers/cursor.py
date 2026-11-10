"""Cursor parser: agent transcripts, composer SQLite, conversation search index."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from urllib.parse import quote

from ai_forensics.collect.parsers.common import (
    emit,
    folder_from_uri,
    iter_jsonl,
    mtime_iso,
    timestamp_tag,
    text_of,
    walk_files,
)
from ai_forensics.ledger import CollectionHost
from ai_forensics.textutil import command_from_input, role_name, text_from_content, to_iso

TOOL = "Cursor"


def _connect(path: Path) -> sqlite3.Connection:
    uri = "file:" + quote(path.as_posix(), safe="/:") + "?mode=ro"
    return sqlite3.connect(uri, uri=True)


def _tables(conn: sqlite3.Connection) -> set[str]:
    return {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type IN ('table','view')")}


def _decode(value: object) -> str:
    if isinstance(value, memoryview):
        value = value.tobytes()
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    return str(value or "")


def _kv_get(conn: sqlite3.Connection, tables: set[str], key: str) -> dict | None:
    if "cursorDiskKV" not in tables:
        return None
    row = conn.execute("SELECT value FROM cursorDiskKV WHERE key = ?", (key,)).fetchone()
    if not row:
        return None
    try:
        value = json.loads(_decode(row[0]))
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def _inventory(ledger: CollectionHost, path: Path, note: str) -> None:
    if path.exists():
        ledger.cover(str(path), TOOL, "inventory-only", notes=note)


def parse_cursor(ledger: CollectionHost, store) -> None:
    root = Path(store.path)
    if root.is_file():
        if root.name == "conversation-search.db":
            _parse_conversation_search(root, ledger, workspace_hint="")
        elif root.suffix.lower() in {".vscdb", ".db"}:
            _parse_state_db(root, ledger, workspace_hint="")
        return

    projects = root / "projects"
    if projects.is_dir():
        for path in walk_files(projects, suffixes={".jsonl"}):
            if "agent-transcripts" not in path.parts:
                continue
            ledger.begin_file(path, TOOL)
            _parse_agent_transcript(path, ledger)
            ledger.end_file()

    base = root / "User" if (root / "User").is_dir() else root
    global_state = base / "globalStorage" / "state.vscdb"
    if global_state.is_file():
        _parse_state_db(global_state, ledger, workspace_hint="")

    search_db = base / "globalStorage" / "conversation-search.db"
    if search_db.is_file():
        _parse_conversation_search(search_db, ledger, workspace_hint="")

    for state in base.glob("workspaceStorage/*/state.vscdb"):
        hint = _workspace_hint(state.parent / "workspace.json")
        _parse_state_db(state, ledger, workspace_hint=hint)

    chats = root / "chats"
    if chats.is_dir():
        for state in walk_files(chats, names={"store.db"}):
            _parse_state_db(state, ledger, workspace_hint="")

    for name in ("ai-tracking", "plans", "rules", "skills", "plugins"):
        _inventory(ledger, root / name, "supporting artifact inventoried")
    for name in ("hooks.json", "mcp.json", ".mcp.json", "AGENTS.md", ".cursorrules"):
        _inventory(ledger, root / name, "configuration/instruction context inventoried")


def _workspace_hint(path: Path) -> str:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return ""
    folder = str(data.get("folder") or "")
    return folder_from_uri(folder)


def _parse_agent_transcript(path: Path, ledger: CollectionHost) -> None:
    parts = path.parts
    is_subagent = "subagents" in parts
    session = path.stem if is_subagent else path.parent.name
    slug = ""
    if "projects" in parts:
        index = parts.index("projects")
        if index + 1 < len(parts):
            slug = parts[index + 1]
    workspace = "" if slug in {"", "empty-window"} else slug
    fallback_time = mtime_iso(path)
    file_time = ""
    timestamp_fallback = False

    for obj, offset in iter_jsonl(path, ledger):
        if not isinstance(obj, dict):
            ledger.error()
            continue
        role = role_name(obj.get("role")) or role_name(obj.get("type"))
        message = obj.get("message") if isinstance(obj.get("message"), dict) else {}
        content = message.get("content", obj.get("content"))
        text = text_from_content(content)
        if not file_time:
            file_time = timestamp_tag(text)
        timestamp = file_time or fallback_time

        if text.strip() and role:
            emit(
                ledger,
                tool=TOOL,
                role=role,
                text=text,
                timestamp=timestamp,
                session_id=session,
                workspace=workspace,
                source_file=path,
                source_offset=offset,
                is_subagent=is_subagent,
            )

        if isinstance(content, list):
            for item in content:
                if not isinstance(item, dict):
                    continue
                kind = item.get("type")
                if kind == "tool_use":
                    name = str(item.get("name") or "")
                    args = item.get("input")
                    if isinstance(args, dict):
                        workspace = str(
                            args.get("working_directory")
                            or args.get("target_directory")
                            or workspace
                        )
                    emit(
                        ledger,
                        tool=TOOL,
                        role="tool",
                        record_type="tool_call",
                        invoked_tool=name,
                        tool_input=args,
                        tool_command=command_from_input(args),
                        timestamp=timestamp,
                        session_id=session,
                        workspace=workspace,
                        source_file=path,
                        source_offset=offset,
                        is_subagent=is_subagent,
                    )
                elif kind == "tool_result":
                    result = text_from_content(item.get("content"))
                    if result.strip():
                        emit(
                            ledger,
                            tool=TOOL,
                            role="tool",
                            record_type="tool_result",
                            text=result,
                            timestamp=timestamp,
                            session_id=session,
                            workspace=workspace,
                            source_file=path,
                            source_offset=offset,
                            is_subagent=is_subagent,
                        )

    if not file_time:
        ledger.add_note("transcript has no per-row timestamp; file mtime used as fallback")


def _parse_state_db(path: Path, ledger: CollectionHost, *, workspace_hint: str) -> None:
    ledger.begin_file(path, TOOL)
    try:
        conn = _connect(path)
    except sqlite3.Error as error:
        ledger.force_status("unavailable", f"sqlite open failed: {error}")
        ledger.end_file()
        return
    try:
        tables = _tables(conn)
        if "composerHeaders" in tables:
            _parse_composer_headers(conn, tables, ledger, path, workspace_hint)
        elif "cursorDiskKV" in tables:
            _parse_composer_kv(conn, tables, ledger, path, workspace_hint)
        else:
            ledger.force_status("inventory-only", "no Cursor composer tables found")
    except sqlite3.Error as error:
        ledger.error()
        ledger.force_status("partial", f"sqlite read failed: {error}")
    finally:
        conn.close()
        ledger.end_file()


def _parse_composer_headers(
    conn: sqlite3.Connection,
    tables: set[str],
    ledger: CollectionHost,
    path: Path,
    workspace_hint: str,
) -> None:
    rows = conn.execute(
        """
        SELECT composerId, workspaceId, createdAt, lastUpdatedAt, isArchived, isSubagent
        FROM composerHeaders
        """
    ).fetchall()
    for composer_id, workspace_id, created_at, updated_at, archived, subagent in rows:
        composer = _kv_get(conn, tables, f"composerData:{composer_id}") or {}
        _emit_composer(
            composer,
            composer_id=str(composer_id),
            workspace_id=str(workspace_id or ""),
            created_at=created_at or composer.get("createdAt"),
            updated_at=updated_at or composer.get("lastUpdatedAt"),
            archived=bool(archived),
            subagent=bool(subagent),
            conn=conn,
            tables=tables,
            ledger=ledger,
            path=path,
            workspace_hint=workspace_hint,
        )


def _parse_composer_kv(
    conn: sqlite3.Connection,
    tables: set[str],
    ledger: CollectionHost,
    path: Path,
    workspace_hint: str,
) -> None:
    keys = [
        row[0]
        for row in conn.execute(
            "SELECT key FROM cursorDiskKV WHERE key LIKE 'composerData:%'"
        ).fetchall()
    ]
    for key in keys:
        composer = _kv_get(conn, tables, key)
        if not composer:
            continue
        composer_id = str(composer.get("composerId") or key.split(":", 1)[1])
        _emit_composer(
            composer,
            composer_id=composer_id,
            workspace_id="",
            created_at=composer.get("createdAt"),
            updated_at=composer.get("lastUpdatedAt"),
            archived=bool(composer.get("isArchived")),
            subagent=bool(composer.get("isSubagent")),
            conn=conn,
            tables=tables,
            ledger=ledger,
            path=path,
            workspace_hint=workspace_hint,
        )


def _emit_composer(
    composer: dict,
    *,
    composer_id: str,
    workspace_id: str,
    created_at: object,
    updated_at: object,
    archived: bool,
    subagent: bool,
    conn: sqlite3.Connection,
    tables: set[str],
    ledger: CollectionHost,
    path: Path,
    workspace_hint: str,
) -> None:
    headers = composer.get("fullConversationHeadersOnly") or []
    title = str(composer.get("name") or composer.get("subtitle") or composer.get("title") or "")
    workspace = (
        str(composer.get("workspaceIdentifier") or "")
        if isinstance(composer.get("workspaceIdentifier"), str)
        else workspace_hint
    ) or workspace_hint
    timestamp = to_iso(updated_at) or to_iso(created_at)
    summary = {
        "composerId": composer_id,
        "title": title,
        "workspaceId": workspace_id,
        "workspace": workspace,
        "bubbles": len(headers) if isinstance(headers, list) else 0,
        "archived": archived,
        "subagent": subagent,
        "createdAt": to_iso(created_at),
        "updatedAt": to_iso(updated_at),
    }
    label = title or f"composer {composer_id}"
    readable = (
        f"{label}: {summary['bubbles']} bubbles"
        f"{', archived' if archived else ''}"
        f"{', subagent' if subagent else ''}"
        f"{', workspace ' + workspace if workspace else ''}"
    )
    emit(
        ledger,
        tool=TOOL,
        role="metadata",
        record_type="session",
        text=readable,
        tool_input=summary,
        timestamp=timestamp,
        session_id=composer_id,
        workspace=workspace,
        source_file=path,
        is_subagent=subagent,
    )

    if not isinstance(headers, list):
        return
    for header in headers:
        if not isinstance(header, dict):
            continue
        bubble_id = str(header.get("bubbleId") or "")
        bubble = _kv_get(conn, tables, f"bubbleId:{composer_id}:{bubble_id}") or {}
        bubble_time = to_iso(bubble.get("createdAt")) or to_iso(header.get("createdAt")) or timestamp
        bubble_type = bubble.get("type", header.get("type"))
        role = "user" if bubble_type == 1 else "assistant" if bubble_type == 2 else "metadata"
        text = str(bubble.get("text") or text_of(bubble.get("content")) or "")
        model = ""
        model_info = bubble.get("modelInfo")
        if isinstance(model_info, dict):
            model = str(model_info.get("modelName") or model_info.get("model") or "")
        model = model or str(composer.get("model") or "")

        if text.strip():
            emit(
                ledger,
                tool=TOOL,
                role=role,
                text=text,
                timestamp=bubble_time,
                session_id=composer_id,
                workspace=workspace,
                source_file=path,
                source_offset=0,
                model=model,
                is_subagent=subagent,
            )

        tool_data = bubble.get("toolFormerData")
        if isinstance(tool_data, dict):
            name = str(tool_data.get("name") or "")
            args = tool_data.get("params")
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except ValueError:
                    pass
            if isinstance(args, dict) and not workspace:
                workspace = str(args.get("workingDirectory") or args.get("targetDirectory") or "")
            emit(
                ledger,
                tool=TOOL,
                role="tool",
                record_type="tool_call",
                invoked_tool=name,
                tool_input=args,
                tool_command=command_from_input(args),
                timestamp=bubble_time,
                session_id=composer_id,
                workspace=workspace,
                source_file=path,
                model=model,
                is_subagent=subagent,
            )
            result = tool_data.get("result")
            if isinstance(result, str) and result.strip():
                emit(
                    ledger,
                    tool=TOOL,
                    role="tool",
                    record_type="tool_result",
                    text=result,
                    timestamp=bubble_time,
                    session_id=composer_id,
                    workspace=workspace,
                    source_file=path,
                    model=model,
                    is_subagent=subagent,
                )


def _parse_conversation_search(path: Path, ledger: CollectionHost, *, workspace_hint: str) -> None:
    ledger.begin_file(path, TOOL)
    try:
        conn = _connect(path)
    except sqlite3.Error as error:
        ledger.force_status("unavailable", f"sqlite open failed: {error}")
        ledger.end_file()
        return
    try:
        tables = _tables(conn)
        if "conversations" not in tables or "conversation_fts" not in tables:
            ledger.force_status("inventory-only", "conversation search schema not recognised")
            return
        rows = conn.execute(
            """
            SELECT c.id, c.title, c.scope, c.updated_at, c.is_archived, f.body, c.branches
            FROM conversations c
            JOIN conversation_fts f ON f.rowid = c.fts_rowid
            """
        ).fetchall()
        for conversation_id, title, scope, updated_at, archived, body, branches in rows:
            text = f"{title}\n{body or ''}".strip()
            if not text:
                continue
            emit(
                ledger,
                tool=TOOL,
                role="metadata",
                record_type="conversation_index",
                text=text,
                timestamp=to_iso(updated_at),
                session_id=str(conversation_id or ""),
                workspace=str(scope or workspace_hint),
                source_file=path,
            )
            if branches:
                emit(
                    ledger,
                    tool=TOOL,
                    role="metadata",
                    record_type="conversation_branches",
                    text=str(branches),
                    timestamp=to_iso(updated_at),
                    session_id=str(conversation_id or ""),
                    workspace=str(scope or workspace_hint),
                    source_file=path,
                )
    except sqlite3.Error as error:
        ledger.error()
        ledger.force_status("partial", f"sqlite read failed: {error}")
    finally:
        conn.close()
        ledger.end_file()


__all__ = ["parse_cursor"]
