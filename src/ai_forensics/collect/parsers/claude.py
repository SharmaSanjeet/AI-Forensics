"""Claude Code and Claude Desktop parsers."""

from __future__ import annotations

import json
from pathlib import Path

from ai_forensics.collect.parsers.common import (
    emit,
    iter_jsonl,
    mtime_iso,
    read_json,
    read_text,
    walk_files,
    walk_named,
)
from ai_forensics.ledger import CollectionHost
from ai_forensics.secrets import redact_structure
from ai_forensics.textutil import (
    command_from_input,
    pick_time,
    role_name,
    text_from_content,
    to_iso,
)

TOOL_CODE = "Claude Code"
TOOL_DESKTOP = "Claude Desktop"

_INVENTORY_DIRS = (
    "backups",
    "cache",
    "downloads",
    "file-history",
    "plugins",
    "skills",
    "plans",
    "tasks",
    "todos",
    "shell-snapshots",
    "statsig",
    "ide",
)


def _inventory(ledger: CollectionHost, path: Path, tool: str, note: str) -> None:
    if path.exists():
        ledger.cover(str(path), tool, "inventory-only", notes=note)


def _excluded(ledger: CollectionHost, path: Path, tool: str, note: str) -> None:
    if path.exists():
        ledger.cover(str(path), tool, "excluded", notes=note)


def _config_row(
    ledger: CollectionHost,
    path: Path,
    tool: str,
    *,
    record_type: str = "config",
    workspace: str = "",
) -> None:
    data = read_json(path, ledger)
    if data is None:
        return
    clean = redact_structure(data)
    text = json.dumps(clean, sort_keys=True, default=str)
    emit(
        ledger,
        tool=tool,
        role="metadata",
        record_type=record_type,
        text=f"{path.name}: {text}",
        timestamp=mtime_iso(path),
        workspace=workspace,
        source_file=path,
    )


def parse_claude_code(ledger: CollectionHost, store) -> None:
    root = Path(store.path)
    if root.is_file():
        if root.name == ".claude.json":
            _config_row(ledger, root, TOOL_CODE)
        return

    history = root / "history.jsonl"
    if history.is_file():
        ledger.begin_file(history, TOOL_CODE)
        _parse_history(history, ledger)
        ledger.end_file()

    projects = root / "projects"
    if projects.is_dir():
        for path in walk_files(projects, suffixes={".jsonl"}):
            ledger.begin_file(path, TOOL_CODE)
            _parse_transcript(path, ledger, TOOL_CODE)
            ledger.end_file()

    config = root / ".claude.json"
    if config.is_file():
        ledger.begin_file(config, TOOL_CODE)
        _config_row(ledger, config, TOOL_CODE)
        ledger.end_file()

    for name in ("settings.json", ".mcp.json"):
        path = root / name
        if path.is_file():
            ledger.begin_file(path, TOOL_CODE)
            _config_row(ledger, path, TOOL_CODE)
            ledger.end_file()

    for name in ("CLAUDE.md", "MEMORY.md"):
        _inventory(ledger, root / name, TOOL_CODE, "instruction/memory context inventoried")
    for name in _INVENTORY_DIRS:
        _inventory(ledger, root / name, TOOL_CODE, "supporting directory inventoried")
    _excluded(
        ledger,
        root / ".credentials.json",
        TOOL_CODE,
        "credential store inventoried by path only; contents never read",
    )


def parse_claude_desktop(ledger: CollectionHost, store) -> None:
    root = Path(store.path)
    if root.is_file():
        return

    for name in ("projects", "local-agent-mode-sessions", "claude-code-sessions"):
        folder = root / name
        if folder.is_dir():
            for path in walk_files(folder, suffixes={".jsonl"}):
                ledger.begin_file(path, TOOL_DESKTOP)
                _parse_transcript(path, ledger, TOOL_DESKTOP)
                ledger.end_file()

    for name in ("plan-usage-history.json", "scheduled-tasks.json", "git-worktrees.json", "bridge-state.json"):
        path = root / name
        if path.is_file():
            ledger.begin_file(path, TOOL_DESKTOP)
            record_type = {
                "plan-usage-history.json": "usage_window",
                "scheduled-tasks.json": "scheduled_task",
                "git-worktrees.json": "workspace_sighting",
                "bridge-state.json": "remote_control",
            }[name]
            _config_row(ledger, path, TOOL_DESKTOP, record_type=record_type)
            ledger.end_file()

    for name in ("claude_desktop_config.json", "config.json", "settings.json"):
        path = root / name
        if path.is_file():
            ledger.begin_file(path, TOOL_DESKTOP)
            _config_row(ledger, path, TOOL_DESKTOP)
            ledger.end_file()

    for tombstone in walk_named(root, r"^deleted_"):
        session = tombstone.name[len("deleted_"):]
        stamp = to_iso(read_text(tombstone, ledger, limit=200).strip()) or mtime_iso(tombstone)
        emit(
            ledger,
            tool=TOOL_DESKTOP,
            role="metadata",
            record_type="deletion_tombstone",
            text=f"Claude session {session} was deleted",
            timestamp=stamp,
            session_id=session,
            source_file=tombstone,
        )

    uploads = root / "pending-uploads"
    if uploads.is_dir():
        for path in walk_files(uploads):
            _inventory(ledger, path, TOOL_DESKTOP, "staged upload inventoried; content never read")

    for local in root.rglob("local_*.json"):
        _inventory(ledger, local, TOOL_DESKTOP, "Cowork session metadata inventoried; transcript not decoded in MVP")

    _excluded(ledger, root / ".audit-key", TOOL_DESKTOP, "audit key inventoried by path only")


def _parse_history(path: Path, ledger: CollectionHost) -> None:
    for obj, offset in iter_jsonl(path, ledger):
        if not isinstance(obj, dict):
            ledger.error()
            continue
        text = str(obj.get("display") or obj.get("text") or "").strip()
        if not text:
            continue
        emit(
            ledger,
            tool=TOOL_CODE,
            role="user",
            record_type="prompt_history",
            text=text,
            timestamp=pick_time(obj),
            workspace=str(obj.get("project") or ""),
            source_file=path,
            source_offset=offset,
        )


def _parse_transcript(path: Path, ledger: CollectionHost, tool: str) -> None:
    session = path.stem
    for obj, offset in iter_jsonl(path, ledger):
        if not isinstance(obj, dict):
            ledger.error()
            continue
        kind = str(obj.get("type") or "")
        message = obj.get("message") if isinstance(obj.get("message"), dict) else {}
        role = role_name(message.get("role")) or role_name(kind)
        timestamp = pick_time(obj) or pick_time(message)
        session_id = str(obj.get("sessionId") or obj.get("session_id") or session)
        workspace = str(obj.get("cwd") or obj.get("project") or "")
        model = str(message.get("model") or obj.get("model") or "")
        is_subagent = bool(obj.get("isSidechain") or obj.get("is_sidechain"))

        if kind == "summary":
            text = str(obj.get("summary") or "").strip()
            if text:
                emit(
                    ledger,
                    tool=tool,
                    role="metadata",
                    record_type="summary",
                    text=text,
                    timestamp=timestamp,
                    session_id=session_id,
                    workspace=workspace,
                    source_file=path,
                    source_offset=offset,
                    model=model,
                )
            continue

        content = message.get("content", obj.get("content"))
        text = text_from_content(content)
        if text.strip() and role:
            emit(
                ledger,
                tool=tool,
                role=role,
                text=text,
                timestamp=timestamp,
                session_id=session_id,
                workspace=workspace,
                source_file=path,
                source_offset=offset,
                model=model,
                is_subagent=is_subagent,
            )

        if isinstance(content, list):
            for item in content:
                if not isinstance(item, dict):
                    continue
                item_type = item.get("type")
                if item_type == "tool_use":
                    name = str(item.get("name") or "")
                    args = item.get("input")
                    description = ""
                    if isinstance(args, dict):
                        description = str(args.get("description") or "")
                    emit(
                        ledger,
                        tool=tool,
                        role="tool",
                        record_type="tool_call",
                        invoked_tool=name,
                        tool_input=args,
                        tool_command=command_from_input(args),
                        tool_description=description,
                        timestamp=timestamp,
                        session_id=session_id,
                        workspace=workspace,
                        source_file=path,
                        source_offset=offset,
                        model=model,
                        is_subagent=is_subagent,
                    )
                elif item_type == "tool_result":
                    result = text_from_content(item.get("content"))
                    if result.strip():
                        emit(
                            ledger,
                            tool=tool,
                            role="tool",
                            record_type="tool_result",
                            text=result,
                            timestamp=timestamp,
                            session_id=session_id,
                            workspace=workspace,
                            source_file=path,
                            source_offset=offset,
                            model=model,
                            is_subagent=is_subagent,
                        )


__all__ = ["parse_claude_code", "parse_claude_desktop"]
