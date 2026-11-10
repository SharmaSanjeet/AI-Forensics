"""Gemini CLI parser: chat JSONL, shell history, legacy sessions, settings."""

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
)
from ai_forensics.ledger import CollectionHost
from ai_forensics.secrets import redact_structure
from ai_forensics.textutil import command_from_input, pick_time, role_name, text_from_content

TOOL = "Gemini CLI"


def _inventory(ledger: CollectionHost, path: Path, note: str) -> None:
    if path.exists():
        ledger.cover(str(path), TOOL, "inventory-only", notes=note)


def _excluded(ledger: CollectionHost, path: Path) -> None:
    if path.exists():
        ledger.cover(str(path), TOOL, "excluded", notes="credential file inventoried by path only")


def parse_gemini(ledger: CollectionHost, store) -> None:
    root = Path(store.path)
    if root.is_file():
        if root.name == "shell_history":
            ledger.begin_file(root, TOOL)
            _parse_shell_history(root, ledger)
            ledger.end_file()
        elif root.suffix.lower() == ".jsonl":
            ledger.begin_file(root, TOOL)
            _parse_chat_jsonl(root, ledger)
            ledger.end_file()
        return

    for folder_name in ("tmp", "history"):
        folder = root / folder_name
        if folder.is_dir():
            for path in walk_files(folder, suffixes={".jsonl"}):
                ledger.begin_file(path, TOOL)
                _parse_chat_jsonl(path, ledger)
                ledger.end_file()
            for path in walk_files(folder, suffixes={".json"}):
                ledger.begin_file(path, TOOL)
                _parse_chat_json(path, ledger)
                ledger.end_file()

    shell_history = root / "shell_history"
    if shell_history.is_file():
        ledger.begin_file(shell_history, TOOL)
        _parse_shell_history(shell_history, ledger)
        ledger.end_file()

    for path in root.glob("session-*.json"):
        ledger.begin_file(path, TOOL)
        _parse_chat_json(path, ledger)
        ledger.end_file()

    for name in ("projects.json", "settings.json", "google_accounts.json", "installation_id", "user_id"):
        path = root / name
        if path.is_file():
            ledger.begin_file(path, TOOL)
            _config_row(ledger, path, "config")
            ledger.end_file()

    trusted = root / "trustedFolders.json"
    if trusted.is_file():
        ledger.begin_file(trusted, TOOL)
        _config_row(ledger, trusted, "trusted_folder")
        ledger.end_file()

    for name in ("GEMINI.md", "skills", "policies", "checkpoints"):
        _inventory(ledger, root / name, "supporting artifact inventoried")

    for name in ("oauth_creds.json", "mcp-tokens.json", "a2a-tokens.json"):
        _excluded(ledger, root / name)


def _config_row(ledger: CollectionHost, path: Path, record_type: str) -> None:
    data = read_json(path, ledger)
    if data is None:
        text = read_text(path, ledger, limit=4096).strip()
    else:
        text = json.dumps(redact_structure(data), sort_keys=True, default=str)
    if not text:
        return
    emit(
        ledger,
        tool=TOOL,
        role="metadata",
        record_type=record_type,
        text=f"{path.name}: {text}",
        timestamp=mtime_iso(path),
        source_file=path,
    )


def _parse_shell_history(path: Path, ledger: CollectionHost) -> None:
    text = read_text(path, ledger)
    stamp = mtime_iso(path)
    ledger.add_note("shell history has no per-command time; file mtime retained as fallback")
    for line in text.splitlines():
        command = line.strip()
        if not command:
            continue
        emit(
            ledger,
            tool=TOOL,
            role="tool",
            record_type="shell_history",
            invoked_tool="Shell",
            tool_command=command,
            text=command,
            timestamp=stamp,
            source_file=path,
        )


def _parse_chat_jsonl(path: Path, ledger: CollectionHost) -> None:
    session = path.stem
    for obj, offset in iter_jsonl(path, ledger):
        if not isinstance(obj, dict):
            ledger.error()
            continue
        _chat_object(obj, ledger, path, offset, session)


def _parse_chat_json(path: Path, ledger: CollectionHost) -> None:
    data = read_json(path, ledger)
    if data is None:
        return
    session = path.stem
    items = data if isinstance(data, list) else data.get("messages") if isinstance(data, dict) else None
    if isinstance(items, list):
        for obj in items:
            if isinstance(obj, dict):
                _chat_object(obj, ledger, path, 0, session)
    elif isinstance(data, dict):
        _chat_object(data, ledger, path, 0, session)


def _chat_object(
    obj: dict, ledger: CollectionHost, path: Path, offset: int, session: str
) -> None:
    kind = str(obj.get("type") or obj.get("role") or "")
    role = role_name(kind) or role_name(obj.get("role"))
    timestamp = pick_time(obj)
    session_id = str(obj.get("sessionId") or obj.get("session_id") or session)
    workspace = str(obj.get("cwd") or obj.get("project") or "")
    text = text_from_content(
        obj.get("content", obj.get("message", obj.get("text", obj.get("parts"))))
    )
    record_type = "message"
    if kind in {"info", "error", "debug", "warning"}:
        record_type = kind
        role = role or "metadata"
    if kind in {"thought", "thoughts", "reasoning"}:
        record_type = "reasoning"
        role = "assistant"

    if text.strip() and role:
        emit(
            ledger,
            tool=TOOL,
            role=role,
            record_type=record_type,
            text=text,
            timestamp=timestamp,
            session_id=session_id,
            workspace=workspace,
            source_file=path,
            source_offset=offset,
        )

    for key in ("functionCall", "function_call"):
        call = obj.get(key)
        if isinstance(call, dict):
            _tool_call(call, ledger, path, offset, timestamp, session_id, workspace)
    for key in ("toolCalls", "tool_calls"):
        calls = obj.get(key)
        if isinstance(calls, list):
            for call in calls:
                if isinstance(call, dict):
                    _tool_call(call, ledger, path, offset, timestamp, session_id, workspace)

    response = obj.get("functionResponse") or obj.get("function_response")
    if isinstance(response, dict):
        result = text_from_content(response.get("response") or response.get("result"))
        if result.strip():
            emit(
                ledger,
                tool=TOOL,
                role="tool",
                record_type="tool_result",
                text=result,
                timestamp=timestamp,
                session_id=session_id,
                workspace=workspace,
                source_file=path,
                source_offset=offset,
            )


def _tool_call(
    call: dict,
    ledger: CollectionHost,
    path: Path,
    offset: int,
    timestamp: str,
    session: str,
    workspace: str,
) -> None:
    name = str(call.get("name") or call.get("toolName") or "")
    args = call.get("args", call.get("arguments", call.get("input")))
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
    )


__all__ = ["parse_gemini"]
