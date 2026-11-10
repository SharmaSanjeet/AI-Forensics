"""GitHub Copilot CLI and VS Code-family chat session parsers."""

from __future__ import annotations

import json
from pathlib import Path

from ai_forensics.collect.parsers.common import (
    emit,
    folder_from_uri,
    iter_jsonl,
    read_json,
    walk_files,
)
from ai_forensics.ledger import CollectionHost
from ai_forensics.secrets import redact_structure
from ai_forensics.textutil import command_from_input, pick_time, text_from_content, to_iso

TOOL = "GitHub Copilot"


def _inventory(ledger: CollectionHost, path: Path, note: str) -> None:
    if path.exists():
        ledger.cover(str(path), TOOL, "inventory-only", notes=note)


def parse_copilot(ledger: CollectionHost, store) -> None:
    root = Path(store.path)
    if root.is_file():
        if root.name == "events.jsonl":
            ledger.begin_file(root, TOOL)
            _parse_events(root, ledger)
            ledger.end_file()
        return

    state = root / "session-state"
    if state.is_dir():
        for path in walk_files(state, names={"events.jsonl"}):
            ledger.begin_file(path, TOOL)
            _parse_events(path, ledger)
            ledger.end_file()
        for folder in state.iterdir():
            if folder.is_dir() and not any(folder.glob("events.jsonl")):
                _inventory(ledger, folder, "session state without events.jsonl inventoried")

    _inventory(ledger, root / "logs", "CLI logs inventoried")
    for name in ("history-session-state", "session-store.db"):
        _inventory(ledger, root / name, "Copilot support store inventoried")


def _parse_events(path: Path, ledger: CollectionHost) -> None:
    session = path.parent.name
    workspace = ""
    model = ""
    for obj, offset in iter_jsonl(path, ledger):
        if not isinstance(obj, dict):
            ledger.error()
            continue
        kind = str(obj.get("type") or "")
        data = obj.get("data") if isinstance(obj.get("data"), dict) else {}
        timestamp = pick_time(obj)
        session = str(data.get("sessionId") or session)
        if isinstance(data.get("context"), dict):
            workspace = str(data["context"].get("cwd") or workspace)
        model = str(data.get("model") or data.get("selectedModel") or model)
        is_subagent = bool(data.get("parentAgentTaskId"))

        common = dict(
            tool=TOOL,
            timestamp=timestamp,
            session_id=session,
            workspace=workspace,
            source_file=path,
            source_offset=offset,
            model=model,
            is_subagent=is_subagent,
        )

        if kind == "user.message":
            text = str(data.get("content") or "")
            if text.strip():
                emit(ledger, role="user", text=text, **common)
        elif kind == "assistant.message":
            text = str(data.get("content") or "")
            if text.strip():
                emit(ledger, role="assistant", text=text, **common)
            for request in data.get("toolRequests") or []:
                if isinstance(request, dict):
                    _tool_request(request, ledger, common)
        elif kind == "system.message":
            text = str(data.get("content") or "")
            if text.strip():
                emit(ledger, role="system", text=text, **common)
        elif kind == "tool.execution_start":
            _tool_request(
                {
                    "name": data.get("toolName"),
                    "arguments": data.get("arguments"),
                    "toolCallId": data.get("toolCallId"),
                },
                ledger,
                common,
            )
        elif kind == "tool.execution_complete":
            result = data.get("result")
            text = text_from_content(result.get("content") if isinstance(result, dict) else result)
            if text.strip():
                emit(ledger, role="tool", record_type="tool_result", text=text, **common)
        elif kind == "permission.requested":
            request = data.get("permissionRequest") if isinstance(data.get("permissionRequest"), dict) else {}
            emit(
                ledger,
                role="metadata",
                record_type="permission_request",
                text=json.dumps(
                    {
                        "toolName": request.get("toolName"),
                        "kind": request.get("kind"),
                        "description": request.get("toolDescription"),
                    },
                    sort_keys=True,
                    default=str,
                ),
                invoked_tool=str(request.get("toolName") or ""),
                tool_input=request.get("args"),
                **common,
            )
        elif kind == "permission.completed":
            emit(
                ledger,
                role="metadata",
                record_type="permission_result",
                text=json.dumps(redact_structure(data), sort_keys=True, default=str),
                **common,
            )
        elif kind in {"session.start", "session.auto_mode_resolved", "session.usage_record", "session.usage_checkpoint", "abort"}:
            emit(
                ledger,
                role="metadata",
                record_type=kind.replace(".", "_"),
                text=json.dumps(redact_structure(data), sort_keys=True, default=str),
                **common,
            )
        elif kind in {"hook.start", "hook.end"}:
            emit(
                ledger,
                role="metadata",
                record_type="hook",
                text=json.dumps(redact_structure(data), sort_keys=True, default=str),
                **common,
            )
        elif kind in {"external_tool.requested", "external_tool.completed"}:
            request = data.get("request") if isinstance(data.get("request"), dict) else data
            _tool_request(
                {
                    "name": request.get("toolName") or request.get("name") or "external_tool",
                    "arguments": request.get("arguments") or request.get("input"),
                },
                ledger,
                common,
            )


def _tool_request(request: dict, ledger: CollectionHost, common: dict) -> None:
    name = str(request.get("name") or request.get("toolName") or "")
    args = request.get("arguments", request.get("input"))
    emit(
        ledger,
        role="tool",
        record_type="tool_call",
        invoked_tool=name,
        tool_input=args,
        tool_command=command_from_input(args),
        **common,
    )


def parse_vscode_chats(ledger: CollectionHost, store) -> None:
    root = Path(store.path)
    if root.is_file() and root.suffix.lower() == ".json":
        _parse_chat_file(root, ledger, workspace_hint="")
        return
    base = root / "User" if (root / "User").is_dir() else root
    storage = base / "workspaceStorage"
    if storage.is_dir():
        for folder in storage.iterdir():
            if not folder.is_dir():
                continue
            hint = _workspace_hint(folder / "workspace.json")
            for name in ("chatSessions", "emptyWindowChatSessions"):
                chats = folder / name
                if chats.is_dir():
                    for path in walk_files(chats, suffixes={".json"}):
                        _parse_chat_file(path, ledger, workspace_hint=hint)
    global_empty = base / "globalStorage" / "emptyWindowChatSessions"
    if global_empty.is_dir():
        for path in walk_files(global_empty, suffixes={".json"}):
            _parse_chat_file(path, ledger, workspace_hint="")


def _workspace_hint(path: Path) -> str:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return ""
    folder = data.get("folder") if isinstance(data, dict) else None
    if isinstance(folder, str):
        return folder_from_uri(folder)
    return ""


def _parse_chat_file(path: Path, ledger: CollectionHost, *, workspace_hint: str) -> None:
    data = read_json(path, ledger)
    if not isinstance(data, dict):
        return
    requests = data.get("requests")
    if not isinstance(requests, list):
        return
    session = path.stem
    for request in requests:
        if not isinstance(request, dict):
            continue
        timestamp = to_iso(request.get("timestamp"))
        model = str(request.get("modelId") or "")
        message = request.get("message") if isinstance(request.get("message"), dict) else {}
        user_text = str(message.get("text") or "")
        if user_text.strip():
            emit(
                ledger,
                tool=TOOL,
                role="user",
                text=user_text,
                timestamp=timestamp,
                session_id=session,
                workspace=workspace_hint,
                source_file=path,
                model=model,
            )
        response = request.get("response")
        if isinstance(response, list):
            parts = []
            for item in response:
                if isinstance(item, dict):
                    value = item.get("value", item.get("text", item.get("content")))
                    if isinstance(value, str):
                        parts.append(value)
            text = "\n".join(parts).strip()
            if text:
                emit(
                    ledger,
                    tool=TOOL,
                    role="assistant",
                    text=text,
                    timestamp=timestamp,
                    session_id=session,
                    workspace=workspace_hint,
                    source_file=path,
                    model=model,
                )
        tools = request.get("toolInvocationSerialized")
        if isinstance(tools, dict):
            tools = [tools]
        if isinstance(tools, list):
            for tool in tools:
                if not isinstance(tool, dict):
                    continue
                name = str(tool.get("toolId") or tool.get("toolName") or "")
                args = tool.get("toolSpecificData") or tool.get("input")
                command = ""
                if isinstance(args, dict):
                    command_line = args.get("commandLine")
                    if isinstance(command_line, dict):
                        command = str(command_line.get("original") or command_line.get("toolEdited") or "")
                emit(
                    ledger,
                    tool=TOOL,
                    role="tool",
                    record_type="tool_call",
                    invoked_tool=name,
                    tool_input=args,
                    tool_command=command or command_from_input(args),
                    timestamp=timestamp,
                    session_id=session,
                    workspace=workspace_hint,
                    source_file=path,
                    model=model,
                )


__all__ = ["parse_copilot", "parse_vscode_chats"]
