"""OpenAI Codex parser: history, rollouts, session index, exec policy."""

from __future__ import annotations

import json
import re
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
from ai_forensics.textutil import (
    command_from_input,
    pick_time,
    role_name,
    text_from_content,
)

TOOL = "OpenAI Codex"

_UUID = re.compile(
    r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", re.IGNORECASE
)


def _inventory(ledger: CollectionHost, path: Path, note: str) -> None:
    if path.exists():
        ledger.cover(str(path), TOOL, "inventory-only", notes=note)


def _excluded(ledger: CollectionHost, path: Path) -> None:
    if path.exists():
        ledger.cover(str(path), TOOL, "excluded", notes="credential file inventoried by path only")


def parse_codex(ledger: CollectionHost, store) -> None:
    root = Path(store.path)
    if root.is_file():
        if root.name == "history.jsonl":
            ledger.begin_file(root, TOOL)
            _parse_history(root, ledger)
            ledger.end_file()
        elif root.name == "session_index.jsonl":
            ledger.begin_file(root, TOOL)
            _parse_index(root, ledger)
            ledger.end_file()
        return

    history = root / "history.jsonl"
    if history.is_file():
        ledger.begin_file(history, TOOL)
        _parse_history(history, ledger)
        ledger.end_file()

    index = root / "session_index.jsonl"
    if index.is_file():
        ledger.begin_file(index, TOOL)
        _parse_index(index, ledger)
        ledger.end_file()

    for folder_name in ("sessions", "archived_sessions"):
        folder = root / folder_name
        if folder.is_dir():
            for path in walk_files(folder, suffixes={".jsonl"}):
                ledger.begin_file(path, TOOL)
                _parse_rollout(path, ledger)
                ledger.end_file()

    rules = root / "rules"
    if rules.is_dir():
        for path in walk_files(rules, suffixes={".rules"}):
            ledger.begin_file(path, TOOL)
            _parse_rules(path, ledger)
            ledger.end_file()

    for name in ("config.toml", "AGENTS.md", "instructions.md", "hooks.json"):
        _inventory(ledger, root / name, "configuration/instruction context inventoried")

    global_state = root / ".codex-global-state.json"
    if global_state.is_file():
        ledger.begin_file(global_state, TOOL)
        data = read_json(global_state, ledger)
        if data is not None:
            emit(
                ledger,
                tool=TOOL,
                role="metadata",
                record_type="remote_control_state",
                text=json.dumps(redact_structure(data), sort_keys=True, default=str),
                timestamp=mtime_iso(global_state),
                source_file=global_state,
            )
        ledger.end_file()

    for folder_name in (
        "memories",
        "skills",
        "plugins",
        "shell_snapshots",
        "ambient-suggestions",
        "dictation-history",
    ):
        _inventory(ledger, root / folder_name, "supporting artifact inventoried")

    for pattern in ("state*.sqlite", "thread_history*.sqlite", "logs*.sqlite", "memories*.sqlite"):
        for path in root.glob(pattern):
            ledger.cover(
                str(path),
                TOOL,
                "inventory-only",
                notes="SQLite projection inventoried; schema not decoded in MVP",
                files_read=0,
            )

    _excluded(ledger, root / "auth.json")


def _parse_history(path: Path, ledger: CollectionHost) -> None:
    for obj, offset in iter_jsonl(path, ledger):
        if not isinstance(obj, dict):
            ledger.error()
            continue
        text = str(obj.get("text") or obj.get("display") or "").strip()
        if not text:
            continue
        emit(
            ledger,
            tool=TOOL,
            role="user",
            record_type="prompt_history",
            text=text,
            timestamp=pick_time(obj),
            session_id=str(obj.get("session_id") or obj.get("sessionId") or ""),
            source_file=path,
            source_offset=offset,
        )


def _parse_index(path: Path, ledger: CollectionHost) -> None:
    for obj, offset in iter_jsonl(path, ledger):
        if not isinstance(obj, dict):
            ledger.error()
            continue
        title = str(obj.get("thread_name") or obj.get("title") or "").strip()
        if not title:
            continue
        emit(
            ledger,
            tool=TOOL,
            role="metadata",
            record_type="session_index",
            text=title,
            timestamp=pick_time(obj),
            session_id=str(obj.get("id") or ""),
            source_file=path,
            source_offset=offset,
        )


def _parse_rules(path: Path, ledger: CollectionHost) -> None:
    text = read_text(path, ledger)
    for block in re.split(r"prefix_rule\s*\(", text)[1:]:
        pattern = re.search(r"pattern\s*=\s*(\[[^\]]*\])", block, re.S)
        decision = re.search(r'decision\s*=\s*"([^"]+)"', block)
        if not pattern:
            continue
        prefix = " ".join(re.findall(r'"([^"]*)"', pattern.group(1)))
        verdict = decision.group(1) if decision else "unknown"
        emit(
            ledger,
            tool=TOOL,
            role="metadata",
            record_type="exec_policy_rule",
            text=f"Exec policy prefix [{prefix}] has decision {verdict}",
            tool_command=prefix,
            timestamp=mtime_iso(path),
            source_file=path,
        )


def _session_from_name(path: Path) -> str:
    match = _UUID.search(path.name)
    return match.group(1) if match else path.stem


def _parse_rollout(path: Path, ledger: CollectionHost) -> None:
    session = _session_from_name(path)
    workspace = ""
    model = ""
    is_subagent = "subagent" in path.name.lower() or "subagents" in path.parts

    for obj, offset in iter_jsonl(path, ledger):
        if not isinstance(obj, dict):
            ledger.error()
            continue
        kind = str(obj.get("type") or "")
        payload = obj.get("payload") if isinstance(obj.get("payload"), dict) else {}
        timestamp = pick_time(obj) or pick_time(payload)

        if kind in {"session_meta", "session_start"}:
            session = str(payload.get("id") or payload.get("session_id") or session)
            workspace = str(payload.get("cwd") or workspace)
            if payload.get("parent_thread_id") or payload.get("parent_id"):
                is_subagent = True
            meta = {
                key: payload.get(key)
                for key in ("id", "cwd", "originator", "cli_version", "model", "source")
                if payload.get(key) is not None
            }
            emit(
                ledger,
                tool=TOOL,
                role="metadata",
                record_type="session",
                text=json.dumps(meta, sort_keys=True, default=str),
                timestamp=timestamp,
                session_id=session,
                workspace=workspace,
                source_file=path,
                source_offset=offset,
                is_subagent=is_subagent,
            )
        elif kind == "turn_context":
            model = str(payload.get("model") or model)
            workspace = str(payload.get("cwd") or workspace)
            emit(
                ledger,
                tool=TOOL,
                role="metadata",
                record_type="turn_context",
                text=json.dumps(redact_structure(payload), sort_keys=True, default=str),
                timestamp=timestamp,
                session_id=session,
                workspace=workspace,
                source_file=path,
                source_offset=offset,
                model=model,
                is_subagent=is_subagent,
            )
        elif kind == "response_item":
            _response_item(payload, ledger, path, offset, timestamp, session, workspace, model, is_subagent)
        elif kind == "event_msg":
            _event_msg(payload, ledger, path, offset, timestamp, session, workspace, model, is_subagent)
        elif kind in {"compacted", "context_compacted"}:
            text = text_from_content(payload.get("message") or payload.get("summary"))
            if text.strip():
                emit(
                    ledger,
                    tool=TOOL,
                    role="metadata",
                    record_type="summary",
                    text=text,
                    timestamp=timestamp,
                    session_id=session,
                    workspace=workspace,
                    source_file=path,
                    source_offset=offset,
                    is_subagent=is_subagent,
                )


def _response_item(
    payload: dict,
    ledger: CollectionHost,
    path: Path,
    offset: int,
    timestamp: str,
    session: str,
    workspace: str,
    model: str,
    is_subagent: bool,
) -> None:
    kind = str(payload.get("type") or "")
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
    if kind == "message":
        role = role_name(payload.get("role"))
        text = text_from_content(payload.get("content"))
        if role and text.strip():
            emit(ledger, role=role, text=text, **common)
    elif kind in {"function_call", "custom_tool_call", "local_shell_call"}:
        name = str(payload.get("name") or payload.get("type") or "Shell")
        args = payload.get("arguments", payload.get("input", payload.get("action")))
        emit(
            ledger,
            role="tool",
            record_type="tool_call",
            invoked_tool=name,
            tool_input=args,
            tool_command=command_from_input(args),
            **common,
        )
    elif kind in {"function_call_output", "custom_tool_call_output"}:
        text = text_from_content(payload.get("output"))
        if text.strip():
            emit(ledger, role="tool", record_type="tool_result", text=text, **common)
    elif kind == "reasoning":
        text = text_from_content(payload.get("summary") or payload.get("content"))
        if text.strip():
            emit(ledger, role="assistant", record_type="reasoning", text=text, **common)
    elif kind == "web_search_call":
        action = payload.get("action") if isinstance(payload.get("action"), dict) else {}
        query = str(action.get("query") or action.get("url") or "")
        emit(
            ledger,
            role="tool",
            record_type="tool_call",
            invoked_tool="web_search",
            tool_command=query,
            **common,
        )


def _event_msg(
    payload: dict,
    ledger: CollectionHost,
    path: Path,
    offset: int,
    timestamp: str,
    session: str,
    workspace: str,
    model: str,
    is_subagent: bool,
) -> None:
    kind = str(payload.get("type") or "")
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
    if kind in {"user_message", "agent_message"}:
        text = text_from_content(payload.get("message") or payload.get("text"))
        role = "user" if kind == "user_message" else "assistant"
        if text.strip():
            emit(ledger, role=role, text=text, **common)
    elif kind == "agent_reasoning":
        text = text_from_content(payload.get("text"))
        if text.strip():
            emit(ledger, role="assistant", record_type="reasoning", text=text, **common)
    elif kind in {"exec_command_begin", "exec_command_end"}:
        command = payload.get("command")
        if isinstance(command, list):
            command = " ".join(str(part) for part in command)
        output = payload.get("aggregated_output") or payload.get("stdout") or payload.get("stderr") or ""
        emit(
            ledger,
            role="tool",
            record_type="tool_call" if kind == "exec_command_begin" else "tool_result",
            invoked_tool="Shell",
            tool_command=command_from_input(command),
            tool_input=payload,
            text=text_from_content(output),
            **common,
        )
    elif kind in {"mcp_tool_call_begin", "mcp_tool_call_end"}:
        name = str(payload.get("tool") or payload.get("name") or "mcp")
        emit(
            ledger,
            role="tool",
            record_type="tool_call" if kind.endswith("begin") else "tool_result",
            invoked_tool=name,
            tool_input=payload,
            tool_command=command_from_input(payload.get("arguments")),
            text=text_from_content(payload.get("result")),
            **common,
        )
    elif kind in {"patch_apply_begin", "patch_apply_end", "token_count", "error", "stream_error"}:
        emit(
            ledger,
            role="metadata",
            record_type=kind,
            text=json.dumps(redact_structure(payload), sort_keys=True, default=str),
            **common,
        )


__all__ = ["parse_codex"]
