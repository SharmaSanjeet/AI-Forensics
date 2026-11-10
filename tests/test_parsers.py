from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from ai_forensics.collect.parsers.claude import parse_claude_code
from ai_forensics.collect.parsers.codex import parse_codex
from ai_forensics.collect.parsers.copilot import parse_copilot, parse_vscode_chats
from ai_forensics.collect.parsers.cursor import parse_cursor
from ai_forensics.collect.parsers.gemini import parse_gemini

from support import rows, store, write_json, write_jsonl, write_text


def test_claude_code_transcript_and_tool_calls(host, tmp_path):
    root = tmp_path / "claude"
    write_jsonl(
        root / "projects" / "ws" / "session-1.jsonl",
        [
            {
                "type": "user",
                "timestamp": "2026-05-01T10:00:00Z",
                "sessionId": "sess-1",
                "cwd": "C:\\work",
                "message": {"role": "user", "content": "Please list files"},
            },
            {
                "type": "assistant",
                "timestamp": "2026-05-01T10:00:05Z",
                "sessionId": "sess-1",
                "cwd": "C:\\work",
                "message": {
                    "role": "assistant",
                    "model": "claude-sonnet-4",
                    "content": [
                        {"type": "text", "text": "Running ls"},
                        {
                            "type": "tool_use",
                            "name": "Bash",
                            "input": {"command": "ls -la", "description": "list files"},
                        },
                    ],
                },
            },
            {
                "type": "assistant",
                "timestamp": "2026-05-01T10:00:06Z",
                "sessionId": "sess-1",
                "cwd": "C:\\work",
                "message": {
                    "role": "user",
                    "content": [{"type": "tool_result", "content": "file1 file2"}],
                },
            },
        ],
    )

    parse_claude_code(host, store(root))
    found = rows(host)

    user = next(item for item in found if item["role"] == "user")
    assert user["summary"] == "Please list files"
    assert user["tool"] == "Claude Code"
    assert user["sessionId"] == "sess-1"
    assert user["workspace"] == "C:\\work"

    assistant = next(item for item in found if item["role"] == "assistant" and item["summary"] == "Running ls")
    assert assistant["timestamp"] == "2026-05-01T10:00:05Z"
    assert assistant["recordType"] == "message"

    call = next(item for item in found if item["recordType"] == "tool_call")
    assert call["invokedTool"] == "Bash"
    assert call["toolCommand"] == "ls -la"

    result = next(item for item in found if item["recordType"] == "tool_result")
    assert result["role"] == "tool"


def test_codex_rollout_session_message_and_shell(host, tmp_path):
    root = tmp_path / "codex"
    write_jsonl(
        root / "sessions" / "2026" / "rollout-abc.jsonl",
        [
            {
                "type": "session_meta",
                "timestamp": "2026-05-02T11:00:00Z",
                "payload": {"id": "thread-1", "cwd": "/repo", "model": "gpt-5"},
            },
            {
                "type": "response_item",
                "timestamp": "2026-05-02T11:00:01Z",
                "payload": {
                    "type": "message",
                    "role": "user",
                    "content": [{"type": "input_text", "text": "Run tests"}],
                },
            },
            {
                "type": "event_msg",
                "timestamp": "2026-05-02T11:00:02Z",
                "payload": {"type": "exec_command_begin", "command": ["bash", "-lc", "pytest -q"]},
            },
            {
                "type": "event_msg",
                "timestamp": "2026-05-02T11:00:09Z",
                "payload": {"type": "exec_command_end", "aggregated_output": "5 passed"},
            },
        ],
    )

    parse_codex(host, store(root))
    found = rows(host)

    session = next(item for item in found if item["recordType"] == "session")
    assert session["role"] == "metadata"

    user = next(item for item in found if item["role"] == "user")
    assert user["summary"] == "Run tests"
    assert user["workspace"] == "/repo"

    call = next(item for item in found if item["recordType"] == "tool_call")
    assert call["invokedTool"] == "Shell"
    assert call["toolCommand"] == "bash -lc pytest -q"

    result = next(item for item in found if item["recordType"] == "tool_result")
    assert result["summary"] == "5 passed"


def test_cursor_state_db_composer_bubbles_and_tools(host, tmp_path):
    root = tmp_path / "cursor"
    base = root / "User"
    global_storage = base / "globalStorage"
    state = global_storage / "state.vscdb"
    state.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(state)
    conn.executescript(
        """
        CREATE TABLE composerHeaders (
            composerId TEXT, workspaceId TEXT, createdAt TEXT,
            lastUpdatedAt TEXT, isArchived INTEGER, isSubagent INTEGER
        );
        CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value BLOB);
        """
    )
    composer = {
        "composerId": "cid",
        "name": "Fix login",
        "fullConversationHeadersOnly": [
            {"bubbleId": "b1", "type": 1},
            {"bubbleId": "b2", "type": 2},
        ],
        "createdAt": "2026-05-03T09:00:00Z",
        "lastUpdatedAt": "2026-05-03T09:05:00Z",
    }
    conn.execute(
        "INSERT INTO composerHeaders VALUES (?,?,?,?,?,?)",
        ("cid", "ws-1", "2026-05-03T09:00:00Z", "2026-05-03T09:05:00Z", 0, 0),
    )
    conn.execute(
        "INSERT INTO cursorDiskKV VALUES (?,?)",
        ("composerData:cid", json.dumps(composer)),
    )
    conn.execute(
        "INSERT INTO cursorDiskKV VALUES (?,?)",
        ("bubbleId:cid:b1", json.dumps({"type": 1, "text": "hello", "createdAt": "2026-05-03T09:00:01Z"})),
    )
    conn.execute(
        "INSERT INTO cursorDiskKV VALUES (?,?)",
        (
            "bubbleId:cid:b2",
            json.dumps(
                {
                    "type": 2,
                    "text": "Checking status",
                    "createdAt": "2026-05-03T09:00:02Z",
                    "modelInfo": {"modelName": "gpt-4.1"},
                    "toolFormerData": {
                        "name": "run_terminal_cmd",
                        "params": json.dumps({"command": "git status"}),
                        "result": "clean",
                    },
                }
            ),
        ),
    )
    conn.commit()
    conn.close()

    write_json(
        base / "workspaceStorage" / "abc" / "workspace.json",
        {"folder": "file:///C:/work"},
    )

    parse_cursor(host, store(root))
    found = rows(host)

    session = next(item for item in found if item["recordType"] == "session")
    assert session["summary"].startswith("Fix login: 2 bubbles")
    assert session["sessionId"] == "cid"

    user = next(item for item in found if item["role"] == "user")
    assert user["summary"] == "hello"

    assistant = next(item for item in found if item["role"] == "assistant")
    assert assistant["summary"] == "Checking status"

    call = next(item for item in found if item["recordType"] == "tool_call")
    assert call["invokedTool"] == "run_terminal_cmd"
    assert call["toolCommand"] == "git status"

    result = next(item for item in found if item["recordType"] == "tool_result")
    assert result["summary"] == "clean"


def test_gemini_chat_and_shell_history(host, tmp_path):
    root = tmp_path / "gemini"
    write_json(
        root / "tmp" / "hash" / "chats" / "session-1.json",
        {
            "sessionId": "g-1",
            "messages": [
                {"type": "user", "timestamp": "2026-05-04T08:00:00Z", "content": "hello"},
                {
                    "type": "gemini",
                    "timestamp": "2026-05-04T08:00:01Z",
                    "content": "hi",
                    "toolCalls": [{"name": "run_shell_command", "args": {"command": "ls"}}],
                },
                {
                    "role": "user",
                    "timestamp": "2026-05-04T08:00:02Z",
                    "functionResponse": {"name": "run_shell_command", "response": {"content": "ok"}},
                },
            ],
        },
    )
    write_text(root / "shell_history", "git status\ngit log\n")

    parse_gemini(host, store(root))
    found = rows(host)

    user = next(item for item in found if item["role"] == "user" and item["recordType"] == "message")
    assert user["summary"] == "hello"

    call = next(item for item in found if item["recordType"] == "tool_call")
    assert call["invokedTool"] == "run_shell_command"
    assert call["toolCommand"] == "ls"

    shell = [item for item in found if item["recordType"] == "shell_history"]
    assert [item["toolCommand"] for item in shell] == ["git status", "git log"]


def test_copilot_events_and_permission_request(host, tmp_path):
    root = tmp_path / "copilot"
    write_jsonl(
        root / "session-state" / "c1" / "events.jsonl",
        [
            {
                "type": "user.message",
                "timestamp": "2026-05-05T12:00:00Z",
                "data": {"sessionId": "c1", "content": "hello", "context": {"cwd": "C:\\repo"}},
            },
            {
                "type": "assistant.message",
                "timestamp": "2026-05-05T12:00:01Z",
                "data": {
                    "content": "running",
                    "toolRequests": [{"name": "bash", "arguments": {"command": "npm test"}}],
                },
            },
            {
                "type": "tool.execution_complete",
                "timestamp": "2026-05-05T12:00:10Z",
                "data": {"result": {"content": "done"}},
            },
            {
                "type": "permission.requested",
                "timestamp": "2026-05-05T12:00:11Z",
                "data": {
                    "permissionRequest": {
                        "toolName": "bash",
                        "kind": "shell",
                        "toolDescription": "run tests",
                        "args": {"command": "npm test"},
                    }
                },
            },
        ],
    )

    parse_copilot(host, store(root))
    found = rows(host)

    user = next(item for item in found if item["role"] == "user")
    assert user["workspace"] == "C:\\repo"
    assert user["sessionId"] == "c1"

    call = next(item for item in found if item["recordType"] == "tool_call")
    assert call["invokedTool"] == "bash"
    assert call["toolCommand"] == "npm test"

    permission = next(item for item in found if item["recordType"] == "permission_request")
    assert permission["invokedTool"] == "bash"
    assert permission["role"] == "metadata"


def test_vscode_chat_session_file(host, tmp_path):
    root = tmp_path / "vscode"
    folder = root / "User" / "workspaceStorage" / "abc"
    write_json(folder / "workspace.json", {"folder": "file:///C:/project"})
    write_json(
        folder / "chatSessions" / "session.json",
        {
            "requests": [
                {
                    "timestamp": 1760000000000,
                    "modelId": "copilot/gpt-4",
                    "message": {"text": "show log"},
                    "response": [{"value": "here it is"}],
                    "toolInvocationSerialized": {
                        "toolId": "terminal",
                        "toolSpecificData": {"commandLine": {"original": "git log"}},
                    },
                }
            ]
        },
    )

    parse_vscode_chats(host, store(root))
    found = rows(host)

    user = next(item for item in found if item["role"] == "user")
    assert user["summary"] == "show log"
    assert user["workspace"] == "C:/project"

    assistant = next(item for item in found if item["role"] == "assistant")
    assert assistant["summary"] == "here it is"

    call = next(item for item in found if item["recordType"] == "tool_call")
    assert call["invokedTool"] == "terminal"
    assert call["toolCommand"] == "git log"
