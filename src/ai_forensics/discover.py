"""Find AI-assistant stores under one authorized root, or on this machine.

Layouts covered: Windows Users\\<name>, Linux home/<name>, macOS Users/<name>
and Application Support. Discovery does not follow symlinks and does not
walk out of the root it was given.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from ai_forensics.paths import (
    inside,
    is_browser_dir,
    should_prune,
    this_machine_candidates,
    identity_from_path,
)

EXPECTED_RELATIVE = (
    "Users/<name>/.claude",
    "Users/<name>/.codex",
    "Users/<name>/.grok",
    "Users/<name>/.grokbot",
    "Users/<name>/.cursor",
    "Users/<name>/.gemini",
    "Users/<name>/.copilot",
    "Users/<name>/.continue",
    "Users/<name>/.claude.json",
    "home/<name>/.claude",
    "home/<name>/.codex",
    "home/<name>/.grok",
    "home/<name>/.cursor",
    "home/<name>/.gemini",
    "AppData/Roaming/Claude",
    "AppData/Roaming/Cursor",
    "AppData/Roaming/Code/User/workspaceStorage/<id>/chatSessions",
    "AppData/Roaming/Windsurf",
    "AppData/Roaming/OpenAI/ChatGPT",
    "AppData/Roaming/Codex",
    "AppData/Roaming/Grok Bot",
    "Library/Application Support/Claude",
    "Library/Application Support/Cursor",
    "Library/Application Support/com.openai.chat",
    "Library/Application Support/Codex",
    "Library/Application Support/Grok Bot",
)


@dataclass
class Store:
    kind: str
    path: Path
    user: str
    host: str


@dataclass
class Discovery:
    stores: list[Store]
    checked: list[tuple[str, bool, str]]
    user_trees_empty: list[str]


def classify_path(path: Path) -> str | None:
    name = path.name.lower()
    parent = path.parent.name.lower()
    if path.is_file():
        if name == ".claude.json":
            return "claude_config"
        if name == "conversation-search.db":
            return "cursor_search"
        if name in {"history.jsonl", "session_index.jsonl"} and parent in {".codex", "sessions"}:
            return "codex"
        return None
    if name == ".claude":
        return "claude_code"
    if name == ".codex":
        return "codex"
    if name == ".grok":
        return "grok"
    if name == ".grokbot":
        return "grokbot"
    if name == ".cursor":
        return "cursor_home"
    if name == ".gemini":
        return "gemini"
    if name == ".copilot":
        return "copilot"
    if name == ".continue":
        return "continue"
    if name in {"claude-code-sessions", "local-agent-mode-sessions"}:
        return "claude_desktop"
    if name == "claude" and (
        parent in {"roaming", "application support", "appdata"}
        or (path / "claude-code-sessions").exists()
        or (path / "pending-uploads").exists()
    ):
        return "claude_desktop"
    if name == "cursor" and parent in {"roaming", "application support", ".config"}:
        return "cursor_app"
    if name == "windsurf":
        return "windsurf"
    if name in {"code", "code - insiders", "vscodium"} and parent in {
        "roaming",
        "application support",
        ".config",
    }:
        return "vscode"
    if name in {"chatgpt", "com.openai.chat"}:
        return "chatgpt"
    if name == "atlas" and parent == "openai":
        return "chatgpt"
    if name == "codex" and parent in {"roaming", "application support", "openai"}:
        return "chatgpt"
    if name == "grok bot":
        return "grokbot_app"
    if name == "gemini" and parent in {"roaming", "application support"}:
        return "gemini_desktop"
    if name == "chatsessions":
        return "vscode_chats"
    if "skysight" in name or name == "computeruse":
        return "computer_history"
    return None


def _store(path: Path, kind: str, default_user: str, default_host: str) -> Store:
    user, host = identity_from_path(path)
    return Store(kind=kind, path=path, user=user or default_user, host=host or default_host)


def discover_roots(
    roots: list[Path],
    *,
    default_user: str = "",
    default_host: str = "",
    cancel=None,
    log=None,
) -> Discovery:
    stores: list[Store] = []
    checked: list[tuple[str, bool, str]] = []
    seen: set[str] = set()
    user_seen: dict[str, bool] = {}

    def add(path: Path, kind: str) -> None:
        try:
            key = str(path.resolve()).lower()
        except OSError:
            key = str(path).lower()
        if key in seen:
            return
        seen.add(key)
        stores.append(_store(path, kind, default_user, default_host))
        user, _host = identity_from_path(path)
        if user:
            user_seen[user] = True
        if log:
            log(f"store {kind}: {path}")

    for root in roots:
        if cancel is not None and cancel.is_set():
            break
        if not root.exists():
            checked.append((str(root), False, "not present"))
            continue
        checked.append((str(root), True, "root"))
        try:
            root_resolved = root.resolve()
        except OSError:
            checked.append((str(root), True, "unavailable"))
            continue
        kind = classify_path(root)
        if kind and root.is_file():
            add(root, kind)
            continue
        if kind and root.is_dir() and kind not in {"computer_history", "gemini_desktop"}:
            add(root, kind)
            continue
        if kind == "computer_history":
            add(root, kind)
            continue
        if kind == "gemini_desktop":
            add(root, kind)
            continue
        _walk(root_resolved, add, user_seen, cancel, log)

    empty_users = [name for name, found in user_seen.items() if not found]
    return Discovery(stores=stores, checked=checked, user_trees_empty=empty_users)


def _walk(root: Path, add, user_seen: dict[str, bool], cancel, log) -> None:
    scanned = 0
    for current, dirs, files in os.walk(root, followlinks=False):
        if cancel is not None and cancel.is_set():
            return
        current_path = Path(current)
        if not inside(root, current_path):
            dirs.clear()
            continue
        scanned += 1
        if log and scanned % 2000 == 0:
            log(f"scanned {scanned} directories under {root}")
        user, _host = identity_from_path(current_path)
        if user and user not in user_seen:
            user_seen[user] = False
        kind = classify_path(current_path)
        if kind:
            add(current_path, kind)
            if user:
                user_seen[user] = True
            dirs.clear()
            continue
        if is_browser_dir(current_path):
            add(current_path, "browser")
            dirs.clear()
            continue
        kept: list[str] = []
        for name in dirs:
            child = current_path / name
            if child.is_symlink():
                continue
            if should_prune(child):
                continue
            if not inside(root, child):
                continue
            kept.append(name)
        dirs[:] = kept
        for name in files:
            file_path = current_path / name
            file_kind = classify_path(file_path)
            if file_kind:
                add(file_path, file_kind)
                if user:
                    user_seen[user] = True


def this_machine_discovery(cancel=None, log=None, default_user: str = "", default_host: str = "") -> Discovery:
    candidates = this_machine_candidates()
    existing = [path for path in candidates if path.exists()]
    missing = [(str(path), False, "not present") for path in candidates if not path.exists()]
    found = discover_roots(
        existing,
        default_user=default_user,
        default_host=default_host,
        cancel=cancel,
        log=log,
    )
    found.checked = missing + found.checked
    return found
