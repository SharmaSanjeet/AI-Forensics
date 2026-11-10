"""Path jail and user/host attribution.

Collection never walks outside the authorized root. Symlinks are not followed,
and a resolved path that leaves the root is skipped.
"""

from __future__ import annotations

import os
from pathlib import Path

_SKIP_USER = {
    "public",
    "default",
    "default user",
    "all users",
    "share",
    "desktop.ini",
}

_CREDENTIAL_NAMES = {
    ".credentials.json",
    "auth.json",
    "mcp_credentials.json",
    "oauth_creds.json",
    "login data",
    "cookies",
    "web data",
    "local-exec-daemon-credential.json",
    "local-exec-daemon-connection.json",
    "sand-secrets.json",
    "gateway-descriptor.json",
    "box-secrets-push-state.v1.json",
    ".audit-key",
    "cookies-journal",
    "login data-journal",
}

_CREDENTIAL_SUFFIXES = {".pem", ".key", ".p12", ".pfx"}

_BROWSER_DIRS = {
    "chrome",
    "google chrome",
    "microsoft edge",
    "firefox",
    "bravesoftware",
    "opera software",
    "safari",
}

_PRUNE_DIRS = {
    "node_modules",
    ".git",
    "windows",
    "program files",
    "program files (x86)",
    "$recycle.bin",
    "system volume information",
    "winsxs",
    "gpucache",
    "code cache",
    "blob_storage",
    "cacheddata",
    "site-packages",
    "__pycache__",
    "inetcache",
    "temp",
    "tmp",
}


def resolve_dir(path: Path) -> Path:
    return path.resolve()


def inside(root: Path, candidate: Path) -> bool:
    """True when candidate resolves inside root. False if it escapes."""
    try:
        root_resolved = root.resolve()
        candidate_resolved = candidate.resolve()
    except OSError:
        return False
    if candidate_resolved == root_resolved:
        return True
    try:
        candidate_resolved.relative_to(root_resolved)
    except ValueError:
        return False
    return True


def is_credential_file(path: Path) -> bool:
    name = path.name.lower()
    if name in _CREDENTIAL_NAMES:
        return True
    if path.suffix.lower() in _CREDENTIAL_SUFFIXES:
        return True
    if name.startswith("login data") or name.startswith("cookies"):
        return True
    return False


def is_browser_dir(path: Path) -> bool:
    return path.name.lower() in _BROWSER_DIRS


def should_prune(path: Path) -> bool:
    return path.name.lower() in _PRUNE_DIRS


def identity_from_path(path: Path) -> tuple[str, str]:
    """User from Users\\<name> or home/<name>. Host from a KAPE-style parent folder."""
    parts = list(path.parts)
    user = ""
    host = ""
    for index, part in enumerate(parts):
        if part.lower() not in {"users", "home"}:
            continue
        if index + 1 >= len(parts):
            continue
        candidate = parts[index + 1]
        if candidate.lower() in _SKIP_USER:
            continue
        user = candidate
        if index >= 2 and parts[index - 1].lower() in {"c", "c:"}:
            host = parts[index - 2]
        elif index >= 1:
            previous = parts[index - 1]
            if previous.lower() not in {"c", "c:", "users", "home", "library", "/"}:
                # /evidence/<host>/home/<user> or <host>\Users\<user>
                if index >= 2 or previous not in {parts[0]}:
                    host = previous
        break
    if host.endswith(":\\") or host.endswith(":/") or len(host) <= 2 and host.endswith(":"):
        host = ""
    return user, host


def this_machine_candidates() -> list[Path]:
    """Known AI-assistant locations for the logged-in profile. Not the whole disk."""
    home = Path.home()
    appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
    local = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
    candidates = [
        home / ".claude",
        home / ".claude.json",
        home / ".codex",
        home / ".grok",
        home / ".grokbot",
        home / ".cursor",
        home / ".gemini",
        home / ".copilot",
        home / ".continue",
        appdata / "Claude",
        appdata / "Cursor",
        appdata / "Code",
        appdata / "Code - Insiders",
        appdata / "VSCodium",
        appdata / "Windsurf",
        appdata / "OpenAI" / "ChatGPT",
        appdata / "OpenAI" / "Atlas",
        appdata / "Codex",
        appdata / "Grok Bot",
        appdata / "Continue",
        home / ".config" / "Cursor",
        home / ".config" / "Code",
        home / ".config" / "Windsurf",
        home / ".config" / "com.openai.chat",
        home / "Library" / "Application Support" / "Claude",
        home / "Library" / "Application Support" / "Cursor",
        home / "Library" / "Application Support" / "com.openai.chat",
        home / "Library" / "Application Support" / "OpenAI" / "Atlas",
        home / "Library" / "Application Support" / "Codex",
        home / "Library" / "Application Support" / "Code",
        home / "Library" / "Application Support" / "Windsurf",
        home / "Library" / "Application Support" / "Grok Bot",
        home / "Library" / "Application Support" / "Gemini",
    ]
    packages = local / "Packages"
    if packages.is_dir():
        try:
            for child in packages.glob("OpenAI.ChatGPT-Desktop_*"):
                candidates.append(child / "LocalCache" / "Roaming" / "ChatGPT")
        except OSError:
            pass
    return candidates


def file_stat(path: Path) -> tuple[int, str]:
    try:
        st = path.stat()
    except OSError:
        return 0, ""
    from datetime import datetime, timezone

    mtime = datetime.fromtimestamp(st.st_mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return int(st.st_size), mtime
