"""Timestamp, text, and JSON helpers. No artifact text is invented."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

_NUMBER = re.compile(r"^\d+(\.\d+)?$")
_TIME_KEYS = (
    "timestamp",
    "timestampMs",
    "timestamp_ms",
    "createdAt",
    "created_at",
    "ts",
    "time",
    "updated_at",
    "updatedAt",
    "opened_at",
    "date",
    "create_time",
    "createTime",
)


def to_iso(value: object) -> str:
    if value is None or value is False:
        return ""
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return ""
        if _NUMBER.fullmatch(text):
            return _from_epoch(float(text))
        iso = text[:-1] + "+00:00" if text.endswith("Z") else text
        try:
            parsed = datetime.fromisoformat(iso)
        except ValueError:
            return ""
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        parsed = parsed.astimezone(timezone.utc)
        if parsed.year < 1990 or parsed.year > 2100:
            return ""
        return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(value, (int, float)):
        return _from_epoch(float(value))
    return ""


def _from_epoch(num: float) -> str:
    if num > 10_000_000_000:
        num = num / 1000.0
    if num < 1_000_000_000:
        return ""
    try:
        parsed = datetime.fromtimestamp(num, timezone.utc)
    except (OverflowError, OSError, ValueError):
        return ""
    if parsed.year < 1990 or parsed.year > 2100:
        return ""
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")


def pick_time(obj: object) -> str:
    if not isinstance(obj, dict):
        return ""
    for key in _TIME_KEYS:
        if key in obj:
            iso = to_iso(obj.get(key))
            if iso:
                return iso
    return ""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: object, limit: int | None = None) -> str:
    digest = hashlib.sha256()
    remaining = limit
    with open(path, "rb") as handle:
        while True:
            if remaining is not None and remaining <= 0:
                break
            chunk = handle.read(1024 * 1024 if remaining is None else min(1024 * 1024, remaining))
            if not chunk:
                break
            digest.update(chunk)
            if remaining is not None:
                remaining -= len(chunk)
    return digest.hexdigest()


def clip_utf8(text: str, max_bytes: int) -> tuple[str, bool]:
    raw = text.encode("utf-8")
    if len(raw) <= max_bytes:
        return text, False
    clipped = raw[:max_bytes]
    while clipped:
        try:
            return clipped.decode("utf-8"), True
        except UnicodeDecodeError:
            clipped = clipped[:-1]
    return "", True


def one_line(text: str, limit: int) -> str:
    flat = " ".join(text.split())
    if len(flat) <= limit:
        return flat
    return flat[: limit - 1].rstrip() + "…"


def json_dumps(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def text_from_content(content: object, depth: int = 0) -> str:
    if depth > 8 or content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, (int, float)):
        return str(content)
    if isinstance(content, list):
        parts = [text_from_content(item, depth + 1) for item in content]
        return "\n".join(part for part in parts if part)
    if isinstance(content, dict):
        kind = str(content.get("type") or content.get("kind") or "")
        if kind in {"image", "document", "input_image", "image_url"} or "base64" in content:
            name = str(content.get("name") or content.get("file_name") or kind or "attachment")
            return f"[attachment omitted: {name}]"
        for key in ("text", "value", "output_text", "input_text"):
            if isinstance(content.get(key), str):
                return str(content[key])
        if "content" in content and kind in {"", "text", "output_text", "message"}:
            return text_from_content(content.get("content"), depth + 1)
        if "message" in content and isinstance(content.get("message"), (str, dict, list)):
            return text_from_content(content.get("message"), depth + 1)
        if isinstance(content.get("content"), str):
            return str(content["content"])
    return ""


def command_from_input(value: object) -> str:
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith("{") and stripped.endswith("}"):
            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError:
                return stripped
            return command_from_input(parsed)
        return stripped
    if isinstance(value, dict):
        for key in ("command", "cmd", "cmdLine", "cmdline", "script"):
            item = value.get(key)
            if isinstance(item, str) and item.strip():
                return item.strip()
            if isinstance(item, list):
                return " ".join(str(part) for part in item)
    return ""


def workspace_from(obj: object) -> str:
    if not isinstance(obj, dict):
        return ""
    for key in ("cwd", "workspace", "workspacePath", "project", "project_path", "folder"):
        value = obj.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def session_from(obj: object) -> str:
    if not isinstance(obj, dict):
        return ""
    for key in ("sessionId", "session_id", "conversationId", "conversation_id", "thread_id", "id"):
        value = obj.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def model_from(obj: object) -> str:
    if not isinstance(obj, dict):
        return ""
    for key in ("model", "modelId", "model_id"):
        value = obj.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def normalize_prompt(text: str) -> str:
    return " ".join(text.casefold().split())


def role_name(value: object) -> str:
    text = str(value or "").strip().lower()
    if text in {"user", "human"}:
        return "user"
    if text in {"assistant", "model", "gemini", "bot", "ai"}:
        return "assistant"
    if text in {"tool", "tool_result", "function", "function_call", "function_call_output"}:
        return "tool"
    if text in {"system", "developer"}:
        return "system"
    if text in {"metadata", "summary", "event", "notice"}:
        return "metadata"
    return ""
