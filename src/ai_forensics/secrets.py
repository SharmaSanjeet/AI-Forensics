"""Deterministic secret scanner.

Matches are masked before a row is stored, exported, or sent to the analyst
model. Cleartext is never written to the case database. Fingerprints are
salted SHA-256 prefixes, not the secret.
"""

from __future__ import annotations

import hashlib
import re

# Longer and more specific patterns run first. Overlapping spans keep the
# longer match so sk-ant- is not also labeled as a generic OpenAI key.
_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (
        "private_key",
        "high",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]{0,12000}?-----END [A-Z0-9 ]*PRIVATE KEY-----"
        ),
    ),
    (
        "private_key",
        "high",
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    ),
    ("aws_access_key", "high", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    (
        "aws_secret_access_key",
        "high",
        re.compile(
            r"(?i)\baws_secret_access_key\b\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})\b"
        ),
    ),
    (
        "github_token",
        "high",
        re.compile(
            r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b"
        ),
    ),
    ("anthropic_api_key", "high", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("openai_api_key", "high", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b")),
    ("xai_api_key", "high", re.compile(r"\bxai-[A-Za-z0-9_\-]{20,}\b")),
    ("slack_token", "high", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")),
    ("google_api_key", "high", re.compile(r"\bAIza[0-9A-Za-z\-_]{30,}\b")),
    ("npm_token", "high", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    (
        "jwt",
        "medium",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
    (
        "bearer_token",
        "medium",
        re.compile(r"(?i)\bBearer\s+([A-Za-z0-9\-._~+/]{20,}={0,2})"),
    ),
    (
        "generic_secret",
        "medium",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|access[_-]?token|auth[_-]?token|password)\b\s*[:=]\s*['\"]?([A-Za-z0-9_\-/.+=]{12,})"
        ),
    ),
)

_SENSITIVE_KEY = re.compile(
    r"(?i)(password|secret|token|credential|api[_-]?key|authorization|private[_-]?key)"
)
_SENSITIVE_NAMES = {
    "env",
    "environment",
    "headers",
    "query",
    "authorization",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "secret",
    "password",
    "passwd",
    "token",
    "auth",
    "cookie",
    "cookies",
    "credentials",
    "private_key",
    "client_secret",
}


def is_sensitive_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    if normalized in _SENSITIVE_NAMES:
        return True
    return _SENSITIVE_KEY.search(key) is not None


def redact_structure(value: object) -> object:
    """Drop values under secret-like keys before any text is retained."""
    if isinstance(value, dict):
        redacted: dict[str, object] = {}
        for key, item in value.items():
            if isinstance(key, str) and is_sensitive_key(key):
                redacted[key] = "[excluded]"
            else:
                redacted[str(key)] = redact_structure(item)
        return redacted
    if isinstance(value, list):
        return [redact_structure(item) for item in value]
    return value


def fingerprint(salt: bytes, secret: str) -> str:
    digest = hashlib.sha256(salt + secret.encode("utf-8")).hexdigest()
    return digest[:16]


def _spans(text: str) -> list[tuple[int, int, str, str, str]]:
    found: list[tuple[int, int, str, str, str]] = []
    for category, confidence, pattern in _PATTERNS:
        for match in pattern.finditer(text):
            if match.lastindex:
                start, end = match.span(match.lastindex)
            else:
                start, end = match.span()
            if end <= start:
                continue
            secret = text[start:end]
            found.append((start, end, category, confidence, secret))
    found.sort(key=lambda item: (item[0], -(item[1] - item[0])))
    kept: list[tuple[int, int, str, str, str]] = []
    cursor = -1
    for span in found:
        if span[0] < cursor:
            continue
        kept.append(span)
        cursor = span[1]
    return kept


def mask_text(text: str, salt: bytes) -> tuple[str, list[dict[str, str]]]:
    if not text:
        return "", []
    spans = _spans(text)
    if not spans:
        return text, []
    pieces: list[str] = []
    findings: list[dict[str, str]] = []
    last = 0
    for start, end, category, confidence, secret in spans:
        pieces.append(text[last:start])
        stamp = fingerprint(salt, secret)
        pieces.append(f"[REDACTED:{category}:{stamp}]")
        findings.append(
            {
                "category": category,
                "confidence": confidence,
                "fingerprint": stamp,
            }
        )
        last = end
    pieces.append(text[last:])
    return "".join(pieces), findings


def mask_fields(values: list[str], salt: bytes) -> tuple[list[str], list[dict[str, str]]]:
    masked: list[str] = []
    findings: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for value in values:
        text, found = mask_text(value, salt)
        masked.append(text)
        for item in found:
            key = (item["category"], item["fingerprint"])
            if key in seen:
                continue
            seen.add(key)
            findings.append(item)
    return masked, findings
