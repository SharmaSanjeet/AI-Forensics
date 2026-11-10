"""Synthetic artifact helpers shared by the test modules."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from ai_forensics.ledger import CollectionHost
from ai_forensics.model import FULLTEXT_BYTES, ROW_CAP


def make_host(case_dir: Path, *, roots: list[Path] | None = None) -> CollectionHost:
    host = CollectionHost(
        roots or [case_dir],
        include_subagents=True,
        row_cap=ROW_CAP,
        fulltext_bytes=FULLTEXT_BYTES,
    )
    host.open_db(case_dir, reset=True)
    return host


def store(path: Path) -> SimpleNamespace:
    return SimpleNamespace(path=str(path))


def write_text(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def write_json(path: Path, value: object) -> Path:
    return write_text(path, json.dumps(value))


def write_jsonl(path: Path, objects: list[object]) -> Path:
    return write_text(path, "\n".join(json.dumps(item) for item in objects) + "\n")


def rows(host: CollectionHost, **filters: str) -> list[dict]:
    return host.query_rows(filters, limit=500)
