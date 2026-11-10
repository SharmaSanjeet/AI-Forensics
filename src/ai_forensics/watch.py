"""Incremental watch mode for a live case.

Only artifact files whose size or mtime changed since the previous scan are
re-parsed. New rows are appended with duplicate suppression, detectors run
again, and explanations are generated only for new leads. Existing review
state, suppressions, and model explanations are left untouched.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ai_forensics.analyze import LLMConfig, explain_anomalies
from ai_forensics.collect.collector import (
    HANDLERS,
    UNHANDLED,
    _tool_for_path,
    open_case,
)
from ai_forensics.collect.parsers.common import walk_files, walk_named
from ai_forensics.detect.anomalies import detect_and_store
from ai_forensics.discover import discover_roots, this_machine_discovery
from ai_forensics.ledger import CollectionHost
from ai_forensics.model import FILE_HASH_CAP
from ai_forensics.paths import file_stat
from ai_forensics.textutil import sha256_file

WATCH_MIN_INTERVAL = 5
WATCH_MAX_INTERVAL = 3600
WATCH_FILE_CAP = 20_000
_WATCH_SUFFIXES = {".jsonl", ".json", ".db", ".vscdb", ".rules"}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _json_dict(raw: str) -> dict:
    try:
        value = json.loads(raw or "{}")
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def _signature(path: Path) -> list[int] | None:
    if path.is_symlink():
        return None
    try:
        stat = path.stat()
    except OSError:
        return None
    return [int(stat.st_size), int(stat.st_mtime_ns)]


def _store_files(store_path: Path):
    if store_path.is_file():
        if not store_path.is_symlink():
            yield store_path
        return
    if not store_path.is_dir():
        return
    seen: set[str] = set()
    for path in walk_files(store_path, suffixes=_WATCH_SUFFIXES):
        text = str(path)
        if text not in seen:
            seen.add(text)
            yield path
    for path in walk_named(store_path, r"^deleted_"):
        text = str(path)
        if text not in seen:
            seen.add(text)
            yield path


def _snapshot(stores) -> tuple[dict[str, dict[str, list[int]]], int]:
    snapshot: dict[str, dict[str, list[int]]] = {}
    count = 0
    for store in stores:
        files: dict[str, list[int]] = {}
        for path in _store_files(Path(store.path)):
            if count >= WATCH_FILE_CAP:
                break
            sig = _signature(path)
            if sig is None:
                continue
            files[str(path)] = sig
            count += 1
        snapshot[str(store.path)] = files
    return snapshot, count


def _changed_stores(stores, previous: dict, current: dict, first_run: bool):
    if first_run:
        return list(stores)
    changed = []
    for store in stores:
        key = str(store.path)
        if current.get(key, {}) != previous.get(key, {}):
            changed.append(store)
    return changed


def _refresh_hashes(host: CollectionHost) -> None:
    """Reuse stored hashes when size and mtime still match; hash the rest."""
    raw = host.get_meta().get("file_hashes", "")
    entries: list[dict] = []
    if raw:
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = []
        if isinstance(parsed, list):
            entries = [item for item in parsed if isinstance(item, dict)]
    by_path = {str(item.get("path")): item for item in entries}

    eligible = sorted(
        {
            str(entry["source"])
            for entry in host.coverage_public()
            if str(entry.get("status")) == "parsed"
        }
    )
    hashes: list[dict] = []
    for path_text in eligible[:FILE_HASH_CAP]:
        path = Path(path_text)
        if not path.is_file() or path.is_symlink() or not host.inside(path):
            continue
        size, mtime = file_stat(path)
        existing = by_path.get(path_text)
        if (
            existing
            and existing.get("sha256")
            and existing.get("size") == size
            and existing.get("mtime") == mtime
        ):
            hashes.append(existing)
            continue
        try:
            digest = sha256_file(path)
        except OSError:
            continue
        hashes.append({"path": path_text, "size": size, "mtime": mtime, "sha256": digest})
    host.set_meta(
        {
            "file_hashes": json.dumps(hashes, separators=(",", ":")),
            "file_hashes_omitted": str(max(0, len(eligible) - len(hashes))),
        }
    )


@dataclass
class WatchReport:
    scanned_at: str
    duration_ms: int
    stores_total: int
    stores_scanned: int
    new_rows: int = 0
    new_leads: int = 0
    explained: int = 0
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "scannedAt": self.scanned_at,
            "durationMs": self.duration_ms,
            "storesTotal": self.stores_total,
            "storesScanned": self.stores_scanned,
            "newRows": self.new_rows,
            "newLeads": self.new_leads,
            "explained": self.explained,
            "errors": self.errors,
        }


def _discover(host: CollectionHost, mode: str, stop_event):
    if mode == "folder":
        return discover_roots(
            host.roots,
            default_user=host.user,
            default_host=host.host_name,
            cancel=stop_event,
        ).stores
    return this_machine_discovery(
        cancel=stop_event, default_user=host.user, default_host=host.host_name
    ).stores


def scan_once(
    host: CollectionHost,
    *,
    explain: bool = True,
    config: LLMConfig | None = None,
    stop_event: threading.Event | None = None,
) -> WatchReport:
    started = time.monotonic()
    scanned_at = _now()
    if not host.incremental:
        host.enable_incremental()
    meta = host.get_meta()
    mode = meta.get("mode", "machine")
    stores = _discover(host, mode, stop_event)

    current, file_count = _snapshot(stores)
    previous = _json_dict(meta.get("watch_files", ""))
    first_run = not previous
    changed = _changed_stores(stores, previous, current, first_run)

    host.parse_errors = 0
    host.truncations = 0
    host.subagents_skipped = 0
    rows_before = host.row_count
    errors: list[str] = []
    parsed = 0
    at_cap = host.row_count >= host.row_cap
    if not at_cap:
        for store in changed:
            if stop_event is not None and stop_event.is_set():
                break
            host.forget_coverage(str(store.path))
            handler = HANDLERS.get(store.kind)
            try:
                if handler is not None:
                    handler(host, store)
                else:
                    status, note = UNHANDLED.get(
                        store.kind, ("inventory-only", "store detected; parser not implemented")
                    )
                    host.cover(
                        str(store.path), _tool_for_path(str(store.path)), status, notes=note
                    )
                parsed += 1
            except Exception as error:  # keep watching; record and continue
                errors.append(f"{store.path}: {type(error).__name__}: {error}")
                host.cover(
                    str(store.path),
                    _tool_for_path(str(store.path)),
                    "malformed",
                    notes=f"watch parser exception: {type(error).__name__}: {error}",
                )
        host.link_prompts()
        _refresh_hashes(host)

    new_rows = host.row_count - rows_before
    before_ids = {item["id"] for item in host.query_anomalies()}
    detect_and_store(host)
    new_items = [item for item in host.query_anomalies() if item["id"] not in before_ids]
    explained = 0
    if new_items:
        chosen = config or LLMConfig.from_env()
        if not explain:
            chosen = LLMConfig(provider="none")
        report = explain_anomalies(
            host, config=chosen, anomaly_ids=[item["id"] for item in new_items]
        )
        explained = report.generated + report.cached
        fresh_ids = {item["id"] for item in new_items}
        new_items = [item for item in host.query_anomalies() if item["id"] in fresh_ids]

    try:
        previous_recent = json.loads(meta.get("watch_recent_leads", "[]") or "[]")
    except ValueError:
        previous_recent = []
    if not isinstance(previous_recent, list):
        previous_recent = []
    recent = previous_recent + [
        {
            "id": item["id"],
            "severity": item["severity"],
            "title": item["title"],
            "rule": item["rule"],
            "tool": item.get("tool", ""),
            "timestamp": item.get("timestamp", ""),
            "explainedBy": item.get("llmModel") or "deterministic",
        }
        for item in new_items[:10]
    ][-10:]
    duration_ms = int((time.monotonic() - started) * 1000)

    def counter(key: str) -> int:
        try:
            return int(meta.get(key, "0") or 0)
        except ValueError:
            return 0

    host.set_meta(
        {
            "watch_last_scan": scanned_at,
            "watch_last_duration_ms": str(duration_ms),
            "watch_last_new_rows": str(new_rows),
            "watch_last_new_leads": str(len(new_items)),
            "watch_total_new_rows": str(counter("watch_total_new_rows") + new_rows),
            "watch_total_new_leads": str(counter("watch_total_new_leads") + len(new_items)),
            "watch_last_parse_errors": str(host.parse_errors),
            "watch_last_truncations": str(host.truncations),
            "watch_scans": str(int(meta.get("watch_scans", "0") or 0) + 1),
            "watch_last_error": "; ".join(errors)[:500],
            "watch_recent_leads": json.dumps(recent, separators=(",", ":")),
            "watch_files": json.dumps(current, separators=(",", ":")),
            "watch_files_count": str(file_count),
            "last_watched_at": scanned_at,
            "rows": str(host.row_count),
            "cap_hit": "1" if host.hit_cap else meta.get("cap_hit", "0"),
        }
    )
    return WatchReport(
        scanned_at=scanned_at,
        duration_ms=duration_ms,
        stores_total=len(stores),
        stores_scanned=parsed,
        new_rows=new_rows,
        new_leads=len(new_items),
        explained=explained,
        errors=errors,
    )


class CaseWatcher:
    """Background thread that scans one case at a fixed interval."""

    def __init__(self, case_dir: Path, *, interval: int = 30, explain: bool = True):
        self.case_dir = Path(case_dir)
        self.interval = max(WATCH_MIN_INTERVAL, min(WATCH_MAX_INTERVAL, int(interval)))
        self.explain = bool(explain)
        self.last_error = ""
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="aif-watch", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    def _run(self) -> None:
        host: CollectionHost | None = None
        try:
            host = open_case(self.case_dir)
            host.enable_incremental()
            host.set_meta(
                {
                    "watch_state": "running",
                    "watch_started_at": _now(),
                    "watch_interval": str(self.interval),
                    "watch_explain": "1" if self.explain else "0",
                    "watch_last_error": "",
                    "watch_recent_leads": "[]",
                    "watch_total_new_rows": "0",
                    "watch_total_new_leads": "0",
                }
            )
            while not self._stop.is_set():
                if host is None:
                    host = open_case(self.case_dir)
                    host.enable_incremental()
                try:
                    scan_once(host, explain=self.explain, stop_event=self._stop)
                    self.last_error = ""
                except Exception as error:
                    self.last_error = f"{type(error).__name__}: {error}"
                    try:
                        host.set_meta({"watch_last_error": self.last_error[:500]})
                    except Exception:
                        pass
                    try:
                        host.close()
                    except Exception:
                        pass
                    host = None
                if self._stop.wait(self.interval):
                    break
        finally:
            if host is not None:
                try:
                    host.set_meta({"watch_state": "stopped", "watch_stopped_at": _now()})
                except Exception:
                    pass
                host.close()


__all__ = [
    "CaseWatcher",
    "WATCH_MAX_INTERVAL",
    "WATCH_MIN_INTERVAL",
    "WatchReport",
    "scan_once",
]
