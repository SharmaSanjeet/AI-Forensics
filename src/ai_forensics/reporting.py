"""CSV, manifest, hash verification, and ZIP exports.

Every export reads the masked case database. Raw artifact bytes and secret
cleartext are never included.
"""

from __future__ import annotations

import csv
import io
import json
import sqlite3
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from ai_forensics.ledger import CollectionHost
from ai_forensics.model import (
    CREATOR_NAME,
    CREATOR_URL,
    FILE_HASH_CAP,
    LLM_CACHE_VERSION,
)
from ai_forensics.paths import file_stat
from ai_forensics.textutil import sha256_file

ROW_COLUMNS = (
    "id",
    "timestamp",
    "role",
    "tool",
    "invokedTool",
    "recordType",
    "toolCommand",
    "summary",
    "workspace",
    "sessionId",
    "user",
    "host",
    "sourceFile",
    "sourceOffset",
    "model",
    "alsoInTools",
    "secretCategories",
    "truncated",
    "contentHash",
)

ANOMALY_COLUMNS = (
    "id",
    "rule",
    "severity",
    "title",
    "summary",
    "tool",
    "workspace",
    "timestamp",
    "confidence",
    "rowIds",
    "sessionId",
    "llmModel",
    "whatHappened",
    "whyItMatters",
    "nextSteps",
    "disposition",
    "dispositionNote",
    "dispositionBy",
    "dispositionAt",
    "suppressed",
    "rankLabel",
    "rankReason",
    "rankModel",
)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _json_list(value: object) -> list:
    try:
        parsed = json.loads(str(value or "[]"))
    except ValueError:
        return []
    return parsed if isinstance(parsed, list) else []


def _csv_stream(header: tuple[str, ...], rows) -> list[bytes]:
    buffer = io.StringIO()
    buffer.write("\ufeff")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(header)
    chunks = [buffer.getvalue().encode("utf-8")]
    buffer.seek(0)
    buffer.truncate(0)
    for row in rows:
        writer.writerow(row)
        chunks.append(buffer.getvalue().encode("utf-8"))
        buffer.seek(0)
        buffer.truncate(0)
    return chunks


def rows_csv_chunks(ledger: CollectionHost, filters: dict[str, str] | None = None):
    def generator():
        for row in ledger.iter_filtered(filters or {}):
            findings = _json_list(row.get("secrets_json"))
            yield (
                row.get("id", ""),
                row.get("timestamp", ""),
                row.get("role", ""),
                row.get("tool", ""),
                row.get("invoked_tool", ""),
                row.get("record_type", ""),
                row.get("tool_command", ""),
                row.get("summary", ""),
                row.get("workspace", ""),
                row.get("session_id", ""),
                row.get("user_name", ""),
                row.get("host", ""),
                row.get("source_file", ""),
                row.get("source_offset", 0),
                row.get("model", ""),
                ",".join(str(item) for item in _json_list(row.get("also_in_tools"))),
                ",".join(
                    sorted({str(item.get("category") or "") for item in findings if item.get("category")})
                ),
                bool(row.get("truncated")),
                row.get("content_hash", ""),
            )

    yield from _csv_stream(ROW_COLUMNS, generator())


def anomalies_csv_chunks(ledger: CollectionHost, severity: str = ""):
    def generator():
        for item in ledger.query_anomalies(severity):
            yield (
                item.get("id", ""),
                item.get("rule", ""),
                item.get("severity", ""),
                item.get("title", ""),
                item.get("summary", ""),
                item.get("tool", ""),
                item.get("workspace", ""),
                item.get("timestamp", ""),
                item.get("confidence", ""),
                ",".join(str(value) for value in item.get("rowIds") or []),
                item.get("sessionId", ""),
                item.get("llmModel", ""),
                item.get("whatHappened", ""),
                item.get("whyItMatters", ""),
                item.get("nextSteps", ""),
                item.get("disposition", "open"),
                item.get("dispositionNote", ""),
                item.get("dispositionBy", ""),
                item.get("dispositionAt", ""),
                bool(item.get("suppressed")),
                item.get("rankLabel", ""),
                item.get("rankReason", ""),
                item.get("rankModel", ""),
            )

    yield from _csv_stream(ANOMALY_COLUMNS, generator())


def collected_hashes(ledger: CollectionHost) -> tuple[list[dict], str, int]:
    """Prefer hashes captured during collection; fall back to hashing now."""
    raw = ledger.get_meta().get("file_hashes", "")
    omitted = 0
    if raw:
        try:
            stored = json.loads(raw)
        except ValueError:
            stored = []
        if isinstance(stored, list) and stored:
            try:
                omitted = int(ledger.get_meta().get("file_hashes_omitted", "0") or 0)
            except ValueError:
                omitted = 0
            return [item for item in stored if isinstance(item, dict)], "collection", omitted
    hashed: list[dict] = []
    for entry in ledger.coverage_public():
        if str(entry.get("status")) != "parsed":
            continue
        path = Path(str(entry.get("source") or ""))
        if not path.is_file() or path.is_symlink() or not ledger.inside(path):
            continue
        try:
            size, mtime = file_stat(path)
            digest = sha256_file(path)
        except OSError:
            continue
        hashed.append({"path": str(path), "size": size, "mtime": mtime, "sha256": digest})
        if len(hashed) >= FILE_HASH_CAP:
            omitted = max(0, len(ledger.coverage_public()) - len(hashed))
            break
    return hashed, "export-time", omitted


def case_manifest(ledger: CollectionHost) -> dict:
    meta = ledger.get_meta()
    stats = ledger.stats()
    anomalies = ledger.query_anomalies()
    files, hash_source, omitted = collected_hashes(ledger)
    explained = sum(
        1
        for item in anomalies
        if item.get("llmModel") and item.get("llmModel") != "deterministic"
    )
    open_leads = sum(
        1
        for item in anomalies
        if not item.get("suppressed") and item.get("disposition", "open") == "open"
    )
    return {
        "product": "Assistant Session Ledger",
        "creator": {"name": CREATOR_NAME, "linkedin": CREATOR_URL},
        "generatedAt": _now(),
        "case": {
            "id": meta.get("case_id", ""),
            "mode": meta.get("mode", ""),
            "user": meta.get("user", ""),
            "host": meta.get("host", ""),
            "createdAt": meta.get("created_at", ""),
            "finishedAt": meta.get("finished_at", ""),
            "rowCapHit": meta.get("cap_hit", "0") == "1",
            "cancelled": meta.get("cancelled", "0") == "1",
        },
        "counts": {
            "rows": stats.get("total_rows", 0),
            "sessions": stats.get("sessions", 0),
            "secretRows": stats.get("secret_rows", 0),
            "anomalies": len(anomalies),
            "openAnomalies": open_leads,
            "anomaliesExplainedByModel": explained,
            "parseErrors": meta.get("parse_errors", "0"),
            "truncations": meta.get("truncations", "0"),
        },
        "timeRange": {
            "first": stats.get("first_timestamp", ""),
            "last": stats.get("last_timestamp", ""),
        },
        "tools": stats.get("by_tool", []),
        "roles": stats.get("by_role", []),
        "recordTypes": stats.get("by_record_type", []),
        "severity": stats.get("by_severity", []),
        "coverage": ledger.coverage_public(),
        "files": files,
        "filesHashSource": hash_source,
        "filesOmitted": omitted,
        "anomalies": [
            {
                "id": item.get("id"),
                "rule": item.get("rule"),
                "severity": item.get("severity"),
                "title": item.get("title"),
                "tool": item.get("tool"),
                "timestamp": item.get("timestamp"),
                "confidence": item.get("confidence"),
                "rowIds": item.get("rowIds"),
                "sessionId": item.get("sessionId", ""),
                "explainedBy": item.get("llmModel") or "deterministic",
                "disposition": item.get("disposition", "open"),
                "suppressed": bool(item.get("suppressed")),
                "suppressionId": item.get("suppressionId", ""),
                "advisoryRank": {
                    "label": item.get("rankLabel", ""),
                    "reason": item.get("rankReason", ""),
                    "model": item.get("rankModel", ""),
                }
                if item.get("rankLabel")
                else None,
            }
            for item in anomalies
        ],
        "masking": (
            "Row text was redacted before storage. Secret values appear only as "
            "[REDACTED:category:fingerprint]; fingerprints are salted SHA-256 prefixes. "
            "Original artifact files are referenced by path and hash, not copied."
        ),
        "llm": {"cacheVersion": LLM_CACHE_VERSION},
    }


def verify_hashes(ledger: CollectionHost) -> dict:
    files, source, _omitted = collected_hashes(ledger)
    checks = []
    for entry in files:
        path = Path(str(entry.get("path") or ""))
        current = {
            "path": str(path),
            "expected": entry.get("sha256", ""),
            "actual": "",
            "status": "",
        }
        if not ledger.inside(path):
            current["status"] = "outside-case"
        elif not path.is_file() or path.is_symlink():
            current["status"] = "missing"
        else:
            try:
                current["actual"] = sha256_file(path)
            except OSError:
                current["status"] = "unreadable"
            else:
                current["status"] = (
                    "match" if current["actual"] == current["expected"] else "mismatch"
                )
        checks.append(current)
    return {
        "checkedAt": _now(),
        "source": source,
        "total": len(checks),
        "matched": sum(1 for item in checks if item["status"] == "match"),
        "checks": checks,
    }


def _db_snapshot(ledger: CollectionHost) -> bytes:
    if ledger.db_path is None or not Path(ledger.db_path).is_file():
        return b""
    with tempfile.TemporaryDirectory(prefix="aif-snapshot-") as folder:
        target = Path(folder) / "ledger.sqlite"
        source = sqlite3.connect(str(ledger.db_path))
        destination = sqlite3.connect(str(target))
        try:
            with destination:
                source.backup(destination)
        finally:
            destination.close()
            source.close()
        return target.read_bytes()


_README = """Assistant Session Ledger export
===============================

Created by {creator}
LinkedIn: {creator_url}

Contents
--------
report.html      Self-contained case report (open in a browser, print to PDF)
report.md        Same report as Markdown
case.json        Collection summary
manifest.json    Counts, coverage, anomaly index, and artifact hashes
rows.csv         Normalized timeline rows (masked)
anomalies.csv    Rule-based leads with explanations
ledger.sqlite    Masked case database

Integrity
---------
Row text was redacted before storage. Secret values are replaced with
[REDACTED:category:fingerprint] where the fingerprint is a salted SHA-256
prefix. The salt lives only inside ledger.sqlite. Original artifact files are
referenced by path and SHA-256, not copied.

Anomaly leads are deterministic pattern or behaviour matches. Treat them as
triage items, not confirmed incidents. Model-written explanations are labeled
in the llm_model column; deterministic text uses the value 'deterministic'.
Advisory ranking (rankLabel / rankReason columns, when generated) is a
model-produced triage hint; it never creates, removes, or re-scores leads.
The case report renders stored data and the stored case brief; no model is
called, so its content is reproducible from the stored case state.

Review state
------------
Anomaly dispositions (confirmed, dismissed, accepted) and suppression rules are
analyst decisions, not detector output. Suppressions hide matching rule +
workspace + command patterns until they expire. Both appear in anomalies.csv
and in manifest.json.
"""


def case_zip(ledger: CollectionHost) -> bytes:
    from ai_forensics.report import build_report, report_html, report_markdown

    meta = ledger.get_meta()
    case_id = meta.get("case_id", "case")
    manifest = json.dumps(case_manifest(ledger), indent=2, ensure_ascii=False).encode("utf-8")
    report = build_report(ledger)
    report_htm = report_html(ledger, report).encode("utf-8")
    report_md = report_markdown(ledger, report).encode("utf-8")
    database = _db_snapshot(ledger)
    case_json = b""
    if ledger.db_path is not None:
        path = Path(ledger.db_path).parent / "case.json"
        if path.is_file():
            case_json = path.read_bytes()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("report.html", report_htm)
        archive.writestr("report.md", report_md)
        archive.writestr("case.json", case_json or json.dumps(
            {"case_id": case_id}, indent=2
        ).encode("utf-8"))
        archive.writestr("manifest.json", manifest)
        with archive.open("rows.csv", "w") as handle:
            for chunk in rows_csv_chunks(ledger):
                handle.write(chunk)
        with archive.open("anomalies.csv", "w") as handle:
            for chunk in anomalies_csv_chunks(ledger):
                handle.write(chunk)
        archive.writestr("ledger.sqlite", database)
        archive.writestr(
            "README.txt",
            _README.format(
                creator=CREATOR_NAME,
                creator_url=CREATOR_URL,
            ).encode("utf-8"),
        )
    return buffer.getvalue()


__all__ = [
    "ANOMALY_COLUMNS",
    "ROW_COLUMNS",
    "anomalies_csv_chunks",
    "case_manifest",
    "case_zip",
    "collected_hashes",
    "rows_csv_chunks",
    "verify_hashes",
]
