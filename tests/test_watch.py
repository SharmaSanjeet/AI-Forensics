from __future__ import annotations

import json
import os

from ai_forensics.collect.collector import open_case
from ai_forensics.model import RawRecord
from ai_forensics.watch import scan_once

from support import make_host, write_jsonl


def _transcript_lines(secret: str) -> list[dict]:
    return [
        {
            "type": "user",
            "timestamp": "2026-05-01T10:00:00Z",
            "sessionId": "s1",
            "cwd": "C:\\work",
            "message": {"role": "user", "content": f"deploy with {secret}"},
        },
        {
            "type": "assistant",
            "timestamp": "2026-05-01T10:00:05Z",
            "sessionId": "s1",
            "cwd": "C:\\work",
            "message": {
                "role": "assistant",
                "model": "claude-sonnet-4",
                "content": [{"type": "text", "text": "Noted."}],
            },
        },
    ]


def _case(tmp_path, secret: str):
    root = tmp_path / "home"
    transcript = root / ".claude" / "projects" / "ws" / "session-1.jsonl"
    write_jsonl(transcript, _transcript_lines(secret))
    case = tmp_path / "case"
    host = make_host(case, roots=[root])
    host.set_meta(
        {
            "case_id": case.name,
            "mode": "folder",
            "roots": json.dumps([str(root)]),
            "user": "analyst",
            "host": "lab",
        }
    )
    host.close()
    return case, transcript


def test_scan_once_only_appends_new_rows(tmp_path):
    secret = "ghp_" + "a" * 36
    case, transcript = _case(tmp_path, secret)

    host = open_case(case)
    first = scan_once(host, explain=False)
    assert first.new_rows == 2
    assert first.new_leads == 1
    base_rows = host.row_count
    base_ids = {item["id"] for item in host.query_anomalies()}
    assert len(base_ids) == 1
    coverage = host.coverage_public()
    assert len(coverage) == 1

    # A second scan with nothing changed does not touch the case.
    second = scan_once(host, explain=False)
    assert second.new_rows == 0
    assert second.new_leads == 0
    assert host.row_count == base_rows
    assert [entry["source"] for entry in host.coverage_public()] == [entry["source"] for entry in coverage]

    # Touching a file forces a reparse; row dedupe keeps the case unchanged.
    stat = transcript.stat()
    os.utime(transcript, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000))
    touched = scan_once(host, explain=False)
    assert touched.stores_scanned == 1
    assert touched.new_rows == 0
    assert host.row_count == base_rows
    assert len(host.coverage_public()) == 1

    # Triaged state survives incremental re-detection.
    host.set_triage(next(iter(base_ids)), disposition="confirmed", note="known test token")

    second_secret = "ghp_" + "b" * 36
    write_jsonl(
        transcript,
        _transcript_lines(secret)
        + [
            {
                "type": "user",
                "timestamp": "2026-05-01T10:02:00Z",
                "sessionId": "s1",
                "cwd": "C:\\work",
                "message": {"role": "user", "content": f"rotate using {second_secret}"},
            }
        ],
    )
    third = scan_once(host, explain=False)
    assert third.new_rows == 1
    assert third.new_leads == 1
    assert host.row_count == base_rows + 1
    items = {item["id"]: item for item in host.query_anomalies()}
    assert base_ids <= set(items)
    assert items[next(iter(base_ids))]["disposition"] == "confirmed"
    assert len(items) == 2
    meta = host.get_meta()
    assert meta["watch_total_new_rows"] == "3"
    assert meta["watch_total_new_leads"] == "2"
    assert {lead["id"] for lead in json.loads(meta["watch_recent_leads"])} == set(items)
    host.close()


def test_incremental_dedupe_survives_reopen(tmp_path):
    case = tmp_path / "case"
    host = make_host(case)
    record = RawRecord(
        tool="Claude Code",
        role="user",
        text="repeatable prompt",
        timestamp="2026-05-01T10:00:00Z",
        source_file="session-1.jsonl",
        source_offset=0,
    )
    host.emit(record)
    assert host.row_count == 1
    host.enable_incremental()
    assert host.emit(record)
    assert host.row_count == 1
    host.close()

    reopened = open_case(case)
    assert reopened.enable_incremental() == 1
    assert reopened.emit(record)
    assert reopened.row_count == 1
    reopened.close()
