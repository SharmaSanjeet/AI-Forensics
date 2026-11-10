"""Case database, collection host, and masked row storage.

The database stores masked text only. Secret cleartext is not inserted.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ai_forensics.model import (
    FILE_HASH_CAP,
    FULLTEXT_BYTES,
    ROW_CAP,
    RULE_PRIORITY,
    SUMMARY_CHARS,
    CoverageEntry,
    RawRecord,
)
from ai_forensics.paths import file_stat, inside
from ai_forensics.secrets import mask_fields, redact_structure
from ai_forensics.textutil import clip_utf8, json_dumps, normalize_prompt, one_line, sha256_bytes, sha256_file


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _row_fingerprint(
    source: object,
    offset: object,
    role: object,
    record_type: object,
    text: object,
    command: object,
    tool_input: object,
    invoked_tool: object,
) -> bytes:
    material = "\x1f".join(
        str(value or "")
        for value in (source, offset, role, record_type, text, command, tool_input, invoked_tool)
    )
    return hashlib.sha256(material.encode("utf-8", "replace")).digest()[:16]


_RULE_CASE = "CASE rule " + " ".join(
    f"WHEN '{rule}' THEN {rank}" for rule, rank in RULE_PRIORITY.items()
) + " ELSE 99 END"

TRIAGE_DISPOSITIONS = ("open", "confirmed", "dismissed", "accepted")
RANK_LABELS = ("likely-real", "likely-benign")

# These rules are defined by a workspace or rate pattern, not one command, so a
# suppression covers the whole rule/workspace pair.
_PATTERN_RULES = {
    "tool_burst",
    "off_hours_activity",
    "cross_tool_prompt",
    "sensitive_workspace",
}


class CollectionHost:
    """Parser callback. `inside` is the path jail for this collection."""

    def __init__(self, roots: list[Path], *, include_subagents: bool, row_cap: int, fulltext_bytes: int):
        self.roots = [root.resolve() for root in roots]
        self.include_subagents = include_subagents
        self.row_cap = row_cap
        self.fulltext_bytes = fulltext_bytes
        self.cancel = threading.Event()
        self.lock = threading.Lock()
        self.user = ""
        self.host_name = ""
        self.row_count = 0
        self.hit_cap = False
        self.parse_errors = 0
        self.truncations = 0
        self.subagents_skipped = 0
        self.activity: list[dict[str, str]] = []
        self.coverage: list[CoverageEntry] = []
        self.eligible: list[str] = []
        self.db_path: Path | None = None
        self._conn: sqlite3.Connection | None = None
        self._salt = b""
        self._file_path = ""
        self._file_tool = ""
        self._file_rows = 0
        self._file_errors = 0
        self._file_trunc = 0
        self._override_status: str | None = None
        self._notes = ""
        self._batch: list[tuple] = []
        self._dedupe = False
        self._seen_rows: set[bytes] = set()
        self.running = False
        self.cancelled = False
        self.roots_display: list[str] = []
        self.checked: list[dict[str, object]] = []
        self.empty_users: list[str] = []
        self.rollout_rows = 0
        self.rollout_errors = 0
        self.case_dir: Path | None = None
        self.case_id = ""
        self.created_at = _now()

    @property
    def stop(self) -> bool:
        return self.cancel.is_set() or self.hit_cap

    def log(self, message: str) -> None:
        entry = {"time": _now(), "message": message}
        with self.lock:
            self.activity.append(entry)
            if len(self.activity) > 500:
                self.activity = self.activity[-500:]

    def inside(self, path: Path) -> bool:
        return any(inside(root, path) for root in self.roots)

    def open_db(self, case_dir: Path | None = None, *, reset: bool = False) -> None:
        folder = Path(case_dir) if case_dir is not None else Path(tempfile.mkdtemp(prefix="asl-case-"))
        folder.mkdir(parents=True, exist_ok=True)
        db_path = folder / "ledger.sqlite"
        if reset and db_path.exists():
            db_path.unlink()
            for suffix in ("-wal", "-shm"):
                sidecar = db_path.with_name(db_path.name + suffix)
                if sidecar.exists():
                    sidecar.unlink()
        self.case_dir = folder
        self.case_id = folder.name
        self.db_path = db_path
        conn = sqlite3.connect(db_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS rows (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                role TEXT NOT NULL,
                record_type TEXT NOT NULL DEFAULT 'message',
                tool TEXT NOT NULL,
                invoked_tool TEXT NOT NULL,
                tool_command TEXT NOT NULL,
                tool_input TEXT NOT NULL,
                tool_description TEXT NOT NULL,
                summary TEXT NOT NULL,
                full_text TEXT NOT NULL,
                session_id TEXT NOT NULL,
                workspace TEXT NOT NULL,
                source_file TEXT NOT NULL,
                source_offset INTEGER NOT NULL,
                model TEXT NOT NULL,
                user_name TEXT NOT NULL,
                host TEXT NOT NULL,
                also_in_tools TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                truncated INTEGER NOT NULL,
                norm_hash TEXT NOT NULL,
                secrets_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_rows_ts ON rows(timestamp);
            CREATE INDEX IF NOT EXISTS idx_rows_norm ON rows(norm_hash);
            CREATE INDEX IF NOT EXISTS idx_rows_tool ON rows(tool);
            CREATE INDEX IF NOT EXISTS idx_rows_session ON rows(session_id);
            CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS coverage (
                source TEXT NOT NULL,
                tool TEXT NOT NULL,
                status TEXT NOT NULL,
                files_read INTEGER NOT NULL,
                rows INTEGER NOT NULL,
                parse_errors INTEGER NOT NULL,
                truncations INTEGER NOT NULL,
                notes TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS anomalies (
                id TEXT PRIMARY KEY,
                rule TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                summary TEXT NOT NULL,
                tool TEXT NOT NULL,
                workspace TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                row_ids TEXT NOT NULL,
                evidence TEXT NOT NULL,
                confidence TEXT NOT NULL,
                what_happened TEXT NOT NULL DEFAULT '',
                why_it_matters TEXT NOT NULL DEFAULT '',
                next_steps TEXT NOT NULL DEFAULT '',
                llm_model TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS llm_cache (
                cache_key TEXT PRIMARY KEY,
                provider TEXT NOT NULL,
                model TEXT NOT NULL,
                response TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS anomaly_triage (
                anomaly_id TEXT PRIMARY KEY,
                disposition TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                reviewer TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS suppressions (
                id TEXT PRIMARY KEY,
                rule TEXT NOT NULL,
                workspace TEXT NOT NULL,
                command_hash TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                created_by TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS anomaly_ranking (
                anomaly_id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                reason TEXT NOT NULL DEFAULT '',
                model TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        columns = {row[1] for row in conn.execute("PRAGMA table_info(rows)")}
        if "record_type" not in columns:
            conn.execute("ALTER TABLE rows ADD COLUMN record_type TEXT NOT NULL DEFAULT 'message'")
        stored = conn.execute("SELECT v FROM meta WHERE k = 'salt_hex'").fetchone()
        if stored:
            self._salt = bytes.fromhex(stored[0])
        else:
            self._salt = os.urandom(16)
            conn.execute("INSERT INTO meta(k, v) VALUES(?, ?)", ("salt_hex", self._salt.hex()))
        conn.commit()
        self._conn = conn
        if not reset:
            self.row_count = int(conn.execute("SELECT COUNT(*) FROM rows").fetchone()[0])

    def enable_incremental(self) -> int:
        """Skip rows already present in this case. Used by watch mode."""
        with self.lock:
            self._flush()
            self._dedupe = True
            self._seen_rows = set()
            if self._conn is not None:
                for row in self._conn.execute(
                    """
                    SELECT source_file, source_offset, role, record_type,
                           full_text, tool_command, tool_input, invoked_tool
                    FROM rows
                    """
                ):
                    self._seen_rows.add(_row_fingerprint(*row))
            return len(self._seen_rows)

    @property
    def incremental(self) -> bool:
        with self.lock:
            return self._dedupe

    def forget_coverage(self, source: str) -> None:
        """Drop coverage entries for one store before it is re-parsed."""
        base = str(source).rstrip("\\/")
        separator = "\\\\" if "\\" in base else "/"
        escaped = (
            base.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            + separator
            + "%"
        )
        with self.lock:
            self.coverage = [
                entry
                for entry in self.coverage
                if entry.source != base and not entry.source.startswith(base + separator[0])
            ]
            if self._conn is not None:
                self._conn.execute(
                    "DELETE FROM coverage WHERE source = ? OR source LIKE ? ESCAPE '\\'",
                    (base, escaped),
                )
                self._conn.commit()

    def close(self) -> None:
        self._flush()
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def discard(self) -> None:
        self.close()
        if self.db_path is not None:
            shutil.rmtree(self.db_path.parent, ignore_errors=True)
            self.db_path = None

    def _flush(self) -> None:
        if not self._batch or self._conn is None:
            return
        self._conn.executemany(
            """
            INSERT INTO rows (
                id, timestamp, role, record_type, tool, invoked_tool, tool_command, tool_input,
                tool_description, summary, full_text, session_id, workspace,
                source_file, source_offset, model, user_name, host, also_in_tools,
                content_hash, truncated, norm_hash, secrets_json
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            self._batch,
        )
        self._conn.commit()
        self._batch.clear()

    def begin_file(self, path: Path, tool: str) -> None:
        self._file_path = str(path)
        self._file_tool = tool
        self._file_rows = 0
        self._file_errors = 0
        self._file_trunc = 0
        self._override_status = None
        self._notes = ""

    def error(self, count: int = 1) -> None:
        self._file_errors += count
        self.parse_errors += count

    def force_status(self, status: str, notes: str = "") -> None:
        self._override_status = status
        if notes:
            self._notes = notes

    def add_note(self, notes: str) -> None:
        if not notes:
            return
        self._notes = f"{self._notes} {notes}".strip() if self._notes else notes

    def end_file(self, files_read: int = 1) -> None:
        if not self._file_path:
            return
        produced = self._file_rows
        errors = self._file_errors
        status = self._override_status
        if status is None:
            if errors and produced:
                status = "partial"
            elif errors:
                status = "malformed"
            elif produced:
                status = "parsed"
            else:
                status = "empty"
        if status == "parsed":
            self.eligible.append(self._file_path)
        self._add_coverage(
            CoverageEntry(
                source=self._file_path,
                tool=self._file_tool,
                status=status,
                files_read=files_read,
                rows=produced,
                parse_errors=errors,
                truncations=self._file_trunc,
                notes=self._notes,
            )
        )
        self._file_path = ""

    def cover(
        self,
        source: str,
        tool: str,
        status: str,
        notes: str = "",
        *,
        files_read: int = 0,
        rows: int = 0,
        parse_errors: int = 0,
        truncations: int = 0,
    ) -> None:
        self._add_coverage(
            CoverageEntry(
                source=source,
                tool=tool,
                status=status,
                files_read=files_read,
                rows=rows,
                parse_errors=parse_errors,
                truncations=truncations,
                notes=notes,
            )
        )

    def _add_coverage(self, entry: CoverageEntry) -> None:
        with self.lock:
            self.coverage.append(entry)
            if self._conn is not None:
                self._conn.execute(
                    """
                    INSERT INTO coverage (
                        source, tool, status, files_read, rows, parse_errors, truncations, notes
                    ) VALUES (?,?,?,?,?,?,?,?)
                    """,
                    (
                        entry.source,
                        entry.tool,
                        entry.status,
                        entry.files_read,
                        entry.rows,
                        entry.parse_errors,
                        entry.truncations,
                        entry.notes,
                    ),
                )
                self._conn.commit()

    def note_subagent(self) -> None:
        self.subagents_skipped += 1

    def emit(self, record: RawRecord) -> bool:
        if self.stop:
            self.hit_cap = self.hit_cap or self.row_count >= self.row_cap
            return False
        if record.is_subagent and not self.include_subagents:
            self.note_subagent()
            return True
        if record.role not in {"user", "assistant", "tool", "system", "metadata"}:
            record.role = "metadata"
        tool_input = record.tool_input
        if tool_input is not None:
            tool_input_text = json_dumps(redact_structure(tool_input))
        else:
            tool_input_text = ""
        masked, findings = mask_fields(
            [
                record.text or "",
                record.tool_command or "",
                tool_input_text,
                record.tool_description or "",
            ],
            self._salt,
        )
        full_source, command, tool_input_masked, description = masked
        original_bytes = len(full_source.encode("utf-8"))
        full_text, truncated = clip_utf8(full_source, self.fulltext_bytes)
        if original_bytes > self.fulltext_bytes:
            truncated = True
        if self._dedupe:
            fingerprint = _row_fingerprint(
                record.source_file or self._file_path,
                record.source_offset,
                record.role,
                record.record_type or "message",
                full_text,
                command,
                tool_input_masked,
                record.invoked_tool or "",
            )
            if fingerprint in self._seen_rows:
                return True
            self._seen_rows.add(fingerprint)
        if truncated:
            self.truncations += 1
            self._file_trunc += 1
        summary_source = full_source or command or record.invoked_tool or record.role
        summary = one_line(summary_source, SUMMARY_CHARS)
        norm = ""
        if record.role == "user":
            normalized = normalize_prompt(full_source)
            if normalized:
                norm = sha256_bytes(normalized.encode("utf-8"))
        self.row_count += 1
        row_id = f"r{self.row_count}"
        self._file_rows += 1
        user = record.user or self.user
        host_name = record.host or self.host_name
        self._batch.append(
            (
                row_id,
                record.timestamp or "",
                record.role,
                record.record_type or "message",
                record.tool,
                record.invoked_tool or "",
                command,
                tool_input_masked,
                description,
                summary,
                full_text,
                record.session_id or "",
                record.workspace or "",
                record.source_file or self._file_path,
                int(record.source_offset or 0),
                record.model or "",
                user,
                host_name,
                "[]",
                record.content_hash or "",
                1 if truncated else 0,
                norm,
                json.dumps(findings, separators=(",", ":")),
            )
        )
        if len(self._batch) >= 400:
            with self.lock:
                self._flush()
        if self.row_count >= self.row_cap:
            self.hit_cap = True
            self.log(f"row cap {self.row_cap} reached")
            with self.lock:
                self._flush()
            return False
        return True

    def link_prompts(self) -> None:
        with self.lock:
            self._flush()
            assert self._conn is not None
            pairs = self._conn.execute(
                """
                SELECT norm_hash, tool FROM rows
                WHERE role = 'user' AND norm_hash != ''
                GROUP BY norm_hash, tool
                """
            ).fetchall()
            grouped: dict[str, set[str]] = {}
            for norm_hash, tool in pairs:
                grouped.setdefault(norm_hash, set()).add(tool)
            for norm_hash, tools in grouped.items():
                if len(tools) < 2:
                    continue
                for tool in tools:
                    others = sorted(tools - {tool})
                    self._conn.execute(
                        """
                        UPDATE rows SET also_in_tools = ?
                        WHERE norm_hash = ? AND tool = ? AND role = 'user'
                        """,
                        (json.dumps(others), norm_hash, tool),
                    )
            self._conn.commit()

    def salt(self) -> bytes:
        return self._salt

    def coverage_public(self) -> list[dict[str, object]]:
        with self.lock:
            if self._conn is not None:
                found = self._conn.execute(
                    """
                    SELECT source, tool, status, files_read, rows, parse_errors, truncations, notes
                    FROM coverage ORDER BY rowid
                    """
                ).fetchall()
                return [
                    {
                        "source": row[0],
                        "tool": row[1],
                        "status": row[2],
                        "filesRead": row[3],
                        "rows": row[4],
                        "parseErrors": row[5],
                        "truncations": row[6],
                        "notes": row[7],
                    }
                    for row in found
                ]
            return [
                {
                    "source": item.source,
                    "tool": item.tool,
                    "status": item.status,
                    "filesRead": item.files_read,
                    "rows": item.rows,
                    "parseErrors": item.parse_errors,
                    "truncations": item.truncations,
                    "notes": item.notes,
                }
                for item in self.coverage
            ]

    def _where(self, filters: dict[str, str]) -> tuple[str, list[str]]:
        clauses = ["1=1"]
        args: list[str] = []
        mapping = {
            "role": "role",
            "tool": "tool",
            "invokedTool": "invoked_tool",
            "recordType": "record_type",
            "workspace": "workspace",
            "user": "user_name",
            "host": "host",
            "sessionId": "session_id",
        }
        for key, column in mapping.items():
            value = (filters.get(key) or "").strip()
            if value:
                clauses.append(f"{column} = ?")
                args.append(value)
        start = (filters.get("start") or "").strip()
        end = (filters.get("end") or "").strip()
        if start or end:
            clauses.append("timestamp != ''")
        if start:
            clauses.append("timestamp >= ?")
            args.append(start)
        if end:
            clauses.append("timestamp <= ?")
            args.append(end)
        query = (filters.get("q") or "").strip()
        if query:
            escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            like = f"%{escaped}%"
            clauses.append(
                "(summary LIKE ? ESCAPE '\\' OR tool_command LIKE ? ESCAPE '\\' OR full_text LIKE ? ESCAPE '\\')"
            )
            args.extend([like, like, like])
        return " AND ".join(clauses), args

    def count(self, filters: dict[str, str]) -> int:
        if self._conn is None:
            return 0
        where, args = self._where(filters)
        with self.lock:
            self._flush()
            row = self._conn.execute(f"SELECT COUNT(*) FROM rows WHERE {where}", args).fetchone()
        return int(row[0]) if row else 0

    def missing_timestamp_count(self) -> int:
        if self._conn is None:
            return 0
        with self.lock:
            self._flush()
            row = self._conn.execute("SELECT COUNT(*) FROM rows WHERE timestamp = ''").fetchone()
        return int(row[0]) if row else 0

    def query_rows(self, filters: dict[str, str], *, offset: int = 0, limit: int = 200, detail: bool = False) -> list[dict]:
        if self._conn is None:
            return []
        where, args = self._where(filters)
        limit = max(1, min(limit, 500))
        offset = max(0, offset)
        sql = f"""
            SELECT * FROM rows WHERE {where}
            ORDER BY CASE WHEN timestamp = '' THEN 1 ELSE 0 END, timestamp ASC, id ASC
            LIMIT ? OFFSET ?
        """
        with self.lock:
            self._flush()
            found = self._conn.execute(sql, [*args, limit, offset]).fetchall()
            columns = [item[0] for item in self._conn.execute("SELECT * FROM rows LIMIT 0").description]
        rows = []
        for record in found:
            mapped = dict(zip(columns, record))
            rows.append(_public_row(mapped, detail=detail))
        return rows

    def get_row(self, row_id: str) -> dict | None:
        if self._conn is None:
            return None
        with self.lock:
            self._flush()
            record = self._conn.execute("SELECT * FROM rows WHERE id = ?", (row_id,)).fetchone()
            if record is None:
                return None
            columns = [item[0] for item in self._conn.execute("SELECT * FROM rows LIMIT 0").description]
        return _public_row(dict(zip(columns, record)), detail=True)

    def iter_filtered(self, filters: dict[str, str]):
        if self._conn is None:
            return
        where, args = self._where(filters)
        sql = f"""
            SELECT * FROM rows WHERE {where}
            ORDER BY CASE WHEN timestamp = '' THEN 1 ELSE 0 END, timestamp ASC, id ASC
        """
        with self.lock:
            self._flush()
            cursor = self._conn.execute(sql, args)
            columns = [item[0] for item in cursor.description]
        while True:
            with self.lock:
                records = cursor.fetchmany(500)
            if not records:
                break
            for record in records:
                yield dict(zip(columns, record))

    def facets(self) -> dict[str, list[str]]:
        if self._conn is None:
            return {
                "role": [],
                "tool": [],
                "invokedTool": [],
                "recordType": [],
                "workspace": [],
                "user": [],
                "host": [],
            }
        with self.lock:
            self._flush()

            def distinct(column: str) -> list[str]:
                assert self._conn is not None
                found = self._conn.execute(
                    f"""
                    SELECT {column} FROM rows
                    WHERE {column} != ''
                    GROUP BY {column}
                    ORDER BY COUNT(*) DESC
                    LIMIT 80
                    """
                ).fetchall()
                return [row[0] for row in found]

            return {
                "role": distinct("role"),
                "tool": distinct("tool"),
                "invokedTool": distinct("invoked_tool"),
                "recordType": distinct("record_type"),
                "workspace": distinct("workspace"),
                "user": distinct("user_name"),
                "host": distinct("host"),
            }

    def read_source_text(self, row: dict) -> str:
        path = Path(str(row.get("sourceFile") or ""))
        if not path.is_file() or path.is_symlink() or not self.inside(path):
            raise FileNotFoundError(str(path))
        offset = int(row.get("sourceOffset") or 0)
        size, _mtime = file_stat(path)
        with path.open("rb") as handle:
            if offset:
                handle.seek(offset)
            chunk = handle.read(min(LINE_CAP, max(0, size - offset)))
        if b"\n" in chunk and offset:
            chunk = chunk.split(b"\n", 1)[0]
        elif size > LINE_CAP and not offset:
            chunk = chunk[:LINE_CAP]
        return chunk.decode("utf-8", errors="replace")

    def file_hashes(self) -> tuple[list[dict[str, object]], int]:
        eligible = list(self.eligible)
        if not eligible and self._conn is not None:
            with self.lock:
                eligible = [
                    row[0]
                    for row in self._conn.execute(
                        "SELECT source FROM coverage WHERE status = 'parsed'"
                    ).fetchall()
                ]
        unique = sorted(set(eligible))
        hashed = []
        omitted = max(0, len(unique) - FILE_HASH_CAP)
        for path_text in unique[:FILE_HASH_CAP]:
            path = Path(path_text)
            if not path.is_file() or path.is_symlink() or not self.inside(path):
                continue
            size, mtime = file_stat(path)
            try:
                digest = sha256_file(path)
            except OSError:
                continue
            hashed.append({"path": path_text, "size": size, "mtime": mtime, "sha256": digest})
        return hashed, omitted

    def set_meta(self, values: dict[str, object]) -> None:
        if self._conn is None:
            return
        with self.lock:
            for key, value in values.items():
                self._conn.execute(
                    "INSERT INTO meta(k, v) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                    (key, json.dumps(value, default=str) if not isinstance(value, str) else value),
                )
            self._conn.commit()

    def get_meta(self) -> dict[str, str]:
        if self._conn is None:
            return {}
        with self.lock:
            return {key: value for key, value in self._conn.execute("SELECT k, v FROM meta")}

    def replace_anomalies(self, items: list[dict]) -> None:
        if self._conn is None:
            return
        with self.lock:
            previous = {
                row[0]: tuple(row[1:5])
                for row in self._conn.execute(
                    """
                    SELECT id, what_happened, why_it_matters, next_steps, llm_model
                    FROM anomalies
                    """
                )
            }
            self._conn.execute("DELETE FROM anomalies")
            rows = []
            for item in items:
                explanation = (
                    item.get("what_happened", ""),
                    item.get("why_it_matters", ""),
                    item.get("next_steps", ""),
                    item.get("llm_model", ""),
                )
                if not explanation[0]:
                    explanation = previous.get(item["id"], ("", "", "", ""))
                rows.append(
                    (
                        item["id"],
                        item["rule"],
                        item["severity"],
                        item["title"],
                        item.get("summary", ""),
                        item.get("tool", ""),
                        item.get("workspace", ""),
                        item.get("timestamp", ""),
                        json.dumps(item.get("row_ids", []), separators=(",", ":")),
                        json.dumps(item.get("evidence", []), separators=(",", ":")),
                        item.get("confidence", "medium"),
                        *explanation,
                        _now(),
                    )
                )
            self._conn.executemany(
                """
                INSERT OR REPLACE INTO anomalies (
                    id, rule, severity, title, summary, tool, workspace, timestamp,
                    row_ids, evidence, confidence, what_happened, why_it_matters,
                    next_steps, llm_model, created_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                rows,
            )
            self._conn.commit()

    def _anomaly_row(self, row: tuple) -> dict:
        keys = (
            "id", "rule", "severity", "title", "summary", "tool", "workspace",
            "timestamp", "row_ids", "evidence", "confidence", "what_happened",
            "why_it_matters", "next_steps", "llm_model", "created_at",
        )
        item = dict(zip(keys, row))
        item["rowIds"] = json.loads(item.pop("row_ids") or "[]")
        item["evidence"] = json.loads(item["evidence"] or "[]")
        item["whatHappened"] = item.pop("what_happened")
        item["whyItMatters"] = item.pop("why_it_matters")
        item["nextSteps"] = item.pop("next_steps")
        item["llmModel"] = item.pop("llm_model")
        item["createdAt"] = item.pop("created_at")
        return item

    def query_anomalies(
        self,
        severity: str = "",
        *,
        exclude_suppressed: bool = False,
        exclude_reviewed: bool = False,
    ) -> list[dict]:
        if self._conn is None:
            return []
        sql = "SELECT * FROM anomalies"
        args: list[str] = []
        if severity:
            sql += " WHERE severity = ?"
            args.append(severity)
        sql += f"""
            ORDER BY CASE severity
                WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
                {_RULE_CASE},
                timestamp DESC
        """
        with self.lock:
            found = self._conn.execute(sql, args).fetchall()
        items = self._decorate_anomalies([self._anomaly_row(row) for row in found])
        if exclude_suppressed:
            items = [item for item in items if not item["suppressed"]]
        if exclude_reviewed:
            items = [item for item in items if item["disposition"] in {"open", "confirmed"}]
        return items

    def get_anomaly(self, anomaly_id: str) -> dict | None:
        if self._conn is None:
            return None
        with self.lock:
            row = self._conn.execute("SELECT * FROM anomalies WHERE id = ?", (anomaly_id,)).fetchone()
        if row is None:
            return None
        return self._decorate_anomalies([self._anomaly_row(row)])[0]

    def suppression_fingerprint(self, anomaly: dict) -> str:
        return _command_fingerprint(anomaly)

    def update_anomaly_explanation(
        self, anomaly_id: str, *, what_happened: str, why_it_matters: str, next_steps: str, model: str
    ) -> None:
        if self._conn is None:
            return
        with self.lock:
            self._conn.execute(
                """
                UPDATE anomalies SET what_happened = ?, why_it_matters = ?, next_steps = ?, llm_model = ?
                WHERE id = ?
                """,
                (what_happened, why_it_matters, next_steps, model, anomaly_id),
            )
            self._conn.commit()

    def set_triage(
        self, anomaly_id: str, *, disposition: str, note: str = "", reviewer: str = ""
    ) -> None:
        if disposition not in TRIAGE_DISPOSITIONS:
            raise ValueError(f"unknown disposition: {disposition}")
        if self._conn is None:
            return
        with self.lock:
            if disposition == "open":
                self._conn.execute(
                    "DELETE FROM anomaly_triage WHERE anomaly_id = ?", (anomaly_id,)
                )
            else:
                self._conn.execute(
                    """
                    INSERT INTO anomaly_triage(anomaly_id, disposition, note, reviewer, updated_at)
                    VALUES (?,?,?,?,?)
                    ON CONFLICT(anomaly_id) DO UPDATE SET
                        disposition = excluded.disposition,
                        note = excluded.note,
                        reviewer = excluded.reviewer,
                        updated_at = excluded.updated_at
                    """,
                    (anomaly_id, disposition, note[:2000], reviewer[:120], _now()),
                )
            self._conn.commit()

    def triage_map(self) -> dict[str, dict]:
        if self._conn is None:
            return {}
        with self.lock:
            found = self._conn.execute(
                "SELECT anomaly_id, disposition, note, reviewer, updated_at FROM anomaly_triage"
            ).fetchall()
        return {
            row[0]: {
                "disposition": row[1],
                "note": row[2],
                "reviewer": row[3],
                "updatedAt": row[4],
            }
            for row in found
        }

    def add_suppression(
        self,
        *,
        rule: str,
        workspace: str,
        command_hash: str,
        note: str = "",
        created_by: str = "",
        days: int = 90,
    ) -> dict:
        seed = f"{rule}|{workspace}|{command_hash}"
        suppression_id = hashlib.sha1(seed.encode("utf-8")).hexdigest()[:16]
        expires_at = ""
        if days > 0:
            expires_at = (
                datetime.now(timezone.utc) + timedelta(days=days)
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
        if self._conn is not None:
            with self.lock:
                self._conn.execute(
                    """
                    INSERT OR REPLACE INTO suppressions(
                        id, rule, workspace, command_hash, note, created_by, created_at, expires_at
                    ) VALUES (?,?,?,?,?,?,?,?)
                    """,
                    (
                        suppression_id,
                        rule,
                        workspace,
                        command_hash,
                        note[:2000],
                        created_by[:120],
                        _now(),
                        expires_at,
                    ),
                )
                self._conn.commit()
        return {
            "id": suppression_id,
            "rule": rule,
            "workspace": workspace,
            "commandHash": command_hash,
            "note": note,
            "createdBy": created_by,
            "createdAt": _now(),
            "expiresAt": expires_at,
        }

    def list_suppressions(self, *, active_only: bool = True) -> list[dict]:
        if self._conn is None:
            return []
        with self.lock:
            found = self._conn.execute(
                """
                SELECT id, rule, workspace, command_hash, note, created_by, created_at, expires_at
                FROM suppressions ORDER BY created_at DESC, id
                """
            ).fetchall()
        now = _now()
        items = [
            {
                "id": row[0],
                "rule": row[1],
                "workspace": row[2],
                "commandHash": row[3],
                "note": row[4],
                "createdBy": row[5],
                "createdAt": row[6],
                "expiresAt": row[7],
                "active": not row[7] or row[7] > now,
            }
            for row in found
        ]
        if active_only:
            items = [item for item in items if item["active"]]
        return items

    def remove_suppression(self, suppression_id: str) -> bool:
        if self._conn is None:
            return False
        with self.lock:
            cursor = self._conn.execute(
                "DELETE FROM suppressions WHERE id = ?", (suppression_id,)
            )
            self._conn.commit()
        return cursor.rowcount > 0

    def _session_ids(self, items: list[dict]) -> dict[str, str]:
        if self._conn is None:
            return {}
        first_ids = []
        for item in items:
            row_ids = item.get("rowIds") or []
            if row_ids:
                first_ids.append(str(row_ids[0]))
        unique = list(dict.fromkeys(first_ids))[:500]
        if not unique:
            return {}
        marks = ",".join("?" for _ in unique)
        with self.lock:
            found = self._conn.execute(
                f"SELECT id, session_id FROM rows WHERE id IN ({marks})", unique
            ).fetchall()
        return {row[0]: row[1] for row in found}

    def _decorate_anomalies(self, items: list[dict]) -> list[dict]:
        triage = self.triage_map()
        suppressions = self.list_suppressions()
        rankings = self.rank_map()
        sessions = self._session_ids(items)
        for item in items:
            row_ids = item.get("rowIds") or []
            item["sessionId"] = sessions.get(str(row_ids[0]), "") if row_ids else ""
            rank = rankings.get(str(item.get("id") or ""))
            item["rankLabel"] = rank["label"] if rank else ""
            item["rankReason"] = rank["reason"] if rank else ""
            item["rankModel"] = rank["model"] if rank else ""
            record = triage.get(str(item.get("id") or ""))
            item["disposition"] = record["disposition"] if record else "open"
            item["dispositionNote"] = record["note"] if record else ""
            item["dispositionBy"] = record["reviewer"] if record else ""
            item["dispositionAt"] = record["updatedAt"] if record else ""
            fingerprint = _command_fingerprint(item)
            match = next(
                (
                    entry
                    for entry in suppressions
                    if entry["rule"] == item.get("rule")
                    and entry["workspace"] == item.get("workspace")
                    and entry["commandHash"] in {"*", fingerprint}
                ),
                None,
            )
            item["suppressed"] = match is not None
            item["suppressionId"] = match["id"] if match else ""
        return items

    def rank_map(self) -> dict[str, dict]:
        if self._conn is None:
            return {}
        with self.lock:
            found = self._conn.execute(
                """
                SELECT anomaly_id, label, reason, model, created_at
                FROM anomaly_ranking
                """
            ).fetchall()
        return {
            row[0]: {"label": row[1], "reason": row[2], "model": row[3], "createdAt": row[4]}
            for row in found
        }

    def set_ranking(self, anomaly_id: str, *, label: str, reason: str = "", model: str = "") -> None:
        if label not in RANK_LABELS:
            raise ValueError(f"unknown ranking label: {label}")
        if self._conn is None:
            return
        with self.lock:
            self._conn.execute(
                """
                INSERT INTO anomaly_ranking(anomaly_id, label, reason, model, created_at)
                VALUES(?,?,?,?,?)
                ON CONFLICT(anomaly_id) DO UPDATE SET
                    label = excluded.label,
                    reason = excluded.reason,
                    model = excluded.model,
                    created_at = excluded.created_at
                """,
                (anomaly_id, label, reason[:240], model[:120], _now()),
            )
            self._conn.commit()

    def cache_get(self, cache_key: str) -> str | None:
        if self._conn is None:
            return None
        with self.lock:
            row = self._conn.execute(
                "SELECT response FROM llm_cache WHERE cache_key = ?", (cache_key,)
            ).fetchone()
        return row[0] if row else None

    def cache_set(self, cache_key: str, provider: str, model: str, response: str) -> None:
        if self._conn is None:
            return
        with self.lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO llm_cache(cache_key, provider, model, response, created_at)
                VALUES (?,?,?,?,?)
                """,
                (cache_key, provider, model, response, _now()),
            )
            self._conn.commit()

    def stats(self) -> dict[str, object]:
        if self._conn is None:
            return {"total_rows": 0}
        open_anomalies = sum(
            1
            for item in self.query_anomalies(exclude_suppressed=True)
            if item["disposition"] == "open"
        )
        with self.lock:
            self._flush()

            def grouped(sql: str) -> list[dict[str, object]]:
                return [{"label": row[0], "count": row[1]} for row in self._conn.execute(sql)]

            total = int(self._conn.execute("SELECT COUNT(*) FROM rows").fetchone()[0])
            span = self._conn.execute(
                "SELECT MIN(timestamp), MAX(timestamp) FROM rows WHERE timestamp != ''"
            ).fetchone()
            hours = {
                str(row[0]).zfill(2): row[1]
                for row in self._conn.execute(
                    """
                    SELECT substr(timestamp, 12, 2) AS hour, COUNT(*) FROM rows
                    WHERE timestamp != '' GROUP BY hour
                    """
                )
            }
            secrets = int(
                self._conn.execute(
                    "SELECT COUNT(*) FROM rows WHERE secrets_json NOT IN ('', '[]')"
                ).fetchone()[0]
            )
            sessions = int(
                self._conn.execute(
                    "SELECT COUNT(DISTINCT session_id) FROM rows WHERE session_id != ''"
                ).fetchone()[0]
            )
            anomalies_total = int(self._conn.execute("SELECT COUNT(*) FROM anomalies").fetchone()[0])
            return {
                "total_rows": total,
                "sessions": sessions,
                "secret_rows": secrets,
                "anomalies": anomalies_total,
                "open_anomalies": open_anomalies,
                "first_timestamp": span[0] or "",
                "last_timestamp": span[1] or "",
                "by_tool": grouped("SELECT tool, COUNT(*) FROM rows GROUP BY tool ORDER BY 2 DESC"),
                "by_role": grouped("SELECT role, COUNT(*) FROM rows GROUP BY role ORDER BY 2 DESC"),
                "by_record_type": grouped(
                    "SELECT record_type, COUNT(*) FROM rows GROUP BY record_type ORDER BY 2 DESC"
                ),
                "top_workspaces": grouped(
                    """
                    SELECT workspace, COUNT(*) FROM rows WHERE workspace != ''
                    GROUP BY workspace ORDER BY 2 DESC LIMIT 10
                    """
                ),
                "by_severity": grouped(
                    "SELECT severity, COUNT(*) FROM anomalies GROUP BY severity ORDER BY 2 DESC"
                ),
                "by_coverage": grouped(
                    "SELECT status, COUNT(*) FROM coverage GROUP BY status ORDER BY 2 DESC"
                ),
                "hourly": [{"hour": hour, "count": hours.get(hour, 0)} for hour in
                           [str(i).zfill(2) for i in range(24)]],
            }

    def secret_rows(self, limit: int = 500) -> list[dict]:
        if self._conn is None:
            return []
        with self.lock:
            found = self._conn.execute(
                """
                SELECT id, timestamp, tool, role, summary, workspace, user_name, host, secrets_json
                FROM rows WHERE secrets_json NOT IN ('', '[]')
                ORDER BY timestamp DESC, id DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {
                "id": row[0],
                "timestamp": row[1],
                "tool": row[2],
                "role": row[3],
                "summary": row[4],
                "workspace": row[5],
                "user": row[6],
                "host": row[7],
                "secrets": json.loads(row[8] or "[]"),
            }
            for row in found
        ]


LINE_CAP = 4 * 1024 * 1024


def _command_fingerprint(item: dict) -> str:
    """Stable pattern key for suppression; '*' means the rule/workspace alone."""
    if str(item.get("rule") or "") in _PATTERN_RULES:
        return "*"
    evidence = item.get("evidence")
    command = ""
    if isinstance(evidence, list) and evidence and isinstance(evidence[0], dict):
        command = str(evidence[0].get("command") or evidence[0].get("snippet") or "")
    normalized = " ".join(command.casefold().split())
    return sha256_bytes(normalized.encode("utf-8"))[:32] if normalized else "*"


def _public_row(row: dict, *, detail: bool) -> dict:
    public = {
        "id": row["id"],
        "timestamp": row["timestamp"],
        "role": row["role"],
        "recordType": row.get("record_type", "message"),
        "tool": row["tool"],
        "invokedTool": row["invoked_tool"],
        "toolCommand": row["tool_command"],
        "summary": row["summary"],
        "workspace": row["workspace"],
        "sessionId": row["session_id"],
        "user": row["user_name"],
        "host": row["host"],
        "sourceFile": row["source_file"],
        "alsoInTools": json.loads(row["also_in_tools"] or "[]"),
        "truncated": bool(row["truncated"]),
    }
    if detail:
        public.update(
            {
                "toolInput": row["tool_input"],
                "toolDescription": row["tool_description"],
                "model": row["model"],
                "fullText": row["full_text"],
                "sourceOffset": row["source_offset"],
                "contentHash": row["content_hash"],
                "secrets": json.loads(row["secrets_json"] or "[]"),
            }
        )
    return public
