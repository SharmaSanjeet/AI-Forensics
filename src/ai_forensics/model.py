"""Shared records for the Assistant Session Ledger."""

from __future__ import annotations

from dataclasses import dataclass, field


ROW_CAP = 3_000_000
FULLTEXT_BYTES = 8 * 1024
SUMMARY_CHARS = 240
LINE_BYTES = 4 * 1024 * 1024
ANALYSIS_ROW_CAP = 120
ANALYSIS_EXCERPT_CHARS = 1500
FILE_HASH_CAP = 250
LLM_MAX_ANOMALIES = 20
LLM_EXCERPT_CHARS = 1200
LLM_CACHE_VERSION = "v1"

SEVERITIES = ("critical", "high", "medium", "low")

RULE_PRIORITY = {
    "secret_exposure": 0,
    "credential_access": 1,
    "exfiltration": 2,
    "risky_command": 3,
    "prompt_injection": 4,
    "unsafe_agent_config": 5,
    "deleted_session": 6,
    "sensitive_workspace": 7,
    "agent_permission_request": 8,
    "cross_tool_prompt": 9,
    "off_hours_activity": 10,
    "tool_burst": 11,
}

ROLES = ("user", "assistant", "tool", "system", "metadata")

TOOLS = (
    "Claude Code",
    "Claude Desktop",
    "OpenAI Codex",
    "ChatGPT Desktop",
    "Grok Build",
    "Grok Bot",
    "Cursor",
    "Gemini CLI",
    "GitHub Copilot",
    "Windsurf",
    "Continue",
)

GRID_COLUMNS = (
    "timestamp",
    "role",
    "tool",
    "invokedTool",
    "toolCommand",
    "summary",
    "workspace",
    "sessionId",
    "user",
    "host",
    "sourceFile",
    "alsoInTools",
)

HIDDEN_COLUMNS = ("toolInput", "toolDescription", "model", "fullText")

COVERAGE_STATUSES = (
    "parsed",
    "empty",
    "partial",
    "malformed",
    "unsupported",
    "excluded",
    "unavailable",
    "inventory-only",
)

CREATOR_NAME = "Sanjeet Sharma"
CREATOR_URL = "https://www.linkedin.com/in/sanjeet-sharma-cissp-17b68570/"


@dataclass
class RawRecord:
    tool: str
    role: str
    text: str = ""
    timestamp: str = ""
    record_type: str = "message"
    invoked_tool: str = ""
    tool_command: str = ""
    tool_input: object | None = None
    tool_description: str = ""
    session_id: str = ""
    workspace: str = ""
    source_file: str = ""
    source_offset: int = 0
    model: str = ""
    user: str = ""
    host: str = ""
    content_hash: str = ""
    is_subagent: bool = False


@dataclass
class CoverageEntry:
    source: str
    tool: str
    status: str
    files_read: int = 0
    rows: int = 0
    parse_errors: int = 0
    truncations: int = 0
    notes: str = ""


@dataclass
class FileNote:
    path: str
    size: int
    mtime: str
    disposition: str
    sha256: str = ""


@dataclass
class SecretFinding:
    category: str
    confidence: str
    fingerprint: str

    def as_dict(self) -> dict[str, str]:
        return {
            "category": self.category,
            "confidence": self.confidence,
            "fingerprint": self.fingerprint,
        }


@dataclass
class CheckedPath:
    path: str
    exists: bool
    note: str = ""


@dataclass
class CollectionResult:
    roots: list[str] = field(default_factory=list)
    checked: list[CheckedPath] = field(default_factory=list)
    row_count: int = 0
    cap_hit: bool = False
    cancelled: bool = False
    truncations: int = 0
    parse_errors: int = 0
