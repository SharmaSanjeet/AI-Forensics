"""Rewrite the knowledge-base workbook's Import sheet for AI-Forensics.

The sheet originally documented another tool's UI menus; this replaces the
rows with this project's collect/detect/analyze/serve workflow and marks
which app families have a parser in the current build.

Usage: py -3.12 tools/build_reference_sheets.py
"""

import pathlib

import openpyxl

ROOT = pathlib.Path(__file__).resolve().parent.parent
XLSX = ROOT / "docs" / "reference" / "AI_Query_Artifacts_Consolidated.xlsx"

ROWS = [
    ("App", "How to import into AI-Forensics", "Notes"),
    (
        "Claude Code",
        "ai-forensics collect --mode folder --path <folder containing .claude>",
        "Supported parser. Use --mode machine to scan this PC; --include-subagents to include sidechains.",
    ),
    (
        "OpenAI Codex",
        "ai-forensics collect --mode folder --path <~/.codex>",
        "Supported parser. Rollout transcripts, session index and prompt history.",
    ),
    (
        "Cursor",
        "ai-forensics collect --mode folder --path <~/.cursor or Cursor User folder>",
        "Supported parser. Agent transcripts plus SQLite composer/workspace chats.",
    ),
    (
        "Gemini CLI",
        "ai-forensics collect --mode folder --path <~/.gemini>",
        "Supported parser. Chats, shell history and legacy JSON consolidate into one timeline.",
    ),
    (
        "GitHub Copilot",
        "ai-forensics collect --mode folder --path <~/.copilot or Code/User folder>",
        "Supported parser. Copilot CLI sessions and VS Code chatSessions.",
    ),
    (
        "ChatGPT Desktop / Atlas",
        "Reference only - no parser in the current build",
        "Documented here for future ingestion; browser-only use is hint-only.",
    ),
    (
        "ChatGPT Computer History",
        "Reference only - no parser in the current build",
        "High-value event stream; candidate for a future parser.",
    ),
    (
        "Grok Build / Grok Bot",
        "Reference only - no parser in the current build",
        "Session trees, search index and replicas documented for future parsers.",
    ),
    (
        "All collected cases",
        "ai-forensics detect --case <id>",
        "Runs the 12 deterministic detectors over every stored row.",
    ),
    (
        "All collected cases",
        "ai-forensics analyze and ai-forensics rank (optional), then ai-forensics serve",
        "Local-model explanations and advisory ranking; review and export in the web UI.",
    ),
]


def main() -> None:
    wb = openpyxl.load_workbook(XLSX)
    ws = wb["Import"]
    for r, row in enumerate(ROWS, start=1):
        for c, value in enumerate(row, start=1):
            ws.cell(row=r, column=c).value = value
    wb.save(XLSX)
    print(f"rewrote Import sheet ({len(ROWS) - 1} data rows) in {XLSX}")


if __name__ == "__main__":
    main()
