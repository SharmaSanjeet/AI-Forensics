"""Render docs/reference/AI_Query_Artifacts_Consolidated.xlsx to Markdown.

Produces docs/reference/ai-artifacts-knowledge-base.md so the knowledge base
is readable on GitHub (which cannot display XLSX inline). Regenerate after
editing the workbook: py -3.12 tools/build_reference_doc.py
"""

import pathlib
from collections import OrderedDict

import openpyxl

ROOT = pathlib.Path(__file__).resolve().parent.parent
XLSX = ROOT / "docs" / "reference" / "AI_Query_Artifacts_Consolidated.xlsx"
OUT = ROOT / "docs" / "reference" / "ai-artifacts-knowledge-base.md"

INTRO = """# AI-Assistant Query Artifacts — Reference Knowledge Base

Where AI assistants store what they store: a consolidated catalogue of on-disk
artifacts for Claude Code / Claude Desktop, OpenAI Codex, ChatGPT Desktop &
Atlas, ChatGPT Computer History, Cursor, Gemini CLI, Grok Build, Grok Bot,
GitHub Copilot, Windsurf and Continue.

Use it to plan acquisitions, explain coverage gaps, and target a full-disk
triage. Every path is a default per-platform location; exact names vary by
app version.

> **Scope note.** The *Evidence status* column reflects the consolidated
> research (what is recoverable and how it was handled). In the current
> AI-Forensics build, parsers ship for **Claude Code, OpenAI Codex, Cursor,
> Gemini CLI and GitHub Copilot**; rows for other applications are reference
> material for future parsers. Credential stores are inventoried or excluded,
> never copied.

*Compiled 2026-11-20 from public DFIR research. The editable master is
[`AI_Query_Artifacts_Consolidated.xlsx`](AI_Query_Artifacts_Consolidated.xlsx);
this page is generated from it by `tools/build_reference_doc.py`.*
"""


def cell_text(value: object) -> str:
    if value is None:
        return ""
    text = str(value).replace("\n", " ").replace("|", "\\|")
    return text.strip()


def rows_of(ws) -> list[tuple]:
    return [tuple(row) for row in ws.iter_rows(values_only=True)]


def table(header: tuple, rows: list[tuple]) -> list[str]:
    lines = ["| " + " | ".join(cell_text(h) for h in header) + " |"]
    lines.append("|" + "|".join(" --- " for _ in header) + "|")
    for row in rows:
        lines.append("| " + " | ".join(cell_text(v) for v in row) + " |")
    return lines


def main() -> None:
    wb = openpyxl.load_workbook(XLSX)
    out: list[str] = [INTRO, ""]

    # Artifact catalogue grouped by app
    ws = wb["Artifacts"]
    rows = rows_of(ws)
    header, data = rows[0], rows[1:]
    grouped: OrderedDict[str, list[tuple]] = OrderedDict()
    for row in data:
        if not any(row):
            continue
        grouped.setdefault(cell_text(row[0]), []).append(row[1:])

    out.append("## Artifact catalogue")
    out.append("")
    for app, items in grouped.items():
        out.append(f"### {app}")
        out.append("")
        out.extend(table(tuple(h for h in header[1:]), items))
        out.append("")

    ws = wb["Survives Deletion"]
    rows = rows_of(ws)
    out.append("## What survives deletion")
    out.append("")
    out.append("Artifacts that outlive the conversation they came from — the "
               "collection targets for proving that something existed and was removed.")
    out.append("")
    out.extend(table(tuple(rows[0]), rows[1:]))
    out.append("")

    ws = wb["Limitations"]
    rows = rows_of(ws)
    out.append("## Limitations and blind spots")
    out.append("")
    out.extend(table(tuple(rows[0]), rows[1:]))
    out.append("")

    ws = wb["Import"]
    rows = rows_of(ws)
    out.append("## Importing into AI-Forensics")
    out.append("")
    out.extend(table(tuple(rows[0]), rows[1:]))
    out.append("")
    out.append("---")
    out.append("")
    out.append("Created by [Sanjeet Sharma](https://www.linkedin.com/in/sanjeet-sharma-cissp-17b68570/).")

    OUT.write_text("\n".join(out), encoding="utf-8")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
