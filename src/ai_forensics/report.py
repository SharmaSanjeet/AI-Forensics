"""Self-contained case report built from the masked case database.

The report is deterministic: every section is rendered from stored rows,
statistics, review state, and the previously generated case brief. It never
calls a model, so downloads are fast and repeatable. The executive summary is
labeled as model-written or deterministic depending on how the brief was made.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from jinja2 import Environment

from ai_forensics.analyze.explain import brief_fallback
from ai_forensics.ledger import CollectionHost
from ai_forensics.model import CREATOR_NAME, CREATOR_URL, SEVERITIES
from ai_forensics.reporting import collected_hashes

_ENV = Environment(autoescape=True, trim_blocks=True, lstrip_blocks=True)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _human(value: object) -> str:
    text = str(value or "")
    if not text:
        return "—"
    return text.replace("T", " ").replace("Z", "")


def _stored_brief(ledger: CollectionHost) -> dict | None:
    raw = ledger.get_meta().get("case_brief", "")
    if not raw:
        return None
    try:
        value = json.loads(raw)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def _finding(item: dict) -> dict:
    steps = [
        line.strip()
        for line in str(item.get("nextSteps") or "").splitlines()
        if line.strip()
    ]
    return {
        "id": item.get("id", ""),
        "rule": item.get("rule", ""),
        "severity": item.get("severity", "low"),
        "title": item.get("title", ""),
        "tool": item.get("tool", ""),
        "workspace": item.get("workspace", ""),
        "timestamp": _human(item.get("timestamp")),
        "session": item.get("sessionId", ""),
        "confidence": item.get("confidence", ""),
        "disposition": item.get("disposition", "open"),
        "disposition_note": item.get("dispositionNote", ""),
        "disposition_by": item.get("dispositionBy", ""),
        "disposition_at": _human(item.get("dispositionAt")),
        "suppressed": bool(item.get("suppressed")),
        "row_ids": [str(value) for value in (item.get("rowIds") or [])],
        "what": item.get("whatHappened") or item.get("summary") or "No explanation stored.",
        "why": item.get("whyItMatters", ""),
        "next_steps": steps,
        "llm_model": item.get("llmModel") or "deterministic",
        "rank_label": item.get("rankLabel", ""),
        "rank_reason": item.get("rankReason", ""),
        "rank_model": item.get("rankModel", ""),
    }


def build_report(ledger: CollectionHost) -> dict:
    meta = ledger.get_meta()
    stats = ledger.stats()
    anomalies = ledger.query_anomalies()
    files, hash_source, omitted = collected_hashes(ledger)

    review = {disposition: 0 for disposition in ("open", "confirmed", "dismissed", "accepted")}
    for item in anomalies:
        disposition = str(item.get("disposition") or "open")
        review[disposition] = review.get(disposition, 0) + 1
    review["total"] = len(anomalies)
    review["suppressed"] = sum(1 for item in anomalies if item.get("suppressed"))

    brief = _stored_brief(ledger) or brief_fallback(stats, anomalies)
    if brief.get("risk_level") not in SEVERITIES:
        brief["risk_level"] = anomalies[0]["severity"] if anomalies else "low"

    findings = [_finding(item) for item in anomalies]
    groups = [
        {"label": severity, "leads": [item for item in findings if item["severity"] == severity]}
        for severity in SEVERITIES
    ]
    groups = [group for group in groups if group["leads"]]

    coverage_entries = ledger.coverage_public()
    coverage_issues = [
        entry for entry in coverage_entries if str(entry.get("status")) != "parsed"
    ]
    suppressions = [
        {
            "rule": entry.get("rule", ""),
            "workspace": entry.get("workspace", ""),
            "scope": "all commands" if entry.get("commandHash") == "*" else "exact command",
            "expires": _human(entry.get("expiresAt")) if entry.get("expiresAt") else "never",
            "created_by": entry.get("createdBy", ""),
            "note": entry.get("note", ""),
        }
        for entry in ledger.list_suppressions()
    ]

    return {
        "product": "Assistant Session Ledger",
        "creator": {"name": CREATOR_NAME, "linkedin": CREATOR_URL},
        "generated_at": _human(_now()),
        "case": {
            "id": meta.get("case_id", "") or "Untitled case",
            "mode": meta.get("mode", ""),
            "user": meta.get("user", ""),
            "host": meta.get("host", ""),
            "created": _human(meta.get("created_at")),
            "finished": _human(meta.get("finished_at")),
            "row_cap_hit": meta.get("cap_hit", "0") == "1",
            "cancelled": meta.get("cancelled", "0") == "1",
        },
        "range": {
            "first": _human(stats.get("first_timestamp")),
            "last": _human(stats.get("last_timestamp")),
        },
        "counts": {
            "rows": stats.get("total_rows", 0),
            "sessions": stats.get("sessions", 0),
            "secret_rows": stats.get("secret_rows", 0),
            "leads": len(anomalies),
            "open_leads": sum(
                1
                for item in anomalies
                if not item.get("suppressed") and item.get("disposition", "open") == "open"
            ),
            "explained": sum(
                1
                for item in anomalies
                if item.get("llmModel") and item.get("llmModel") != "deterministic"
            ),
            "advisory_ranked": sum(1 for item in anomalies if item.get("rankLabel")),
            "parse_errors": meta.get("parse_errors", "0"),
            "truncations": meta.get("truncations", "0"),
        },
        "tools": stats.get("by_tool") or [],
        "review": review,
        "brief": brief,
        "findings": findings,
        "groups": groups,
        "suppressions": suppressions,
        "coverage": {
            "counts": stats.get("by_coverage") or [],
            "issues": coverage_issues,
            "total": len(coverage_entries),
        },
        "integrity": {
            "files": len(files),
            "hash_source": hash_source,
            "files_omitted": omitted,
            "row_cap_hit": meta.get("cap_hit", "0") == "1",
            "cancelled": meta.get("cancelled", "0") == "1",
        },
    }


def _md_cell(value: object) -> str:
    return str(value if value not in (None, "") else "—").replace("|", "\\|")


def report_markdown(ledger: CollectionHost, data: dict | None = None) -> str:
    report = data or build_report(ledger)
    case = report["case"]
    counts = report["counts"]
    review = report["review"]
    brief = report["brief"]
    lines: list[str] = [
        f"# Case report — {case['id']}",
        "",
        f"**Product:** {report['product']}  ",
        f"**Created by:** {report['creator']['name']} · {report['creator']['linkedin']}  ",
        f"**Generated:** {report['generated_at']}  ",
        f"**Case:** {case['id']} ({case['mode'] or 'unknown mode'})  ",
        f"**Analyst / host:** {case['user'] or '—'} / {case['host'] or '—'}  ",
        f"**Collection window:** {case['created']} → {case['finished']}  ",
        f"**Data span:** {report['range']['first']} → {report['range']['last']}",
        "",
        "> Generated from a masked case database. Secret values are stored only as",
        "> `[REDACTED:category:fingerprint]` and are not reproduced in this report.",
        "",
        "## Executive summary",
        "",
        f"**Risk level:** {brief.get('risk_level', 'low')}",
        "",
        str(brief.get("headline") or ""),
        "",
        str(brief.get("overview") or ""),
        "",
    ]
    if brief.get("key_findings"):
        lines.append("**Key findings**")
        lines.append("")
        lines.extend(f"- {item}" for item in brief["key_findings"])
        lines.append("")
    if brief.get("next_steps"):
        lines.append("**Suggested next steps**")
        lines.append("")
        lines.extend(f"{index}. {item}" for index, item in enumerate(brief["next_steps"], 1))
        lines.append("")
    if brief.get("caveats"):
        lines.extend([str(brief["caveats"]), ""])
    source = "model-written" if brief.get("source") == "llm" else "deterministic"
    if brief.get("model"):
        source += f" ({brief['model']})"
    lines.append(f"*Summary source: {source}.*")
    lines.extend(
        [
            "",
            "## Case metrics",
            "",
            "| Metric | Value |",
            "|---|---|",
            f"| Normalized rows | {counts['rows']} |",
            f"| Sessions | {counts['sessions']} |",
            f"| Rows with masked secrets | {counts['secret_rows']} |",
            f"| Leads detected | {counts['leads']} |",
            f"| Open leads (not suppressed) | {counts['open_leads']} |",
            f"| Leads explained by a model | {counts['explained']} |",
            f"| Leads with advisory model ranking | {counts['advisory_ranked']} |",
            f"| Parse errors | {counts['parse_errors']} |",
            f"| Truncated records | {counts['truncations']} |",
            "",
        ]
    )
    if report["tools"]:
        lines.append("Tools present: " + ", ".join(
            f"{item['label']} ({item['count']})" for item in report["tools"]
        ) + ".")
        lines.append("")

    lines.extend(
        [
            "## Review status",
            "",
            "| Disposition | Leads |",
            "|---|---|",
            f"| Open | {review.get('open', 0)} |",
            f"| Confirmed | {review.get('confirmed', 0)} |",
            f"| Dismissed | {review.get('dismissed', 0)} |",
            f"| Accepted risk | {review.get('accepted', 0)} |",
            f"| Suppressed (hidden by rule) | {review.get('suppressed', 0)} |",
            "",
            "Review state and suppression rules are analyst decisions, not detector output.",
            "",
            "## Findings",
            "",
        ]
    )
    if not report["groups"]:
        lines.extend(["No anomaly leads were detected by the deterministic rules.", ""])
    for group in report["groups"]:
        lines.extend([f"### {group['label'].title()} ({len(group['leads'])})", ""])
        for item in group["leads"]:
            lines.append(f"#### {item['title']}")
            lines.append("")
            facts = [
                f"Rule: `{item['rule']}`",
                f"Tool: {item['tool'] or 'unknown'}",
                f"Time: {item['timestamp']}",
            ]
            if item["session"]:
                facts.append(f"Session: `{item['session']}`")
            if item["workspace"]:
                facts.append(f"Workspace: `{item['workspace']}`")
            facts.append(f"Detector confidence: {item['confidence'] or '—'}")
            facts.append(f"Explanation: {item['llm_model']}")
            if item["rank_label"]:
                facts.append(
                    f"Advisory ranking: {item['rank_label']} ({item['rank_model']}) — {item['rank_reason']}"
                )
            state = item["disposition"]
            if item["suppressed"]:
                state += ", suppressed"
            facts.append(f"Review: {state}")
            lines.append("- " + " · ".join(facts))
            lines.extend(["", f"**What happened:** {item['what']}", ""])
            if item["why"]:
                lines.extend([f"**Why it matters:** {item['why']}", ""])
            if item["next_steps"]:
                lines.append("**Next steps:**")
                lines.append("")
                lines.extend(f"{index}. {step}" for index, step in enumerate(item["next_steps"], 1))
                lines.append("")
            if item["row_ids"]:
                lines.extend(
                    [
                        "**Evidence rows:** " + ", ".join(f"`{row}`" for row in item["row_ids"]),
                        "",
                    ]
                )
            if item["disposition"] != "open":
                note = f" by {item['disposition_by']}" if item["disposition_by"] else ""
                when = f" at {item['disposition_at']}" if item["disposition_at"] != "—" else ""
                extra = f" — {item['disposition_note']}" if item["disposition_note"] else ""
                lines.extend([f"*Reviewed{note}{when}{extra}.*", ""])
        lines.append("")

    lines.extend(["## Suppression rules", ""])
    if report["suppressions"]:
        for rule in report["suppressions"]:
            lines.append(
                f"- `{rule['rule']}` · {rule['workspace'] or '(no workspace)'} · "
                f"{rule['scope']} · expires {rule['expires']}"
            )
        lines.append("")
    else:
        lines.extend(["No active suppression rules.", ""])

    lines.extend(
        [
            "## Coverage and integrity",
            "",
            f"- Coverage entries: {report['coverage']['total']}",
            f"- Hashed artifact files: {report['integrity']['files']} "
            f"(hash source: {report['integrity']['hash_source']})",
        ]
    )
    if report["integrity"]["files_omitted"]:
        lines.append(f"- Files over the hash cap, not hashed: {report['integrity']['files_omitted']}")
    if report["integrity"]["row_cap_hit"]:
        lines.append("- Row cap was reached during collection; the timeline may be incomplete.")
    if report["integrity"]["cancelled"]:
        lines.append("- Collection was cancelled before completion.")
    if report["coverage"]["counts"]:
        lines.append(
            "- Coverage by status: "
            + ", ".join(f"{item['label']} {item['count']}" for item in report["coverage"]["counts"])
        )
    if report["coverage"]["issues"]:
        lines.extend(["", "Paths that were not fully parsed:", ""])
        for entry in report["coverage"]["issues"][:20]:
            note = f" — {entry['notes']}" if entry.get("notes") else ""
            lines.append(f"- {entry.get('status')}: `{entry.get('source')}`{note}")
        if len(report["coverage"]["issues"]) > 20:
            lines.append(
                f"- … {len(report['coverage']['issues']) - 20} more entries; see the coverage ledger."
            )
    lines.extend(
        [
            "",
            "## Methodology and limitations",
            "",
            "- Parsers read local AI-assistant artifact files read-only and record coverage, row counts,",
            "  parse errors, and SHA-256 hashes at collection time.",
            "- Text is masked before storage. Secret values never appear in the database, exports, or",
            "  model prompts; only salted fingerprint prefixes remain.",
            "- Anomaly leads are deterministic pattern and behaviour matches. They are triage items,",
            "  not confirmed incidents, and the model never decides which leads exist.",
            "- Model explanations are bounded to the lead plus masked excerpts and validated against",
            "  the lead's evidence row IDs. Deterministic text is labeled as such.",
            "- Advisory model ranking labels leads likely-real or likely-benign as triage hints only.",
            "  They cannot create, remove, or re-score leads; severity order stays deterministic.",
            "- This report renders stored data and the stored case brief. Re-run coverage verification",
            "  in the app to detect artifact changes after collection.",
            "",
            "---",
            "",
            f"Generated by {report['product']}. Created by {report['creator']['name']} — "
            f"{report['creator']['linkedin']}",
            "",
        ]
    )
    return "\n".join(lines)


_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Case report — {{ report.case.id }}</title>
<style>
  :root {
    --ink: #16202b; --muted: #5b6b7c; --line: #d8e0e8; --soft: #eef2f6;
    --accent: #0f6e8c; --crit: #b91c1c; --high: #c2410c; --med: #a16207; --low: #475569;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: #f3f6f9; color: var(--ink);
    font: 14px/1.6 "Segoe UI", system-ui, -apple-system, Arial, sans-serif;
  }
  .page { max-width: 900px; margin: 0 auto; padding: 36px 40px 60px; background: #fff; }
  header.cover { border-left: 6px solid var(--accent); padding: 4px 0 4px 18px; margin-bottom: 26px; }
  .eyebrow { color: var(--accent); font-size: 11px; letter-spacing: 0.12em; text-transform: uppercase; font-weight: 650; }
  h1 { font-size: 27px; margin: 6px 0 8px; letter-spacing: -0.02em; }
  h2 { font-size: 18px; margin: 30px 0 10px; padding-bottom: 5px; border-bottom: 1px solid var(--line); }
  h3 { font-size: 14.5px; margin: 18px 0 8px; }
  p { margin: 0 0 9px; }
  ul, ol { margin: 4px 0 12px; padding-left: 20px; }
  li { margin: 3px 0; }
  .meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 4px 18px; margin-top: 10px; color: var(--muted); font-size: 12.5px; }
  .meta b { color: var(--ink); font-weight: 600; }
  .creator { margin-top: 12px; font-size: 12px; color: var(--muted); }
  .creator a { color: var(--accent); text-decoration: none; }
  .note {
    background: var(--soft); border: 1px solid var(--line); border-radius: 8px;
    padding: 9px 12px; font-size: 12px; color: var(--muted); margin: 14px 0 20px;
  }
  .badge {
    display: inline-block; padding: 1px 8px; border-radius: 999px;
    font-size: 10.5px; font-weight: 650; text-transform: uppercase; letter-spacing: 0.06em;
  }
  .sev-critical { background: #fee2e2; color: var(--crit); }
  .sev-high { background: #ffedd5; color: var(--high); }
  .sev-medium { background: #fef3c7; color: var(--med); }
  .sev-low { background: #e2e8f0; color: var(--low); }
  .summary-risk { margin: 10px 0 12px; }
  .headline { font-size: 16px; font-weight: 650; margin: 6px 0 8px; }
  table { width: 100%; border-collapse: collapse; margin: 8px 0 16px; font-size: 12.5px; }
  th, td { text-align: left; border-bottom: 1px solid var(--line); padding: 6px 8px; vertical-align: top; }
  th { background: var(--soft); font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); }
  .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 8px; margin: 10px 0 16px; }
  .metric { border: 1px solid var(--line); border-radius: 8px; padding: 9px 11px; }
  .metric span { display: block; color: var(--muted); font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.06em; }
  .metric b { font-size: 18px; }
  .metric small { display: block; color: var(--muted); font-size: 11px; }
  .finding { border: 1px solid var(--line); border-left: 4px solid var(--line); border-radius: 8px; padding: 12px 14px; margin: 10px 0; break-inside: avoid; }
  .finding.sev-border-critical { border-left-color: var(--crit); }
  .finding.sev-border-high { border-left-color: var(--high); }
  .finding.sev-border-medium { border-left-color: var(--med); }
  .finding.sev-border-low { border-left-color: var(--low); }
  .finding h4 { margin: 0; font-size: 13.5px; }
  .finding-head { display: flex; gap: 8px; align-items: flex-start; margin-bottom: 6px; }
  .facts { color: var(--muted); font-size: 11.5px; margin-bottom: 8px; }
  .facts span:not(:last-child)::after { content: " · "; }
  .why { color: #334155; }
  .label { font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.07em; color: var(--muted); margin: 9px 0 3px; }
  .mono { font-family: ui-monospace, Consolas, "Cascadia Code", monospace; font-size: 11.5px; }
  .pill { display: inline-block; border: 1px solid var(--line); border-radius: 999px; padding: 0 7px; font-size: 10.5px; color: var(--muted); }
  .empty { color: var(--muted); font-style: italic; }
  footer { margin-top: 34px; padding-top: 14px; border-top: 1px solid var(--line); color: var(--muted); font-size: 11.5px; }
  footer a { color: inherit; }
  .creator-link { display: inline-flex; align-items: center; gap: 4px; }
  .li-logo { width: 12px; height: 12px; fill: #0a66c2; flex: none; }
  @media print {
    body { background: #fff; }
    .page { max-width: none; padding: 0; }
    h2 { break-after: avoid; }
    .finding { break-inside: avoid; }
  }
</style>
</head>
<body>
<div class="page">
  <header class="cover">
    <div class="eyebrow">{{ report.product }} · Case report</div>
    <h1>{{ report.case.id }}</h1>
    <div class="meta">
      <div>Mode <b>{{ report.case.mode or "unknown" }}</b></div>
      <div>Analyst <b>{{ report.case.user or "—" }}</b></div>
      <div>Host <b>{{ report.case.host or "—" }}</b></div>
      <div>Collection <b>{{ report.case.created }} → {{ report.case.finished }}</b></div>
      <div>Data span <b>{{ report.range.first }} → {{ report.range.last }}</b></div>
      <div>Generated <b>{{ report.generated_at }}</b></div>
    </div>
    <div class="creator">
      Created by {{ report.creator.name }} · <a href="{{ report.creator.linkedin }}">{{ report.creator.linkedin }}</a>
    </div>
  </header>

  <div class="note">
    Generated from a masked case database. Secret values are stored only as
    <span class="mono">[REDACTED:category:fingerprint]</span> and are not reproduced in this report.
    Leads are deterministic triage items, not confirmed incidents.
  </div>

  <h2>Executive summary</h2>
  <div class="summary-risk">
    <span class="badge sev-{{ report.brief.risk_level }}">{{ report.brief.risk_level }}</span>
    <span class="pill">
      {% if report.brief.source == 'llm' %}model-written{% if report.brief.model %} · {{ report.brief.model }}{% endif %}
      {% else %}deterministic summary{% endif %}
    </span>
  </div>
  <p class="headline">{{ report.brief.headline }}</p>
  <p>{{ report.brief.overview }}</p>
  {% if report.brief.key_findings %}
  <div class="label">Key findings</div>
  <ul>
    {% for item in report.brief.key_findings %}<li>{{ item }}</li>{% endfor %}
  </ul>
  {% endif %}
  {% if report.brief.next_steps %}
  <div class="label">Suggested next steps</div>
  <ol>
    {% for item in report.brief.next_steps %}<li>{{ item }}</li>{% endfor %}
  </ol>
  {% endif %}
  {% if report.brief.caveats %}<p class="empty">{{ report.brief.caveats }}</p>{% endif %}

  <h2>Case metrics</h2>
  <div class="metrics">
    <div class="metric"><span>Rows</span><b>{{ report.counts.rows }}</b><small>{{ report.counts.sessions }} sessions</small></div>
    <div class="metric"><span>Secret rows</span><b>{{ report.counts.secret_rows }}</b><small>masked at rest</small></div>
    <div class="metric"><span>Leads</span><b>{{ report.counts.leads }}</b><small>{{ report.counts.open_leads }} open</small></div>
    <div class="metric"><span>Model explained</span><b>{{ report.counts.explained }}</b><small>of {{ report.counts.leads }} leads</small></div>
    <div class="metric"><span>Parse errors</span><b>{{ report.counts.parse_errors }}</b><small>{{ report.counts.truncations }} truncations</small></div>
  </div>
  {% if report.tools %}
  <table>
    <thead><tr><th>Tool</th><th>Rows</th></tr></thead>
    <tbody>
      {% for item in report.tools %}<tr><td>{{ item.label }}</td><td>{{ item.count }}</td></tr>{% endfor %}
    </tbody>
  </table>
  {% endif %}

  <h2>Review status</h2>
  <table>
    <thead><tr><th>Disposition</th><th>Leads</th></tr></thead>
    <tbody>
      <tr><td>Open</td><td>{{ report.review.open }}</td></tr>
      <tr><td>Confirmed</td><td>{{ report.review.confirmed }}</td></tr>
      <tr><td>Dismissed</td><td>{{ report.review.dismissed }}</td></tr>
      <tr><td>Accepted risk</td><td>{{ report.review.accepted }}</td></tr>
      <tr><td>Suppressed by rule</td><td>{{ report.review.suppressed }}</td></tr>
    </tbody>
  </table>
  <p class="empty">Review state and suppression rules are analyst decisions, not detector output.</p>

  <h2>Findings</h2>
  {% if not report.groups %}
  <p class="empty">No anomaly leads were detected by the deterministic rules.</p>
  {% endif %}
  {% for group in report.groups %}
  <h3>{{ group.label|title }} ({{ group.leads|length }})</h3>
  {% for item in group.leads %}
  <article class="finding sev-border-{{ item.severity }}">
    <div class="finding-head">
      <span class="badge sev-{{ item.severity }}">{{ item.severity }}</span>
      <h4>{{ item.title }}</h4>
    </div>
    <div class="facts">
      <span class="mono">{{ item.rule }}</span>
      <span>{{ item.tool or "unknown tool" }}</span>
      <span>{{ item.timestamp }}</span>
      {% if item.session %}<span class="mono">session {{ item.session }}</span>{% endif %}
      {% if item.workspace %}<span class="mono">{{ item.workspace }}</span>{% endif %}
      <span>confidence {{ item.confidence or "—" }}</span>
      <span>explanation {{ item.llm_model }}</span>
      {% if item.rank_label %}<span>advisory {{ item.rank_label }} ({{ item.rank_model }})</span>{% endif %}
      <span>{{ item.disposition }}{% if item.suppressed %} · suppressed{% endif %}</span>
    </div>
    {% if item.rank_reason %}
    <p class="why">Advisory ranking ({{ item.rank_model }}): {{ item.rank_reason }}</p>
    {% endif %}
    <p>{{ item.what }}</p>
    {% if item.why %}<p class="why">{{ item.why }}</p>{% endif %}
    {% if item.next_steps %}
    <div class="label">Next steps</div>
    <ol>{% for step in item.next_steps %}<li>{{ step }}</li>{% endfor %}</ol>
    {% endif %}
    {% if item.row_ids %}
    <div class="label">Evidence rows</div>
    <div>{% for row in item.row_ids %}<span class="mono">{{ row }}</span>{% if not loop.last %} · {% endif %}{% endfor %}</div>
    {% endif %}
    {% if item.disposition != 'open' %}
    <div class="label">Review</div>
    <div class="empty">
      {{ item.disposition }}{% if item.disposition_by %} by {{ item.disposition_by }}{% endif %}{% if item.disposition_at != '—' %} at {{ item.disposition_at }}{% endif %}{% if item.disposition_note %} — {{ item.disposition_note }}{% endif %}
    </div>
    {% endif %}
  </article>
  {% endfor %}
  {% endfor %}

  <h2>Suppression rules</h2>
  {% if report.suppressions %}
  <table>
    <thead><tr><th>Rule</th><th>Workspace</th><th>Scope</th><th>Expires</th></tr></thead>
    <tbody>
      {% for rule in report.suppressions %}
      <tr>
        <td class="mono">{{ rule.rule }}</td>
        <td class="mono">{{ rule.workspace or "(no workspace)" }}</td>
        <td>{{ rule.scope }}</td>
        <td>{{ rule.expires }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p class="empty">No active suppression rules.</p>
  {% endif %}

  <h2>Coverage and integrity</h2>
  <ul>
    <li>Coverage entries: {{ report.coverage.total }}</li>
    <li>Hashed artifact files: {{ report.integrity.files }} (hash source: {{ report.integrity.hash_source }})</li>
    {% if report.integrity.files_omitted %}<li>Files over the hash cap, not hashed: {{ report.integrity.files_omitted }}</li>{% endif %}
    {% if report.integrity.row_cap_hit %}<li>The row cap was reached during collection; the timeline may be incomplete.</li>{% endif %}
    {% if report.integrity.cancelled %}<li>Collection was cancelled before completion.</li>{% endif %}
    {% if report.coverage.counts %}
    <li>Coverage by status:
      {% for item in report.coverage.counts %}{{ item.label }} {{ item.count }}{% if not loop.last %}, {% endif %}{% endfor %}
    </li>
    {% endif %}
  </ul>
  {% if report.coverage.issues %}
  <div class="label">Paths that were not fully parsed</div>
  <table>
    <thead><tr><th>Status</th><th>Source</th><th>Notes</th></tr></thead>
    <tbody>
      {% for entry in report.coverage.issues[:20] %}
      <tr>
        <td>{{ entry.status }}</td>
        <td class="mono">{{ entry.source }}</td>
        <td>{{ entry.notes or "—" }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% endif %}

  <h2>Methodology and limitations</h2>
  <ul>
    <li>Artifacts are read-only and referenced by path and SHA-256; they are not copied into the case.</li>
    <li>Text is masked before storage. Secret values never reach the database, exports, or model prompts.</li>
    <li>Leads come from deterministic rules. The model only explains leads and may add an advisory likely-real / likely-benign label; it cannot add, remove, or re-score leads, and severity order stays deterministic.</li>
    <li>Model output is validated against the lead's evidence row IDs; deterministic text is labeled as such.</li>
    <li>This report renders stored data and the stored case brief. Re-run coverage verification in the app to detect post-collection artifact changes.</li>
  </ul>

  <footer>
    Generated by {{ report.product }}. Created by
    <a href="{{ report.creator.linkedin }}" class="creator-link">
      <svg class="li-logo" viewBox="0 0 24 24" role="img" aria-label="LinkedIn"><path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.225 0z"/></svg>
      {{ report.creator.name }}
    </a>
    —
    <a href="{{ report.creator.linkedin }}">{{ report.creator.linkedin }}</a>
  </footer>
</div>
</body>
</html>
"""

_TEMPLATE = _ENV.from_string(_HTML)


def report_html(ledger: CollectionHost, data: dict | None = None) -> str:
    return _TEMPLATE.render(report=data or build_report(ledger))


__all__ = ["build_report", "report_html", "report_markdown"]
