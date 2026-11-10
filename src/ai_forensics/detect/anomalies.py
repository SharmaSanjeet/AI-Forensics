"""Rule-based anomaly detection.

The detector never asks a model to find anomalies. It reads normalized rows,
applies deterministic patterns and session statistics, and produces bounded
evidence-linked leads. The LLM layer only explains these leads afterwards.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ai_forensics.ledger import CollectionHost
from ai_forensics.model import ANALYSIS_ROW_CAP, RULE_PRIORITY
from ai_forensics.textutil import one_line

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

_RISKY_COMMANDS = (
    (r"(?i)\brm\s+-rf\s+(/|~|\$HOME|\*)", "recursive destructive delete", "critical"),
    (r"(?i)\b(del|erase)\s+/[fsq].*", "forced recursive delete", "critical"),
    (r"(?i)\bformat\s+[a-z]:", "disk format command", "critical"),
    (r"(?i)\bdiskpart\b", "disk partitioning tool", "critical"),
    (r"(?i)\bvssadmin\s+delete\s+shadows", "shadow copy deletion", "critical"),
    (r"(?i)\bwbadmin\s+delete\b", "backup deletion", "critical"),
    (r"(?i)\bbcdedit\b", "boot configuration modification", "critical"),
    (r"(?i)\bcipher\s+/w\b", "free-space wipe", "high"),
    (r"(?i)\b(wevtutil\s+cl|Clear-EventLog)\b", "event log clearing", "critical"),
    (r"(?i)\bnet\s+user\s+\S+\s+.*\/add\b", "local account creation", "high"),
    (r"(?i)\bnet\s+localgroup\s+administrators\s+.*\/add\b", "administrator group addition", "critical"),
    (r"(?i)\bschtasks\s+/create\b", "scheduled task creation", "high"),
    (r"(?i)\breg\s+add\b.*\\(run|runonce)\b", "registry persistence", "high"),
    (r"(?i)\bpowershell(\.exe)?\b.*(-enc|-encodedcommand)\b", "encoded PowerShell", "critical"),
    (r"(?i)\bpowershell(\.exe)?\b.*(-nop|-noprofile).*(-w|-windowstyle)\s+hidden", "hidden PowerShell", "critical"),
    (r"(?i)(curl|wget)\b[^\n|]*\|\s*(sh|bash)\b", "download piped to shell", "critical"),
    (r"(?i)(iwr|invoke-webrequest)\b[^\n|]*\|\s*iex\b", "download executed in memory", "critical"),
    (r"(?i)\bcertutil\b.*-urlcache\b", "certutil download", "high"),
    (r"(?i)\bbitsadmin\b", "BITS transfer", "high"),
    (r"(?i)\b(mshta|rundll32|regsvr32)\b", "signed-binary proxy execution", "high"),
    (r"(?i)\bwmic\s+process\s+call\s+create\b", "WMI process creation", "high"),
    (r"(?i)\bbash\s+-i\s+>&\s*/dev/tcp/", "reverse shell", "critical"),
    (r"(?i)\bnc(\.exe)?\s+.*-e\b", "netcat execution", "critical"),
    (r"(?i)\bchmod\s+777\b", "world-writable permission", "medium"),
)

_CREDENTIAL_ACCESS = (
    (r"(?i)\bmimikatz\b", "Mimikatz credential theft"),
    (r"(?i)\bsekurlsa\b", "LSASS credential extraction"),
    (r"(?i)\blsass(\.exe|\.dmp)?\b", "LSASS access"),
    (r"(?i)\bntds\.dit\b", "Active Directory database access"),
    (r"(?i)\breg\s+save\s+hklm\\(sam|security|system)\b", "registry hive export"),
    (r"(?i)\b(procdump|comsvcs\.dll)\b.*(lsass|minidump)", "process memory dump"),
    (r"(?i)(\.ssh[/\\]id_(rsa|ed25519)|\.aws[/\\]credentials)\b", "private key/credential file access"),
    (r"(?i)\b(login data|cookies|web data)\b", "browser credential store access"),
    (r"(?i)\b(cmdkey|vaultcmd)\b", "Windows credential manager access"),
    (r"(?i)\bsecurity\s+find-(generic|internet)-password\b", "macOS keychain access"),
    (r"(?i)\bdpapi\b", "DPAPI credential access"),
)

_EXFIL = (
    (r"(?i)\brclone\b", "rclone transfer", "high"),
    (r"(?i)\b(scp|sftp|ftp)\s+", "remote file transfer", "high"),
    (r"(?i)\bcurl\b.*(-F|--upload-file|-T)\b", "HTTP upload", "high"),
    (r"(?i)\b(invoke-webrequest|invoke-restmethod)\b.*(-method\s+post|-body)", "PowerShell HTTP upload", "high"),
    (r"(?i)\baws\s+s3\s+(cp|sync)\b", "S3 upload", "high"),
    (r"(?i)\b(azcopy|megacmd|dropbox)\b", "cloud transfer tool", "high"),
    (r"(?i)(transfer\.sh|0x0\.st|pastebin\.com)", "public paste/upload service", "high"),
    (r"(?i)\b(tar\s+-?c|7z\s+a|zip\s+-r|compress-archive)\b", "archive staging", "medium"),
    (r"(?i)\bbase64\s+(-d|--decode)\b.*\|", "encoded payload pipe", "medium"),
)

_SENSITIVE_WORKSPACE = re.compile(
    r"(?i)(\\windows\\system32|\\program files|\\programdata|"
    r"[/\\]\.ssh\b|[/\\]\.aws\b|[/\\]\.env\b|"
    r"(^|[\\/])(secrets?|credentials?|prod|production|evidence)([\\/]|$))"
)

_INJECTION = (
    (r"(?i)\bignore\s+(all\s+)?(previous|prior)\s+instructions\b", "instruction override attempt"),
    (r"(?i)\b(reveal|print|show)\s+(your\s+)?system\s+prompt\b", "system prompt extraction"),
    (r"(?i)\byou\s+are\s+now\s+(in\s+)?(developer|god|admin)\s+mode\b", "persona/jailbreak attempt"),
    (r"(?i)\b(jailbreak|developer\s+mode|do\s+anything\s+now)\b", "jailbreak language"),
)

_UNSAFE_CONFIG = (
    (r"(?i)localToolPermission\s*[:=]\s*\"?always", "local tools run without approval"),
    (r"(?i)decision\s*=\s*\"allow\"", "exec policy allows commands without approval"),
    (r"(?i)(bypassPermissions|dangerously-skip-permissions|allowAll|autoApprove)", "permission bypass configured"),
    (r"(?i)(approval_policy|sandbox)\s*[:=]\s*\"?(never|none|danger-full-access)", "restricted approval/sandbox disabled"),
    (r"(?i)trustedFolders|trusted_folders", "trusted folder configuration"),
    (r"(?i)hooks?\s*[:=].*command", "lifecycle hook executes a command"),
)

_UNSAFE_RECORD_TYPES = {
    "config",
    "exec_policy_rule",
    "permission_request",
    "permission_result",
    "trusted_folder",
    "remote_control_state",
    "scheduled_task",
    "session_auto_mode_resolved",
}

_SHELL_TOOLS = re.compile(
    r"(?i)(shell|bash|terminal|exec|command|run-command|run_command|local_shell|powershell)"
)


@dataclass
class AnomalyDraft:
    rule: str
    severity: str
    title: str
    summary: str
    tool: str = ""
    workspace: str = ""
    timestamp: str = ""
    row_ids: list[str] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)
    confidence: str = "medium"

    def as_dict(self) -> dict:
        seed = f"{self.rule}|{','.join(self.row_ids[:3])}|{self.title}"
        anomaly_id = hashlib.sha1(seed.encode("utf-8")).hexdigest()[:16]
        return {
            "id": anomaly_id,
            "rule": self.rule,
            "severity": self.severity,
            "title": self.title,
            "summary": self.summary,
            "tool": self.tool,
            "workspace": self.workspace,
            "timestamp": self.timestamp,
            "row_ids": self.row_ids,
            "evidence": self.evidence,
            "confidence": self.confidence,
        }


def _evidence(row: dict, snippet_chars: int = 320) -> dict:
    snippet = row.get("full_text") or row.get("summary") or row.get("tool_command") or ""
    return {
        "rowId": row.get("id", ""),
        "timestamp": row.get("timestamp", ""),
        "tool": row.get("tool", ""),
        "role": row.get("role", ""),
        "recordType": row.get("record_type", ""),
        "snippet": one_line(str(snippet), snippet_chars),
        "command": one_line(str(row.get("tool_command") or ""), 400),
    }


def _title(tool: str, message: str) -> str:
    return f"{tool}: {message}" if tool else message


def _bucket(timestamp: str, minutes: int = 10) -> str:
    if not timestamp:
        return ""
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return ""
    return parsed.strftime(f"%Y-%m-%dT%H:{parsed.minute // minutes * minutes:02d}")


def run_detectors(ledger: CollectionHost, *, max_rows: int = 500_000) -> list[dict]:
    drafts: list[AnomalyDraft] = []
    seen: set[tuple[str, str]] = set()
    tool_burst: dict[tuple[str, str], list[dict]] = {}
    off_hours: dict[str, list[dict]] = {}
    cross_tool: dict[str, dict] = {}
    scanned = 0

    def add(draft: AnomalyDraft) -> None:
        key = (draft.rule, draft.row_ids[0] if draft.row_ids else draft.title)
        if key in seen:
            return
        seen.add(key)
        drafts.append(draft)

    for row in ledger.iter_filtered({}):
        scanned += 1
        if scanned > max_rows:
            break
        tool = str(row.get("tool") or "")
        role = str(row.get("role") or "")
        record_type = str(row.get("record_type") or "message")
        timestamp = str(row.get("timestamp") or "")
        workspace = str(row.get("workspace") or "")
        command = str(row.get("tool_command") or "")
        text = str(row.get("full_text") or "")
        summary = str(row.get("summary") or "")
        combined = f"{command}\n{text}"

        findings = []
        try:
            findings = json.loads(row.get("secrets_json") or "[]")
        except ValueError:
            findings = []
        if findings:
            categories = sorted({str(item.get("category") or "secret") for item in findings})
            specific = any(
                str(item.get("category")) not in {"generic_secret", "bearer_token", "jwt"}
                for item in findings
            )
            add(
                AnomalyDraft(
                    rule="secret_exposure",
                    severity="critical" if specific else "medium",
                    title=_title(tool, f"possible {', '.join(categories)} exposure"),
                    summary=one_line(summary or "Secret-like value found in prompt, response or tool output", 240),
                    tool=tool,
                    workspace=workspace,
                    timestamp=timestamp,
                    row_ids=[row["id"]],
                    evidence=[_evidence(row)],
                    confidence="high" if specific else "medium",
                )
            )

        for pattern, label, severity in _RISKY_COMMANDS:
            if command and re.search(pattern, command):
                add(
                    AnomalyDraft(
                        rule="risky_command",
                        severity=severity,
                        title=_title(tool, label),
                        summary=one_line(command, 240),
                        tool=tool,
                        workspace=workspace,
                        timestamp=timestamp,
                        row_ids=[row["id"]],
                        evidence=[_evidence(row)],
                        confidence="high",
                    )
                )
                break

        for pattern, label in _CREDENTIAL_ACCESS:
            if command and re.search(pattern, command):
                add(
                    AnomalyDraft(
                        rule="credential_access",
                        severity="critical",
                        title=_title(tool, label),
                        summary=one_line(command, 240),
                        tool=tool,
                        workspace=workspace,
                        timestamp=timestamp,
                        row_ids=[row["id"]],
                        evidence=[_evidence(row)],
                        confidence="high",
                    )
                )
                break

        for pattern, label, severity in _EXFIL:
            if command and re.search(pattern, command):
                add(
                    AnomalyDraft(
                        rule="exfiltration",
                        severity=severity,
                        title=_title(tool, label),
                        summary=one_line(command, 240),
                        tool=tool,
                        workspace=workspace,
                        timestamp=timestamp,
                        row_ids=[row["id"]],
                        evidence=[_evidence(row)],
                        confidence="medium",
                    )
                )
                break

        if workspace and _SENSITIVE_WORKSPACE.search(workspace):
            add(
                AnomalyDraft(
                    rule="sensitive_workspace",
                    severity="medium",
                    title=_title(tool, "AI activity in a sensitive workspace"),
                    summary=one_line(workspace, 240),
                    tool=tool,
                    workspace=workspace,
                    timestamp=timestamp,
                    row_ids=[row["id"]],
                    evidence=[_evidence(row)],
                    confidence="medium",
                )
            )

        if role == "user" and record_type in {"message", "prompt_history"}:
            for pattern, label in _INJECTION:
                if re.search(pattern, combined):
                    add(
                        AnomalyDraft(
                            rule="prompt_injection",
                            severity="medium",
                            title=_title(tool, label),
                            summary=one_line(text or summary, 240),
                            tool=tool,
                            workspace=workspace,
                            timestamp=timestamp,
                            row_ids=[row["id"]],
                            evidence=[_evidence(row)],
                            confidence="medium",
                        )
                    )
                    break

        if record_type in _UNSAFE_RECORD_TYPES:
            for pattern, label in _UNSAFE_CONFIG:
                if re.search(pattern, combined):
                    add(
                        AnomalyDraft(
                            rule="unsafe_agent_config",
                            severity="high" if "bypass" in label or "without approval" in label else "medium",
                            title=_title(tool, label),
                            summary=one_line(summary or text, 240),
                            tool=tool,
                            workspace=workspace,
                            timestamp=timestamp,
                            row_ids=[row["id"]],
                            evidence=[_evidence(row)],
                            confidence="medium",
                        )
                    )
                    break

        if record_type == "deletion_tombstone":
            add(
                AnomalyDraft(
                    rule="deleted_session",
                    severity="high",
                    title=_title(tool, "deleted AI session detected"),
                    summary=one_line(text or summary, 240),
                    tool=tool,
                    workspace=workspace,
                    timestamp=timestamp,
                    row_ids=[row["id"]],
                    evidence=[_evidence(row)],
                    confidence="high",
                )
            )

        if record_type == "permission_request" and (
            _SHELL_TOOLS.search(str(row.get("invoked_tool") or "")) or command
        ):
            add(
                AnomalyDraft(
                    rule="agent_permission_request",
                    severity="medium",
                    title=_title(tool, f"agent requested permission for {row.get('invoked_tool') or 'a tool'}"),
                    summary=one_line(command or summary, 240),
                    tool=tool,
                    workspace=workspace,
                    timestamp=timestamp,
                    row_ids=[row["id"]],
                    evidence=[_evidence(row)],
                    confidence="medium",
                )
            )

        if record_type in {"tool_call", "shell_history"}:
            session = str(row.get("session_id") or "")
            if session:
                key = (session, _bucket(timestamp))
                if key[1]:
                    tool_burst.setdefault(key, []).append(row)
            if timestamp[11:13] and (int(timestamp[11:13]) < 6 or int(timestamp[11:13]) >= 22):
                off_hours.setdefault(session or row["id"], []).append(row)

        try:
            also_in_tools = json.loads(row.get("also_in_tools") or "[]")
        except ValueError:
            also_in_tools = []
        if also_in_tools:
            cross_tool.setdefault(str(row.get("norm_hash") or row["id"]), row)

    for (_session, bucket), rows in tool_burst.items():
        if len(rows) < 20:
            continue
        samples = rows[:3]
        add(
            AnomalyDraft(
                rule="tool_burst",
                severity="medium",
                title=_title(str(rows[0].get("tool") or ""), f"{len(rows)} tool calls in 10 minutes"),
                summary=f"Burst starting {bucket} in session {_session}",
                tool=str(rows[0].get("tool") or ""),
                workspace=str(rows[0].get("workspace") or ""),
                timestamp=str(rows[0].get("timestamp") or ""),
                row_ids=[row["id"] for row in rows[:10]],
                evidence=[_evidence(row) for row in samples],
                confidence="medium",
            )
        )

    for session, rows in off_hours.items():
        if len(rows) < 5:
            continue
        samples = rows[:3]
        add(
            AnomalyDraft(
                rule="off_hours_activity",
                severity="low",
                title=_title(str(rows[0].get("tool") or ""), f"{len(rows)} events outside 06:00-22:00 UTC"),
                summary=f"Off-hours activity concentrated in session {session}",
                tool=str(rows[0].get("tool") or ""),
                workspace=str(rows[0].get("workspace") or ""),
                timestamp=str(rows[0].get("timestamp") or ""),
                row_ids=[row["id"] for row in rows[:10]],
                evidence=[_evidence(row) for row in samples],
                confidence="low",
            )
        )

    for row in cross_tool.values():
        add(
            AnomalyDraft(
                rule="cross_tool_prompt",
                severity="low",
                title=_title(str(row.get("tool") or ""), "same prompt used across multiple AI tools"),
                summary=one_line(str(row.get("summary") or ""), 240),
                tool=str(row.get("tool") or ""),
                workspace=str(row.get("workspace") or ""),
                timestamp=str(row.get("timestamp") or ""),
                row_ids=[row["id"]],
                evidence=[_evidence(row)],
                confidence="low",
            )
        )

    drafts.sort(key=lambda item: item.timestamp or "", reverse=True)
    drafts.sort(
        key=lambda item: (
            _SEVERITY_ORDER.get(item.severity, 4),
            RULE_PRIORITY.get(item.rule, 20),
        )
    )
    return [draft.as_dict() for draft in drafts[:ANALYSIS_ROW_CAP * 4]]


def detect_and_store(ledger: CollectionHost) -> list[dict]:
    items = run_detectors(ledger)
    ledger.replace_anomalies(items)
    ledger.set_meta({"detected_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")})
    return items


__all__ = ["run_detectors", "detect_and_store", "AnomalyDraft"]
