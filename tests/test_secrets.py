from __future__ import annotations

from ai_forensics.model import RawRecord
from ai_forensics.secrets import fingerprint, mask_text, redact_structure


def test_mask_text_redacts_and_fingerprints():
    salt = b"unit-test-salt"
    text = "config: api_key = 'abcdefghijklmnopqrstuvwxyz' done"
    masked, findings = mask_text(text, salt)

    assert "abcdefghijklmnopqrstuvwxyz" not in masked
    assert "[REDACTED:generic_secret:" in masked
    assert findings[0]["category"] == "generic_secret"
    assert findings[0]["fingerprint"] == fingerprint(salt, "abcdefghijklmnopqrstuvwxyz")


def test_fingerprint_is_salted_and_stable():
    first = fingerprint(b"one", "ghp_" + "a" * 36)
    second = fingerprint(b"two", "ghp_" + "a" * 36)
    assert first != second
    assert first == fingerprint(b"one", "ghp_" + "a" * 36)


def test_specific_key_wins_over_generic_pattern():
    masked, findings = mask_text("key sk-ant-" + "a" * 30, b"salt")
    categories = [item["category"] for item in findings]
    assert "anthropic_api_key" in categories
    assert "openai_api_key" not in categories


def test_redact_structure_drops_sensitive_values():
    clean = redact_structure(
        {"env": {"API_KEY": "abc"}, "headers": {"Authorization": "Bearer x"}, "safe": "ok"}
    )
    assert clean == {"env": "[excluded]", "headers": "[excluded]", "safe": "ok"}


def test_ledger_never_stores_cleartext(host):
    secret = "ghp_" + "b" * 36
    host.emit(
        RawRecord(
            tool="Claude Code",
            role="user",
            text=f"deploy with {secret}",
            timestamp="2026-05-01T10:00:00Z",
            source_file="synthetic.jsonl",
        )
    )
    row = host.get_row("r1")

    assert secret not in row["fullText"]
    assert "[REDACTED:github_token:" in row["fullText"]
    assert row["secrets"][0]["category"] == "github_token"


def test_cleartext_not_in_database_file(host):
    secret = "AKIA" + "A" * 16
    host.emit(
        RawRecord(
            tool="Cursor",
            role="assistant",
            text=f"credentials {secret}",
            timestamp="2026-05-01T10:00:00Z",
        )
    )
    host.close()
    raw = host.db_path.read_bytes()
    wal = host.db_path.with_name(host.db_path.name + "-wal")
    if wal.exists():
        raw += wal.read_bytes()
    assert secret.encode() not in raw
