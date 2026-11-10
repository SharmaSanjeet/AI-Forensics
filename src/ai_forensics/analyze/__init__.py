"""LLM explanation layer.

Detection is deterministic and lives in `ai_forensics.detect`. This package
only turns stored anomaly leads into plain-language explanations.
"""

from ai_forensics.analyze.explain import (
    ExplainReport,
    LLMConfig,
    LLMError,
    brief_fallback,
    explain_anomalies,
    explain_anomaly,
    explain_case,
    probe,
)
from ai_forensics.analyze.rank import RANK_MAX, RankReport, rank_anomalies

__all__ = [
    "ExplainReport",
    "LLMConfig",
    "LLMError",
    "RANK_MAX",
    "RankReport",
    "brief_fallback",
    "explain_anomalies",
    "explain_anomaly",
    "explain_case",
    "probe",
    "rank_anomalies",
]
