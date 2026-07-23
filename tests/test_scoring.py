from __future__ import annotations

from mcp_sentry.models import Finding, Severity
from mcp_sentry.scoring import calculate_grade, calculate_score


def test_score_handles_empty_and_critical_findings():
    assert calculate_score([], 5) == 0.0
    assert calculate_score([Finding(check_id="TEST", severity=Severity.CRITICAL, title="Example")], 1) == 25.0


def test_grade_boundaries():
    assert calculate_grade(0.0) == "A"
    assert calculate_grade(2.01) == "B"
    assert calculate_grade(7.01) == "C"
    assert calculate_grade(15.01) == "D"
    assert calculate_grade(25.01) == "F"
