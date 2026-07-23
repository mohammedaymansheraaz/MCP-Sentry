"""Scoring engine for MCP-Sentry."""

from mcp_sentry.models import Finding


def calculate_score(findings: list[Finding], tool_count: int) -> float:
    """Calculate the normalized score based on findings and tool count."""
    if not findings:
        return 0.0

    penalty = sum(f.severity.points for f in findings)
    # Normalize by tool count to prevent penalizing servers just for having many tools.
    # We use max(tool_count, 1) to avoid division by zero.
    normalized = penalty / max(tool_count, 1)
    return round(normalized, 2)


def calculate_grade(score: float) -> str:
    """Calculate the letter grade based on the normalized score."""
    if score <= 2.0:
        return "A"
    elif score <= 7.0:
        return "B"
    elif score <= 15.0:
        return "C"
    elif score <= 25.0:
        return "D"
    else:
        return "F"
