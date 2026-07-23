from __future__ import annotations

from mcp_sentry.models import Severity
from mcp_sentry.scanner import scan_server


def test_scanner_sorts_findings_and_builds_summary(filesystem_surface):
    report = scan_server(filesystem_surface)

    assert report.server.server_name == "filesystem"
    assert report.summary.startswith("Scanned 3 tools.")
    assert report.score > 0

    severity_order = [finding.severity for finding in report.findings]
    expected_order = sorted(
        severity_order,
        key=lambda severity: {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }[severity],
    )
    assert severity_order == expected_order
