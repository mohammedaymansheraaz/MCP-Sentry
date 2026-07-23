from __future__ import annotations

import json

from mcp_sentry.models import Finding, ScanReport, Severity, ServerSurface


def test_severity_metadata():
    assert Severity.CRITICAL.points == 25
    assert Severity.INFO.color == "dim"


def test_surface_and_report_serialization(filesystem_surface: ServerSurface):
    serialized = filesystem_surface.model_dump_json()
    data = json.loads(serialized)

    assert data["server_name"] == "filesystem"
    assert len(data["tools"]) == 3
    assert data["transport_type"] == "stdio"

    report = ScanReport(
        server=filesystem_surface,
        findings=[
            Finding(
                check_id="TEST",
                severity=Severity.LOW,
                title="Example finding",
                remediation="Fix it.",
            )
        ],
        grade="B",
        score=4.2,
        summary="Example summary",
        scan_duration_ms=12,
    )

    round_trip = ScanReport.model_validate_json(report.model_dump_json())
    assert round_trip.grade == "B"
    assert round_trip.findings[0].severity == Severity.LOW
