"""Scanner orchestrator for MCP-Sentry."""

import time

from mcp_sentry.checks import get_all_checks, get_checks_by_ids
from mcp_sentry.models import Finding, ScanReport, ServerSurface, Severity
from mcp_sentry.scoring import calculate_grade, calculate_score


def scan_server(surface: ServerSurface, check_ids: list[str] | None = None) -> ScanReport:
    """Run security checks against a server surface and generate a report."""
    start_time = time.time()

    if check_ids:
        checks = get_checks_by_ids(check_ids)
    else:
        checks = get_all_checks()

    all_findings: list[Finding] = []
    
    for check in checks:
        try:
            findings = check.run(surface)
            all_findings.extend(findings)
        except Exception as e:
            # We don't want one failing check to crash the whole scan
            all_findings.append(
                Finding(
                    check_id="SCANNER_ERROR",
                    severity=Severity.INFO,
                    title=f"Check '{check.check_id}' failed to run",
                    description=str(e),
                    remediation="Check scanner logs.",
                )
            )

    # Sort findings by severity (highest first)
    severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
    all_findings.sort(key=lambda f: severity_order.get(f.severity, 99))

    # Calculate score and grade
    score = calculate_score(all_findings, len(surface.tools))
    grade = calculate_grade(score)

    # Generate summary
    counts = {s: sum(1 for f in all_findings if f.severity == s) for s in Severity}
    summary = f"Scanned {len(surface.tools)} tools. Found {len(all_findings)} issues "
    summary += f"({counts[Severity.CRITICAL]} critical, {counts[Severity.HIGH]} high, {counts[Severity.MEDIUM]} medium, {counts[Severity.LOW]} low, {counts[Severity.INFO]} info)."

    duration_ms = int((time.time() - start_time) * 1000)

    return ScanReport(
        server=surface,
        findings=all_findings,
        grade=grade,
        score=score,
        summary=summary,
        scan_duration_ms=duration_ms,
    )
