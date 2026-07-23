from __future__ import annotations

import json

from mcp_sentry.report import render_json, render_markdown
from mcp_sentry.scanner import scan_server


def test_markdown_report_includes_surface_and_methodology_sections(filesystem_surface):
    report = scan_server(filesystem_surface)
    markdown = render_markdown(report)

    assert "## Server Surface" in markdown
    assert "## Methodology" in markdown
    assert "## All Findings" in markdown
    assert "## Executive Summary" in markdown


def test_json_report_round_trips(filesystem_surface):
    report = scan_server(filesystem_surface)
    payload = json.loads(render_json(report))

    assert payload["server"]["server_name"] == "filesystem"
    assert payload["findings"]
