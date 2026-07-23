from __future__ import annotations

from mcp_sentry.checks.credential_leak import CredentialLeakCheck
from mcp_sentry.checks.hbv import HBVCheck
from mcp_sentry.checks.path_traversal import PathTraversalCheck
from mcp_sentry.checks.ssrf import SSRFCheck
from mcp_sentry.checks.transport_security import TransportSecurityCheck
from mcp_sentry.checks.unvalidated_input import UnvalidatedInputCheck
from mcp_sentry.checks.weak_auth import WeakAuthCheck
from mcp_sentry.models import Severity, ToolInfo


def test_unvalidated_input_flags_path_and_content(filesystem_surface):
    findings = UnvalidatedInputCheck().run(filesystem_surface)

    assert any(
        finding.tool_name == "read_file"
        and finding.field_name == "path"
        and finding.severity == Severity.CRITICAL
        for finding in findings
    )
    assert any(
        finding.tool_name == "write_file"
        and finding.field_name == "content"
        and finding.severity == Severity.MEDIUM
        for finding in findings
    )


def test_weak_auth_flags_stdio_and_http_without_auth(filesystem_surface):
    stdio_findings = WeakAuthCheck().run(filesystem_surface)
    assert any(finding.severity == Severity.INFO for finding in stdio_findings)

    http_surface = filesystem_surface.model_copy(
        deep=True,
        update={
            "transport_type": "streamable_http",
            "connection_info": {"url": "https://example.com/mcp", "headers": {}},
            "auth_configured": False,
        },
    )
    http_findings = WeakAuthCheck().run(http_surface)
    assert any(
        finding.severity == Severity.CRITICAL and "No authentication configured" in finding.title
        for finding in http_findings
    )


def test_ssrf_flags_outbound_url_parameters(filesystem_surface):
    outbound_tool = ToolInfo(
        name="fetch_url",
        description="Fetch a URL and retrieve the response from a remote service.",
        input_schema={
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                }
            },
            "required": ["url"],
        },
    )
    surface = filesystem_surface.model_copy(deep=True, update={"tools": [*filesystem_surface.tools, outbound_tool]})

    findings = SSRFCheck().run(surface)

    assert any(
        finding.tool_name == "fetch_url" and finding.severity == Severity.HIGH for finding in findings
    )


def test_path_traversal_cross_references_allowed_directories(filesystem_surface):
    findings = PathTraversalCheck().run(filesystem_surface)

    assert any(
        finding.tool_name == "write_file"
        and finding.field_name == "path"
        and finding.severity == Severity.CRITICAL
        and finding.evidence["has_allowed_dirs_tool"] is True
        for finding in findings
    )


def test_hbv_flags_short_and_destructive_descriptions(filesystem_surface):
    findings = HBVCheck().run(filesystem_surface)

    assert any("Brief tool description" in finding.title and finding.tool_name == "write_file" for finding in findings)
    assert any(
        "Destructive tool lacks scope constraints" in finding.title and finding.tool_name == "write_file"
        for finding in findings
    )


def test_credential_leak_scans_recursive_metadata(filesystem_surface):
    surface = filesystem_surface.model_copy(
        deep=True,
        update={
            "capabilities": {
                "oauth": {
                    "client_secret": "postgres://user:password@example.com/db",
                }
            }
        },
    )

    findings = CredentialLeakCheck().run(surface)

    assert any(
        finding.severity == Severity.CRITICAL
        and finding.tool_name == "filesystem"
        and finding.field_name == "capabilities.oauth.client_secret"
        for finding in findings
    )


def test_transport_security_flags_insecure_http_urls(filesystem_surface):
    remote_surface = filesystem_surface.model_copy(
        deep=True,
        update={
            "transport_type": "streamable_http",
            "connection_info": {"url": "http://example.com/mcp"},
        },
    )
    local_surface = remote_surface.model_copy(
        deep=True,
        update={"connection_info": {"url": "http://127.0.0.1:8080/mcp"}},
    )

    remote_findings = TransportSecurityCheck().run(remote_surface)
    local_findings = TransportSecurityCheck().run(local_surface)

    assert any(finding.severity == Severity.CRITICAL for finding in remote_findings)
    assert any(finding.severity == Severity.INFO for finding in local_findings)
