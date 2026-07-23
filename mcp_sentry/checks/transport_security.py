"""Check for Transport Security."""

from mcp_sentry.checks import BaseCheck, register_check
from mcp_sentry.models import Finding, ServerSurface, Severity


@register_check
class TransportSecurityCheck(BaseCheck):
    check_id = "TRANSPORT_SECURITY"
    name = "Transport Security"
    description = "Detects insecure HTTP transport configurations."

    def run(self, surface: ServerSurface) -> list[Finding]:
        findings = []

        if surface.transport_type != "streamable_http":
            return findings

        url = surface.connection_info.get("url", "").lower()
        
        if not url:
            return findings

        # Check 1: HTTP instead of HTTPS
        if url.startswith("http://"):
            # If it's localhost, it's info. Otherwise critical.
            is_local = "localhost" in url or "127.0.0.1" in url or "::1" in url
            severity = Severity.INFO if is_local else Severity.CRITICAL
            title = "Unencrypted HTTP transport used" if not is_local else "Local HTTP transport"
            
            findings.append(
                Finding(
                    check_id=self.check_id,
                    severity=severity,
                    title=title,
                    evidence={"url": url},
                    remediation="Use HTTPS for all remote MCP connections to protect data and credentials in transit.",
                )
            )

        # Check 2: 0.0.0.0 binding
        if "0.0.0.0" in url:
             findings.append(
                Finding(
                    check_id=self.check_id,
                    severity=Severity.HIGH,
                    title="Server URL points to 0.0.0.0 (All interfaces)",
                    evidence={"url": url},
                    remediation="Bind the server to a specific internal interface or 127.0.0.1 if it does not need public exposure.",
                )
            )

        # Note: TLS certificate validation and security headers checking 
        # requires active connection/probing, which is out of scope for the static
        # part, but can be added if the tool expands to active network probing.

        return findings
