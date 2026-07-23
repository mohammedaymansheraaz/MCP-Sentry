"""Check for SSRF-shaped tools."""

from mcp_sentry.checks import BaseCheck, register_check
from mcp_sentry.models import Finding, ServerSurface, Severity

URL_KW = ["url", "uri", "endpoint", "host", "hostname", "address"]
NETWORK_KW = ["ip", "ip_address", "ipv4", "ipv6", "port", "subnet", "cidr"]
OUTBOUND_KW = ["fetch", "request", "download", "connect", "proxy", "forward", "scrape", "crawl", "load", "retrieve"]


@register_check
class SSRFCheck(BaseCheck):
    check_id = "SSRF_RISK"
    name = "SSRF Risk"
    description = "Detects tools that accept URLs and make outbound requests without clear allowlists."

    def run(self, surface: ServerSurface) -> list[Finding]:
        findings = []

        for tool in surface.tools:
            tool_desc = (tool.description or "").lower()
            schema = tool.input_schema or {}
            properties = schema.get("properties", {})
            
            # Check if this tool likely makes outbound requests
            is_outbound = any(kw in tool_desc for kw in OUTBOUND_KW) or any(kw in tool.name.lower() for kw in OUTBOUND_KW)
            
            for param_name, param_details in properties.items():
                context = f"{param_name.lower()} {param_details.get('description', '').lower()}"
                
                # Check if this is a URL/Host parameter
                if any(kw in context for kw in URL_KW + NETWORK_KW):
                    
                    has_pattern = "pattern" in param_details
                    has_enum = "enum" in param_details
                    has_allowlist = "allowlist" in tool_desc or "blocklist" in tool_desc or "whitelist" in tool_desc
                    
                    if is_outbound:
                        if not (has_pattern or has_enum):
                            findings.append(
                                Finding(
                                    check_id=self.check_id,
                                    severity=Severity.HIGH,
                                    title=f"SSRF Risk: Unconstrained outbound request parameter '{param_name}'",
                                    tool_name=tool.name,
                                    field_name=param_name,
                                    evidence=param_details,
                                    remediation="Use an 'enum' or strict 'pattern' regex to enforce an allowlist of permitted domains.",
                                )
                            )
                        elif not has_allowlist:
                             findings.append(
                                Finding(
                                    check_id=self.check_id,
                                    severity=Severity.MEDIUM,
                                    title=f"Potential SSRF: Outbound parameter '{param_name}' lacks explicit allowlist documentation",
                                    tool_name=tool.name,
                                    field_name=param_name,
                                    evidence=param_details,
                                    remediation="Document the exact allowed domains in the tool description to guide LLM behavior.",
                                )
                            )

        return findings
