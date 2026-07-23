"""Check for missing or weak authentication."""

import re

from mcp_sentry.checks import BaseCheck, register_check
from mcp_sentry.models import Finding, ServerSurface, Severity

WRITE_EXECUTE_KW = [
    "write", "delete", "create", "execute", "update", "modify", 
    "remove", "insert", "drop", "move", "rename"
]

SECRET_PATTERNS = [
    (r'Bearer\s+([A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*)', "Hardcoded JWT Token"),
    (r'sk-[a-zA-Z0-9]{20,}', "Hardcoded OpenAI Key"),
    (r'ghp_[a-zA-Z0-9]{36}', "Hardcoded GitHub PAT"),
    (r'AKIA[0-9A-Z]{16}', "Hardcoded AWS Access Key"),
    (r'(?=.{20,}$)(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9+/=_\-.]{20,}', "Hardcoded Secret"),
]


@register_check
class WeakAuthCheck(BaseCheck):
    check_id = "WEAK_AUTH"
    name = "Weak Authentication"
    description = "Detects missing auth on remote servers or hardcoded credentials in configs."

    def run(self, surface: ServerSurface) -> list[Finding]:
        findings = []

        # 1. Transport-specific checks
        if surface.transport_type == "stdio":
            findings.append(
                Finding(
                    check_id=self.check_id,
                    severity=Severity.INFO,
                    title="Stdio transport used (local only)",
                    description="Authentication is generally not required for local subprocesses.",
                    evidence={"transport": "stdio"},
                    remediation="Ensure the client running the server is properly secured.",
                )
            )
        elif surface.transport_type == "streamable_http":
            if not surface.auth_configured:
                # Check if server has write/execute tools
                has_write_tools = False
                for tool in surface.tools:
                    context = f"{tool.name.lower()} {(tool.description or '').lower()}"
                    annotations = tool.annotations or {}
                    if any(kw in context for kw in WRITE_EXECUTE_KW) or \
                       annotations.get("destructiveHint") is True or \
                       annotations.get("readOnlyHint") is False:
                        has_write_tools = True
                        break
                        
                severity = Severity.CRITICAL if has_write_tools else Severity.HIGH
                title = "No authentication configured for HTTP transport"
                desc = "Server exposes write/execute capabilities" if has_write_tools else "Server exposes read-only capabilities"
                
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        severity=severity,
                        title=title,
                        description=desc,
                        evidence={"url": surface.connection_info.get("url")},
                        remediation="Configure authentication headers (e.g., Bearer token) and ensure the server enforces them.",
                    )
                )

        # 2. Hardcoded Credentials Check (scan connection_info for raw secrets instead of env vars)
        # Note: We can only see the config we were passed, but it's a good hygiene check
        headers = surface.connection_info.get("headers", {})
        for header_name, header_value in headers.items():
             # If it looks like a literal secret and not an env var interpolation ${VAR}
             if not re.search(r'\$\{[^}]+\}', header_value):
                 for pattern, secret_type in SECRET_PATTERNS:
                     if re.search(pattern, header_value):
                         findings.append(
                             Finding(
                                 check_id=self.check_id,
                                 severity=Severity.HIGH,
                                 title=f"{secret_type} in configuration",
                                 field_name=header_name,
                                 evidence={"header": header_name, "value": "***"}, # Don't leak the actual secret in the report
                                 remediation="Use environment variable interpolation (e.g., ${API_KEY}) instead of hardcoding secrets in configuration files.",
                             )
                         )

        return findings
