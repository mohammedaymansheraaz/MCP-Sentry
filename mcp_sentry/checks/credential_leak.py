"""Check for Credential Leakage in static analysis."""

import re

from mcp_sentry.checks import BaseCheck, register_check
from mcp_sentry.models import Finding, ServerSurface, Severity

SECRET_PATTERNS = [
    (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']?[\w-]{20,}', "API Key"),
    (r'(?:password|passwd|pwd)\s*[:=]\s*["\']?[^\s"\']{8,}', "Password"),
    (r'Bearer\s+eyJ[\w-]+\.[\w-]+\.[\w-]+', "JWT Token"),
    (r'sk-[a-zA-Z0-9]{20,}', "OpenAI Key"),
    (r'ghp_[a-zA-Z0-9]{36}', "GitHub PAT"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
    (r'mongodb(?:\+srv)?://[^\s]+:[^\s]+@[^\s]+', "MongoDB URI with credentials"),
    (r'postgres(?:ql)?://[^\s]+:[^\s]+@[^\s]+', "PostgreSQL URI with credentials"),
]


@register_check
class CredentialLeakCheck(BaseCheck):
    check_id = "CREDENTIAL_LEAK"
    name = "Credential Leakage (Static)"
    description = "Detects hardcoded secrets in tool descriptions, prompt arguments, and resource URIs."

    def run(self, surface: ServerSurface) -> list[Finding]:
        findings = []

        def _scan_text(text: str, context: str, source_name: str, field_name: str):
            if not text:
                return

            for pattern, secret_type in SECRET_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            severity=Severity.CRITICAL,
                            title=f"Hardcoded {secret_type} in {context}",
                            tool_name=source_name,
                            field_name=field_name,
                            evidence={"matched_pattern": secret_type, "text_excerpt": "***"},
                            remediation="Remove hardcoded credentials from server metadata. Use environment variables instead.",
                        )
                    )
                    break

        def _scan_node(node, context: str, source_name: str, path: str):
            if isinstance(node, str):
                _scan_text(node, context, source_name, path)
                return

            if isinstance(node, dict):
                for key, value in node.items():
                    _scan_node(value, context, source_name, f"{path}.{key}" if path else str(key))
                return

            if isinstance(node, list):
                for index, value in enumerate(node):
                    _scan_node(value, context, source_name, f"{path}[{index}]")
                return

        # Scan tools
        for tool in surface.tools:
            _scan_text(tool.description, "tool description", tool.name, "description")
            _scan_node(tool.input_schema, "tool schema", tool.name, "input_schema")
            _scan_node(tool.annotations, "tool metadata", tool.name, "annotations")
            
        # Scan prompts
        for prompt in surface.prompts:
            _scan_text(prompt.description, "prompt description", prompt.name, "description")
            _scan_node(prompt.arguments, "prompt arguments", prompt.name, "arguments")
            
        # Scan resources
        for resource in surface.resources:
            _scan_text(resource.uri, "resource URI", resource.name, "uri")
            _scan_text(resource.description, "resource description", resource.name, "description")

        # Scan arbitrary server metadata/capabilities for leaked config values.
        _scan_node(surface.capabilities, "server metadata", surface.server_name, "capabilities")

        return findings
