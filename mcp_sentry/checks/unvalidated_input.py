"""Check for unvalidated input schemas (injection risks)."""

from typing import Any

from mcp_sentry.checks import BaseCheck, register_check
from mcp_sentry.models import Finding, ServerSurface, Severity

PATH_KW = ["path", "file", "directory", "folder", "filename", "filepath"]
URL_KW = ["url", "uri", "endpoint", "host", "hostname", "address"]
CMD_KW = ["command", "cmd", "exec", "shell", "script", "query", "sql"]


@register_check
class UnvalidatedInputCheck(BaseCheck):
    check_id = "UNVALIDATED_INPUT"
    name = "Unvalidated Input Schemas"
    description = "Detects tool parameters that lack validation constraints (enum, pattern, etc.) and could be used for injection attacks."

    def run(self, surface: ServerSurface) -> list[Finding]:
        findings = []

        for tool in surface.tools:
            schema = tool.input_schema or {}
            properties = schema.get("properties", {})
            
            for param_name, param_details in properties.items():
                param_type = param_details.get("type")
                desc = param_details.get("description", "").lower()
                
                # Check 1: Unconstrained strings
                if param_type == "string":
                    has_enum = "enum" in param_details
                    has_pattern = "pattern" in param_details
                    has_max = "maxLength" in param_details
                    has_format = "format" in param_details
                    
                    if not (has_enum or has_pattern or has_max or has_format):
                        # Determine severity based on context
                        context = f"{param_name.lower()} {desc}"
                        
                        severity = Severity.MEDIUM
                        title = f"Unconstrained string parameter: {param_name}"
                        
                        if any(kw in context for kw in PATH_KW):
                            severity = Severity.CRITICAL
                            title = f"Path injection risk: Unconstrained path parameter '{param_name}'"
                        elif any(kw in context for kw in URL_KW):
                            severity = Severity.HIGH
                            title = f"SSRF/Injection risk: Unconstrained URL parameter '{param_name}'"
                        elif any(kw in context for kw in CMD_KW):
                            severity = Severity.HIGH
                            title = f"Command injection risk: Unconstrained command parameter '{param_name}'"
                            
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                severity=severity,
                                title=title,
                                tool_name=tool.name,
                                field_name=param_name,
                                evidence=param_details,
                                remediation="Add 'pattern', 'enum', or 'maxLength' constraints to the parameter schema to strictly validate input.",
                            )
                        )
                        
                # Check 2: Schemaless objects
                elif param_type == "object":
                    has_properties = "properties" in param_details and bool(param_details.get("properties"))
                    if (not has_properties) or param_details.get("additionalProperties") is not False:
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                severity=Severity.HIGH,
                                title=f"Schemaless object parameter: {param_name}",
                                tool_name=tool.name,
                                field_name=param_name,
                                evidence=param_details,
                                remediation="Define strict 'properties' for the object and set 'additionalProperties: false'.",
                            )
                        )

        return findings
