"""Check for path traversal risks."""

from mcp_sentry.checks import BaseCheck, register_check
from mcp_sentry.models import Finding, ServerSurface, Severity

PATH_KW = ["path", "file", "directory", "folder", "filename", "filepath"]
WRITE_KW = ["write", "delete", "create", "execute", "update", "modify", "remove", "insert", "move", "rename"]
SANDBOX_KW = ["restricted", "within", "allowed", "sandboxed", "base directory", "sandbox", "root directory"]


@register_check
class PathTraversalCheck(BaseCheck):
    check_id = "PATH_TRAVERSAL"
    name = "Path Traversal Risk"
    description = "Detects file-touching tools where path parameters are not strictly constrained to a sandbox."

    def run(self, surface: ServerSurface) -> list[Finding]:
        findings = []

        # Check if server explicitly exposes allowed directories
        has_allowed_dirs_tool = any(t.name == "list_allowed_directories" for t in surface.tools)

        for tool in surface.tools:
            tool_name = tool.name.lower()
            tool_desc = (tool.description or "").lower()
            
            is_write_tool = any(kw in tool_name or kw in tool_desc for kw in WRITE_KW)
            
            schema = tool.input_schema or {}
            properties = schema.get("properties", {})
            
            for param_name, param_details in properties.items():
                context = f"{param_name.lower()} {param_details.get('description', '').lower()}"
                
                # If it's a path parameter
                if any(kw in context for kw in PATH_KW):
                    has_pattern = "pattern" in param_details
                    has_enum = "enum" in param_details
                    
                    if not (has_pattern or has_enum):
                        # It's an unconstrained path
                        mentions_sandbox = any(kw in tool_desc for kw in SANDBOX_KW)
                        evidence = dict(param_details)
                        evidence["has_allowed_dirs_tool"] = has_allowed_dirs_tool
                        remediation = "Ensure the path is validated against allowed roots before file access."
                        if has_allowed_dirs_tool:
                            remediation = (
                                "The server exposes list_allowed_directories, but this parameter still accepts unconstrained paths. "
                                + remediation
                            )
                        
                        if is_write_tool:
                            findings.append(
                                Finding(
                                    check_id=self.check_id,
                                    severity=Severity.CRITICAL,
                                    title=f"Path Traversal: Unconstrained path parameter '{param_name}' on write/delete tool",
                                    tool_name=tool.name,
                                    field_name=param_name,
                                    evidence=evidence,
                                    remediation=(
                                        remediation
                                        if has_allowed_dirs_tool
                                        else "Enforce directory constraints using a 'pattern' schema (e.g., ^/allowed/dir/) or handle path sanitization securely server-side."
                                    ),
                                )
                            )
                        else:
                             severity = Severity.MEDIUM if mentions_sandbox else Severity.HIGH
                             title = f"Path Traversal: Unconstrained path parameter '{param_name}' on read tool"
                             findings.append(
                                Finding(
                                    check_id=self.check_id,
                                    severity=severity,
                                    title=title,
                                    tool_name=tool.name,
                                    field_name=param_name,
                                    evidence=evidence,
                                    remediation=remediation,
                                )
                            )

        return findings
