"""Check for Hallucination-Based Vulnerabilities (HBV)."""

import difflib

from mcp_sentry.checks import BaseCheck, register_check
from mcp_sentry.models import Finding, ServerSurface, Severity

DESTRUCTIVE = ["delete", "remove", "drop", "truncate", "destroy", "wipe", "kill", "terminate", "purge"]
SCOPE_WORDS = ["only", "limited to", "restricted", "within", "sandboxed", "allowed", "permitted"]
AMBIGUOUS = ["any", "all", "everything", "anything", "whatever", "arbitrary"]
BOUNDARY_WORDS = ["directory", "folder", "allowed", "permitted", "root", "base", "prefix", "sandbox"]
PATH_URL_KW = ["path", "url", "file", "endpoint", "uri", "directory"]


@register_check
class HBVCheck(BaseCheck):
    check_id = "HBV"
    name = "Hallucination-Based Vulnerabilities"
    description = "Detects tool descriptions that are ambiguous and could mislead an LLM to over-privilege or misroute."

    def run(self, surface: ServerSurface) -> list[Finding]:
        findings = []

        descriptions = {}

        for tool in surface.tools:
            tool_name = tool.name.lower()
            desc = tool.description
            
            # Check 1: Missing description
            if not desc or not desc.strip():
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        severity=Severity.HIGH,
                        title=f"Missing tool description: {tool.name}",
                        tool_name=tool.name,
                        evidence={"description": None},
                        remediation="Provide a detailed, unambiguous description of what the tool does and its constraints.",
                    )
                )
                continue
                
            desc_lower = desc.lower()
            word_count = len(desc.split())
            descriptions[tool.name] = desc_lower

            # Check 2: Too brief
            if word_count < 10:
                 findings.append(
                    Finding(
                        check_id=self.check_id,
                        severity=Severity.MEDIUM,
                        title=f"Brief tool description: {tool.name}",
                        tool_name=tool.name,
                        evidence={"description": desc},
                        remediation="Expand the description to explicitly state boundaries, side effects, and exact purpose to guide LLM reasoning safely.",
                    )
                )

            # Check 3: Destructive action without scope
            is_destructive = any(kw in tool_name or kw in desc_lower for kw in DESTRUCTIVE)
            has_scope = any(kw in desc_lower for kw in SCOPE_WORDS)
            
            if is_destructive and not has_scope:
                 findings.append(
                    Finding(
                        check_id=self.check_id,
                        severity=Severity.HIGH,
                        title=f"Destructive tool lacks scope constraints: {tool.name}",
                        tool_name=tool.name,
                        evidence={"description": desc},
                        remediation="Specify exactly what records/files this tool is allowed to delete, or state that it requires user confirmation.",
                    )
                )
                
            # Check 4: Ambiguous scope words
            if any(kw in desc_lower for kw in AMBIGUOUS):
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        severity=Severity.MEDIUM,
                        title=f"Ambiguous scope words in description: {tool.name}",
                        tool_name=tool.name,
                        evidence={"description": desc},
                        remediation="Remove absolute terms like 'all' or 'any' unless strictly true and safe; define explicit boundaries.",
                    )
                )
                
            # Check 5: Path/URL boundary declaration
            has_path_param = False
            schema = tool.input_schema or {}
            for param_name, param_details in schema.get("properties", {}).items():
                 if any(kw in param_name.lower() or kw in param_details.get("description", "").lower() for kw in PATH_URL_KW):
                     has_path_param = True
                     break
                     
            if has_path_param and not any(kw in desc_lower for kw in BOUNDARY_WORDS):
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        severity=Severity.HIGH,
                        title=f"Path/URL tool lacks boundary declaration: {tool.name}",
                        tool_name=tool.name,
                        evidence={"description": desc},
                        remediation="Explicitly state the allowed directory or domain whitelist in the tool description.",
                    )
                )

        # Check 6: Similar descriptions
        tool_names = list(descriptions.keys())
        for i, name1 in enumerate(tool_names):
            for name2 in tool_names[i+1:]:
                desc1 = descriptions[name1]
                desc2 = descriptions[name2]
                
                # Simple similarity check
                matcher = difflib.SequenceMatcher(None, desc1, desc2)
                ratio = matcher.ratio()
                
                if ratio > 0.85:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            severity=Severity.MEDIUM,
                            title=f"Highly similar descriptions: {name1} and {name2}",
                            tool_name=name1,
                            evidence={"tool1": desc1, "tool2": desc2, "similarity": round(ratio, 2)},
                            remediation="Ensure descriptions have clear semantic differences to prevent the LLM from misrouting calls.",
                        )
                    )

        return findings
