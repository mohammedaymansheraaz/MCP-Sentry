"""Report generators for MCP-Sentry."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mcp_sentry.models import ScanReport, Severity


def _format_bool(value: bool) -> str:
    return "yes" if value else "no"


def _format_description(text: str | None) -> str:
    return text.strip() if text else "-"


def _format_param_names(items) -> str:
    if not items:
        return "-"
    names = []
    for item in items:
        if isinstance(item, dict):
            name = item.get("name") or item.get("title")
            if name:
                names.append(str(name))
    return ", ".join(names) if names else "-"


def _render_server_surface(report: ScanReport) -> list[str]:
    md = [
        "## Server Surface",
        "",
        f"- **Transport:** `{report.server.transport_type}`",
        f"- **Authentication configured:** {_format_bool(report.server.auth_configured)}",
        f"- **Tools discovered:** {len(report.server.tools)}",
        f"- **Prompts discovered:** {len(report.server.prompts)}",
        f"- **Resources discovered:** {len(report.server.resources)}",
    ]

    if report.server.server_version:
        md.append(f"- **Server version:** `{report.server.server_version}`")

    md.extend(["", "### Tools", ""])
    if report.server.tools:
        md.extend(["| Name | Description | Parameters |", "|---|---|---|"])
        for tool in report.server.tools:
            params = ", ".join(sorted((tool.input_schema or {}).get("properties", {}).keys())) or "-"
            md.append(f"| `{tool.name}` | {_format_description(tool.description)} | `{params}` |")
    else:
        md.append("No tools discovered.")

    md.extend(["", "### Prompts", ""])
    if report.server.prompts:
        md.extend(["| Name | Description | Arguments |", "|---|---|---|"])
        for prompt in report.server.prompts:
            md.append(
                f"| `{prompt.name}` | {_format_description(prompt.description)} | {_format_param_names(prompt.arguments)} |"
            )
    else:
        md.append("No prompts discovered.")

    md.extend(["", "### Resources", ""])
    if report.server.resources:
        md.extend(["| URI | Name | Description |", "|---|---|---|"])
        for resource in report.server.resources:
            md.append(
                f"| `{resource.uri}` | `{resource.name}` | {_format_description(resource.description)} |"
            )
    else:
        md.append("No resources discovered.")

    return md


def _render_methodology(report: ScanReport) -> list[str]:
    return [
        "## Methodology",
        "",
        "MCP-Sentry performs a detection-only pass over the enumerated MCP surface.",
        "It does not send exploit payloads or mutate server state.",
        "",
        "The scan pipeline for this report was:",
        "",
        f"1. Connect to the server over `{report.server.transport_type}`.",
        "2. Enumerate tools, prompts, resources, and server capabilities.",
        "3. Run the configured static security checks against the normalized surface.",
        "4. Rank findings by severity and compute a normalized score and grade.",
    ]


def render_terminal(report: ScanReport, console: Console | None = None):
    """Render a colored report to the terminal using Rich."""
    if console is None:
        console = Console()

    # Header
    grade_color = {
        "A": "bold green",
        "B": "bold blue",
        "C": "bold yellow",
        "D": "bold magenta",
        "F": "bold red",
    }.get(report.grade, "white")

    header_text = Text()
    header_text.append(f"MCP-Sentry Report: {report.server.server_name}\n", style="bold")
    header_text.append(f"Grade: {report.grade} ", style=grade_color)
    header_text.append(f"(Score: {report.score})\n", style="dim")
    header_text.append(f"{report.summary}\n")
    header_text.append(f"Scan duration: {report.scan_duration_ms}ms", style="dim")
    
    console.print(Panel(header_text, title="Security Scan Results", expand=False))

    # Top findings
    if report.findings:
        console.print("\n[bold]Top Findings[/bold]")
        top_findings = report.findings[:3]
        for f in top_findings:
            title = f"[{f.severity.color}]{f.severity.value}[/{f.severity.color}] {f.title}"
            details = []
            if f.tool_name:
                details.append(f"Tool: [cyan]{f.tool_name}[/cyan]")
            if f.field_name:
                details.append(f"Field: [cyan]{f.field_name}[/cyan]")
            if f.description:
                details.append(f.description)
                
            body = "\n".join(details)
            body += f"\n\n[bold]Remediation:[/bold] {f.remediation}"
            
            console.print(Panel(body, title=title, border_style=f.severity.color, expand=False))

        # Full table
        console.print("\n[bold]All Findings[/bold]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Severity")
        table.add_column("Check")
        table.add_column("Tool")
        table.add_column("Title")

        for f in report.findings:
            table.add_row(
                f"[{f.severity.color}]{f.severity.value}[/{f.severity.color}]",
                f.check_id,
                f.tool_name or "-",
                f.title,
            )
            
        console.print(table)
    else:
        console.print("\n[bold green]No vulnerabilities found![/bold green] 🎉")


def render_markdown(report: ScanReport) -> str:
    """Generate a markdown report."""
    md = [
        f"# MCP-Sentry Security Report: {report.server.server_name}",
        "",
        f"**Grade:** {report.grade} | **Score:** {report.score} | **Scanned:** {report.server.scan_timestamp.isoformat()}",
        "",
        f"{report.summary}",
        "",
    ]

    md.extend(_render_server_surface(report))
    md.extend(["", "---", ""])

    if report.findings:
        md.extend([
            "## Executive Summary",
            "",
        ])
        
        for f in report.findings[:3]:
            md.extend([
                f"### {f.severity.value}: {f.title}",
                f"**Check:** {f.check_id} | **Tool:** {f.tool_name or 'N/A'}",
                "",
                f"{f.description}",
                "",
                "**Remediation:**",
                f"{f.remediation}",
                "",
            ])

        md.extend([
            "## All Findings",
            "",
            "| Severity | Check | Tool | Title |",
            "|---|---|---|---|",
        ])
        
        for f in report.findings:
            md.append(f"| {f.severity.value} | {f.check_id} | {f.tool_name or '-'} | {f.title} |")
            
        md.append("")
    else:
        md.extend(["## Results", "", "No vulnerabilities found."])

    md.extend(["", "---", ""])
    md.extend(_render_methodology(report))

    return "\n".join(md)


def render_json(report: ScanReport) -> str:
    """Generate JSON report."""
    # Use pydantic's model_dump_json
    return report.model_dump_json(indent=2)
