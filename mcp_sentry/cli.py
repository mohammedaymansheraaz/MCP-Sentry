"""Command Line Interface for MCP-Sentry."""

import asyncio
import logging
import shlex
import sys
from pathlib import Path

import click
from rich.console import Console

from mcp_sentry import __version__
from mcp_sentry.client import enumerate_server
from mcp_sentry.config import ServerConfig, load_config
from mcp_sentry.models import ScanReport, ServerSurface
from mcp_sentry.scanner import scan_server
from mcp_sentry.report import render_terminal, render_markdown, render_json

console = Console()
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger("mcp_sentry")


@click.group()
@click.version_option(version=__version__)
def main():
    """MCP-Sentry: Security Auditor for Model Context Protocol servers."""
    pass


@main.command()
@click.option("--config", type=click.Path(exists=True), help="Path to YAML config file")
@click.option("--target", help="Name of the server in config to scan")
@click.option("--stdio", help="Inline stdio command (e.g. 'npx -y @modelcontextprotocol/server-filesystem /tmp')")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["terminal", "markdown", "json"], case_sensitive=False),
    default="terminal",
    help="Output format",
)
@click.option("--output", type=click.Path(), help="Output file path (for markdown/json)")
@click.option("--checks", help="Comma-separated list of check IDs to run (default: all)")
@click.option("--recon-only", is_flag=True, help="Only enumerate attack surface, skip security checks")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
def scan(config, target, stdio, output_format, output, checks, recon_only, verbose):
    """Scan a specific MCP server for vulnerabilities."""
    if verbose:
        logging.getLogger().setLevel(logging.INFO)

    if not config and not stdio:
        console.print("[bold red]Error:[/bold red] Must provide either --config or --stdio")
        sys.exit(1)

    server_config = None
    server_name = target or "inline-server"

    if stdio:
        parts = shlex.split(stdio)
        if not parts:
            console.print("[bold red]Error:[/bold red] Invalid stdio command")
            sys.exit(1)
        server_config = ServerConfig(
            transport="stdio",
            command=parts[0],
            args=parts[1:]
        )
    else:
        if not target:
            console.print("[bold red]Error:[/bold red] Must provide --target when using --config")
            sys.exit(1)
        try:
            sentry_config = load_config(config)
            if target not in sentry_config.servers:
                console.print(f"[bold red]Error:[/bold red] Target '{target}' not found in {config}")
                sys.exit(1)
            server_config = sentry_config.servers[target]
        except Exception as e:
            console.print(f"[bold red]Configuration Error:[/bold red] {e}")
            sys.exit(1)

    check_ids = checks.split(",") if checks else None

    # Run the async orchestration
    try:
        asyncio.run(
            _run_scan(
                server_name,
                server_config,
                recon_only,
                check_ids,
                output_format,
                output,
            )
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        sys.exit(130)


@main.command(name="scan-all")
@click.option("--config", required=True, type=click.Path(exists=True), help="Path to YAML config file")
@click.option("--output-dir", default="reports", type=click.Path(), help="Directory to save reports")
def scan_all(config, output_dir):
    """Scan all servers defined in a config file."""
    try:
        sentry_config = load_config(config)
    except Exception as e:
        console.print(f"[bold red]Configuration Error:[/bold red] {e}")
        sys.exit(1)

    try:
        asyncio.run(_run_scan_all(sentry_config, Path(output_dir)))
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        sys.exit(130)


async def _connect_surface(server_name: str, server_config: ServerConfig) -> ServerSurface:
    with console.status(f"[bold blue]Connecting to {server_name}...[/bold blue]"):
        try:
            return await enumerate_server(server_name, server_config)
        except Exception as e:
            raise RuntimeError(f"Connection failed: {e}")


async def _generate_report(
    surface: ServerSurface,
    server_name: str,
    check_ids: list[str] | None,
) -> ScanReport:
    console.print(f"[green]Successfully connected to {server_name}[/green]")
    console.print(
        f"Discovered: {len(surface.tools)} tools, {len(surface.prompts)} prompts, {len(surface.resources)} resources."
    )

    with console.status(f"[bold blue]Running security checks on {server_name}...[/bold blue]"):
        report = scan_server(surface, check_ids)

    return report


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


async def _run_scan(
    server_name: str,
    server_config: ServerConfig,
    recon_only: bool,
    check_ids: list[str] | None,
    output_format: str,
    output: str | None,
):
    try:
        surface = await _connect_surface(server_name, server_config)
    except Exception as e:
        console.print(f"[bold red]{e}[/bold red]")
        sys.exit(1)

    if recon_only:
        # Just dump the surface
        out_str = surface.model_dump_json(indent=2)
        if output:
            _write_text(Path(output), out_str)
            console.print(f"[green]Recon output saved to {output}[/green]")
        else:
            console.print(out_str)
        return

    report = await _generate_report(surface, server_name, check_ids)

    if output_format == "terminal":
        render_terminal(report, console)
    elif output_format == "markdown":
        out_str = render_markdown(report)
        if output:
            _write_text(Path(output), out_str)
            console.print(f"[green]Markdown report saved to {output}[/green]")
        else:
            console.print(out_str)
    elif output_format == "json":
        out_str = render_json(report)
        if output:
            _write_text(Path(output), out_str)
            console.print(f"[green]JSON report saved to {output}[/green]")
        else:
            console.print(out_str)


async def _run_scan_all(sentry_config, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    if not sentry_config.servers:
        console.print("[yellow]No servers found in configuration.[/yellow]")
        return

    total = len(sentry_config.servers)
    console.print(f"[bold]Scanning {total} server(s)...[/bold]")

    for server_name, server_config in sentry_config.servers.items():
        console.print(f"\n[bold cyan]Scanning {server_name}[/bold cyan]")
        try:
            surface = await _connect_surface(server_name, server_config)
            report = await _generate_report(surface, server_name, None)
        except Exception as e:
            console.print(f"[bold red]Failed to scan {server_name}:[/bold red] {e}")
            continue

        markdown_path = output_dir / f"{server_name}.md"
        json_path = output_dir / f"{server_name}.json"
        _write_text(markdown_path, render_markdown(report))
        _write_text(json_path, render_json(report))
        render_terminal(report, console)
        console.print(f"[green]Saved reports:[/green] {markdown_path} and {json_path}")

if __name__ == "__main__":
    main()
