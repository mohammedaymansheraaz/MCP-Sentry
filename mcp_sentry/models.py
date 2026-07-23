"""Data models for MCP-Sentry.

All models use Pydantic v2 for validation and serialization.
These models represent the normalized attack surface of an MCP server
and the findings produced by security checks.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Finding severity levels with associated penalty points for scoring."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

    @property
    def points(self) -> int:
        """Penalty points for the scoring rubric."""
        return {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 5,
            Severity.LOW: 2,
            Severity.INFO: 0,
        }[self]

    @property
    def color(self) -> str:
        """Rich color string for terminal output."""
        return {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "dim",
        }[self]


class ToolInfo(BaseModel):
    """Normalized representation of an MCP tool."""

    name: str
    description: str | None = None
    input_schema: dict[str, Any] = Field(default_factory=dict)
    output_schema: dict[str, Any] | None = None
    annotations: dict[str, Any] | None = None


class PromptInfo(BaseModel):
    """Normalized representation of an MCP prompt template."""

    name: str
    description: str | None = None
    arguments: list[dict[str, Any]] = Field(default_factory=list)


class ResourceInfo(BaseModel):
    """Normalized representation of an MCP resource."""

    uri: str
    name: str
    description: str | None = None
    mime_type: str | None = None


class ServerSurface(BaseModel):
    """The complete enumerated attack surface of an MCP server.

    This is the input to all security checks — it represents everything
    the server exposes via the MCP protocol.
    """

    server_name: str
    server_version: str | None = None
    capabilities: dict[str, Any] = Field(default_factory=dict)
    tools: list[ToolInfo] = Field(default_factory=list)
    prompts: list[PromptInfo] = Field(default_factory=list)
    resources: list[ResourceInfo] = Field(default_factory=list)
    transport_type: str = "stdio"  # "stdio" | "streamable_http"
    connection_info: dict[str, Any] = Field(default_factory=dict)
    auth_configured: bool = False
    scan_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Finding(BaseModel):
    """A single security finding produced by a check.

    Every finding includes evidence (the raw data that triggered it)
    and a concrete remediation suggestion.
    """

    check_id: str
    severity: Severity
    title: str
    description: str = ""
    tool_name: str | None = None
    field_name: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: str = ""


class ScanReport(BaseModel):
    """Complete scan report with findings, score, and grade."""

    server: ServerSurface
    findings: list[Finding] = Field(default_factory=list)
    grade: str = "A"
    score: float = 0.0
    summary: str = ""
    scan_duration_ms: int = 0
