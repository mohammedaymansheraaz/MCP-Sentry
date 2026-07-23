"""Configuration loader for MCP-Sentry.

Loads YAML configuration files, expands environment variables,
and validates server configurations.
"""

import os
import re
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator


class ServerConfig(BaseModel):
    """Configuration for connecting to an MCP server."""

    transport: str = Field(pattern="^(stdio|streamable_http)$")
    
    # stdio transport fields
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    
    # streamable_http transport fields
    url: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)

    model_config = ConfigDict(extra="ignore")

    @field_validator("command")
    @classmethod
    def validate_command(cls, v: str | None, info: Any) -> str | None:
        if info.data.get("transport") == "stdio" and not v:
            raise ValueError("command is required for stdio transport")
        return v

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str | None, info: Any) -> str | None:
        if info.data.get("transport") == "streamable_http" and not v:
            raise ValueError("url is required for streamable_http transport")
        return v


class SentryConfig(BaseModel):
    """Root configuration object containing multiple servers."""

    servers: dict[str, ServerConfig] = Field(default_factory=dict)


def _expand_env_vars(node: Any) -> Any:
    """Recursively expand ${VAR} syntax in strings."""
    if isinstance(node, dict):
        return {k: _expand_env_vars(v) for k, v in node.items()}
    elif isinstance(node, list):
        return [_expand_env_vars(v) for v in node]
    elif isinstance(node, str):
        # Match ${VAR_NAME} pattern
        pattern = re.compile(r'\$\{([A-Za-z0-9_]+)\}')
        
        def replace_match(match: re.Match) -> str:
            var_name = match.group(1)
            return os.environ.get(var_name, match.group(0))
            
        return pattern.sub(replace_match, node)
    return node


def load_config(path: str) -> SentryConfig:
    """Load, expand, and validate a YAML config file."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Configuration file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        try:
            raw_data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in {path}: {e}")

    if not raw_data:
        raw_data = {}

    expanded_data = _expand_env_vars(raw_data)
    
    try:
        return SentryConfig.model_validate(expanded_data)
    except Exception as e:
         raise ValueError(f"Configuration validation failed: {e}")
