from __future__ import annotations

from pathlib import Path

import pytest

from mcp_sentry.config import load_config


def test_load_config_expands_environment_variables(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MCP_API_KEY", "token-123")

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
servers:
  remote:
    transport: streamable_http
    url: "https://example.com/mcp"
    headers:
      Authorization: "Bearer ${MCP_API_KEY}"
""".strip(),
        encoding="utf-8",
    )

    config = load_config(str(config_path))

    assert config.servers["remote"].headers["Authorization"] == "Bearer token-123"


def test_load_config_validates_required_fields(tmp_path: Path):
    config_path = tmp_path / "invalid.yaml"
    config_path.write_text(
        """
servers:
  broken:
    transport: stdio
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="command is required"):
        load_config(str(config_path))
