from __future__ import annotations

import asyncio

from mcp_sentry.cli import _run_scan_all
from mcp_sentry.config import SentryConfig, ServerConfig


def test_scan_all_writes_report_files(tmp_path, monkeypatch, filesystem_surface):
    async def fake_connect(server_name, server_config):
        return filesystem_surface

    monkeypatch.setattr("mcp_sentry.cli._connect_surface", fake_connect)

    config = SentryConfig(
        servers={
            "filesystem": ServerConfig(
                transport="stdio",
                command="npx",
                args=["-y", "@modelcontextprotocol/server-filesystem", "/tmp/mcp-sentry-test"],
            )
        }
    )

    asyncio.run(_run_scan_all(config, tmp_path))

    assert (tmp_path / "filesystem.md").exists()
    assert (tmp_path / "filesystem.json").exists()
