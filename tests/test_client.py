from __future__ import annotations

import asyncio
from types import SimpleNamespace

from mcp_sentry.client import enumerate_server
from mcp_sentry.config import ServerConfig


class _FakeResult:
    def __init__(self, field_name: str, payload):
        setattr(self, field_name, payload)


class _FakeSession:
    def __init__(self):
        self.server_capabilities = SimpleNamespace(model_dump=lambda: {"tools": True})

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def initialize(self):
        return None

    async def list_tools(self):
        return _FakeResult(
            "tools",
            [
                SimpleNamespace(
                    model_dump=lambda: {
                        "name": "read_file",
                        "description": "Read a file.",
                        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
                    }
                )
            ],
        )

    async def list_prompts(self):
        return _FakeResult(
            "prompts",
            [
                SimpleNamespace(
                    model_dump=lambda: {
                        "name": "prompt",
                        "description": "Example prompt",
                        "arguments": [{"name": "path", "type": "string"}],
                    }
                )
            ],
        )

    async def list_resources(self):
        return _FakeResult(
            "resources",
            [SimpleNamespace(model_dump=lambda: {"uri": "file:///tmp/example", "name": "example"})],
        )


class _FakeStdioClient:
    def __init__(self, params):
        self.params = params

    async def __aenter__(self):
        return ("read", "write")

    async def __aexit__(self, exc_type, exc, tb):
        return False


def test_enumerate_server_normalizes_surface(monkeypatch):
    import mcp_sentry.client as client_module

    monkeypatch.setattr(client_module, "stdio_client", lambda params: _FakeStdioClient(params))
    monkeypatch.setattr(client_module, "ClientSession", lambda read, write: _FakeSession())

    config = ServerConfig(transport="stdio", command="fake", args=["--flag"], env={"FOO": "BAR"})
    surface = asyncio.run(enumerate_server("fake-server", config))

    assert surface.server_name == "fake-server"
    assert surface.tools[0].name == "read_file"
    assert surface.prompts[0].name == "prompt"
    assert surface.resources[0].uri == "file:///tmp/example"
    assert surface.connection_info["env"] == {"FOO": "BAR"}
