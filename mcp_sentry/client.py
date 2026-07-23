"""MCP Client wrapper for enumerating server attack surfaces."""

import asyncio
import logging
import os
from datetime import datetime, timezone
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from mcp_sentry.config import ServerConfig
from mcp_sentry.models import (
    PromptInfo,
    ResourceInfo,
    ServerSurface,
    ToolInfo,
)

logger = logging.getLogger(__name__)


async def _collect_surface(
    session: ClientSession, config: ServerConfig, server_name: str
) -> ServerSurface:
    """Enumerate the server surface via an initialized session."""
    try:
        tools_response = await session.list_tools()
        tools_data = tools_response.tools if hasattr(tools_response, "tools") else []
    except Exception as e:
        logger.warning("Failed to list tools: %s", e)
        tools_data = []

    try:
        prompts_response = await session.list_prompts()
        prompts_data = prompts_response.prompts if hasattr(prompts_response, "prompts") else []
    except Exception as e:
        logger.warning("Failed to list prompts: %s", e)
        prompts_data = []

    try:
        resources_response = await session.list_resources()
        resources_data = resources_response.resources if hasattr(resources_response, "resources") else []
    except Exception as e:
        logger.warning("Failed to list resources: %s", e)
        resources_data = []

    # Map to our normalized models
    tools = []
    for t in tools_data:
        t_dict = t.model_dump() if hasattr(t, "model_dump") else vars(t) if hasattr(t, "__dict__") else t
        
        tools.append(
            ToolInfo(
                name=t_dict.get("name", "unknown"),
                description=t_dict.get("description"),
                input_schema=t_dict.get("inputSchema", {}),
                output_schema=t_dict.get("outputSchema"),
                annotations=t_dict.get("annotations"),
            )
        )

    prompts = []
    for p in prompts_data:
        p_dict = p.model_dump() if hasattr(p, "model_dump") else vars(p) if hasattr(p, "__dict__") else p
        arguments = p_dict.get("arguments", [])
        parsed_args = [a.model_dump() if hasattr(a, "model_dump") else (vars(a) if hasattr(a, "__dict__") else a) for a in arguments]
        prompts.append(
            PromptInfo(
                name=p_dict.get("name", "unknown"),
                description=p_dict.get("description"),
                arguments=parsed_args,
            )
        )

    resources = []
    for r in resources_data:
        r_dict = r.model_dump() if hasattr(r, "model_dump") else vars(r) if hasattr(r, "__dict__") else r
        resources.append(
            ResourceInfo(
                uri=r_dict.get("uri", "unknown"),
                name=r_dict.get("name", "unknown"),
                description=r_dict.get("description"),
                mime_type=r_dict.get("mimeType"),
            )
        )

    capabilities = {}
    server_version = None
    if hasattr(session, "server_capabilities") and session.server_capabilities:
         capabilities = session.server_capabilities.model_dump() if hasattr(session.server_capabilities, "model_dump") else vars(session.server_capabilities)
         
    # Check if auth is configured
    auth_configured = False
    if config.transport == "streamable_http" and config.headers.get("Authorization"):
        auth_configured = True

    if config.transport == "stdio":
        conn_info = {"command": config.command, "args": config.args}
        if config.env:
            conn_info["env"] = config.env
    else:
        conn_info = {"url": config.url, "headers": dict(config.headers)}

    return ServerSurface(
        server_name=server_name,
        server_version=server_version,
        capabilities=capabilities,
        tools=tools,
        prompts=prompts,
        resources=resources,
        transport_type=config.transport,
        connection_info=conn_info,
        auth_configured=auth_configured,
        scan_timestamp=datetime.now(timezone.utc),
    )


async def enumerate_server(server_name: str, config: ServerConfig) -> ServerSurface:
    """Connect to an MCP server and enumerate its attack surface."""
    if config.transport == "stdio":
        if not config.command:
             raise ValueError("Command is required for stdio transport")
             
        env = None
        if config.env:
             env = {**os.environ, **config.env}
             
        params = StdioServerParameters(
            command=config.command,
            args=config.args,
            env=env,
        )
        
        logger.info(f"Connecting to stdio server '{server_name}' via {config.command}...")
        try:
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await asyncio.wait_for(session.initialize(), timeout=10.0)
                    return await asyncio.wait_for(_collect_surface(session, config, server_name), timeout=20.0)
        except Exception as e:
            raise RuntimeError(f"Failed to connect to stdio server '{server_name}': {e}")

    elif config.transport == "streamable_http":
        raise NotImplementedError("streamable_http transport is not yet fully implemented in client wrapper.")
    else:
        raise ValueError(f"Unsupported transport: {config.transport}")
