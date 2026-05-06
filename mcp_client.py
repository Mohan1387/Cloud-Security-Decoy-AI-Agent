"""
MCP Client — connects to mcp_server.py via stdio transport.

Spawns the MCP server as a subprocess and communicates over the MCP
protocol.  Provides synchronous wrappers so the (sync) LangGraph agent
can call MCP tools without caring about async internals.
"""

import asyncio
import json
import logging
import sys
import threading
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

logger = logging.getLogger(__name__)

_SERVER_SCRIPT = str(Path(__file__).parent / "mcp_server.py")


class MCPClient:
    """Manages an MCP server subprocess and exposes a sync call_tool API."""

    def __init__(self, server_command: str | None = None, server_args: list[str] | None = None):
        self._server_command = server_command or sys.executable
        self._server_args = server_args or [_SERVER_SCRIPT]
        self._session: ClientSession | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._shutdown_event: asyncio.Event | None = None
        self._startup_error: Exception | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self):
        """Start the MCP server subprocess and block until connected."""
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="mcp-client")
        self._thread.start()
        if not self._ready.wait(timeout=30):
            raise RuntimeError("MCP client: timed out waiting for server connection")
        if self._startup_error:
            raise self._startup_error
        logger.info("MCP client connected (server: %s %s)", self._server_command, self._server_args)

    def stop(self):
        """Shut down the MCP server subprocess gracefully."""
        if self._loop and self._shutdown_event:
            self._loop.call_soon_threadsafe(self._shutdown_event.set)
        if self._thread:
            self._thread.join(timeout=10)
        self._session = None
        self._loop = None
        logger.info("MCP client disconnected")

    # ------------------------------------------------------------------
    # Background event loop
    # ------------------------------------------------------------------

    def _run_loop(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._connect())
        except Exception as exc:
            self._startup_error = exc
            self._ready.set()

    async def _connect(self):
        server_params = StdioServerParameters(
            command=self._server_command,
            args=self._server_args,
            env=None,  # inherit parent environment
        )
        async with stdio_client(server_params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                self._session = session
                self._shutdown_event = asyncio.Event()
                self._ready.set()
                # Block until stop() is called
                await self._shutdown_event.wait()

    # ------------------------------------------------------------------
    # Tool invocation
    # ------------------------------------------------------------------

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None, timeout: float = 120) -> Any:
        """Call an MCP tool synchronously.  Returns the parsed JSON result."""
        if self._session is None or self._loop is None:
            raise RuntimeError("MCP client not connected — call start() first")

        future = asyncio.run_coroutine_threadsafe(
            self._session.call_tool(name, arguments or {}),
            self._loop,
        )
        result = future.result(timeout=timeout)

        if result.isError:
            error_text = " ".join(
                block.text for block in result.content if hasattr(block, "text")
            )
            raise RuntimeError(f"MCP tool '{name}' returned error: {error_text}")

        # Extract text content blocks and parse as JSON
        text_parts = [
            block.text for block in result.content if hasattr(block, "text")
        ]
        combined = "\n".join(text_parts)

        try:
            return json.loads(combined)
        except json.JSONDecodeError:
            return combined

    def list_tools(self, timeout: float = 30) -> list[dict]:
        """List tools available on the MCP server."""
        if self._session is None or self._loop is None:
            raise RuntimeError("MCP client not connected — call start() first")

        future = asyncio.run_coroutine_threadsafe(
            self._session.list_tools(),
            self._loop,
        )
        result = future.result(timeout=timeout)
        return [{"name": t.name, "description": t.description} for t in result.tools]


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
_client: MCPClient | None = None


def get_client() -> MCPClient:
    """Return the singleton MCPClient, starting it if necessary."""
    global _client
    if _client is None:
        _client = MCPClient()
        _client.start()
    return _client


def call_tool(name: str, arguments: dict[str, Any] | None = None) -> Any:
    """Convenience: call an MCP tool via the singleton client."""
    return get_client().call_tool(name, arguments)


def shutdown():
    """Shut down the singleton client."""
    global _client
    if _client is not None:
        _client.stop()
        _client = None
