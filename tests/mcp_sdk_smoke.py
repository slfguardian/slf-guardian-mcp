"""Smoke-test the stdio server using the official MCP Python client SDK.

This test only initializes the server and lists tools; it does not call the
SLF Guardian API or consume an API credit.
"""

from __future__ import annotations

import asyncio
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main() -> None:
    server = StdioServerParameters(
        command=sys.executable,
        args=["-c", "from slf_guardian_mcp.server import main; main()"],
    )
    async with stdio_client(server) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            initialized = await session.initialize()
            assert initialized.serverInfo.name == "slf-guardian"
            tools = await session.list_tools()
            assert [tool.name for tool in tools.tools] == [
                "audit_code",
                "check_package",
                "check_prompt",
                "check_command",
                "check_domain",
                "scan_site",
            ]
            audit = next(tool for tool in tools.tools if tool.name == "audit_code")
            assert audit.inputSchema["properties"]["files"]["items"]["required"] == [
                "path",
                "content",
            ]
            # Empty domains are rejected locally before any API/network access.
            # This exercises tools/call without spending a credit.
            invalid = await session.call_tool("check_domain", {"domains": []})
            assert invalid.isError is True
            assert "invalid_input" in invalid.content[0].text


if __name__ == "__main__":
    asyncio.run(main())
    print("Official MCP SDK stdio smoke test passed (initialize/tools/list/call).")
