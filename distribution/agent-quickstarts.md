# Agent install quickstarts

These examples intentionally pin the **currently published PyPI version 1.2.2**. They use `SLF_API_KEY` from the local environment or the client’s secret store; do not put a real key in a checked-in file or shell history. Obtain a key from the [SLF Guardian API](https://slfguardian.com/api). Each key begins with 1,000 free calls; the API lists $0.01/call after those and a 20-call/minute limit. Paid API credits currently require a prepaid top-up arranged with `team@slfguardian.com`; this setup does not enable automatic card billing. The API also supports direct HTTP x402 payment, but the published 1.2.2 stdio MCP package does not sign payments.

If `uvx` is unavailable, install `uv` from its [official guide](https://docs.astral.sh/uv/getting-started/installation/). These are the local stdio MCP setup instructions, not a hosted remote service.

**Data flow:** The stdio MCP process runs on the agent's machine, but each tool call sends its input over HTTPS to SLF Guardian's hosted API for analysis. This is not local/offline analysis. The API documents submitted code and prompt content as analyzed in memory and not stored; limited billing and operational metadata may be retained. Do not submit credentials or secrets.

## Claude Code

Set `SLF_API_KEY` in the terminal environment or the machine’s secret manager, then add the stdio server:

```bash
claude mcp add --transport stdio --scope user slf-guardian -- \
  uvx --from slf-guardian-mcp==1.2.2 slf-guardian-mcp
claude mcp get slf-guardian
```

Launch Claude Code from a process that has access to `SLF_API_KEY`. The MCP child inherits that environment. Avoid passing the literal key on the `claude mcp add --env ...` command line because command arguments may be stored in shell history or client configuration. See [Claude Code MCP docs](https://code.claude.com/docs/en/mcp).

## Cursor

Add this to `~/.cursor/mcp.json` for user-wide access, or `.cursor/mcp.json` for a workspace:

```json
{
  "mcpServers": {
    "slf-guardian": {
      "type": "stdio",
      "command": "uvx",
      "args": ["--from", "slf-guardian-mcp==1.2.2", "slf-guardian-mcp"],
      "env": {"SLF_API_KEY": "${env:SLF_API_KEY}"}
    }
  }
}
```

Set `SLF_API_KEY` in the environment visible to Cursor, then restart or refresh the MCP connection. Do not replace the placeholder with a committed literal key. See [Cursor MCP docs](https://cursor.com/docs/mcp).

## Codex CLI

Set `SLF_API_KEY` in the local environment. Add this server to `~/.codex/config.toml` (or a trusted project `.codex/config.toml`):

```toml
[mcp_servers.slf-guardian]
command = "uvx"
args = ["--from", "slf-guardian-mcp==1.2.2", "slf-guardian-mcp"]
env_vars = ["SLF_API_KEY"]
```

`env_vars` forwards the named variable from the local environment; it does not store a credential literal in the file. Verify with `codex mcp list` and `/mcp` in the Codex TUI. See [Codex MCP docs](https://developers.openai.com/codex/mcp).

## VS Code editor-managed MCP

Use the editor-managed MCP configuration (`mcp.json`) and a password input. Example:

```json
{
  "inputs": [
    {
      "type": "promptString",
      "id": "slf-api-key",
      "description": "SLF Guardian API key",
      "password": true
    }
  ],
  "servers": {
    "slf-guardian": {
      "type": "stdio",
      "command": "uvx",
      "args": ["--from", "slf-guardian-mcp==1.2.2", "slf-guardian-mcp"],
      "env": {"SLF_API_KEY": "${input:slf-api-key}"}
    }
  }
}
```

VS Code prompts for the key and stores the input securely for the supported editor-managed session. Current VS Code documentation warns that input variables are unsupported in portable configuration files and do not make the server available to Copilot harness sessions. Check your active session type before assuming this setup works there. See [VS Code MCP configuration](https://code.visualstudio.com/docs/agents/reference/mcp-configuration).

## Verify installation

After configuring the MCP, restart or reload the client and check its MCP/server log. It should expose six tool names: `audit_code`, `check_package`, `check_prompt`, `check_command`, `check_domain`, and `scan_site`. An invalid/missing key or network error is a failed setup—not a successful safety check. Never send a real API key in a screenshot or demo recording.
