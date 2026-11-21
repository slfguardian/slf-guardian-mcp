# Claude Code setup

This example uses the published `slf-guardian-mcp==1.2.2` package. Set `SLF_API_KEY` in the local environment or secret manager used to launch Claude Code, then add the stdio server:

```bash
claude mcp add --transport stdio --scope user slf-guardian -- \
  uvx --from slf-guardian-mcp==1.2.2 slf-guardian-mcp
claude mcp get slf-guardian
```

Launch Claude Code from a process that can access `SLF_API_KEY`; the server child inherits it. Do not pass the literal key via `--env` on a command line, where it may remain in shell history or client configuration. See the [official Claude Code MCP documentation](https://code.claude.com/docs/en/mcp).
