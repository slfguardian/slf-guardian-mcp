# VS Code MCP setup boundary

Use `vscode.mcp.json` with the editor-managed MCP configuration. It prompts for the API key as a password and stores the input securely for supported local editor-managed sessions.

As of the checked VS Code documentation, `${input:...}` variables are not supported in the portable configuration format, and servers requiring such variables are not forwarded to Copilot harness sessions. Do not claim that the local setup automatically works in Copilot cloud/harness sessions. For the current details, see [VS Code MCP configuration](https://code.visualstudio.com/docs/agents/reference/mcp-configuration).
