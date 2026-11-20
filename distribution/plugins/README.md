# Local agent plugins — READY FOR CLIENT QA, NOT PUBLISHED

These bundles use the currently published `slf-guardian-mcp==1.2.1`. The plugin package itself is versioned `1.0.0`. No plugin marketplace submission was made.

## Claude Code

The plugin requests `SLF_API_KEY` through Claude's `userConfig` with `sensitive: true` and passes it into the local MCP child process. Official docs say sensitive userConfig is stored in secure credential storage.

From the repository root, test locally with:

```bash
claude plugin validate distribution/plugins/claude-code
claude --plugin-dir distribution/plugins/claude-code
```

Then open `/mcp` and `/config`; confirm the server starts and asks for the API key securely. Do not set the key in a repository file or include a live key in test logs. This needs a local Claude Code client session and has not been run in this sandbox.

## Cursor

The plugin declares an `SLF_API_KEY` variable and references `${SLF_API_KEY}` in the bundled `mcp.json`. Cursor's official docs state plugin variables are configured in **Plugins → Configure** and are not stored in the plugin source. Test by placing this directory under `~/.cursor/plugins/local/slf-guardian`, reloading Cursor, configuring the key through its UI, then verifying the plugin server in Customize. The client-specific UI test has not been run in this sandbox.

## Scope and caveats

Both plugins bundle the same pre-action skill and local stdio MCP setup. They still require the customer to obtain an SLF API key. Each valid call consumes one credit; no API key is included. Package 1.2.2/x402 support remains unreleased, so these bundles deliberately use 1.2.1 and do not enable auto-payment. Plugin source is available for review before installation.
