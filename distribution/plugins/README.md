# Local agent plugins — READY FOR CLIENT QA, NOT PUBLISHED

These bundles use the currently published `slf-guardian-mcp==1.2.1`. Each plugin bundle itself is versioned `1.0.0`. No marketplace submission was made. Both packages contain the same 1024px square SLF Guardian shield/check icon; the Claude icon warning is now cleared.

## Claude Code

The plugin requests `SLF_API_KEY` through Claude's `userConfig` with `sensitive: true` and passes it into the local MCP child process. Anthropic's official Claude Code CLI 2.1.311 was installed only in the sandbox's temporary HOME. `claude plugin validate ... --strict` passed with no warnings. The validator checks local plugin files; it does not perform Anthropic's marketplace security scan or policy review.

The actual interactive Claude session has not been launched because it would require a Claude account and model access. To test on a developer machine, run:

```bash
claude --plugin-dir distribution/plugins/claude-code
```

Then use `/mcp` and `/config` to verify the server appears and the key prompt is masked. Do not place a live key in repository files or logs.

## Cursor

The plugin declares an `SLF_API_KEY` variable and references `${SLF_API_KEY}` in its bundled `mcp.json`. Cursor's official docs state plugin variables are configured in **Plugins → Configure** and are not stored in the plugin source. The Cursor CLI/UI is not installed in this sandbox, so this integration is structurally validated but not loaded in a real Cursor session. To test, place the folder under `~/.cursor/plugins/local/slf-guardian`, reload Cursor, configure the key in the UI, then verify the server in Customize.

## Scope and caveats

Both plugins bundle the same pre-action skill and local stdio MCP setup. They still require the customer to obtain an SLF API key. Each valid call consumes one credit; no API key is included. Package 1.2.2/x402 support remains unreleased, so these bundles deliberately use 1.2.1 and do not enable auto-payment. No login, live API call, credit spend, marketplace submission or payment was performed by these tests.
