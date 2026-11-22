# Marketplace copy and submission checklist — DRAFT ONLY

No directory submission was made by creating this draft. Use only after confirming each platform's current rules and the published package version.

## Repository / GitHub catalogue

**Name:** SLF Guardian MCP

**One-line description:** Six pre-action checks for coding agents: packages, commands, code, prompt injection, domains, and owner-authorized passive site checks.

**Install:** Follow the repository README; pin `slf-guardian-mcp==1.2.3` until a newer release is actually published.

**Claims to avoid:** Automatically blocks OS actions; guarantees safety; runs code; active website pentesting; has users/revenue based on directory totals.

**Checklist:** Check list license/category requirements; link the source repo and PyPI package; submit through a public PR if accepted; verify the merged entry points to the correct repository.

## Claude Code plugin / directory

The current product is a local stdio MCP server, not an available hosted remote MCP endpoint. A Claude Code local plugin can be evaluated using official plugin format and the local `stdio` setup; Anthropic Directory/claude.ai distribution may require a remote connector or supported plugin package. Do not state it has been submitted or is available until review and publication are confirmed.

## Cursor plugin / marketplace

The user-facing MCP configuration and environment-variable examples are prepared under `examples/` and `distribution/agent-quickstarts.md`. A marketplace publisher application requires the publisher account to be signed in. No marketplace application or listing has been submitted.

## VS Code / Copilot

Distinguish editor-managed `mcp.json` from portable Copilot `mcp-config.json`. The examples document each applicable secret interpolation. Do not claim `${input:...}` works in portable Copilot configuration; use the documented `${SLF_API_KEY}` reference and set the variable in the host environment.

## Agensi

Use [listing-draft.md](agensi/listing-draft.md), submit as free initially, and attach the prepared ZIP only after testing the trigger prompts/output behavior. Do not promise MCP API credits are included in the skill purchase.
