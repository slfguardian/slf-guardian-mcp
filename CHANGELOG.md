# Changelog

## 1.2.2

- Negotiate the supported MCP protocol version during initialization.
- Return JSON-RPC errors for malformed requests, invalid parameters, and unknown tools.
- Align the code-audit file schema with the API's required `path` and `content` fields.
- Reject ambiguous single-item/batch inputs before making billable API calls.
- Handle unexpected or invalid API response shapes without crashing the stdio server.
- Improve registry and PyPI discovery metadata and document the distinct API-key and HTTP x402 paths.
- Refuse API redirects so an authenticated bearer key is not forwarded to a redirect target.
- Treat all non-2xx responses as errors and validate endpoint-specific success fields before returning a safety verdict.
- Validate tool arguments at runtime, enforce published batch/audit limits, and bound response reads by size and timeout configuration.
- Add tests for authentication redirects, fail-closed API bodies, runtime validation, bounded reads, numeric JSON-RPC IDs, notifications, and MCP SDK tool calls.

## 1.2.1

- Align package, MCP runtime, and registry manifest versions.
- Clarify when agents should call each security tool and how to interpret verdicts.
- Publish through GitHub Actions Trusted Publishing with PyPI attestations.
- Add automated tests, package metadata checks, and agent-discovery documentation.

## 1.2.0

- Six MCP tools for code, package, prompt, command, domain, and passive site checks.
- Four normalized verdicts: `pass`, `warn`, `review`, and `block`.
- Honest static/passive analysis limits documented.
- No-dependency stdio client with API-key based authentication.
