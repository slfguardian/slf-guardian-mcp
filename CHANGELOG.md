# Changelog

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
