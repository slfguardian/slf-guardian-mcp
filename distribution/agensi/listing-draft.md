# Agensi listing draft — NOT SUBMITTED

## Suggested title

SLF Guardian Pre-Action Checks for Coding Agents

## Short description

Teach coding agents to check packages, commands, generated code, untrusted text, domains, and authorized passive site checks with the SLF Guardian MCP before acting.

## Full description

This skill guides a coding agent to use an already-configured SLF Guardian MCP at the right point in a development workflow. It covers dependency/package checks, risky command review, static code checks, prompt-injection checks, domain checks, and owner-authorized passive site checks. It explains how to handle `block`, `review`, `warn`, `pass`, API errors, rate limits, metered use, and private inputs.

Requirements: install and configure the SLF Guardian MCP separately and provide an API key locally. The skill does not contain a key, install the MCP by itself, enforce a verdict, execute submitted code, or guarantee safety. Each valid call uses one credit; the API key starts with 1,000 free calls, with published usage priced at $0.01/call after credits. Use passive site checks only with explicit owner authorization.

## Tags to consider

MCP, coding agents, security, dependency safety, prompt injection, developer tools.

## Launch recommendation

Submit as **free** first. The skill is an onboarding/integration layer for a separate metered API; charging for this short instruction pack before measuring activation would add friction and could mislead buyers into expecting API access. Consider a paid version only after the skill itself has independently tested value and the publisher payout path is understood.

## Status and blockers

This is listing copy only. It has not been uploaded or submitted to Agensi. The skill source has passed structural validation and is packaged, but Agensi's requested trigger (5 relevant + 5 irrelevant prompts), output-quality, edge-case, and cross-agent evaluations have not yet been run with actual agents. The API live-call flow has not been tested here because doing so uses account credits; no live API request has been made as part of this packaging.

[Agensi creator guide](https://www.agensi.io/learn/for-creators) · [Sell a skill](https://www.agensi.io/sell) · [Submit](https://www.agensi.io/dashboard/submit)
