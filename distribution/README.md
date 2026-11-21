# Agent distribution and proof assets

These assets prepare the product work that can be done without a logged-in marketplace UI. Local client examples pin the publicly released PyPI version `1.2.2`; these examples now use the published 1.2.2 package.

The repository includes Claude Code and Cursor plugin packages under `plugins/`; each uses client-supported secret configuration, bundles the pre-action skill, and runs the 1.2.2 stdio server. Downloadable archives are `plugins/slf-guardian-claude-code-plugin.zip` and `plugins/slf-guardian-cursor-plugin.zip`. The local format/static checks do not replace opening each actual client; client UI tests remain unrun.

The Agensi skill source under `agensi/slf-guardian-pre-action/` passed the official structural validator and is packaged at `agensi/slf-guardian-pre-action.zip`. Its listing copy and creator-style trigger/edge-case evaluation plan are also provided; the tests have not been run inside live Claude/Cursor/Codex agents and the ZIP has not been uploaded.

`agent-quickstarts.md` has browser-free setup examples for Claude Code, Cursor, Codex and VS Code. `user-test-kit.md` is a pilot protocol and feedback form; no participants were contacted and no results were collected. `demo-recording-plan.md` is a recording plan only—no live video or API results were generated. `marketplace-copy-draft.md` contains accurate submission notes; no submissions were made.

`benchmarks/quality-candidates-v1.json` is a pool of synthetic candidate inputs, all deliberately unlabelled. It must not be sent to the production API or scored until two independent reviewers label and adjudicate the cases. The existing smoke corpus is a structural smoke check, not an accuracy result.

`analytics-and-benchmark-next-steps.md` outlines backend telemetry requirements. It is not deployed instrumentation: the API backend source was not available in this workspace.

No external listing submission, outreach, purchase, wallet action or payment was performed. PyPI/Registry publication is handled by the separate 1.2.2 release workflow.
