# SLF Guardian 45-second demo: recording plan

## Recording status

This is a **recording plan**, not a video and not proof of a live run. No API call was made while preparing it. Record the finished demo only after the published client version and an authorized API key are available. Use synthetic inputs, hide the key and client logs, and do not show invented results.

## One-line promise

“Before a coding agent installs an unfamiliar dependency or runs a risky command, SLF Guardian gives it an evidence-based check to consider.” Avoid saying the tool blocks actions automatically or guarantees safety.

## Capture setup

- Use a clean Claude Code, Cursor, or Codex test profile with only the published package version and a locally stored `SLF_API_KEY`.
- Confirm the exact package version shown in the client log; current published version is 1.2.2.
- Use two synthetic requests: a known package check such as `requests` and a destructive command string such as `rm -rf /`. Do not execute the command; submit it only to the checker.
- Before capture, verify the account’s credit state and rate limit. Each valid call consumes one credit; after the 1,000 free credits, the published API price is $0.01 per call.
- Turn off terminal prompt echo and notifications. Never reveal the API key, account email, private source code, or user data.

## Shot list (about 45 seconds)

1. **0–4 sec:** Show a coding-agent task: “Check this dependency before adding it.” Keep the cursor and text readable.
2. **4–13 sec:** The agent calls `check_package` for `requests`; show the actual output. Narration: “One check before install; it uses one API credit.” Do not claim every package call has the same result.
3. **13–24 sec:** Ask the agent to inspect, but not run, `rm -rf /`. Show `check_command` output and the agent pausing to explain the finding. Make clear the command was never executed.
4. **24–34 sec:** Show the six available tool names briefly and state the verdict is a signal, not an enforcement guarantee.
5. **34–45 sec:** End with a readable install command pinned to the current public release and link to the quickstart/API pricing page.

## Post-capture verification

Check that outputs are authentic and not edited to change the verdict, the key is not visible in frames/audio/logs, the command never ran, and the footage does not imply a marketplace listing or revenue that is not verified. Keep a note of recording date, client version, MCP package version, two tool calls, and whether each came from free credits or was billed. If any condition fails, do not publish the recording.
