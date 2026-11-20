# SLF Guardian developer pilot — preparation only

This is a test script and feedback form, not a completed user study. No participant has been contacted and no results have been collected.

## Pilot goals

Test whether a developer can install the published MCP, make one successful check, understand what the verdict does and does not mean, and decide whether the integration is useful enough to keep. This is an onboarding/usability test, not a security-efficacy benchmark.

## Before the session

- Use only the published package `slf-guardian-mcp==1.2.1` until a newer version is actually released.
- Ask the participant not to share API keys, source code, commands containing secrets, private company information, or customer data.
- Explain that each valid tool call consumes one credit; their key starts with 1,000 free calls and then the listed price is $0.01/call, with a 20-call/minute limit. The participant chooses whether to make any call.
- Use synthetic package/command examples. Never ask them to run a destructive command; a command may only be sent as text to `check_command`.
- Record timings and error category only with the participant's consent. Do not record screen/audio or collect their name/email unless separately needed and consented to.

## 10-minute protocol

1. Ask the participant to install from the pinned README instructions without coaching. Record time to first successful MCP connection and any point where they get stuck.
2. Ask them to identify the six available tools. Record whether they understand that calls are metered and that `pass` is not a safety guarantee.
3. If they choose to proceed, ask them to check one public dependency with `check_package` and one synthetic dangerous command string with `check_command`. The participant must not execute the command.
4. Ask: “What would you do if the result were `review`? What would you do if the API times out?” Look for pausing and explaining rather than proceeding or claiming a pass.
5. Ask whether they would keep the MCP connected; why or why not; and what would remove the biggest installation or usage friction.

## Minimal metrics

Record only: anonymized session ID, client name/version, success/failure stage, time-to-first-success in seconds, whether the metering disclosure was understood, whether the verdict limitations were understood, and the participant's optional qualitative comment. Do not combine this small pilot with API logs to infer a unique person. Delete raw notes after summarizing findings.

## Feedback form

- Agent/client and version:
- Did setup work? yes / no / partial
- Time from starting install to first connected server:
- Which setup step was unclear?
- Did you understand that a valid call uses one credit? yes / no
- Did you understand that `pass` does not guarantee safety? yes / no
- Was the tool output actionable? 1–5
- Would you keep it installed? yes / no / unsure
- Biggest reason to use it or uninstall it:
- Optional comment (no secrets, private code, or target details):

## Reporting

Report the number of consenting participants, denominators, client versions, test period, drop-off stage, and nonresponse. Do not call a small convenience sample representative of the market. Do not claim revenue, accuracy, or increased safety from usability feedback.
