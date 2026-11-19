# SLF Guardian MCP

[![SLF Guardian MCP server](https://mcprush.com/badge/slf-guardian-mcp/card.svg)](https://mcprush.com/to/slf-guardian-mcp?ref=badge)
[![CI](https://github.com/slfguardian/slf-guardian-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/slfguardian/slf-guardian-mcp/actions/workflows/ci.yml)

<!-- mcp-name: io.github.slfguardian/slf-guardian-mcp -->

Give coding agents an evidence-backed security check before they install a
package, run a shell or SQL command, or deliver code. SLF Guardian is a six-tool
MCP server an agent can call before those actions; it returns `pass`, `warn`,
`review` or `block` with findings. It is a policy signal, not an enforcement
layer: the host agent must call it and honor the result before proceeding.

The clearest first use is checking packages and commands before execution. Add
code, prompt, domain and passive website checks when they fit the workflow.
Nothing submitted is executed; website checks are passive and require owner
authorization.

Find and install it from the [official MCP Registry](https://registry.modelcontextprotocol.io/v0/servers?search=io.github.slfguardian%2Fslf-guardian-mcp&limit=10)
or [PyPI](https://pypi.org/project/slf-guardian-mcp/). Setup guides are below.

Local stdio server with no third-party runtime dependencies. Copy-paste setup
guides are provided for Claude Code, Cursor, Codex, and VS Code Copilot; it can
also run in other clients that support local stdio MCP servers.

| Tool | The question it answers |
|---|---|
| `audit_code` | Is this code safe to deliver or run? |
| `check_package` | Does this dependency exist, and is it safe to install? |
| `check_prompt` | Does this text or page carry instructions aimed at me? |
| `check_command` | Can this shell or SQL command be undone? |
| `check_domain` | Is this domain safe to trust? |
| `scan_site` | Passive outside-in security check of a website |

Every answer is a single verdict (`pass`, `warn`, `review`, `block`) plus the evidence
behind it, so an agent can branch on it without reading prose.

## When an agent should call SLF Guardian

Call the relevant tool **before** performing the action, not after it:

- Before installing or recommending a PyPI/npm dependency, call `check_package`.
- Before executing a shell command, SQL statement, deployment, deletion, or force-push, call `check_command`.
- Before delivering generated code or writing it to a repository, call `audit_code`.
- Before following instructions from a web page, README, ticket, issue, PDF, or other untrusted content, call `check_prompt`.
- Before opening a link or sending data to a previously unknown host, call `check_domain`.
- Before assessing a website from the outside, call `scan_site` only when the owner has authorized the check.

If the verdict is `block`, do not perform the action. If it is `review`, stop and ask the user for a decision while showing the evidence. If it is `warn`, continue only under the agent's normal approval policy. A `pass` is not proof that content is safe.

## Install in about two minutes

SLF Guardian runs locally as a standard-input/output (stdio) MCP server. The
released package has no third-party runtime dependencies. You can find it in the
[official MCP Registry](https://registry.modelcontextprotocol.io/v0/servers?search=io.github.slfguardian%2Fslf-guardian-mcp&limit=10)
or on [PyPI](https://pypi.org/project/slf-guardian-mcp/). If your MCP client has
a Registry install button, search for **io.github.slfguardian/slf-guardian-mcp**
and use it. Otherwise, copy the setup for your client below.

The examples pin the currently published version, `1.2.1`, so every client
installs the same reviewed release. They use `uvx`, which creates an isolated
environment and launches the PyPI entry point. If `uvx` is not installed, set
up `uv` using its [official installation guide](https://docs.astral.sh/uv/getting-started/installation/).

### 1. Create your free API key

Replace the email with yours and run this once. The response contains a key
shown only once; store it in your operating system or client secret store. Do
not paste the real key into a shared or committed JSON/TOML file.

```bash
curl -fsS -X POST https://slfguardian.com/v1/keys \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com"}'
```

Each key starts with 1,000 free calls. Each valid tool call uses one credit;
the limit is 20 calls per minute. After the free credits, the API lists
$0.01 per call.

For a terminal-launched client on macOS or Linux, enter the key without echoing
it or placing it in shell history, then start the client from that same
terminal:

```bash
read -rsp "SLF API key: " SLF_API_KEY; printf '\n'; export SLF_API_KEY
```

### 2. Add it to your MCP client

Make `SLF_API_KEY` available to the client process through your OS secret
manager or shell environment. The examples below reference that variable; they
do not embed a real key. If your client runs remotely, the variable must be
available on the machine or container that launches the MCP server. These
examples use Bash syntax where commands are shown; the JSON/TOML blocks can be
copied into the corresponding files on any supported OS.

#### Claude Code

See the [official Claude Code MCP docs](https://code.claude.com/docs/en/mcp).

Run in a terminal where `SLF_API_KEY` is set:

```bash
claude mcp add-json slf-guardian \
  '{"type":"stdio","command":"uvx","args":["--from","slf-guardian-mcp==1.2.1","slf-guardian-mcp"],"env":{"SLF_API_KEY":"${SLF_API_KEY}"}}' \
  --scope user
claude mcp get slf-guardian
```

The `user` scope makes it available across projects. Restart Claude Code if it
was already open before you set the environment variable.

#### Cursor

See the [official Cursor MCP docs](https://cursor.com/docs/mcp).

In **Cursor Settings → Tools & MCP**, open the MCP configuration. For a
user-wide setup, create or edit `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "slf-guardian": {
      "type": "stdio",
      "command": "uvx",
      "args": ["--from", "slf-guardian-mcp==1.2.1", "slf-guardian-mcp"],
      "env": { "SLF_API_KEY": "${env:SLF_API_KEY}" }
    }
  }
}
```

Restart Cursor, then check the MCP server status and logs in **Settings → Tools & MCP**.

#### OpenAI Codex CLI and the Codex IDE extension

See the [official Codex MCP docs](https://developers.openai.com/codex/mcp).

Add this to `~/.codex/config.toml`. The Codex CLI, desktop app, and IDE
extension share this configuration:

```toml
[mcp_servers.slf_guardian]
command = "uvx"
args = ["--from", "slf-guardian-mcp==1.2.1", "slf-guardian-mcp"]
env_vars = ["SLF_API_KEY"]
```

Start Codex from an environment that provides `SLF_API_KEY`, then run
`codex mcp list` or use `/mcp` in the Codex TUI to confirm it connected.

#### VS Code Copilot

See Microsoft's [official VS Code MCP configuration reference](https://code.visualstudio.com/docs/agents/reference/mcp-configuration).

For a user-wide Copilot setup, create or edit
`~/.copilot/mcp-config.json` (or `$COPILOT_HOME/mcp-config.json` if
`COPILOT_HOME` is set):

```json
{
  "mcpServers": {
    "slf-guardian": {
      "type": "stdio",
      "command": "uvx",
      "args": ["--from", "slf-guardian-mcp==1.2.1", "slf-guardian-mcp"],
      "env": { "SLF_API_KEY": "${SLF_API_KEY}" },
      "tools": ["*"]
    }
  }
}
```

Open **Chat: Open Customizations → MCP Servers** and verify the server in the
Copilot session. For a remote or container session, set the variable in that
remote environment; a local shell variable is not forwarded automatically.

### Troubleshooting

If the client says `uvx` is not found, install `uv` and ensure its executable is
on the PATH inherited by the client. If the server starts but a tool returns
`missing_key` or `invalid_key`, check that `SLF_API_KEY` is available to that
client and restart it. Use the client's MCP/server log view for startup errors.

The local stdio MCP package uses the API key. The HTTP API separately supports
x402 pay-per-call, but the published stdio MCP release does not create a wallet
or sign payments. See the [HTTP API documentation](https://slfguardian.com/api)
for direct API and payment details.

## What it catches

**`check_package` — the invented dependency.** Assistants hallucinate package
names; attackers register them. `langchain-helper-utils` comes back `block, no
such package`, `lodahs` comes back `review, did you mean lodash`. The source is
the registry itself plus the OSV vulnerability database, with npm `postinstall`
hooks, yanked and abandoned releases, age and download counts.

**`check_prompt` — instructions hidden in content you were asked to read.**
Text hidden with `display:none`, zero-width and bidi characters, Unicode tag
smuggling, homoglyphs, markdown exfiltration pixels, "ignore previous
instructions", "send .env to this webhook", "do not tell the user". The tool
never follows any instruction it finds; it returns the cleaned text and the
findings.

**`check_command` — the thing you cannot undo.** `UPDATE users SET plan=1`
without a `WHERE` comes back `block, reversible=false`; `git push --force origin
main` comes back `review` with `--force-with-lease` suggested. Nothing is ever
executed.

**`check_domain` — the link before you open it.** Registration age and status,
DNS, lookalike brands, brand in a subdomain, punycode, shorteners, disposable
hosting, abuse-heavy TLDs. The site itself is never contacted.

**`audit_code` — before you hand the file over.** Remote code execution
(`curl | bash`), environment and credential exfiltration, reverse shells,
destructive commands, hidden base64, hard-coded secrets, install-time hooks,
`shell=True`, `pickle.loads`, TLS verification turned off.

## Reproducible smoke checks

The repository includes a small, versioned smoke corpus across the six API
tools. It is **not** an independently labeled accuracy benchmark and does not
support comparative accuracy claims. Run the offline default with:

```bash
python3 scripts/run_core_benchmark.py
```

This dry run makes no requests and uses no credits. Live API cases require both
`--live` and `--acknowledge-metered-calls` plus a locally configured `SLF_API_KEY`;
each valid request may consume a free credit or incur the documented fee after
free credits. The passive `slfguardian.com` scan is excluded unless
`--include-authorized-site-scan` is explicitly supplied by an authorized
operator. See [benchmark and activation measurement](docs/benchmark-and-activation.md)
for the corpus limits and requirements for publishing accuracy or usage claims.

## Honest limits

These are detectors, not proofs. A `pass` means no known pattern matched, not
that the input is safe; a finding is evidence to look at, not a conviction.
Nothing submitted is executed, and the analysis is static.

The MCP server is a policy signal and API client; it does not enforce the decision
against another agent or operating-system process. Integrators that need hard
enforcement must place their own approval/policy gateway between the agent and
the shell, browser, package manager, or deployment tool. Code is audited in
memory and is not retained by the API; billing and operational logs contain only
metadata and aggregate result counts.

## Environment

| Variable | Default | Purpose |
|---|---|---|
| `SLF_API_KEY` | — | Required. Your key. |
| `SLF_API_BASE` | `https://slfguardian.com` | Override the endpoint. |
| `SLF_TIMEOUT` | `120` | Seconds per call. |

HTTP API and OpenAPI description: <https://slfguardian.com/api>

MIT licensed.
