# SLF Guardian MCP

Six security checks an AI agent can call **before** it acts — before it delivers
code, installs a dependency, runs a shell or SQL command, opens a link or reads
an untrusted page.

One file, no dependencies, stdio transport. Works with Claude Desktop, Cursor,
Cline, Windsurf, Continue and anything else that speaks MCP.

| Tool | The question it answers |
|---|---|
| `audit_code` | Is this code safe to deliver or run? |
| `check_package` | Does this dependency exist, and is it safe to install? |
| `check_prompt` | Does this text or page carry instructions aimed at me? |
| `check_command` | Can this shell or SQL command be undone? |
| `check_domain` | Is this domain safe to trust? |
| `scan_site` | Passive outside-in security check of a website |

Every answer is a single verdict (`pass`, `review`, `block`) plus the evidence
behind it, so an agent can branch on it without reading prose.

## Install

```bash
pip install slf-guardian-mcp
# or straight from this repository
pip install git+https://github.com/slfguardian/slf-guardian-mcp
```

## Get a key

```bash
curl -X POST https://slfguardian.com/v1/keys \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com"}'
```

25 calls are free. The raw key is shown once.

## Configure your client

```json
{
  "mcpServers": {
    "slf-guardian": {
      "command": "slf-guardian-mcp",
      "env": { "SLF_API_KEY": "slf_live_..." }
    }
  }
}
```

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

## Honest limits

These are detectors, not proofs. A `pass` means no known pattern matched, not
that the input is safe; a finding is evidence to look at, not a conviction.
Nothing submitted is executed, and the analysis is static.

## Environment

| Variable | Default | Purpose |
|---|---|---|
| `SLF_API_KEY` | — | Required. Your key. |
| `SLF_API_BASE` | `https://slfguardian.com` | Override the endpoint. |
| `SLF_TIMEOUT` | `120` | Seconds per call. |

HTTP API and OpenAPI description: <https://slfguardian.com/api>

MIT licensed.
