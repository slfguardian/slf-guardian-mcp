# Benchmark and activation measurement

## Purpose and limits

`benchmarks/core-v1.json` is a small, versioned smoke corpus spanning all six API tools. It checks obvious cases and validates that the API returns a structurally useful result. It is not an independently adjudicated accuracy benchmark, does not estimate false-positive or false-negative rates, and must not be presented as proof that SLF Guardian is safer than another product.

The corpus contains ten default cases. It has one separate passive website check for `slfguardian.com`, excluded unless the operator explicitly supplies `--include-authorized-site-scan`. Run a live test only against assets you own or have permission to assess. The tool sends candidate code, text, commands, package names or domains as test inputs; no malicious code or command is executed. Use synthetic inputs only.

The runner is dry-run by default and makes zero HTTP requests in that mode. To send test cases to the production API, an operator must set `SLF_API_KEY` locally and supply both `--live` and `--acknowledge-metered-calls`. The default live suite makes ten API requests; the optional owner-authorized site case adds one. Each valid request can consume a free credit or be billed at the documented price after free credits. The runner spaces calls below the documented rate limit, refuses redirects, and never retries a call with an uncertain outcome. Do not run the live suite as part of ordinary CI.

Example offline check:

```bash
python3 scripts/run_core_benchmark.py
```

For a live check, first set `SLF_API_KEY` through a local secret manager or a protected environment, review the billing terms, then explicitly run:

```bash
python3 scripts/run_core_benchmark.py --live --acknowledge-metered-calls
```

For the optional website case, append `--include-authorized-site-scan` only when the operator is authorized for `slfguardian.com`.

## What a real accuracy benchmark still needs

Before making accuracy or comparative claims, expand this bootstrap suite into a versioned, human-labeled corpus for each tool. Include benign, borderline, risky, and adversarial cases. Have a second reviewer independently label cases and resolve disagreements before freezing the expected outcome. Record dataset provenance, exclusions, tool/package/API version, run date, per-tool precision, recall, false-positive rate, false-negative rate, latency, and error/timeout rate. Publish the raw input corpus only when it contains no secrets, private code, personal data or unsafe live targets. Keep evaluation inputs synthetic and safe to replay.

Do not tune expected answers after observing a test run without a new corpus version and a changelog. Do not count a smoke-test pass as a true positive; flexible accepted verdict sets are only a coarse compatibility check.

## Activation and revenue funnel

Measure the following separately over explicit time windows:

1. `listing_visit` and referral source, when the marketplace provides it.
2. `install_or_config_intent`, only when the client/marketplace can report it reliably.
3. `first_successful_tool_call` and subsequent successful call counts.
4. `returning_install_or_key_7d` and `returning_install_or_key_30d`.
5. `free_credit_exhausted_or_paid_mode_started`.
6. `settled_paid_call`, unique paying wallet/account, refunds, processing fees, and net payout.

The current public `GET /v1/stats` is a 30-day aggregate of finding categories and verdicts. It does not expose total calls, unique users, active agents, paid calls, unique payers or revenue. PyPI downloads and public directory counters cannot fill in those gaps.

For any server-side activation or billing analytics, collect the minimum metadata needed: time bucket, tool/endpoint, success/error class, meter state, and—only if justified—an internal rotating pseudonymous key or payer identifier. Do not log raw API keys, submitted code, prompts, commands, scanned URLs, credentials, or payment secrets. Publish a retention period and deletion process. Never infer a unique human from an API key or unique wallet.

Reconcile paid-call counts against facilitator settlement records and payouts, not HTTP 402 challenges or an advertised price. Report gross amount, processing/network fees, refunds and net received separately. A successful 402 negotiation, quote validation or marketplace listing is not revenue.
