# Product measurement implementation contract

This file is a **design handoff**, not production telemetry and not a report of usage. The API backend source is not present in this repository; no production events were added or collected.

## Activation events to add when backend source is available

Record aggregate, timestamp-bucketed events only where they can be derived reliably:

- `key_created`: count by day; do not log raw email or raw API key.
- `tool_request`: tool name and coarse outcome class (`success`, `input_error`, `auth_error`, `rate_limited`, `timeout`, `upstream_error`); do not store request payloads.
- `first_success_per_key` and `returning_success_7d/30d`: derive server-side using a keyed rotating HMAC of the API key, not the key itself. Store the HMAC key separately, rotate under a documented retention policy, and avoid representing an API key as a unique human.
- `paid_call_settled`: reconcile against facilitator/chain settlement identifiers and record gross amount, fee, refund and net received. Never count 402 quotes or signatures as settled revenue.

Minimize collection, define retention/deletion, restrict access, document in the privacy notice, and add a disable/opt-out option if required by the deployment and legal review. Never log code, prompts, commands, URLs, API keys, CDP credentials, wallet secrets, or payment signatures.

## Integration gates

1. Obtain the API backend repository and deployment/test environment from the owner.
2. Trace API key creation, request accounting, free-credit decrement, x402 facilitator callback and payout reconciliation.
3. Write tests against synthetic requests and a fake settlement provider; tests must make no real payment.
4. Review data minimization, privacy notice, retention and access controls before deployment.
5. Deploy via the service owner’s approved CI; verify aggregate counters against existing billing records before claiming metrics.

## Blind benchmark labels

The existing `benchmarks/core-v1.json` is a smoke corpus, not an accuracy evaluation. Build a larger synthetic candidate set first, but keep expected labels blank until two reviewers independently label each case. For each input, record `reviewer_a`, `reviewer_b`, `adjudicated_label`, rationale, tool/API version, and case provenance. Resolve disagreements before running the candidate against the API. Publish per-tool precision, recall, false-positive rate, false-negative rate, latency and timeout rate only after the corpus and evaluation are frozen.

Do not create a fake benchmark score or use flexible expected-verdict lists as accuracy labels. Passive website-scan cases must remain excluded unless the operator controls or has explicit authorization for that exact target.
