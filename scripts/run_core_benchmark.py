#!/usr/bin/env python3
"""Run the SLF Guardian smoke corpus. Dry-run by default; never retries calls."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "benchmarks" / "core-v1.json"
ENDPOINTS = {
    "audit_code": "/v1/audit",
    "check_package": "/v1/package",
    "check_prompt": "/v1/prompt",
    "check_command": "/v1/command",
    "check_domain": "/v1/domain",
    "scan_site": "/v1/scan",
}
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--live",
        action="store_true",
        help="Send selected cases to the configured live API (metered).",
    )
    parser.add_argument(
        "--acknowledge-metered-calls",
        action="store_true",
        help="Acknowledge each valid live case can consume a credit or cost money.",
    )
    parser.add_argument(
        "--include-authorized-site-scan",
        action="store_true",
        help="Include the fixed slfguardian.com passive scan only if authorized.",
    )
    parser.add_argument(
        "--base-url",
        default=os.environ.get("SLF_API_BASE", "https://slfguardian.com"),
        help="HTTPS API base URL; defaults to SLF_API_BASE or https://slfguardian.com.",
    )
    args = parser.parse_args()

    try:
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Cannot read benchmark corpus: {exc}", file=sys.stderr)
        return 2

    all_cases = corpus.get("cases")
    if not isinstance(all_cases, list) or not all_cases:
        print("Benchmark corpus has no cases.", file=sys.stderr)
        return 2
    cases = [
        case
        for case in all_cases
        if not case.get("requires_explicit_authorized_site_scan")
        or args.include_authorized_site_scan
    ]
    for case in cases:
        if case.get("tool") not in ENDPOINTS:
            print(f"Unsupported tool in case {case.get('id')!r}.", file=sys.stderr)
            return 2

    if not args.live:
        print(f"DRY RUN: {len(cases)} cases; 0 requests; 0 credits used.")
        if len(cases) != len(all_cases):
            print(
                "The site scan is excluded; use --include-authorized-site-scan "
                "only if authorized."
            )
        for case in cases:
            print(f"{case['id']}: {case['tool']} {ENDPOINTS[case['tool']]}")
        print(
            "To send live, use --live --acknowledge-metered-calls with SLF_API_KEY set."
        )
        return 0

    if not args.acknowledge_metered_calls:
        print(
            "Refusing live run: add --acknowledge-metered-calls explicitly.",
            file=sys.stderr,
        )
        return 2
    key = os.environ.get("SLF_API_KEY", "")
    if not key:
        print(
            "Refusing live run: SLF_API_KEY is not set in this process.",
            file=sys.stderr,
        )
        return 2
    if (
        not args.base_url.startswith("https://")
        or args.base_url.rstrip("/") != "https://slfguardian.com"
    ):
        print(
            "Refusing live run: only the canonical HTTPS production API is allowed.",
            file=sys.stderr,
        )
        return 2

    total = len(cases)
    passed = 0
    failed = 0
    opener = urllib.request.build_opener(NoRedirectHandler())
    print(f"LIVE RUN: at most {total} API calls; no automatic retries or redirects.")
    for index, case in enumerate(cases):
        if index:
            time.sleep(3.1)  # Stay below the documented 20 calls/minute limit.
        url = args.base_url.rstrip("/") + ENDPOINTS[case["tool"]]
        request = urllib.request.Request(
            url,
            data=json.dumps(case["payload"], separators=(",", ":")).encode("utf-8"),
            headers={
                "Authorization": "Bearer " + key,
                "Content-Type": "application/json",
                "User-Agent": "slf-guardian-benchmark/1.0",
            },
            method="POST",
        )
        try:
            with opener.open(request, timeout=30) as response:
                status = response.status
                body = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            status = exc.code
            body = exc.read(MAX_RESPONSE_BYTES + 1)
        except Exception as exc:  # No retry: a timeout can have an uncertain outcome.
            failed += 1
            print(f"{case['id']}: ERROR {type(exc).__name__}; not retried")
            continue

        if len(body) > MAX_RESPONSE_BYTES:
            failed += 1
            print(f"{case['id']}: FAIL HTTP {status}, response exceeded 2 MiB")
            continue
        try:
            result = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            failed += 1
            print(f"{case['id']}: FAIL HTTP {status}, invalid JSON")
            continue

        if not isinstance(result, dict):
            failed += 1
            print(f"{case['id']}: FAIL HTTP {status}, response is not an object")
            continue
        verdict = result.get("verdict")
        expected_verdicts = case.get("expected_verdict_any")
        required_fields = case.get("expected_fields")
        behavior_matches = (
            isinstance(expected_verdicts, list) and verdict in expected_verdicts
            if expected_verdicts is not None
            else isinstance(required_fields, list)
            and all(field in result for field in required_fields)
        )
        if status == 200 and behavior_matches:
            passed += 1
            suffix = (
                f"verdict={verdict}"
                if verdict is not None
                else "required fields present"
            )
            print(f"{case['id']}: PASS HTTP {status}, {suffix}")
        else:
            failed += 1
            print(f"{case['id']}: FAIL HTTP {status}, verdict={verdict!r}")

    print(f"RESULT: {passed}/{total} smoke checks matched; {failed} failed or errored.")
    print("This small smoke corpus is not an accuracy benchmark or safety guarantee.")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
