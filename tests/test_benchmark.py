import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "benchmarks" / "core-v1.json"
RUNNER = ROOT / "scripts" / "run_core_benchmark.py"
EXPECTED_TOOLS = {
    "audit_code",
    "check_package",
    "check_prompt",
    "check_command",
    "check_domain",
    "scan_site",
}


def run_runner(*args, env=None):
    clean_env = dict(os.environ)
    clean_env.pop("SLF_API_KEY", None)
    if env:
        clean_env.update(env)
    return subprocess.run(
        [sys.executable, str(RUNNER), *args],
        cwd=ROOT,
        env=clean_env,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


def test_benchmark_corpus_covers_all_tools_and_site_scan_requires_opt_in():
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    cases = corpus["cases"]
    assert len(cases) == 11
    assert {case["tool"] for case in cases} == EXPECTED_TOOLS
    assert (
        sum(bool(case.get("requires_explicit_authorized_site_scan")) for case in cases)
        == 1
    )
    assert len({case["id"] for case in cases}) == len(cases)
    for case in cases:
        assert isinstance(case["payload"], dict)
        assert isinstance(case["rationale"], str) and case["rationale"]
        assert "expected_verdict_any" in case or "expected_fields" in case


def test_default_dry_run_is_offline_and_excludes_site_scan():
    result = run_runner()
    assert result.returncode == 0
    assert "DRY RUN: 10 cases; 0 requests; 0 credits used." in result.stdout
    assert "site-owned-domain-passive-smoke" not in result.stdout


def test_site_scan_requires_an_explicit_opt_in_even_in_dry_run():
    result = run_runner("--include-authorized-site-scan")
    assert result.returncode == 0
    assert "DRY RUN: 11 cases; 0 requests; 0 credits used." in result.stdout
    assert "site-owned-domain-passive-smoke" in result.stdout


def test_live_run_refuses_without_explicit_metered_call_acknowledgement():
    result = run_runner("--live")
    assert result.returncode == 2
    assert "add --acknowledge-metered-calls explicitly" in result.stderr
    assert "LIVE RUN" not in result.stdout


def test_live_run_refuses_noncanonical_api_base_before_network():
    result = run_runner(
        "--live",
        "--acknowledge-metered-calls",
        "--base-url",
        "https://example.invalid",
        env={"SLF_API_KEY": "non-secret-test-sentinel"},
    )
    assert result.returncode == 2
    assert "only the canonical HTTPS production API is allowed" in result.stderr
    assert "non-secret-test-sentinel" not in result.stdout + result.stderr
