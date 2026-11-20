import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "benchmarks/quality-candidates-v1.json"
EXPECTED_NON_SITE_TOOLS = {
    "audit_code",
    "check_package",
    "check_prompt",
    "check_command",
    "check_domain",
}


def test_quality_candidate_pool_is_explicitly_unlabelled_and_unscored():
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    assert corpus["status"] == "unlabelled_not_an_accuracy_benchmark"
    assert corpus["rules"]["required_independent_reviewers"] == 2
    assert (
        corpus["rules"]["do_not_send_to_live_api_until_independently_labelled"] is True
    )
    assert len(corpus["cases"]) >= 20
    assert len({case["id"] for case in corpus["cases"]}) == len(corpus["cases"])
    assert all(case["expected_label"] is None for case in corpus["cases"])
    assert all(case["label_status"] != "labelled" for case in corpus["cases"])


def test_site_scan_candidate_cannot_be_run_without_exact_authorized_target():
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    site_cases = [case for case in corpus["cases"] if case["tool"] == "scan_site"]
    assert len(site_cases) == 1
    site = site_cases[0]
    assert site["payload"] is None
    assert site["execution_permitted"] is False
    assert site["label_status"] == "deferred_until_owner_authorized_target_provided"


def test_candidate_pool_spans_all_non_site_tool_families():
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    assert EXPECTED_NON_SITE_TOOLS <= {case["tool"] for case in corpus["cases"]}
