import datetime
import json
import os
from concurrent.futures import ThreadPoolExecutor

import pytest

from slf_guardian_mcp import x402_bridge as bridge


def valid_context(endpoint="/v1/audit", **overrides):
    selected = {
        "scheme": "exact",
        "network": bridge.BASE_NETWORK,
        "asset": bridge.BASE_USDC,
        "amount": bridge.PRICE_ATOMIC,
        "payTo": bridge.SLF_PAY_TO,
        "maxTimeoutSeconds": 60,
        "extra": {"name": "USD Coin", "version": "2"},
    }
    selected.update(overrides)
    return {
        "payment_required": {
            "resource": {"url": "https://slfguardian.com" + endpoint},
            "extensions": {"bazaar": {"schema": {}, "info": {}}},
        },
        "selected_requirements": selected,
    }


def enable_auto_pay(monkeypatch, budget="0.10"):
    monkeypatch.setenv("SLF_X402_AUTO_PAY", "true")
    monkeypatch.setenv("SLF_X402_MAX_DAILY_USDC", budget)


def test_auto_pay_is_disabled_unless_literal_true(monkeypatch):
    monkeypatch.delenv("SLF_X402_AUTO_PAY", raising=False)
    with pytest.raises(bridge.PaymentPolicyError):
        bridge.validate_payment_context(
            valid_context(), "https://slfguardian.com", "/v1/audit"
        )
    monkeypatch.setenv("SLF_X402_AUTO_PAY", "1")
    assert not bridge.auto_pay_enabled()


def test_valid_quote_requires_canonical_resource_and_fixed_terms(monkeypatch):
    enable_auto_pay(monkeypatch)
    bridge.validate_payment_context(
        valid_context(), "https://slfguardian.com", "/v1/audit"
    )
    for endpoint in sorted(bridge.ALLOWED_ENDPOINTS):
        bridge.validate_payment_context(
            valid_context(endpoint), "https://slfguardian.com", endpoint
        )


@pytest.mark.parametrize(
    "base",
    [
        "http://slfguardian.com",
        "https://slfguardian.com.evil.example",
        "https://user@slfguardian.com",
        "https://slfguardian.com:444",
        "https://slfguardian.com/path",
    ],
)
def test_rejects_noncanonical_api_base(monkeypatch, base):
    enable_auto_pay(monkeypatch)
    with pytest.raises(bridge.PaymentPolicyError):
        bridge.validate_payment_context(valid_context(), base, "/v1/audit")


@pytest.mark.parametrize(
    "context,endpoint",
    [
        (valid_context("/v1/scan"), "/v1/audit"),
        (
            valid_context()
            | {
                "payment_required": {
                    "resource": {"url": "https://evil.example/v1/audit"}
                }
            },
            "/v1/audit",
        ),
        (
            valid_context()
            | {
                "payment_required": {
                    "resource": {"url": "https://slfguardian.com/v1/audit?x=1"}
                }
            },
            "/v1/audit",
        ),
        (valid_context(scheme="upto"), "/v1/audit"),
        (valid_context(network="eip155:84532"), "/v1/audit"),
        (
            valid_context(asset="0x0000000000000000000000000000000000000001"),
            "/v1/audit",
        ),
        (valid_context(amount="10001"), "/v1/audit"),
        (valid_context(amount=10000), "/v1/audit"),
        (
            valid_context(payTo="0x0000000000000000000000000000000000000001"),
            "/v1/audit",
        ),
        (valid_context(maxTimeoutSeconds=61), "/v1/audit"),
        (valid_context(maxTimeoutSeconds=True), "/v1/audit"),
        (valid_context(extra={"name": "USDC", "version": "2"}), "/v1/audit"),
        (
            valid_context()
            | {
                "payment_required": {
                    "resource": {"url": "https://slfguardian.com/v1/audit"},
                    "extensions": {"permit2": {"arbitrary": "payload"}},
                }
            },
            "/v1/audit",
        ),
        ({"payment_required": {}, "selected_requirements": {}}, "/v1/audit"),
    ],
)
def test_rejects_wrong_offer_before_any_budget_reservation(
    monkeypatch, tmp_path, context, endpoint
):
    enable_auto_pay(monkeypatch)
    ledger = tmp_path / "x402-spend.json"
    with pytest.raises(bridge.PaymentPolicyError):
        bridge.validate_payment_context(context, "https://slfguardian.com", endpoint)
    assert not ledger.exists()


def test_budget_reserves_exact_calls_and_enforces_cap(monkeypatch, tmp_path):
    enable_auto_pay(monkeypatch, "0.02")
    ledger = tmp_path / "x402-spend.json"
    now = datetime.datetime(2026, 11, 20, 12, tzinfo=datetime.timezone.utc)
    assert bridge.reserve_daily_budget(ledger, now) == (True, "")
    assert bridge.reserve_daily_budget(ledger, now) == (True, "")
    ok, message = bridge.reserve_daily_budget(ledger, now)
    assert not ok and "exhausted" in message
    assert json.loads(ledger.read_text()) == {
        "utc_day": "2026-11-20",
        "reserved_atomic": 20000,
    }
    assert os.stat(ledger).st_mode & 0o777 == 0o600


def test_budget_reservation_is_thread_safe(monkeypatch, tmp_path):
    enable_auto_pay(monkeypatch, "0.05")
    ledger = tmp_path / "x402-spend.json"
    now = datetime.datetime(2026, 11, 20, tzinfo=datetime.timezone.utc)
    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(
            pool.map(lambda _i: bridge.reserve_daily_budget(ledger, now), range(30))
        )
    assert sum(success for success, _reason in results) == 5
    assert json.loads(ledger.read_text())["reserved_atomic"] == 50000


def test_budget_resets_only_after_utc_day_changes(monkeypatch, tmp_path):
    enable_auto_pay(monkeypatch, "0.01")
    ledger = tmp_path / "x402-spend.json"
    day_one = datetime.datetime(2026, 11, 20, 23, 59, tzinfo=datetime.timezone.utc)
    day_two = datetime.datetime(2026, 11, 21, 0, 1, tzinfo=datetime.timezone.utc)
    assert bridge.reserve_daily_budget(ledger, day_one)[0]
    assert not bridge.reserve_daily_budget(ledger, day_one)[0]
    assert bridge.reserve_daily_budget(ledger, day_two)[0]
    assert json.loads(ledger.read_text()) == {
        "utc_day": "2026-11-21",
        "reserved_atomic": 10000,
    }


@pytest.mark.parametrize(
    "raw",
    [
        "not-json",
        '{"utc_day":"2026-11-20","reserved_atomic":-1}',
        '{"utc_day":"2026-11-20","reserved_atomic":true}',
        '{"utc_day":"2026-11-21","reserved_atomic":0}',
    ],
)
def test_corrupt_or_future_budget_fails_closed(monkeypatch, tmp_path, raw):
    enable_auto_pay(monkeypatch, "1.00")
    ledger = tmp_path / "x402-spend.json"
    ledger.write_text(raw)
    ok, message = bridge.reserve_daily_budget(
        ledger, datetime.datetime(2026, 11, 20, tzinfo=datetime.timezone.utc)
    )
    assert not ok
    assert message


def test_symlink_budget_and_lock_files_fail_closed(monkeypatch, tmp_path):
    enable_auto_pay(monkeypatch)
    ledger = tmp_path / "x402-spend.json"
    external = tmp_path / "external.json"
    external.write_text('{"utc_day":"2026-11-20","reserved_atomic":0}')
    ledger.symlink_to(external)
    assert not bridge.reserve_daily_budget(ledger)[0]
    ledger.unlink()
    lock = tmp_path / "x402-spend.json.lock"
    lock.symlink_to(external)
    assert not bridge.reserve_daily_budget(ledger)[0]


def test_shared_permission_state_directory_fails_closed(monkeypatch, tmp_path):
    enable_auto_pay(monkeypatch)
    state_dir = tmp_path / "shared-state"
    state_dir.mkdir(mode=0o755)
    state_dir.chmod(0o755)
    ok, message = bridge.reserve_daily_budget(state_dir / "x402-spend.json")
    assert not ok
    assert "private" in message
    assert not (state_dir / "x402-spend.json").exists()


def test_real_sdk_policy_abort_happens_before_fake_signer(monkeypatch, tmp_path):
    x402 = pytest.importorskip("x402")
    from x402.mechanisms.evm.exact import ExactEvmScheme
    from x402.schemas import (
        PaymentAbortedError,
        PaymentRequired,
        PaymentRequirements,
        ResourceInfo,
    )

    enable_auto_pay(monkeypatch)
    calls = []

    class FakeScheme:
        address = "0x0000000000000000000000000000000000000002"

        def sign_typed_data(self, *_args, **_kwargs):
            calls.append("sign")
            return "fake-signature"

    requirement = PaymentRequirements(
        scheme="exact",
        network=bridge.BASE_NETWORK,
        asset=bridge.BASE_USDC,
        amount=bridge.PRICE_ATOMIC,
        payTo="0x0000000000000000000000000000000000000001",
        maxTimeoutSeconds=60,
        extra={"name": "USD Coin", "version": "2"},
    )
    required = PaymentRequired(
        resource=ResourceInfo(url="https://slfguardian.com/v1/audit"),
        accepts=[requirement],
    )
    client = x402.x402ClientSync()
    client.register(bridge.BASE_NETWORK, ExactEvmScheme(FakeScheme()))
    client.on_before_payment_creation(
        bridge.payment_policy_hook(
            "https://slfguardian.com", "/v1/audit", tmp_path / "spend.json"
        )
    )
    with pytest.raises(PaymentAbortedError):
        client.create_payment_payload(required)
    assert calls == []
    assert not (tmp_path / "spend.json").exists()


def test_server_auto_pay_route_requires_missing_key_and_explicit_flag(monkeypatch):
    import slf_guardian_mcp.server as server

    monkeypatch.setattr(server, "API_KEY", "")
    monkeypatch.setattr(server, "API_BASE", "https://slfguardian.com")
    monkeypatch.setattr(server, "TIMEOUT", "2")
    monkeypatch.delenv("SLF_X402_AUTO_PAY", raising=False)
    assert server.call_api("/v1/audit", {"code": "x"})["error"] == "missing_key"

    monkeypatch.setenv("SLF_X402_AUTO_PAY", "true")
    called = {}

    def fake_paid_api(*args):
        called["args"] = args
        return {"ok": False, "error": "test_sentinel"}

    monkeypatch.setattr(bridge, "call_paid_api", fake_paid_api)
    # A sentinel return proves routing only; it constructs no wallet and sends no HTTP.
    result = server.call_api("/v1/audit", {"code": "x"})
    assert called["args"][0:2] == ("/v1/audit", {"code": "x"})
    assert result["error"] == "test_sentinel"


def test_api_key_always_takes_precedence_over_auto_pay(monkeypatch):
    import io

    import slf_guardian_mcp.server as server

    monkeypatch.setattr(server, "API_KEY", "test-key")
    monkeypatch.setattr(server, "API_BASE", "https://slfguardian.com")
    monkeypatch.setenv("SLF_X402_AUTO_PAY", "true")

    class FakeResponse(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.close()

    class FakeOpener:
        def open(self, *_args, **_kwargs):
            return FakeResponse(
                b'{"ok":true,"verdict":"pass","safe_to_deliver":true,"findings":[]}'
            )

    monkeypatch.setattr(
        server.urllib.request, "build_opener", lambda *_args: FakeOpener()
    )
    monkeypatch.setattr(
        bridge,
        "call_paid_api",
        lambda *_args: pytest.fail("API-key mode must not fall back to payment"),
    )
    assert server.call_api("/v1/audit", {"code": "x"})["ok"] is True


class FakePaidResponse:
    def __init__(self, status_code, chunks=(), headers=None):
        self.status_code = status_code
        self.headers = headers or {}
        self._chunks = chunks
        self.closed = False

    def iter_content(self, chunk_size=65536):
        del chunk_size
        yield from self._chunks

    def close(self):
        self.closed = True


class FakePaidSession:
    def __init__(self, response):
        self.response = response
        self.kwargs = None

    def post(self, url, **kwargs):
        self.url = url
        self.kwargs = kwargs
        return self.response


def test_paid_transport_refuses_redirect_and_never_follows_it(monkeypatch):
    enable_auto_pay(monkeypatch)
    response = FakePaidResponse(302, headers={"Location": "https://evil.example/"})
    session = FakePaidSession(response)
    attempt_state = type("AttemptState", (), {"payment_signatures": 0})()
    monkeypatch.setattr(
        bridge,
        "_get_payment_runtime",
        lambda *_args: (session, "test-wallet", attempt_state),
    )
    result = bridge.call_paid_api(
        "/v1/audit",
        {"code": "x"},
        "https://slfguardian.com",
        2,
        lambda *_args: pytest.fail("redirect must not yield a successful result"),
    )
    assert result["error"] == "redirect_refused"
    assert response.closed
    assert session.kwargs["allow_redirects"] is False
    assert session.kwargs["stream"] is True
    assert session.url == "https://slfguardian.com/v1/audit"


def test_paid_transport_preserves_retry_after_before_response_close(monkeypatch):
    enable_auto_pay(monkeypatch)
    response = FakePaidResponse(
        429, chunks=[b'{"ok":false}'], headers={"Retry-After": "25"}
    )
    session = FakePaidSession(response)
    attempt_state = type("AttemptState", (), {"payment_signatures": 0})()
    monkeypatch.setattr(
        bridge,
        "_get_payment_runtime",
        lambda *_args: (session, "test-wallet", attempt_state),
    )
    result = bridge.call_paid_api(
        "/v1/audit",
        {"code": "x"},
        "https://slfguardian.com",
        2,
        lambda *_args: pytest.fail("429 must not be treated as a result"),
    )
    assert result["http_status"] == 429
    assert result["retry_after"] == "25"
    assert response.closed


def test_paid_response_body_is_bounded(monkeypatch):
    enable_auto_pay(monkeypatch)
    response = FakePaidResponse(200, chunks=[b"x" * (bridge.MAX_RESPONSE_BYTES + 1)])
    session = FakePaidSession(response)
    attempt_state = type("AttemptState", (), {"payment_signatures": 0})()
    monkeypatch.setattr(
        bridge,
        "_get_payment_runtime",
        lambda *_args: (session, "test-wallet", attempt_state),
    )
    result = bridge.call_paid_api(
        "/v1/audit",
        {"code": "x"},
        "https://slfguardian.com",
        2,
        lambda *_args: pytest.fail(
            "oversized response must be rejected before JSON validation"
        ),
    )
    assert result["error"] == "invalid_response"
    assert "2 MiB" in result["hint"]
    assert response.closed


def test_payment_recovery_cannot_request_a_second_signature(monkeypatch, tmp_path):
    hooks = pytest.importorskip("x402.schemas.hooks")
    enable_auto_pay(monkeypatch)
    attempt_state = type("AttemptState", (), {"payment_signatures": 1})()
    ledger = tmp_path / "spend.json"
    hook = bridge.payment_policy_hook(
        "https://slfguardian.com",
        "/v1/audit",
        state_file=ledger,
        attempt_state=attempt_state,
    )
    result = hook(valid_context())
    assert isinstance(result, hooks.AbortResult)
    assert "one payment signature" in result.message.lower()
    assert not ledger.exists()
