"""Opt-in, fail-closed x402 HTTP buyer for the SLF Guardian API.

This is intentionally optional. The ordinary stdio server remains dependency-free
and uses SLF_API_KEY unless SLF_X402_AUTO_PAY=true is explicitly configured.
"""

from __future__ import annotations

import asyncio
import datetime
import decimal
import json
import os
import stat
import tempfile
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

BASE_NETWORK = "eip155:8453"
BASE_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
SLF_PAY_TO = "0x10aCe92514ca10242a5738C3B108f3195eF50974"
PRICE_ATOMIC = "10000"  # $0.01 USDC; USDC has six decimal places.
MAX_TIMEOUT_SECONDS = 60
ALLOWED_ENDPOINTS = frozenset(
    {
        "/v1/audit",
        "/v1/package",
        "/v1/prompt",
        "/v1/command",
        "/v1/domain",
        "/v1/scan",
    }
)
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class PaymentPolicyError(ValueError):
    """Raised when an x402 quote does not match the user's fixed payment policy."""


class PaymentBridgeError(RuntimeError):
    """Raised for local bridge configuration or transport failures."""


def auto_pay_enabled() -> bool:
    """Only the literal true value enables automatic signing."""
    return os.environ.get("SLF_X402_AUTO_PAY", "").strip().lower() == "true"


def _field(value: Any, name: str, alias: Optional[str] = None) -> Any:
    if isinstance(value, dict):
        if name in value:
            return value[name]
        if alias and alias in value:
            return value[alias]
        return None
    if hasattr(value, name):
        return getattr(value, name)
    if alias and hasattr(value, alias):
        return getattr(value, alias)
    return None


def _safe_api_base(api_base: str) -> bool:
    try:
        parsed = urllib.parse.urlsplit(api_base)
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except (TypeError, ValueError):
        return False
    return (
        parsed.scheme.lower() == "https"
        and host == "slfguardian.com"
        and port in (None, 443)
        and parsed.path in ("", "/")
        and not parsed.username
        and not parsed.password
        and not parsed.query
        and not parsed.fragment
    )


def validate_payment_context(context: Any, api_base: str, endpoint: str) -> None:
    """Require the exact published SLF route, recipient, network, token and price."""
    if not auto_pay_enabled():
        raise PaymentPolicyError("Automatic x402 payment is disabled.")
    if endpoint not in ALLOWED_ENDPOINTS or not _safe_api_base(api_base):
        raise PaymentPolicyError(
            "Only the six canonical SLF Guardian API routes are allowed."
        )

    payment_required = _field(context, "payment_required")
    resource = _field(payment_required, "resource")
    resource_url = _field(resource, "url")
    if not isinstance(resource_url, str):
        raise PaymentPolicyError("The payment offer has no valid resource URL.")
    try:
        parsed_resource = urllib.parse.urlsplit(resource_url)
        resource_port = parsed_resource.port
    except (TypeError, ValueError):
        raise PaymentPolicyError("The payment offer resource URL is invalid.")
    if (
        parsed_resource.scheme.lower() != "https"
        or (parsed_resource.hostname or "").lower().rstrip(".") != "slfguardian.com"
        or resource_port not in (None, 443)
        or parsed_resource.path != endpoint
        or parsed_resource.username
        or parsed_resource.password
        or parsed_resource.query
        or parsed_resource.fragment
    ):
        raise PaymentPolicyError(
            "The payment offer is not for the expected SLF Guardian route."
        )
    extensions = _field(payment_required, "extensions") or {}
    if (
        not isinstance(extensions, dict)
        or not set(extensions).issubset({"bazaar"})
        or ("bazaar" in extensions and not isinstance(extensions["bazaar"], dict))
    ):
        raise PaymentPolicyError("The payment offer contains an unapproved extension.")

    selected = _field(context, "selected_requirements")
    if selected is None:
        raise PaymentPolicyError(
            "No single payment option was selected for validation."
        )
    scheme = _field(selected, "scheme")
    network = _field(selected, "network")
    asset = _field(selected, "asset")
    amount = _field(selected, "amount")
    pay_to = _field(selected, "pay_to", "payTo")
    timeout = _field(selected, "max_timeout_seconds", "maxTimeoutSeconds")
    extra = _field(selected, "extra") or {}

    if scheme != "exact":
        raise PaymentPolicyError("Only fixed-price exact payments are allowed.")
    if network != BASE_NETWORK:
        raise PaymentPolicyError("Only Base mainnet is allowed.")
    if not isinstance(asset, str) or asset.lower() != BASE_USDC.lower():
        raise PaymentPolicyError("Only the canonical Base USDC contract is allowed.")
    if not isinstance(amount, str) or amount != PRICE_ATOMIC:
        raise PaymentPolicyError(
            "The fixed price must be exactly 0.01 USDC per API call."
        )
    if not isinstance(pay_to, str) or pay_to.lower() != SLF_PAY_TO.lower():
        raise PaymentPolicyError(
            "The payment recipient does not match SLF Guardian's verified address."
        )
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, int)
        or not 1 <= timeout <= MAX_TIMEOUT_SECONDS
    ):
        raise PaymentPolicyError(
            "The payment validity window exceeds the 60-second policy."
        )
    if extra != {"name": "USD Coin", "version": "2"}:
        raise PaymentPolicyError("The offered token metadata does not match Base USDC.")


def _budget_atomic_from_environment() -> int:
    raw = os.environ.get("SLF_X402_MAX_DAILY_USDC", "0.10")
    try:
        amount = decimal.Decimal(raw)
    except decimal.InvalidOperation:
        raise PaymentBridgeError(
            "SLF_X402_MAX_DAILY_USDC must be a positive decimal amount."
        )
    if not amount.is_finite() or amount <= 0:
        raise PaymentBridgeError(
            "SLF_X402_MAX_DAILY_USDC must be a positive decimal amount."
        )
    atomic = amount * decimal.Decimal(1_000_000)
    if atomic != atomic.to_integral_value():
        raise PaymentBridgeError(
            "Daily budget must be expressible in USDC's six decimal places."
        )
    return int(atomic)


def _state_file() -> Path:
    override = os.environ.get("SLF_X402_STATE_DIR")
    if override:
        root = Path(override).expanduser()
    else:
        root = Path(
            os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local" / "state"))
        )
        root = root / "slf-guardian-mcp"
    return root / "x402-spend.json"


def _lock_file(file_object: Any) -> None:
    file_object.seek(0)
    if os.name == "nt":
        import msvcrt

        if file_object.read(1) == b"":
            file_object.seek(0)
            file_object.write(b"0")
            file_object.flush()
        file_object.seek(0)
        msvcrt.locking(file_object.fileno(), msvcrt.LK_LOCK, 1)
    else:
        import fcntl

        fcntl.flock(file_object.fileno(), fcntl.LOCK_EX)


def _unlock_file(file_object: Any) -> None:
    if os.name == "nt":
        import msvcrt

        file_object.seek(0)
        msvcrt.locking(file_object.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(file_object.fileno(), fcntl.LOCK_UN)


def reserve_daily_budget(
    state_file: Optional[Path] = None,
    now: Optional[datetime.datetime] = None,
) -> Tuple[bool, str]:
    """Reserve one $0.01 payment atomically before signing; uncertainty is fail-closed.

    A reserved amount remains counted until the next UTC day, including after an
    ambiguous network outcome. This favors an unused budget over an accidental
    overspend. The local ledger is a guardrail, not a blockchain balance check.
    """
    target = Path(state_file) if state_file else _state_file()
    budget_atomic = _budget_atomic_from_environment()
    payment_atomic = int(PRICE_ATOMIC)
    if payment_atomic > budget_atomic:
        return False, "The daily x402 budget is below the 0.01 USDC per-call price."

    today = (now or datetime.datetime.now(datetime.timezone.utc)).date().isoformat()
    try:
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if target.parent.is_symlink():
            return False, "The x402 budget directory must not be a symbolic link."
        directory_mode = stat.S_IMODE(target.parent.stat().st_mode)
        if directory_mode & 0o077:
            return False, "The x402 budget directory must be private (mode 0700)."
        lock_path = target.with_suffix(target.suffix + ".lock")
        if lock_path.is_symlink() or target.is_symlink():
            return False, "The x402 budget file must not be a symbolic link."
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        lock_fd = os.open(str(lock_path), flags, 0o600)
        os.fchmod(lock_fd, 0o600)
        with os.fdopen(lock_fd, "r+b") as lock_handle:
            _lock_file(lock_handle)
            try:
                state = {"utc_day": today, "reserved_atomic": 0}
                if target.exists():
                    read_flags = os.O_RDONLY
                    if hasattr(os, "O_NOFOLLOW"):
                        read_flags |= os.O_NOFOLLOW
                    read_fd = os.open(str(target), read_flags)
                    with os.fdopen(read_fd, "rb") as state_handle:
                        info = os.fstat(state_handle.fileno())
                        if not stat.S_ISREG(info.st_mode) or info.st_size > 4096:
                            return (
                                False,
                                "The x402 budget file is not a small regular file.",
                            )
                        raw_bytes = state_handle.read(4097)
                    if len(raw_bytes) > 4096:
                        return (
                            False,
                            "The x402 budget file is too large; automatic payment "
                            "is blocked.",
                        )
                    try:
                        loaded = json.loads(raw_bytes.decode("utf-8"))
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        return (
                            False,
                            "The x402 budget file is invalid; automatic payment "
                            "is blocked.",
                        )
                    if (
                        not isinstance(loaded, dict)
                        or not isinstance(loaded.get("utc_day"), str)
                        or type(loaded.get("reserved_atomic")) is not int
                        or loaded["reserved_atomic"] < 0
                    ):
                        return (
                            False,
                            "The x402 budget file is invalid; automatic payment "
                            "is blocked.",
                        )
                    try:
                        stored_day = datetime.date.fromisoformat(loaded["utc_day"])
                    except ValueError:
                        return (
                            False,
                            "The x402 budget date is invalid; automatic payment "
                            "is blocked.",
                        )
                    current_day = datetime.date.fromisoformat(today)
                    if stored_day > current_day:
                        return (
                            False,
                            "The x402 budget date is in the future; automatic "
                            "payment is blocked.",
                        )
                    if stored_day == current_day:
                        state = loaded
                used = state["reserved_atomic"]
                if used + payment_atomic > budget_atomic:
                    return (
                        False,
                        "The daily x402 budget is exhausted; no new payment was "
                        "signed.",
                    )
                state["reserved_atomic"] = used + payment_atomic
                fd, temp_name = tempfile.mkstemp(
                    prefix=".x402-spend-", dir=str(target.parent)
                )
                try:
                    os.fchmod(fd, 0o600)
                    with os.fdopen(fd, "w", encoding="utf-8") as temp_handle:
                        json.dump(
                            state, temp_handle, separators=(",", ":"), sort_keys=True
                        )
                        temp_handle.flush()
                        os.fsync(temp_handle.fileno())
                    os.replace(temp_name, str(target))
                    try:
                        dir_fd = os.open(str(target.parent), os.O_RDONLY)
                        try:
                            os.fsync(dir_fd)
                        finally:
                            os.close(dir_fd)
                    except OSError:
                        return (
                            False,
                            "The x402 budget reservation could not be durably "
                            "confirmed; no payment was signed.",
                        )
                except Exception:
                    try:
                        os.unlink(temp_name)
                    except OSError:
                        pass
                    raise
                return True, ""
            finally:
                _unlock_file(lock_handle)
    except PaymentBridgeError:
        raise
    except Exception:  # noqa: BLE001 - ledger uncertainty must block payment.
        return (
            False,
            "The x402 budget ledger could not be safely updated; no payment "
            "was signed.",
        )


def payment_policy_hook(
    api_base: str,
    endpoint: str,
    state_file: Optional[Path] = None,
    attempt_state: Optional[Any] = None,
) -> Callable[[Any], Any]:
    """Build an x402 pre-sign hook that enforces terms and reserves the budget."""
    try:
        from x402.schemas.hooks import AbortResult
    except ImportError as exc:
        raise PaymentBridgeError(
            "Install the optional x402 extra to enable automatic payment."
        ) from exc

    def before_payment_creation(context: Any) -> Any:
        try:
            if (
                attempt_state is not None
                and getattr(attempt_state, "payment_signatures", 0) >= 1
            ):
                return AbortResult(
                    reason="slf_payment_policy_blocked",
                    message="Only one payment signature is allowed per MCP tool call.",
                )
            validate_payment_context(context, api_base, endpoint)
            reserved, reason = reserve_daily_budget(state_file=state_file)
            if not reserved:
                return AbortResult(reason="slf_payment_policy_blocked", message=reason)
            if attempt_state is not None:
                attempt_state.payment_signatures = (
                    getattr(attempt_state, "payment_signatures", 0) + 1
                )
            return None
        except PaymentPolicyError as exc:
            return AbortResult(reason="slf_payment_policy_blocked", message=str(exc))
        except PaymentBridgeError as exc:
            return AbortResult(reason="slf_payment_policy_blocked", message=str(exc))

    return before_payment_creation


def _run_async(coroutine: Any) -> Any:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coroutine)
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coroutine).result()


_payment_runtime: Dict[Tuple[str, str], Tuple[Any, str, Any]] = {}
_payment_runtime_lock = threading.Lock()


def _get_payment_runtime(api_base: str, endpoint: str) -> Tuple[Any, str, Any]:
    key = (api_base, endpoint)
    if key in _payment_runtime:
        return _payment_runtime[key]
    with _payment_runtime_lock:
        if key in _payment_runtime:
            return _payment_runtime[key]
        if not _safe_api_base(api_base) or endpoint not in ALLOWED_ENDPOINTS:
            raise PaymentBridgeError(
                "x402 is restricted to the canonical SLF Guardian HTTPS API."
            )
        try:
            import requests
            from cdp import CdpClient
            from cdp.evm_local_account import EvmLocalAccount
            from x402 import x402ClientSync
            from x402.http import x402HTTPClientSync
            from x402.http.clients.requests import x402HTTPAdapter
            from x402.mechanisms.evm import EthAccountSigner
            from x402.mechanisms.evm.exact import ExactEvmScheme
        except ImportError as exc:
            raise PaymentBridgeError(
                "Automatic payment requires Python 3.10+ and the optional "
                "[x402] dependencies."
            ) from exc

        required_env = ("CDP_API_KEY_ID", "CDP_API_KEY_SECRET", "CDP_WALLET_SECRET")
        if any(not os.environ.get(name) for name in required_env):
            raise PaymentBridgeError(
                "Automatic payment needs CDP_API_KEY_ID, CDP_API_KEY_SECRET, and "
                "CDP_WALLET_SECRET in the local secret manager."
            )

        async def create_account() -> Any:
            async with CdpClient() as cdp:
                return await cdp.evm.get_or_create_account(
                    name="slf-guardian-mcp-x402-buyer"
                )

        try:
            account = _run_async(create_account())
            signer = EthAccountSigner(EvmLocalAccount(account))
            client = x402ClientSync()
            client.register(BASE_NETWORK, ExactEvmScheme(signer))
            attempt_state = threading.local()
            client.on_before_payment_creation(
                payment_policy_hook(
                    api_base=api_base,
                    endpoint=endpoint,
                    attempt_state=attempt_state,
                )
            )
            http_client = x402HTTPClientSync(client)
            session = requests.Session()
            session.trust_env = False
            session.verify = True
            session.headers.update({"User-Agent": "slf-guardian-mcp/1.2.2"})
            session.mount("https://", x402HTTPAdapter(http_client))
            _payment_runtime[key] = (session, signer.address, attempt_state)
            return _payment_runtime[key]
        except PaymentBridgeError:
            raise
        except Exception as exc:
            raise PaymentBridgeError(
                "The CDP-managed x402 wallet could not be initialized; no paid "
                "API call was made."
            ) from exc


def _read_bounded_response(response: Any, timeout: float) -> bytes:
    chunks = []
    total = 0
    deadline = time.monotonic() + timeout
    raw = getattr(response, "raw", None)
    sock = None
    for path in (
        ("_connection", "sock"),
        ("_fp", "fp", "raw", "_sock"),
    ):
        current = raw
        try:
            for part in path:
                current = getattr(current, part)
            sock = current
            break
        except AttributeError:
            continue
    if sock is not None:
        sock.settimeout(timeout)
    for chunk in response.iter_content(chunk_size=65536):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("x402 response deadline exceeded")
        if sock is not None:
            sock.settimeout(remaining)
        if not chunk:
            continue
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            raise ValueError("x402 response exceeds the 2 MiB limit")
        chunks.append(chunk)
    return b"".join(chunks)


def call_paid_api(
    endpoint: str,
    payload: Dict[str, Any],
    api_base: str,
    timeout: float,
    validate_success_response: Callable[
        [str, Dict[str, Any], Dict[str, Any]], Dict[str, Any]
    ],
) -> Dict[str, Any]:
    """Call one SLF endpoint with explicit opt-in x402 payment, or fail closed."""
    if not auto_pay_enabled():
        return {
            "ok": False,
            "error": "x402_disabled",
            "hint": "No payment was made. Set SLF_API_KEY for the 1,000 free calls, "
            "or explicitly enable the optional x402 bridge after configuring "
            "its budget and CDP wallet.",
        }
    try:
        session, _wallet_address, attempt_state = _get_payment_runtime(
            api_base, endpoint
        )
        attempt_state.payment_signatures = 0
        url = api_base.rstrip("/") + endpoint
        request_started = time.monotonic()
        response = session.post(
            url,
            json=payload,
            timeout=timeout,
            allow_redirects=False,
            stream=True,
        )
        try:
            status = response.status_code
            headers = response.headers
            if 300 <= status < 400:
                return {
                    "ok": False,
                    "error": "redirect_refused",
                    "http_status": status,
                    "hint": "The paid API request was not redirected; payment "
                    "policy permits only the canonical endpoint.",
                }
            remaining = timeout - (time.monotonic() - request_started)
            if remaining <= 0:
                raise TimeoutError("x402 request deadline exceeded")
            raw = _read_bounded_response(response, remaining)
        finally:
            response.close()

        if status < 200 or status >= 300:
            result = {
                "ok": False,
                "error": "payment_required" if status == 402 else "api_http_error",
                "http_status": status,
                "hint": "The API did not return a successful paid response. "
                "Do not retry automatically; "
                "check the payment/settlement result and daily budget first.",
            }
            if status == 429:
                retry_after = headers.get("Retry-After")
                if retry_after:
                    result["retry_after"] = retry_after
            return result

        try:
            data = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {
                "ok": False,
                "error": "invalid_response",
                "hint": "The paid API returned invalid JSON; inspect payment "
                "status before any retry.",
            }
        if not isinstance(data, dict):
            return {
                "ok": False,
                "error": "invalid_response",
                "hint": "The paid API response is not a JSON object.",
            }
        return validate_success_response(endpoint, data, payload)
    except (PaymentBridgeError, PaymentPolicyError) as exc:
        return {"ok": False, "error": "x402_policy_blocked", "hint": str(exc)}
    except TimeoutError:
        return {
            "ok": False,
            "error": "timeout",
            "hint": "The x402 call timed out. Its payment outcome may be "
            "uncertain; the reservation remains counted until the next UTC day.",
        }
    except ValueError as exc:
        return {"ok": False, "error": "invalid_response", "hint": str(exc)[:200]}
    except Exception:
        return {
            "ok": False,
            "error": "x402_payment_failed",
            "hint": "The x402 request failed or settlement is uncertain. "
            "No automatic retry was attempted; "
            "check the wallet and payment record before retrying.",
        }
