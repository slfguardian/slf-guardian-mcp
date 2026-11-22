import io
import json
import time
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.metadata import version as installed_version
from pathlib import Path
from threading import Thread
from types import SimpleNamespace

from slf_guardian_mcp.server import TOOLS, VERSION


def test_version_and_tool_inventory():
    assert VERSION == "1.2.3"
    assert [tool["name"] for tool in TOOLS] == [
        "audit_code",
        "check_package",
        "check_prompt",
        "check_command",
        "check_domain",
        "scan_site",
    ]


def test_runtime_package_and_registry_versions_match():
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / "server.json").read_text())
    assert installed_version("slf-guardian-mcp") == VERSION
    assert manifest["version"] == VERSION
    assert manifest["packages"][0]["version"] == VERSION
    assert manifest["name"] == "io.github.slfguardian/slf-guardian-mcp"


def test_tool_schemas_are_json_objects():
    for tool in TOOLS:
        assert tool["inputSchema"]["type"] == "object"
        json.dumps(tool)


def test_input_schemas_validate_as_json_schema_2020_12():
    from jsonschema import Draft202012Validator

    for tool in TOOLS:
        Draft202012Validator.check_schema(tool["inputSchema"])

    domain_schema = next(
        tool["inputSchema"] for tool in TOOLS if tool["name"] == "check_domain"
    )
    validator = Draft202012Validator(domain_schema)
    assert not validator.is_valid({})
    assert validator.is_valid({"domain": "example.com"})
    assert not validator.is_valid({"domains": []})


def test_audit_files_schema_matches_api_required_fields():
    from jsonschema import Draft202012Validator

    schema = next(tool["inputSchema"] for tool in TOOLS if tool["name"] == "audit_code")
    item_schema = schema["properties"]["files"]["items"]
    assert item_schema["required"] == ["path", "content"]
    assert item_schema["properties"]["path"]["minLength"] == 1
    validator = Draft202012Validator(schema)
    assert not validator.is_valid({"files": [{"content": "print(1)"}]})
    assert not validator.is_valid(
        {"code": "print(1)", "files": [{"path": "a.py", "content": "print(1)"}]}
    )


def test_tools_have_conservative_behavior_annotations():
    for tool in TOOLS:
        assert tool["annotations"] == {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": True,
        }


def test_tool_schemas_require_a_nonempty_input_path():
    schemas = {tool["name"]: tool["inputSchema"] for tool in TOOLS}
    assert schemas["audit_code"]["oneOf"] == [
        {"required": ["code"]}, {"required": ["files"]}
    ]
    assert schemas["check_package"]["oneOf"] == [
        {"required": ["name"]}, {"required": ["packages"]}
    ]
    assert schemas["check_prompt"]["oneOf"] == [
        {"required": ["text"]}, {"required": ["html"]}, {"required": ["url"]}
    ]
    assert schemas["check_command"]["oneOf"] == [
        {"required": ["command"]}, {"required": ["commands"]}
    ]
    assert schemas["check_domain"]["oneOf"] == [
        {"required": ["domain"]}, {"required": ["domains"]}
    ]
    assert schemas["scan_site"]["required"] == ["domain"]
    assert schemas["check_domain"]["properties"]["domains"]["minItems"] == 1
    assert schemas["check_domain"]["properties"]["domains"]["maxItems"] == 20
    assert schemas["check_package"]["properties"]["packages"]["maxItems"] == 20
    assert schemas["check_command"]["properties"]["commands"]["maxItems"] == 20
    assert schemas["audit_code"]["properties"]["files"]["maxItems"] == 40
    assert schemas["check_command"]["properties"]["commands"]["items"]["properties"]["kind"]["enum"] == [
        "shell", "sql", "auto"
    ]


def test_single_and_batch_inputs_cannot_be_mixed_before_api_call(monkeypatch):
    import slf_guardian_mcp.server as server

    def api_must_not_be_called(*_args, **_kwargs):
        raise AssertionError("ambiguous input must not call the API")

    monkeypatch.setattr(server, "call_api", api_must_not_be_called)
    assert server.run_tool("audit_code", {
        "code": "print(1)", "files": [{"path": "a.py", "content": "print(1)"}]
    })["error"] == "ambiguous_input"
    assert server.run_tool("check_package", {
        "name": "requests", "packages": [{"ecosystem": "pypi", "name": "requests"}]
    })["error"] == "ambiguous_input"
    assert server.run_tool("check_prompt", {"text": "hello", "html": "<p>hello</p>"})[
        "error"
    ] == "ambiguous_input"
    assert server.run_tool("check_command", {
        "command": "pwd", "commands": [{"command": "pwd"}]
    })["error"] == "ambiguous_input"
    assert server.run_tool("check_domain", {
        "domain": "example.com", "domains": ["example.com"]
    })["error"] == "ambiguous_input"


def test_initialize_includes_verdict_and_retry_policy(monkeypatch):
    import slf_guardian_mcp.server as server

    monkeypatch.setattr(
        server, "sys",
        type("FakeSys", (), {
            "stdin": io.StringIO(
                '{"jsonrpc":"2.0","id":1,"method":"initialize",'
                '"params":{"protocolVersion":"2024-11-05"}}\n'
            ),
            "stdout": io.StringIO(),
        })(),
    )
    server.main()
    result = json.loads(server.sys.stdout.getvalue())
    instructions = result["result"]["instructions"]
    assert "If verdict is block, do not proceed" in instructions
    assert "If review, show the findings to the user" in instructions
    assert "wait for Retry-After and do not retry in a loop" in instructions


def test_initialize_negotiates_supported_protocol_version(monkeypatch):
    import slf_guardian_mcp.server as server

    monkeypatch.setattr(
        server, "sys",
        type("FakeSys", (), {
            "stdin": io.StringIO(
                '{"jsonrpc":"2.0","id":1,"method":"initialize",'
                '"params":{"protocolVersion":"2025-11-25"}}\n'
            ),
            "stdout": io.StringIO(),
        })(),
    )
    server.main()
    result = json.loads(server.sys.stdout.getvalue())
    assert result["result"]["protocolVersion"] == server.PROTOCOL_VERSION


def test_initialize_echoes_exact_supported_protocol_version(monkeypatch):
    import slf_guardian_mcp.server as server

    monkeypatch.setattr(
        server, "sys",
        type("FakeSys", (), {
            "stdin": io.StringIO(
                '{"jsonrpc":"2.0","id":1,"method":"initialize",'
                '"params":{"protocolVersion":"2024-11-05"}}\n'
            ),
            "stdout": io.StringIO(),
        })(),
    )
    server.main()
    result = json.loads(server.sys.stdout.getvalue())
    assert result["result"]["protocolVersion"] == "2024-11-05"


def test_initialize_requires_protocol_version(monkeypatch):
    import slf_guardian_mcp.server as server

    monkeypatch.setattr(
        server, "sys",
        type("FakeSys", (), {
            "stdin": io.StringIO(
                '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n'
            ),
            "stdout": io.StringIO(),
        })(),
    )
    server.main()
    result = json.loads(server.sys.stdout.getvalue())
    assert result["error"]["code"] == -32602


def test_malformed_json_rpc_request_returns_parse_error(monkeypatch):
    import slf_guardian_mcp.server as server

    monkeypatch.setattr(
        server, "sys",
        type("FakeSys", (), {
            "stdin": io.StringIO('{"jsonrpc":\n'),
            "stdout": io.StringIO(),
        })(),
    )
    server.main()
    result = json.loads(server.sys.stdout.getvalue())
    assert result["error"]["code"] == -32700


def test_invalid_jsonrpc_version_returns_invalid_request(monkeypatch):
    import slf_guardian_mcp.server as server

    monkeypatch.setattr(
        server, "sys",
        type("FakeSys", (), {
            "stdin": io.StringIO(
                '{"jsonrpc":"1.0","id":3,"method":"ping"}\n'
            ),
            "stdout": io.StringIO(),
        })(),
    )
    server.main()
    result = json.loads(server.sys.stdout.getvalue())
    assert result["error"]["code"] == -32600


def test_non_object_params_return_invalid_params(monkeypatch):
    import slf_guardian_mcp.server as server

    monkeypatch.setattr(
        server, "sys",
        type("FakeSys", (), {
            "stdin": io.StringIO(
                '{"jsonrpc":"2.0","id":4,"method":"tools/list","params":[]}\n'
            ),
            "stdout": io.StringIO(),
        })(),
    )
    server.main()
    result = json.loads(server.sys.stdout.getvalue())
    assert result["error"]["code"] == -32602


def test_invalid_tools_call_arguments_return_protocol_error(monkeypatch):
    import slf_guardian_mcp.server as server

    monkeypatch.setattr(
        server, "sys",
        type("FakeSys", (), {
            "stdin": io.StringIO(
                '{"jsonrpc":"2.0","id":2,"method":"tools/call",'
                '"params":{"name":"check_package","arguments":[]} }\n'
            ),
            "stdout": io.StringIO(),
        })(),
    )
    server.main()
    result = json.loads(server.sys.stdout.getvalue())
    assert result["error"]["code"] == -32602
    assert "arguments must be a JSON object" in result["error"]["message"]


def test_unknown_tool_returns_protocol_error(monkeypatch):
    import slf_guardian_mcp.server as server

    monkeypatch.setattr(
        server, "sys",
        type("FakeSys", (), {
            "stdin": io.StringIO(
                '{"jsonrpc":"2.0","id":2,"method":"tools/call",'
                '"params":{"name":"not_a_tool","arguments":{}}}\n'
            ),
            "stdout": io.StringIO(),
        })(),
    )
    server.main()
    result = json.loads(server.sys.stdout.getvalue())
    assert result["error"]["code"] == -32602
    assert "unknown tool" in result["error"]["message"]


def test_non_object_api_response_is_reported(monkeypatch):
    import slf_guardian_mcp.server as server

    monkeypatch.setattr(server, "API_KEY", "test-key")
    class FakeOpener:
        def open(self, *_args, **_kwargs):
            return io.BytesIO(b"[]")

    monkeypatch.setattr(server.urllib.request, "build_opener", lambda *_a: FakeOpener())
    result = server.call_api("/v1/audit", {"code": "print(1)"})
    assert result["ok"] is False
    assert result["error"] == "invalid_response"


def test_http_error_cannot_claim_successful_security_verdict(monkeypatch):
    import slf_guardian_mcp.server as server

    monkeypatch.setattr(server, "API_KEY", "test-key")

    class FakeOpener:
        def open(self, *_args, **_kwargs):
            raise urllib.error.HTTPError(
                "https://slfguardian.com/v1/audit", 400, "Bad Request", {},
                io.BytesIO(b'{"ok":true,"verdict":"pass",'
                           b'"safe_to_deliver":true,"findings":[]}')
            )

    monkeypatch.setattr(server.urllib.request, "build_opener", lambda *_a: FakeOpener())
    result = server.call_api("/v1/audit", {"code": "print(1)"})
    assert result["ok"] is False
    assert result["error"] == "http_400"
    assert result["http_status"] == 400
    assert "verdict" not in result
    assert "safe_to_deliver" not in result


def test_authenticated_request_does_not_follow_redirect(monkeypatch):
    import slf_guardian_mcp.server as server

    seen = {"authorization": None}

    class SinkHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            seen["authorization"] = self.headers.get("Authorization")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"ok":true}')

        def log_message(self, *_args):
            pass

    sink = ThreadingHTTPServer(("127.0.0.1", 0), SinkHandler)

    class RedirectHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:%d/capture" % sink.server_port)
            self.end_headers()

        def log_message(self, *_args):
            pass

    redirect = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    threads = [Thread(target=srv.serve_forever, daemon=True) for srv in (sink, redirect)]
    for thread in threads:
        thread.start()
    monkeypatch.setattr(server, "API_KEY", "test-key")
    monkeypatch.setattr(server, "API_BASE", "http://127.0.0.1:%d" % redirect.server_port)
    try:
        result = server.call_api("/v1/audit", {"code": "print(1)"})
        assert result["ok"] is False
        assert result["http_status"] == 302
        assert seen["authorization"] is None
    finally:
        redirect.shutdown()
        sink.shutdown()
        redirect.server_close()
        sink.server_close()


def test_api_endpoint_and_timeout_configuration_fail_closed(monkeypatch):
    import slf_guardian_mcp.server as server

    monkeypatch.setattr(server, "API_KEY", "test-key")
    monkeypatch.setattr(server, "API_BASE", "http://example.com")
    monkeypatch.setattr(server.urllib.request, "build_opener", lambda *_a: (_ for _ in ()).throw(
        AssertionError("insecure endpoint must be rejected before network access")))
    assert server.call_api("/v1/audit", {"code": "x"})["error"] == "invalid_config"
    monkeypatch.setattr(server, "API_BASE", "https://slfguardian.com")
    monkeypatch.setattr(server, "TIMEOUT", "nan")
    assert server.call_api("/v1/audit", {"code": "x"})["error"] == "invalid_config"


def test_api_response_body_is_bounded(monkeypatch):
    import slf_guardian_mcp.server as server

    monkeypatch.setattr(server, "API_KEY", "test-key")

    class FakeOpener:
        def open(self, *_args, **_kwargs):
            return io.BytesIO(b" " * (server.MAX_RESPONSE_BYTES + 1))

    monkeypatch.setattr(server.urllib.request, "build_opener", lambda *_a: FakeOpener())
    result = server.call_api("/v1/audit", {"code": "x"})
    assert result["ok"] is False
    assert result["error"] == "invalid_response"


def test_bounded_response_ignores_closed_socket_timeout_error():
    import slf_guardian_mcp.server as server

    class FakeSocket:
        def __init__(self):
            self.calls = 0

        def settimeout(self, _remaining):
            self.calls += 1
            if self.calls > 1:
                raise OSError(9, "Bad file descriptor")

    fake_socket = FakeSocket()

    class FakeResponse:
        def __init__(self):
            self.fp = SimpleNamespace(raw=SimpleNamespace(_sock=fake_socket))
            self.chunks = [b"body", b""]

        def read1(self, _size):
            return self.chunks.pop(0)

        def read(self, size):
            return self.read1(size)

    response = FakeResponse()
    assert server._read_bounded_response(response, time.monotonic() + 1) == b"body"
    assert fake_socket.calls == 2


def test_call_api_succeeds_when_server_closes_after_response_body(monkeypatch):
    import slf_guardian_mcp.server as server

    body = b'{"ok":true,"verdict":"pass","safe_to_deliver":true,"findings":[]}'

    class ClosingHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.wfile.flush()

        def log_message(self, *_args):
            pass

    local = ThreadingHTTPServer(("127.0.0.1", 0), ClosingHandler)
    thread = Thread(target=local.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(server, "API_KEY", "dummy-loopback-key")
    monkeypatch.setattr(
        server, "API_BASE", "http://127.0.0.1:%d" % local.server_port
    )
    monkeypatch.setattr(server, "TIMEOUT", "2")
    try:
        result = server.call_api("/v1/audit", {"code": "print(1)"})
    finally:
        local.shutdown()
        local.server_close()
    assert result["ok"] is True, result


def test_api_total_response_deadline_is_enforced(monkeypatch):
    import slf_guardian_mcp.server as server

    class SlowHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":')
            self.wfile.flush()
            for byte in b'true,"verdict":"pass","safe_to_deliver":true,"findings":[]}':
                time.sleep(0.08)
                try:
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    break

        def log_message(self, *_args):
            pass

    local = ThreadingHTTPServer(("127.0.0.1", 0), SlowHandler)
    thread = Thread(target=local.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(server, "API_KEY", "test-key")
    monkeypatch.setattr(server, "API_BASE", "http://127.0.0.1:%d" % local.server_port)
    monkeypatch.setattr(server, "TIMEOUT", "0.25")
    start = time.monotonic()
    try:
        result = server.call_api("/v1/audit", {"code": "x"})
        elapsed = time.monotonic() - start
    finally:
        local.shutdown()
        local.server_close()
    assert result["ok"] is False
    assert result["error"] == "timeout"
    assert elapsed < 1.0


def test_invalid_tool_inputs_are_rejected_before_api_call(monkeypatch):
    import slf_guardian_mcp.server as server

    def api_must_not_be_called(*_args, **_kwargs):
        raise AssertionError("invalid input must not call the API")

    monkeypatch.setattr(server, "call_api", api_must_not_be_called)
    bad_calls = [
        ("audit_code", {"files": [{"path": "a.py"}]}),
        ("audit_code", {"files": [{"path": "a.py", "content": "x"}] * 41}),
        ("audit_code", {"code": "x" * (server.MAX_AUDIT_BYTES + 1)}),
        ("check_package", {"packages": [{"ecosystem": "npm", "name": "x"}] * 21}),
        ("check_package", {"packages": [{"ecosystem": [], "name": "x"}]}),
        ("check_prompt", {"text": "x", "url": "https://example.com"}),
        ("check_command", {"commands": [{"command": "x", "kind": []}]}),
        ("check_domain", {"domains": ["example.com"] * 21}),
        ("check_domain", {"domains": [None]}),
        ("scan_site", {"domain": 123}),
    ]
    for name, args in bad_calls:
        result = server.run_tool(name, args)
        assert result["ok"] is False, (name, args)
        assert result["error"] in {"invalid_input", "ambiguous_input"}, (name, args, result)


def test_success_response_requires_endpoint_verdict_fields():
    import slf_guardian_mcp.server as server

    cases = [
        ("/v1/audit", {"code": "x"}),
        ("/v1/package", {"name": "x"}),
        ("/v1/prompt", {"text": "x"}),
        ("/v1/command", {"command": "x"}),
        ("/v1/domain", {"domain": "example.com"}),
        ("/v1/scan", {"domain": "example.com"}),
    ]
    for path, request in cases:
        result = server._validate_success_response(path, {"ok": True}, request)
        assert result["ok"] is False, path
        assert result["error"] == "invalid_response", path


def test_success_response_accepts_documented_single_and_batch_shapes():
    import slf_guardian_mcp.server as server

    examples = [
        ("/v1/audit", {"code": "x"}, {"ok": True, "verdict": "pass",
         "safe_to_deliver": True, "findings": []}),
        ("/v1/package", {"name": "x"}, {"ok": True, "verdict": "pass",
         "safe_to_install": True}),
        ("/v1/package", {"packages": [{"ecosystem": "pypi", "name": "x"}]},
         {"ok": True, "safe_to_install": True,
          "packages": [{"verdict": "pass"}]}),
        ("/v1/prompt", {"text": "x"}, {"ok": True, "verdict": "pass",
         "injection_detected": False, "clean_text": "x"}),
        ("/v1/command", {"command": "x"}, {"ok": True, "verdict": "pass",
         "reversible": True, "safe_to_run": True, "needs_human_approval": False}),
        ("/v1/command", {"commands": [{"command": "x"}]},
         {"ok": True, "safe_to_run": True, "commands": [{"verdict": "pass"}]}),
        ("/v1/domain", {"domain": "example.com"}, {"ok": True, "verdict": "pass",
         "safe_to_trust": True, "safe_to_open": True}),
        ("/v1/domain", {"domains": ["example.com"]},
         {"ok": True, "safe_to_trust": True, "domains": [{"verdict": "pass"}]}),
        ("/v1/scan", {"domain": "example.com"},
         {"score": 95, "grade": "A", "findings": []}),
    ]
    for path, request, response in examples:
        assert server._validate_success_response(path, response, request) == response


def test_success_response_rejects_conflicting_verdict_or_malformed_findings():
    import slf_guardian_mcp.server as server

    bad_responses = [
        ("/v1/audit", {"code": "x"}, {"ok": True, "verdict": "block",
         "safe_to_deliver": True, "findings": []}),
        ("/v1/package", {"name": "x"}, {"ok": True, "verdict": "block",
         "safe_to_install": True, "flags": [], "advisories": []}),
        ("/v1/prompt", {"text": "x"}, {"ok": True, "verdict": "pass",
         "injection_detected": True, "clean_text": "x", "findings": []}),
        ("/v1/command", {"command": "x"}, {"ok": True, "verdict": "block",
         "reversible": False, "safe_to_run": True, "needs_human_approval": True}),
        ("/v1/domain", {"domain": "example.com"}, {"ok": True, "verdict": "block",
         "safe_to_trust": True, "safe_to_open": False}),
        ("/v1/scan", {"domain": "example.com"},
         {"score": 95, "grade": "A", "findings": ["not-an-object"]}),
    ]
    for path, request, response in bad_responses:
        result = server._validate_success_response(path, response, request)
        assert result["ok"] is False, path
        assert result["error"] == "invalid_response", path


def test_unexpected_upstream_shape_does_not_crash_summary():
    from slf_guardian_mcp.server import summarize

    text = summarize("check_package", {
        "ok": True, "name": "example", "verdict": "pass", "flags": [{}]
    })
    assert "unexpected result shape" in text


def test_rate_limit_error_tells_agent_to_wait_without_looping(monkeypatch):
    import slf_guardian_mcp.server as server

    monkeypatch.setattr(server, "API_KEY", "test-key")

    def rate_limited(*_args, **_kwargs):
        raise urllib.error.HTTPError(
            "https://slfguardian.com/v1/audit", 429, "Too Many Requests",
            {"Retry-After": "30"}, io.BytesIO(b'{"ok":false,"error":"rate_limited"}')
        )

    class FakeOpener:
        def open(self, *_args, **_kwargs):
            return rate_limited()

    monkeypatch.setattr(server.urllib.request, "build_opener", lambda *_a: FakeOpener())
    result = server.call_api("/v1/audit", {"code": "print('safe')"})
    assert result["http_status"] == 429
    assert result["retry_after"] == "30"
    assert "do not retry in a loop" in result["hint"].lower()


def test_payment_error_explains_keyed_stdio_limit(monkeypatch):
    import slf_guardian_mcp.server as server

    monkeypatch.setattr(server, "API_KEY", "test-key")

    def payment_required(*_args, **_kwargs):
        raise urllib.error.HTTPError(
            "https://slfguardian.com/v1/audit", 402, "Payment Required",
            {}, io.BytesIO(b'{"ok":false,"error":"payment_required"}')
        )

    class FakeOpener:
        def open(self, *_args, **_kwargs):
            return payment_required()

    monkeypatch.setattr(server.urllib.request, "build_opener", lambda *_a: FakeOpener())
    result = server.call_api("/v1/audit", {"code": "print('safe')"})
    assert result["http_status"] == 402
    assert "does not sign or submit payments" in result["hint"]
    assert "Do not retry" in result["hint"]


def test_numeric_jsonrpc_id_is_echoed(monkeypatch):
    import slf_guardian_mcp.server as server

    monkeypatch.setattr(
        server, "sys",
        type("FakeSys", (), {
            "stdin": io.StringIO('{"jsonrpc":"2.0","id":1.5,"method":"ping"}\n'),
            "stdout": io.StringIO(),
        })(),
    )
    server.main()
    result = json.loads(server.sys.stdout.getvalue())
    assert result["id"] == 1.5
    assert result["result"] == {}


def test_initialized_notification_has_no_response(monkeypatch):
    import slf_guardian_mcp.server as server

    monkeypatch.setattr(
        server, "sys",
        type("FakeSys", (), {
            "stdin": io.StringIO(
                '{"jsonrpc":"2.0","method":"notifications/initialized"}\n'
            ),
            "stdout": io.StringIO(),
        })(),
    )
    server.main()
    assert server.sys.stdout.getvalue() == ""


def test_tool_descriptions_contain_safe_limits():
    text = " ".join(tool["description"] for tool in TOOLS)
    assert "Nothing is executed" in text
    assert "static" in text.lower()
