import io
import json
import urllib.error
from importlib.metadata import version as installed_version
from pathlib import Path

from slf_guardian_mcp.server import TOOLS, VERSION


def test_version_and_tool_inventory():
    assert VERSION == "1.2.2"
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
    monkeypatch.setattr(server.urllib.request, "urlopen", lambda *_a, **_kw: io.BytesIO(b"[]"))
    result = server.call_api("/v1/audit", {"code": "print(1)"})
    assert result["ok"] is False
    assert result["error"] == "invalid_response"


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

    monkeypatch.setattr(server.urllib.request, "urlopen", rate_limited)
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

    monkeypatch.setattr(server.urllib.request, "urlopen", payment_required)
    result = server.call_api("/v1/audit", {"code": "print('safe')"})
    assert result["http_status"] == 402
    assert "does not sign or submit payments" in result["hint"]
    assert "Do not retry" in result["hint"]


def test_tool_descriptions_contain_safe_limits():
    text = " ".join(tool["description"] for tool in TOOLS)
    assert "Nothing is executed" in text
    assert "static" in text.lower()
