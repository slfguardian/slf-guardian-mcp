import io
import json
import urllib.error

from slf_guardian_mcp.server import TOOLS, VERSION


def test_version_and_tool_inventory():
    assert VERSION == "1.2.1"
    assert [tool["name"] for tool in TOOLS] == [
        "audit_code",
        "check_package",
        "check_prompt",
        "check_command",
        "check_domain",
        "scan_site",
    ]


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
    assert schemas["audit_code"]["anyOf"] == [
        {"required": ["code"]}, {"required": ["files"]}
    ]
    assert schemas["check_package"]["anyOf"] == [
        {"required": ["name"]}, {"required": ["packages"]}
    ]
    assert schemas["check_prompt"]["anyOf"] == [
        {"required": ["text"]}, {"required": ["html"]}, {"required": ["url"]}
    ]
    assert schemas["check_command"]["anyOf"] == [
        {"required": ["command"]}, {"required": ["commands"]}
    ]
    assert schemas["check_domain"]["anyOf"] == [
        {"required": ["domain"]}, {"required": ["domains"]}
    ]
    assert schemas["scan_site"]["required"] == ["domain"]
    assert schemas["check_domain"]["properties"]["domains"]["minItems"] == 1
    assert schemas["check_domain"]["properties"]["domains"]["maxItems"] == 20
    assert schemas["check_package"]["properties"]["packages"]["maxItems"] == 20
    assert schemas["check_command"]["properties"]["commands"]["maxItems"] == 20
    assert schemas["audit_code"]["properties"]["files"]["maxItems"] == 40


def test_initialize_includes_verdict_and_retry_policy(monkeypatch):
    import slf_guardian_mcp.server as server

    monkeypatch.setattr(
        server, "sys",
        type("FakeSys", (), {
            "stdin": io.StringIO('{"jsonrpc":"2.0","id":1,"method":"initialize"}\n'),
            "stdout": io.StringIO(),
        })(),
    )
    server.main()
    result = json.loads(server.sys.stdout.getvalue())
    instructions = result["result"]["instructions"]
    assert "If verdict is block, do not proceed" in instructions
    assert "If review, show the findings to the user" in instructions
    assert "wait for Retry-After and do not retry in a loop" in instructions


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
