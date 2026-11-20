import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUBLISHED_VERSION = "1.2.1"


def test_cursor_and_vscode_configs_are_valid_and_secret_safe():
    cursor = json.loads((ROOT / "examples/cursor.mcp.json").read_text(encoding="utf-8"))
    vscode = json.loads((ROOT / "examples/vscode.mcp.json").read_text(encoding="utf-8"))

    cursor_server = cursor["mcpServers"]["slf-guardian"]
    assert cursor_server["args"] == [
        "--from",
        f"slf-guardian-mcp=={PUBLISHED_VERSION}",
        "slf-guardian-mcp",
    ]
    assert cursor_server["env"]["SLF_API_KEY"] == "${env:SLF_API_KEY}"

    vscode_server = vscode["servers"]["slf-guardian"]
    assert vscode_server["args"] == [
        "--from",
        f"slf-guardian-mcp=={PUBLISHED_VERSION}",
        "slf-guardian-mcp",
    ]
    assert vscode_server["env"]["SLF_API_KEY"] == "${input:slf-api-key}"
    assert vscode["inputs"][0]["password"] is True


def test_codex_example_forwards_secret_from_local_environment():
    config = (ROOT / "examples/codex.config.toml").read_text(encoding="utf-8")
    assert '"slf-guardian-mcp==1.2.1"' in config
    assert 'env_vars = ["SLF_API_KEY"]' in config
    assert "slf_live_" not in config


def test_claude_example_pins_published_package_and_never_embeds_a_key():
    doc = (ROOT / "examples/claude-code.md").read_text(encoding="utf-8")
    assert "slf-guardian-mcp==1.2.1" in doc
    assert "claude mcp add" in doc
    assert "SLF_API_KEY" in doc
    assert "slf_live_" not in doc


def test_quickstart_never_presents_unreleased_x402_as_installable():
    doc = (ROOT / "distribution/agent-quickstarts.md").read_text(encoding="utf-8")
    assert "slf-guardian-mcp==1.2.1" in doc
    assert "published PyPI version 1.2.1" in doc
    assert "SLF_API_KEY" in doc
    assert "CDP_WALLET_SECRET=" not in doc
    assert "pip install 'slf-guardian-mcp[x402]'" not in doc


def test_agensi_skill_frontmatter_and_six_tool_workflows_are_complete():
    skill = ROOT / "distribution/agensi/slf-guardian-pre-action/SKILL.md"
    content = skill.read_text(encoding="utf-8")
    assert content.startswith("---\nname: slf-guardian-pre-action\n")
    assert "[TODO:" not in content
    for tool in (
        "check_package",
        "check_command",
        "audit_code",
        "check_prompt",
        "check_domain",
        "scan_site",
    ):
        assert f"`{tool}`" in content
    assert "limited signal from this check" in content
    assert "owner has explicitly authorized" in content
    assert "1,000 free calls" in content


def test_skill_reference_exists_and_does_not_claim_enforcement_or_payment():
    skill_dir = ROOT / "distribution/agensi/slf-guardian-pre-action"
    reference = skill_dir / "references/api_reference.md"
    assert reference.is_file()
    skill_text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
    reference_text = reference.read_text(encoding="utf-8")
    assert "does not install the MCP" in skill_text
    assert "enforce decisions in the operating system" in skill_text
    assert "not in that PyPI version" in reference_text
    assert "seller-side MCP settlement" in reference_text


def test_demo_and_analytics_material_are_explicitly_not_live_results():
    demo = (ROOT / "distribution/demo-recording-plan.md").read_text(encoding="utf-8")
    analytics = (ROOT / "distribution/analytics-and-benchmark-next-steps.md").read_text(
        encoding="utf-8"
    )
    assert "not a video and not proof of a live run" in demo
    assert "No API call was made" in demo
    assert "not production telemetry" in analytics
    assert "Do not create a fake benchmark score" in analytics


def test_all_agent_configs_pin_the_current_public_release():
    files = (
        ROOT / "examples/cursor.mcp.json",
        ROOT / "examples/vscode.mcp.json",
        ROOT / "examples/codex.config.toml",
        ROOT / "examples/claude-code.md",
        ROOT / "distribution/agent-quickstarts.md",
    )
    for path in files:
        text = path.read_text(encoding="utf-8")
        assert f"slf-guardian-mcp=={PUBLISHED_VERSION}" in text, path
        assert "slf-guardian-mcp==1.2.2" not in text, path
        assert not re.search(r"slf_live_[A-Za-z0-9_-]{12,}", text), path
