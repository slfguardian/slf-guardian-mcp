import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = ROOT / "distribution" / "plugins"
PUBLISHED_VERSION = "1.2.3"


def test_claude_plugin_uses_sensitive_user_config_and_released_mcp():
    plugin_dir = PLUGIN_ROOT / "claude-code"
    manifest = json.loads((plugin_dir / ".claude-plugin/plugin.json").read_text())
    server = json.loads((plugin_dir / ".mcp.json").read_text())["mcpServers"][
        "slf-guardian"
    ]

    assert manifest["name"] == "slf-guardian"
    assert manifest["userConfig"]["api_key"]["sensitive"] is True
    assert manifest["userConfig"]["api_key"]["required"] is True
    assert server["args"] == [
        "--from",
        f"slf-guardian-mcp=={PUBLISHED_VERSION}",
        "slf-guardian-mcp",
    ]
    assert server["env"]["SLF_API_KEY"] == "${user_config.api_key}"
    assert (plugin_dir / "skills/slf-guardian-pre-action/SKILL.md").is_file()
    assert "slf_live_" not in (plugin_dir / ".mcp.json").read_text()


def test_cursor_plugin_declares_secret_variable_and_released_mcp():
    plugin_dir = PLUGIN_ROOT / "cursor"
    manifest = json.loads((plugin_dir / ".cursor-plugin/plugin.json").read_text())
    server = json.loads((plugin_dir / "mcp.json").read_text())["mcpServers"][
        "slf-guardian"
    ]

    assert manifest["name"] == "slf-guardian"
    assert manifest["variables"]["type"] == "object"
    assert "SLF_API_KEY" in manifest["variables"]["required"]
    assert "SLF_API_KEY" in manifest["variables"]["properties"]
    assert server["args"] == [
        "--from",
        f"slf-guardian-mcp=={PUBLISHED_VERSION}",
        "slf-guardian-mcp",
    ]
    assert server["env"]["SLF_API_KEY"] == "${SLF_API_KEY}"
    assert (plugin_dir / "skills/slf-guardian-pre-action/SKILL.md").is_file()
    assert "slf_live_" not in (plugin_dir / "mcp.json").read_text()


def test_agent_plugin_skill_copies_match_the_validated_agensi_source():
    source = (
        ROOT / "distribution/agensi/slf-guardian-pre-action/SKILL.md"
    ).read_bytes()
    for client in ("claude-code", "cursor"):
        bundled = (
            PLUGIN_ROOT / client / "skills/slf-guardian-pre-action/SKILL.md"
        ).read_bytes()
        assert bundled == source
