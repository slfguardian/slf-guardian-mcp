import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ARTIFACTS = ROOT / "distribution/plugins"


def _members(path):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        return set(names), {
            name: archive.read(name) for name in names if not name.endswith("/")
        }


def test_agensi_skill_archive_has_expected_root_and_matches_source():
    path = ROOT / "distribution/agensi/slf-guardian-pre-action.zip"
    names, members = _members(path)
    assert "SKILL.md" in names
    assert "references/api_reference.md" in names
    assert "slf-guardian-pre-action/SKILL.md" not in names
    assert (
        members["SKILL.md"]
        == (ROOT / "distribution/agensi/slf-guardian-pre-action/SKILL.md").read_bytes()
    )
    assert (
        members["references/api_reference.md"]
        == (
            ROOT
            / "distribution/agensi/slf-guardian-pre-action/references/api_reference.md"
        ).read_bytes()
    )


def test_claude_plugin_archive_contains_manifest_server_and_skill():
    names, members = _members(PLUGIN_ARTIFACTS / "slf-guardian-claude-code-plugin.zip")
    assert ".claude-plugin/plugin.json" in names
    assert ".mcp.json" in names
    assert "skills/slf-guardian-pre-action/SKILL.md" in names
    manifest = json.loads(members[".claude-plugin/plugin.json"])
    assert manifest["userConfig"]["api_key"]["sensitive"] is True
    server = json.loads(members[".mcp.json"])["mcpServers"]["slf-guardian"]
    assert server["env"]["SLF_API_KEY"] == "${user_config.api_key}"
    assert b"slf_live_" not in b"".join(members.values())


def test_cursor_plugin_archive_contains_manifest_server_and_skill():
    names, members = _members(PLUGIN_ARTIFACTS / "slf-guardian-cursor-plugin.zip")
    assert ".cursor-plugin/plugin.json" in names
    assert "mcp.json" in names
    assert "skills/slf-guardian-pre-action/SKILL.md" in names
    manifest = json.loads(members[".cursor-plugin/plugin.json"])
    assert "SLF_API_KEY" in manifest["variables"]["required"]
    server = json.loads(members["mcp.json"])["mcpServers"]["slf-guardian"]
    assert server["env"]["SLF_API_KEY"] == "${SLF_API_KEY}"
    assert b"slf_live_" not in b"".join(members.values())
