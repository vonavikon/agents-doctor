"""Tests for the Claude Code harness adapter
(skills/agents-doctor/scripts/harness/adapters/claude_code.py).

Everything runs on temp directories via pathlib; stdlib only. The
helpers shared with the other test modules come from
tests/integration/fixtures.py.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skills' / 'agents-doctor' / 'scripts'))
sys.path.insert(0, str(Path(__file__).resolve().parent / 'integration'))

from harness import adapter_ids, get_adapter
from harness.base import HarnessContext
from fixtures import put  # noqa: E402


class ClaudeCodeAdapterTestCase(unittest.TestCase):
    def setUp(self):
        self._root_tmp = tempfile.TemporaryDirectory()
        self._home_tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._root_tmp.name)
        self.home = Path(self._home_tmp.name)
        self.ctx = HarnessContext(root=self.root, home=self.home)
        self.adapter = get_adapter('claude_code')

    def tearDown(self):
        self._root_tmp.cleanup()
        self._home_tmp.cleanup()

    # ---- helpers -------------------------------------------------
    def write(self, rel, text):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding='utf-8')
        return p

    def wjson(self, rel, data):
        return self.write(rel, json.dumps(data))

    def write_home(self, rel, text):
        p = self.home / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding='utf-8')
        return p

    def findings_by_id(self, check_id):
        return [f for f in self.adapter.validate(self.ctx)
                if f.check_id == check_id]

    def link_map(self, target=None):
        chain = self.adapter.resolve_chain(self.ctx, target)
        return chain, {str(l.source.path): l for l in chain.links}


# ---- registry / identity ----------------------------------------
class TestRegistry(ClaudeCodeAdapterTestCase):
    def test_registered(self):
        self.assertIn('claude_code', adapter_ids())
        self.assertEqual(self.adapter.harness_id, 'claude_code')
        self.assertEqual(self.adapter.display_name, 'Claude Code')

    def test_markers(self):
        self.assertEqual(set(self.adapter.project_markers(self.ctx)),
                         {'.claude', 'CLAUDE.md', '.mcp.json',
                          '.claude/settings.json'})
        self.assertEqual(self.adapter.home_markers(self.ctx),
                         [self.home / '.claude'])

    def test_detect_version_is_none(self):
        self.assertIsNone(self.adapter.detect_version(self.ctx))

    def test_spec_metadata(self):
        info = self.adapter.spec_info()
        self.assertEqual(info['spec_source'],
                         'https://docs.anthropic.com/en/docs/claude-code')
        self.assertEqual(info['spec_verified'], '2026-11-17')
        self.assertIn('2.x', info['supported_versions'])
        self.assertTrue(info['known_limitations'])
        for limitation in info['known_limitations']:
            self.assertIsInstance(limitation, str)

    def test_capabilities(self):
        self.assertIsNone(self.adapter.context_budget_bytes())
        skills = self.adapter.skills_locations(self.ctx)
        self.assertEqual(len(skills), 4)
        self.assertIn(self.root / '.claude' / 'skills', skills)
        self.assertIn(self.home / '.claude' / 'skills', skills)
        self.assertIn(self.root / '.claude' / 'commands', skills)
        self.assertIn(self.home / '.claude' / 'plugins', skills)
        # config/mcp files: only existing ones are listed
        self.assertEqual(self.adapter.config_files(self.ctx), [])
        self.assertEqual(self.adapter.mcp_config_files(self.ctx), [])
        self.wjson('.claude/settings.json', {})
        self.wjson('.mcp.json', {})
        self.assertEqual(self.adapter.config_files(self.ctx),
                         [self.root / '.claude' / 'settings.json'])
        self.assertEqual(self.adapter.mcp_config_files(self.ctx),
                         [self.root / '.mcp.json'])


# ---- instruction sources ----------------------------------------
class TestInstructionSources(ClaudeCodeAdapterTestCase):
    def test_scopes(self):
        self.write('CLAUDE.md', 'project')
        self.write('CLAUDE.local.md', 'local')
        self.write('sub/pkg/CLAUDE.md', 'nested')
        self.write_home('.claude/CLAUDE.md', 'user')
        self.wjson('.claude/settings.json', {})
        sources = self.adapter.instruction_sources(self.ctx)
        scopes = {(str(s.path), s.scope) for s in sources}
        self.assertIn((str(self.root / 'CLAUDE.md'), 'project'), scopes)
        self.assertIn((str(self.root / 'CLAUDE.local.md'), 'project'), scopes)
        self.assertIn((str(self.root / 'sub' / 'pkg' / 'CLAUDE.md'),
                       'nested'), scopes)
        self.assertIn((str(self.home / '.claude' / 'CLAUDE.md'), 'user'),
                      scopes)

    def test_agents_md_alongside_claude_md(self):
        self.write('CLAUDE.md', 'a')
        self.write('AGENTS.md', 'b')
        sources = self.adapter.instruction_sources(self.ctx)
        paths = {str(s.path) for s in sources}
        self.assertIn(str(self.root / 'CLAUDE.md'), paths)
        self.assertIn(str(self.root / 'AGENTS.md'), paths)
        self.assertTrue(all(s.scope == 'project' for s in sources))

    def test_rules_frontmatter_variants(self):
        self.write('.claude/rules/glob_list.md',
                   '---\nglobs:\n  - "*.py"\n  - "*.ts"\ndescription: code\n---\n')
        self.write('.claude/rules/glob_string.md',
                   '---\nglobs: "docs/**, guides/**"\ndescription: docs\n---\n')
        self.write('.claude/rules/always.md',
                   '---\ndescription: x\nalwaysApply: true\n---\n')
        self.write('.claude/rules/onrequest.md',
                   '---\ndescription: ask me\n---\n')
        rules = {s.path.name: s for s in self.adapter.instruction_sources(self.ctx)
                 if s.scope == 'path_scoped'}
        self.assertEqual(rules['glob_list.md'].globs, ['*.py', '*.ts'])
        self.assertFalse(rules['glob_list.md'].always_apply)
        self.assertEqual(rules['glob_string.md'].globs,
                         ['docs/**', 'guides/**'])
        self.assertTrue(rules['always.md'].always_apply)
        self.assertEqual(rules['always.md'].globs, [])
        # description-only rule: agent-requested, not always applied
        self.assertFalse(rules['onrequest.md'].always_apply)
        self.assertEqual(rules['onrequest.md'].globs, [])


# ---- resolve_chain ----------------------------------------------
class TestResolveChain(ClaudeCodeAdapterTestCase):
    def test_precedence_hierarchy(self):
        self.write_home('.claude/CLAUDE.md', 'user')
        self.write('CLAUDE.md', 'project')
        self.write('.claude/rules/always.md',
                   '---\nalwaysApply: true\n---\n')
        chain, links = self.link_map(self.root)
        self.assertTrue(chain.approximated)
        self.assertEqual(
            links[str(self.home / '.claude' / 'CLAUDE.md')].precedence, 10)
        self.assertEqual(
            links[str(self.root / 'CLAUDE.md')].precedence, 20)
        self.assertEqual(
            links[str(self.root / '.claude' / 'rules' / 'always.md')].precedence,
            40)
        # sorted strongest first
        precs = [l.precedence for l in chain.links]
        self.assertEqual(precs, sorted(precs, reverse=True))

    def test_nested_active_and_inactive(self):
        self.write('sub1/CLAUDE.md', 'a')
        self.write('sub1/sub2/CLAUDE.md', 'b')
        self.write('other/CLAUDE.md', 'c')
        target = self.root / 'sub1' / 'sub2'
        chain, links = self.link_map(target)
        near = links[str(self.root / 'sub1' / 'sub2' / 'CLAUDE.md')]
        far = links[str(self.root / 'sub1' / 'CLAUDE.md')]
        outside = links[str(self.root / 'other' / 'CLAUDE.md')]
        self.assertTrue(near.active)
        self.assertEqual(near.precedence, 30)
        self.assertTrue(far.active)
        self.assertEqual(far.precedence, 30)
        self.assertFalse(outside.active)
        self.assertEqual(outside.reason, 'outside target path')

    def test_path_scoped_rule_match_and_miss(self):
        self.write('.claude/rules/src.md',
                   '---\nglobs: "src/**"\ndescription: src\n---\n')
        chain, links = self.link_map(self.root / 'src' / 'lib')
        rule = links[str(self.root / '.claude' / 'rules' / 'src.md')]
        self.assertTrue(rule.active)
        self.assertEqual(rule.precedence, 40)
        self.assertIn('globs match', rule.reason)
        chain, links = self.link_map(self.root / 'docs')
        rule = links[str(self.root / '.claude' / 'rules' / 'src.md')]
        self.assertFalse(rule.active)
        self.assertIn('do not match', rule.reason)

    def test_agent_requested_rule_inactive(self):
        self.write('.claude/rules/ondemand.md',
                   '---\ndescription: ask me\n---\n')
        _chain, links = self.link_map(self.root)
        rule = links[str(self.root / '.claude' / 'rules' / 'ondemand.md')]
        self.assertFalse(rule.active)
        self.assertEqual(rule.reason, 'agent-requested: model decides')

    def test_imports_expansion(self):
        self.write('CLAUDE.md', 'See @docs/extra.md for details.')
        self.write('docs/extra.md', 'extra rules')
        sources = self.adapter.instruction_sources(self.ctx)
        imported = [s for s in sources if s.scope == 'imported']
        self.assertEqual(len(imported), 1)
        self.assertEqual(imported[0].path, self.root / 'docs' / 'extra.md')
        _chain, links = self.link_map(self.root)
        link = links[str(self.root / 'docs' / 'extra.md')]
        self.assertTrue(link.active)
        # project (20) + 1
        self.assertEqual(link.precedence, 21)

    def test_import_depth_limit(self):
        self.write('CLAUDE.md', '@i1.md')
        for n in range(1, 7):
            if n < 6:
                self.write('i%d.md' % n, '@i%d.md' % (n + 1))
            else:
                self.write('i6.md', 'end')
        sources = self.adapter.instruction_sources(self.ctx)
        paths = {str(s.path) for s in sources}
        for n in range(1, 6):
            self.assertIn(str(self.root / ('i%d.md' % n)), paths)
        # 6th hop is not loaded
        self.assertNotIn(str(self.root / 'i6.md'), paths)
        chain = self.adapter.resolve_chain(self.ctx, self.root)
        self.assertEqual(len(chain.unloaded), 1)
        self.assertIn('hops', chain.unloaded[0][1])
        findings = self.findings_by_id('CLAUDE_IMPORT_DEPTH')
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, 'warn')

    def test_chain_serializable(self):
        self.write('CLAUDE.md', 'root @docs/e.md')
        self.write('docs/e.md', 'e')
        self.write('.claude/rules/r.md', '---\nglobs: "*.py"\n---\n')
        chain = self.adapter.resolve_chain(self.ctx, self.root / 'src')
        data = chain.to_dict()
        json.dumps(data)  # must not raise
        self.assertEqual(data['harness'], 'claude_code')
        self.assertTrue(data['approximated'])


# ---- validate ----------------------------------------------------
class TestValidate(ClaudeCodeAdapterTestCase):
    def test_clean_workspace_zero_findings(self):
        self.write('CLAUDE.md', 'Be helpful.')
        self.wjson('.claude/settings.json', {
            'permissions': {'allow': ['Bash(npm run test)']},
            'hooks': {'PreToolUse': [{
                'matcher': 'Bash',
                'hooks': [{'type': 'command', 'command': 'echo hi'}]}]},
        })
        self.write('.claude/rules/always.md',
                   '---\ndescription: always\nalwaysApply: true\n---\n')
        self.write('.claude/rules/py.md',
                   '---\nglobs: "*.py"\ndescription: py\n---\n')
        self.write('src/main.py', 'x = 1')
        self.write('.claude/agents/helper.md',
                   '---\nname: helper\ndescription: helps\n---\nbody\n')
        self.assertEqual(self.adapter.validate(self.ctx), [])

    def test_local_deprecated(self):
        self.write('CLAUDE.local.md', 'legacy')
        findings = self.findings_by_id('CLAUDE_LOCAL_DEPRECATED')
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, 'warn')
        self.assertEqual(findings[0].evidence[0]['file'],
                         str(self.root / 'CLAUDE.local.md'))

    def test_permissions_bash_wildcard_fail(self):
        self.wjson('.claude/settings.json',
                   {'permissions': {'allow': ['Bash(*)']}})
        findings = self.findings_by_id('CLAUDE_SETTINGS_PERMISSIONS_WILDCARD')
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, 'fail')
        self.assertEqual(findings[0].severity, 'high')
        self.assertEqual(findings[0].evidence[0]['rule'], 'Bash(*)')

    def test_permissions_other_wildcards_warn(self):
        self.wjson('.claude/settings.local.json',
                   {'permissions': {'allow': ['Edit(*)', 'WebFetch(*)']}})
        findings = self.findings_by_id('CLAUDE_SETTINGS_PERMISSIONS_WILDCARD')
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, 'warn')
        self.assertEqual(findings[0].severity, 'medium')
        rules = {e['rule'] for e in findings[0].evidence}
        self.assertEqual(rules, {'Edit(*)', 'WebFetch(*)'})

    def test_hooks_invalid(self):
        self.wjson('.claude/settings.json', {'hooks': {
            'OnShutdown': [{'matcher': 'Bash',
                            'hooks': [{'type': 'command', 'command': 'x'}]}],
            'Stop': [{'hooks': []}],
        }})
        findings = self.findings_by_id('CLAUDE_HOOKS_INVALID')
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, 'warn')
        details = {e['detail'] for e in findings[0].evidence}
        self.assertIn('unknown hook event', details)
        self.assertIn('hook without command', details)
        # matcher is optional in Claude Code (it only filters tool
        # events); its absence must not be reported at all
        self.assertNotIn('hook without matcher', details)

    def test_session_hooks_without_matcher_valid(self):
        # SessionStart/SessionEnd groups never carry a matcher; they
        # are the canonical vault-sync pattern and must be clean
        self.wjson('.claude/settings.json', {'hooks': {
            'SessionStart': [{'hooks': [{'type': 'command',
                                         'command': 'pull'}]}],
            'SessionEnd': [{'hooks': [{'type': 'command',
                                       'command': 'push'}]}],
        }})
        self.assertEqual(self.findings_by_id('CLAUDE_HOOKS_INVALID'), [])

    def test_settings_dangerous(self):
        self.wjson('.claude/settings.json',
                   {'dangerouslySkipPermissions': True,
                    'bypassPermissionsMode': 'always'})
        findings = self.findings_by_id('CLAUDE_SETTINGS_DANGEROUS')
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, 'fail')
        self.assertEqual(findings[0].severity, 'high')
        flags = {e['flag'] for e in findings[0].evidence}
        self.assertEqual(flags, {'dangerouslySkipPermissions',
                                 'bypassPermissionsMode'})

    def test_agents_frontmatter(self):
        self.write('.claude/agents/bad.md', 'no frontmatter here')
        self.write('.claude/agents/good.md',
                   '---\nname: g\ndescription: d\n---\nbody\n')
        findings = self.findings_by_id('CLAUDE_AGENTS_FRONTMATTER')
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, 'warn')
        self.assertEqual(findings[0].evidence[0]['file'],
                         str(self.root / '.claude' / 'agents' / 'bad.md'))

    def test_rules_glob_nomatch(self):
        self.write('.claude/rules/dead.md',
                   '---\nglobs: "*.zzz"\ndescription: dead\n---\n')
        self.write('src/main.py', 'x = 1')
        findings = self.findings_by_id('CLAUDE_RULES_GLOB_NOMATCH')
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, 'warn')
        self.assertIn('no applicable scope', findings[0].description)

    def test_import_missing(self):
        self.write('CLAUDE.md', 'See @docs/missing.md now.')
        findings = self.findings_by_id('CLAUDE_IMPORT_MISSING')
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, 'fail')
        self.assertEqual(findings[0].severity, 'medium')
        self.assertEqual(findings[0].evidence[0]['import'],
                         'docs/missing.md')

    def test_mcp_duplicate_servers(self):
        self.wjson('.mcp.json', {'mcpServers': {'db': {'command': 'x'}}})
        self.wjson('.claude/settings.json',
                   {'mcpServers': {'db': {'command': 'y'}}})
        findings = self.findings_by_id('CLAUDE_MCP_DUPLICATE_SERVERS')
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, 'warn')
        evidence_files = {e['file'] for e in findings[0].evidence}
        self.assertIn(str(self.root / '.mcp.json'), evidence_files)
        self.assertIn(str(self.root / '.claude' / 'settings.json'),
                      evidence_files)

    def test_findings_serializable_with_file_evidence(self):
        self.write('CLAUDE.local.md', 'legacy')
        self.wjson('.claude/settings.json',
                   {'permissions': {'allow': ['Bash(*:*)']}})
        self.write('.claude/agents/bad.md', 'no frontmatter')
        findings = self.adapter.validate(self.ctx)
        self.assertTrue(findings)
        for f in findings:
            data = f.to_dict()
            json.dumps(data)  # must not raise
            self.assertTrue(f.evidence)
            for e in f.evidence:
                self.assertIsInstance(e, dict)
                self.assertIn('file', e)


# ---- where one @import points ------------------------------------

class ImportTargetTests(ClaudeCodeAdapterTestCase):
    """@imports are resolved the way the scanner sees the machine:
    '@~/' against its own home, and a target outside the audited area
    is neither dead nor read."""

    put = staticmethod(put)

    def setUp(self):
        # targets are judged on resolved paths (symlinks included)
        super().setUp()
        self.ctx = HarnessContext(root=self.root.resolve(),
                                  home=self.home.resolve())

    def findings(self, check_id):
        return self.findings_by_id(check_id)

    def test_home_relative_import_resolves_against_the_scanners_home(self):
        self.put(self.home, '.claude/CLAUDE.md', '# User\n\n@~/.claude/rules/common.md\n')
        self.put(self.home, '.claude/rules/common.md', '# Common\n\nBe brief.\n')
        self.assertEqual(self.findings('CLAUDE_IMPORT_MISSING'), [])
        self.assertEqual(self.findings('CLAUDE_IMPORT_OUTSIDE'), [])
        sources = [s.path for s in self.adapter.instruction_sources(self.ctx)]
        self.assertIn((self.home / '.claude' / 'rules' / 'common.md').resolve(),
                      [p.resolve() for p in sources])

    def test_home_relative_missing_file_is_a_dead_import(self):
        self.put(self.home, '.claude/CLAUDE.md', '# User\n\n@~/claude/absent.md\n')
        hits = self.findings('CLAUDE_IMPORT_MISSING')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].evidence[0]['import'], '~/claude/absent.md')

    def test_absolute_import_outside_the_area_is_not_dead_and_not_read(self):
        with tempfile.TemporaryDirectory() as other:
            target = self.put(Path(other), 'shared/abs.md', '# Outside\n\nSECRET-RULE\n')
            self.put(self.root, 'CLAUDE.md', '# Project\n\n@%s\n' % target.as_posix())
            self.assertEqual(self.findings('CLAUDE_IMPORT_MISSING'), [])
            hits = self.findings('CLAUDE_IMPORT_OUTSIDE')
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0].status, 'unknown')
            # the real path is neither read nor reported
            self.assertNotIn(str(other), json.dumps(hits[0].to_dict()))
            texts = [p.read_text(encoding='utf-8')
                     for p in [s.path for s in
                               self.adapter.instruction_sources(self.ctx)]
                     if p.is_file()]
            self.assertNotIn('SECRET-RULE', ''.join(texts))

    def test_relative_escape_through_parent_is_outside(self):
        with tempfile.TemporaryDirectory() as other:
            self.put(Path(other), 'up.md', '# Up\n')
            # the import is written inside the audited folder and walks
            # out of it with '..'
            self.put(self.root, 'CLAUDE.md',
                     '# Project\n\n@../%s/up.md\n' % Path(other).name)
            self.assertEqual(self.findings('CLAUDE_IMPORT_MISSING'), [])
            self.assertEqual(len(self.findings('CLAUDE_IMPORT_OUTSIDE')), 1)

    def test_chain_lists_an_outside_target_as_unloaded(self):
        with tempfile.TemporaryDirectory() as other:
            target = self.put(Path(other), 'shared/abs.md', '# Outside\n')
            self.put(self.root, 'CLAUDE.md', '# Project\n\n@%s\n' % target.as_posix())
            chain = self.adapter.resolve_chain(self.ctx, self.root)
            self.assertEqual(len(chain.loaded), 1)
            self.assertEqual(len(chain.unloaded), 1)
            source, reason = chain.unloaded[0]
            self.assertIn('outside the audited area', reason)
            self.assertNotIn(str(other), str(source.path))

    def test_plain_windows_absolute_path_is_recognised(self):
        # the drive-letter form must count as absolute on every platform
        target, state = self.adapter._import_target(
            self.ctx, self.root / 'CLAUDE.md', 'C:/definitely/missing/file.md')
        self.assertEqual((target, state), (None, 'missing'))

    def test_depth_finding_ignores_outside_targets(self):
        with tempfile.TemporaryDirectory() as other:
            target = self.put(Path(other), 'shared/abs.md', '# Outside\n')
            self.put(self.root, 'CLAUDE.md', '# Project\n\n@%s\n' % target.as_posix())
            self.assertEqual(self.findings('CLAUDE_IMPORT_DEPTH'), [])


if __name__ == '__main__':
    unittest.main()
