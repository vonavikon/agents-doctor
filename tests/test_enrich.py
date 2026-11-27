"""Tests for skills/agents-doctor/scripts/enrich.py (fact-enrichment).

Covers config parse integrity, heavy dirs outside git, junk classification
with real git fixtures, harness activity states and SKILL.md frontmatter
health, including the position a broken header reports. PyYAML-dependent
expectations branch on its availability; the toml branch skips when the
interpreter has no tomllib.
"""
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skills' / 'agents-doctor' / 'scripts'))
sys.path.insert(0, str(Path(__file__).resolve().parent / 'integration'))

import enrich
import gates  # noqa: E402
from fixtures import BROKEN_LINE, TmpCase, skill_file  # noqa: E402
# report lookups, under the names the frontmatter tests were written with
from fixtures import by_check as _by_check, gate_of as _gate  # noqa: E402
from fixtures import rule_of as _rule  # noqa: E402

GIT_AVAILABLE = shutil.which('git') is not None
MB = 1024 * 1024


def _force_rmtree(path):
    """rmtree that clears the read-only bit git puts on .git internals."""
    def _handler(func, target, _exc):
        try:
            os.chmod(target, stat.S_IWRITE)
            func(target)
        except OSError:
            pass
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_handler)
    else:
        shutil.rmtree(path, onerror=_handler)


def _run_git(repo, *args):
    env = dict(os.environ, GIT_OPTIONAL_LOCKS='0')
    subprocess.run(
        ['git', '-C', str(repo), '-c', 'user.name=Test User',
         '-c', 'user.email=test@example.com', *args],
        capture_output=True, env=env, check=True)


def _age(path, days):
    when = time.time() - days * 86400 - 3600  # 1h slack against floor()
    os.utime(path, (when, when))


class EnrichTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='wa-enrich-'))
        self.addCleanup(_force_rmtree, self.tmp)


# --- 1) config_integrity ---------------------------------------------------------

class ConfigIntegrityTests(EnrichTestCase):

    def test_valid_json_ok(self):
        (self.tmp / '.mcp.json').write_text('{"mcpServers": {}}',
                                            encoding='utf-8')
        entries = enrich.config_integrity(self.tmp, [])
        self.assertEqual(len(entries), 1)
        e = entries[0]
        self.assertEqual(e['format'], 'json')
        self.assertTrue(e['ok'])
        self.assertIsNone(e['error'])
        self.assertEqual(e['dup_keys'], [])

    def test_broken_json_reported_with_error(self):
        (self.tmp / '.zcode' ).mkdir()
        (self.tmp / '.zcode' / 'config.json').write_text('{"a":',
                                                         encoding='utf-8')
        entries = enrich.config_integrity(self.tmp, [])
        e = next(x for x in entries if x['path'].endswith('config.json'))
        self.assertFalse(e['ok'])
        self.assertTrue(e['error'])
        self.assertLessEqual(len(e['error']), 120)

    def test_duplicate_keys_detected(self):
        (self.tmp / '.claude').mkdir()
        (self.tmp / '.claude' / 'settings.json').write_text(
            '{"permissions": [], "permissions": ["x"]}', encoding='utf-8')
        entries = enrich.config_integrity(self.tmp, [])
        e = next(x for x in entries if 'settings.json' in x['path'])
        self.assertTrue(e['ok'])  # json.loads accepts duplicates silently
        self.assertEqual(e['dup_keys'], ['permissions'])

    def test_missing_files_skipped(self):
        entries = enrich.config_integrity(self.tmp, [])
        self.assertEqual(entries, [])

    def test_repo_dir_config_reported(self):
        repo = self.tmp / 'repo'
        repo.mkdir()
        (repo / 'settings.local.json').write_text('{}', encoding='utf-8')
        entries = enrich.config_integrity(self.tmp, [repo])
        self.assertEqual(len(entries), 1)
        self.assertTrue(entries[0]['ok'])
        self.assertIn('settings.local.json', entries[0]['path'].replace('\\', '/'))

    @unittest.skipIf(enrich.tomllib is None, 'tomllib requires Python 3.11+')
    def test_toml_branch(self):
        good = self.tmp / 'config.toml'
        good.write_text('x = 1\n', encoding='utf-8')
        e = enrich._check_config(good, self.tmp)
        self.assertEqual(e['format'], 'toml')
        self.assertTrue(e['ok'])

        bad = self.tmp / 'broken.toml'
        bad.write_text('x =\n', encoding='utf-8')
        e = enrich._check_config(bad, self.tmp)
        self.assertEqual(e['format'], 'toml')
        self.assertFalse(e['ok'])
        self.assertTrue(e['error'])

    def test_toml_unavailable_reported_as_unknown(self):
        # simulate interpreters without tomllib
        saved = enrich.tomllib
        enrich.tomllib = None
        try:
            p = self.tmp / 'config.toml'
            p.write_text('x = 1\n', encoding='utf-8')
            e = enrich._check_config(p, self.tmp)
            self.assertIsNone(e['ok'])
            self.assertEqual(e['error'], 'toml parser unavailable')
        finally:
            enrich.tomllib = saved


# --- 2) heavy_outside_git ----------------------------------------------------------

class HeavyOutsideGitTests(EnrichTestCase):

    def _big_file(self, path, size=2 * MB):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'\0' * size)

    def test_nested_heavy_reported_once_at_outermost(self):
        self._big_file(self.tmp / 'heavy' / 'sub' / 'f.bin')
        entries = enrich.heavy_outside_git(self.tmp)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]['path'],
                         str(Path('heavy')))
        self.assertEqual(entries[0]['depth'], 1)
        self.assertEqual(entries[0]['size_bytes'], 2 * MB)

    def test_heavy_inside_git_repo_not_reported(self):
        (self.tmp / 'repo' / '.git').mkdir(parents=True)
        self._big_file(self.tmp / 'repo' / 'big' / 'f.bin')
        self.assertEqual(enrich.heavy_outside_git(self.tmp), [])

    def test_build_and_junk_dirs_excluded(self):
        self._big_file(self.tmp / 'node_modules' / 'f.bin')
        self._big_file(self.tmp / 'старое' / 'f.bin')
        self._big_file(self.tmp / 'tempstuff' / 'f.bin')
        self.assertEqual(enrich.heavy_outside_git(self.tmp), [])

    def test_depth_cap_heavy_at_depth_3_not_reported(self):
        self._big_file(self.tmp / 'a' / 'b' / 'heavy' / 'f.bin')
        entries = enrich.heavy_outside_git(self.tmp)
        for e in entries:
            self.assertLessEqual(e['depth'], 2)
        self.assertFalse(any('heavy' in e['path'].replace('\\', '/')
                             for e in entries))

    def test_root_repo_means_nothing_outside(self):
        (self.tmp / '.git').mkdir()
        self._big_file(self.tmp / 'plain' / 'f.bin')
        self.assertEqual(enrich.heavy_outside_git(self.tmp), [])

    def test_symlinked_dir_skipped(self):
        real = self.tmp / 'real-heavy'
        self._big_file(real / 'f.bin')
        link = self.tmp / 'link-heavy'
        try:
            link.symlink_to(real, target_is_directory=True)
        except OSError:
            self.skipTest('symlinks unavailable on this system')
        entries = enrich.heavy_outside_git(self.tmp)
        names = [e['path'] for e in entries]
        self.assertIn(str(Path('real-heavy')), names)
        self.assertNotIn(str(Path('link-heavy')), names)


# --- 3) classify_junk ---------------------------------------------------------------

@unittest.skipUnless(GIT_AVAILABLE, 'git is required for classify_junk fixtures')
class ClassifyJunkTests(EnrichTestCase):

    def setUp(self):
        super().setUp()
        self.root = self.tmp
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        _run_git(self.repo, 'init', '-q')
        (self.repo / 'backup_old.txt').write_text('tracked junk\n',
                                                  encoding='utf-8')
        _run_git(self.repo, 'add', 'backup_old.txt')

    def _classify(self, cands, refs=()):
        return {r['path']: r for r in
                enrich.classify_junk(self.root, cands, list(refs))}

    def test_untracked_old_unreferenced_confirmed(self):
        p = self.root / 'old_copy.txt'
        p.write_text('stale\n', encoding='utf-8')
        _age(p, 60)
        res = self._classify([{'path': 'old_copy.txt', 'reason': 'copy',
                               'size_bytes': 10}])
        r = res['old_copy.txt']
        self.assertEqual(r['classification'], 'confirmed_unused')
        self.assertEqual(r['confidence'], 0.7)
        self.assertFalse(r['tracked'])
        self.assertFalse(r['referenced'])

    def test_very_old_confirmed_with_higher_confidence(self):
        p = self.root / 'ancient_backup.txt'
        p.write_text('ancient\n', encoding='utf-8')
        _age(p, 120)
        res = self._classify([{'path': 'ancient_backup.txt', 'reason': 'backup',
                               'size_bytes': 10}])
        self.assertEqual(res['ancient_backup.txt']['classification'],
                         'confirmed_unused')
        self.assertEqual(res['ancient_backup.txt']['confidence'], 0.9)

    def test_tracked_junk_name_potentially_unused(self):
        res = self._classify([{'path': 'repo/backup_old.txt',
                               'reason': 'backup', 'size_bytes': 20}])
        r = res['repo/backup_old.txt']
        self.assertTrue(r['tracked'])
        self.assertEqual(r['classification'], 'potentially_unused')
        self.assertEqual(r['confidence'], 0.5)

    def test_referenced_basename_potentially_unused(self):
        p = self.root / 'final_report.md'
        p.write_text('report\n', encoding='utf-8')
        _age(p, 60)
        res = self._classify(
            [{'path': 'final_report.md', 'reason': '"final" version marker',
              'size_bytes': 10}],
            refs=['see final_report.md for details'])
        r = res['final_report.md']
        self.assertTrue(r['referenced'])
        self.assertEqual(r['classification'], 'potentially_unused')

    def test_nonexistent_path_unknown(self):
        res = self._classify([{'path': 'ghost.txt', 'reason': 'temp file',
                               'size_bytes': 10}])
        r = res['ghost.txt']
        self.assertEqual(r['classification'], 'unknown')
        self.assertEqual(r['confidence'], 0.3)
        self.assertIsNone(r['age_days'])

    def test_fresh_untracked_potentially_unused(self):
        p = self.root / 'temp_notes.txt'
        p.write_text('fresh\n', encoding='utf-8')
        res = self._classify([{'path': 'temp_notes.txt', 'reason': 'temp file',
                               'size_bytes': 10}])
        r = res['temp_notes.txt']
        self.assertFalse(r['tracked'])
        self.assertEqual(r['classification'], 'potentially_unused')


# --- 4) harness_states ---------------------------------------------------------------

class HarnessStatesTests(EnrichTestCase):

    def test_old_activity_abandoned(self):
        d = self.tmp / '.zcode'
        d.mkdir()
        f = d / 'notes.txt'
        f.write_text('x', encoding='utf-8')
        _age(f, 200)
        states = enrich.harness_states(self.tmp)
        s = states['zcode']
        self.assertEqual(s['state'], 'abandoned')
        self.assertTrue(190 <= s['last_activity_days_ago'] <= 210)
        self.assertEqual(s['evidence_source'], 'recursive mtime scan')
        self.assertEqual(s['confidence'], 0.9)
        self.assertNotIn('capped', s)

    def test_empty_dir_unknown_not_abandoned(self):
        (self.tmp / '.claude').mkdir()
        states = enrich.harness_states(self.tmp)
        s = states['claude']
        self.assertEqual(s['state'], 'unknown')
        self.assertIsNone(s['last_activity_days_ago'])
        self.assertIn('no readable files', s['reason'])

    def test_deep_recent_file_means_active(self):
        d = self.tmp / '.codex'
        d.mkdir()
        old = d / 'old.txt'
        old.write_text('old', encoding='utf-8')
        _age(old, 300)
        _age(d, 300)
        deep = d / 'l1' / 'l2' / 'l3' / 'deep.txt'
        deep.parent.mkdir(parents=True)
        deep.write_text('recent', encoding='utf-8')
        states = enrich.harness_states(self.tmp)
        s = states['codex']
        self.assertEqual(s['state'], 'active')
        self.assertLessEqual(s['last_activity_days_ago'], 1)

    def test_missing_dirs_absent_from_result(self):
        self.assertEqual(enrich.harness_states(self.tmp), {})

    def test_entry_cap_marks_capped(self):
        d = self.tmp / '.zcode'
        d.mkdir()
        for i in range(enrich.HARNESS_ENTRY_CAP + 100):
            (d / f'f{i}.txt').touch()
        states = enrich.harness_states(self.tmp)
        s = states['zcode']
        self.assertTrue(s.get('capped'))
        self.assertEqual(s['confidence'], 0.5)
        self.assertEqual(s['evidence_source'],
                         'recursive mtime scan (capped)')


# --- 5) skills_frontmatter -------------------------------------------------------------

class SkillsFrontmatterTests(EnrichTestCase):

    def _skill(self, fm, body=''):
        d = self.tmp / ('skill-' + str(len(list(self.tmp.iterdir()))))
        d.mkdir()
        md = d / 'SKILL.md'
        md.write_text(f'---\n{fm}\n---\n{body}', encoding='utf-8')
        return d, md

    def _check(self, md):
        result = enrich.skills_frontmatter([{'path': str(md)}])
        self.assertEqual(len(result), 1)
        return next(iter(result.values()))

    def test_valid_frontmatter(self):
        _d, md = self._skill('name: test-skill\ndescription: Does useful work',
                             'Body text.')
        rec = self._check(md)
        self.assertIn(rec['parser'], ('yaml', 'fallback'))
        self.assertIs(rec['frontmatter_ok'], True)
        self.assertEqual(rec['missing_fields'], [])
        self.assertEqual(rec['dead_refs'], [])

    def test_missing_description(self):
        _d, md = self._skill('name: half-skill')
        rec = self._check(md)
        self.assertEqual(rec['missing_fields'], ['description'])

    def test_dead_reference_collected(self):
        _d, md = self._skill('name: ref-skill\ndescription: refs',
                             'Run scripts/foo.py, see assets/bar.png.')
        rec = self._check(md)
        self.assertEqual(set(rec['dead_refs']),
                         {'scripts/foo.py', 'assets/bar.png'})

    def test_live_reference_not_dead(self):
        d, md = self._skill('name: live-skill\ndescription: refs',
                            'Run scripts/run.py.')
        (d / 'scripts').mkdir()
        (d / 'scripts' / 'run.py').write_text('pass', encoding='utf-8')
        rec = self._check(md)
        self.assertEqual(rec['dead_refs'], [])

    def test_unclosed_quote_malformed(self):
        _d, md = self._skill('name: "unclosed\ndescription: works')
        rec = self._check(md)
        if enrich.yaml is not None:
            self.assertEqual(rec['parser'], 'yaml')
            self.assertIs(rec['frontmatter_ok'], False)
        else:
            self.assertEqual(rec['parser'], 'fallback')
            self.assertIs(rec['frontmatter_ok'], None)

    def test_multiline_value_unknown_under_fallback(self):
        _d, md = self._skill('name: multi\ndescription: >-\n  long text')
        rec = self._check(md)
        if enrich.yaml is not None:
            self.assertEqual(rec['parser'], 'yaml')
            self.assertIs(rec['frontmatter_ok'], True)  # valid yaml
            self.assertEqual(rec['missing_fields'], [])
        else:
            self.assertEqual(rec['parser'], 'fallback')
            self.assertIs(rec['frontmatter_ok'], None)  # unknown, not ok

    def test_no_frontmatter_at_all(self):
        d = self.tmp / 'skill-bare'
        d.mkdir()
        md = d / 'SKILL.md'
        md.write_text('Just body, no fences.', encoding='utf-8')
        rec = self._check(md)
        self.assertIs(rec['frontmatter_ok'], False)
        self.assertEqual(rec['missing_fields'], ['name', 'description'])

    def test_unreadable_skill_unknown(self):
        rec = enrich.skills_frontmatter([{'path': str(self.tmp / 'nope' / 'SKILL.md')}])
        self.assertEqual(len(rec), 1)
        rec = next(iter(rec.values()))
        self.assertIs(rec['frontmatter_ok'], None)

    def test_fallback_parser_when_pyyaml_absent(self):
        # simulate interpreters without PyYAML: flat pairs must still parse
        saved = enrich.yaml
        enrich.yaml = None
        try:
            d, md = self._skill('name: fb-skill\ndescription: Works fine')
            result = enrich.skills_frontmatter([{'path': str(md)}])
            self.assertIn('fb-skill', result)
            rec = result['fb-skill']
            self.assertEqual(rec['parser'], 'fallback')
            self.assertIs(rec['frontmatter_ok'], True)
            self.assertEqual(rec['missing_fields'], [])
            # quoted single-line values are within fallback's reach
            _d2, md2 = self._skill('name: "quoted skill"\ndescription: ok')
            rec2 = next(iter(enrich.skills_frontmatter(
                [{'path': str(md2)}]).values()))
            self.assertIs(rec2['frontmatter_ok'], True)
            self.assertEqual(rec2['missing_fields'], [])
        finally:
            enrich.yaml = saved


# --- broken frontmatter: the position of the error ----------------------------

class FrontmatterErrorTests(TmpCase):
    """A header that does not parse reports where the error sits, not a
    list of fields that are in fact present."""

    def _skill(self, frontmatter, name='skill'):
        return skill_file(self.root, name, frontmatter)

    def _record(self, path):
        recs = enrich.skills_frontmatter([{'path': str(path)}])
        return next(iter(recs.values()))

    def test_broken_line_reports_position_not_missing_fields(self):
        rec = self._record(self._skill('name: broken\n' + BROKEN_LINE))
        self.assertIs(rec['frontmatter_ok'], False)
        # the fields are written in the file; they were not evaluated
        self.assertEqual(rec['missing_fields'], [])
        self.assertIs(rec['fields_checked'], False)
        err = rec['parse_error']
        self.assertEqual((err['line'], err['column']), (3, 24))

    def test_valid_yaml_without_description_is_still_missing(self):
        rec = self._record(self._skill('name: nodesc'))
        self.assertIs(rec['frontmatter_ok'], True)
        self.assertIs(rec['fields_checked'], True)
        self.assertEqual(rec['missing_fields'], ['description'])
        self.assertIsNone(rec['parse_error'])

    def test_no_block_means_the_fields_are_absent(self):
        p = self.put(self.root, 'bare/SKILL.md', 'Just body, no fences.')
        rec = self._record(p)
        self.assertIs(rec['frontmatter_ok'], False)
        self.assertEqual(rec['missing_fields'], ['name', 'description'])
        self.assertIsNone(rec['parse_error'])

    def test_unreadable_file_claims_nothing(self):
        recs = enrich.skills_frontmatter(
            [{'path': str(self.root / 'nope' / 'SKILL.md')}])
        rec = next(iter(recs.values()))
        self.assertIs(rec['frontmatter_ok'], None)
        self.assertEqual(rec['missing_fields'], [])
        self.assertIs(rec['fields_checked'], False)

    def test_without_pyyaml_the_same_line_is_rejected_too(self):
        # stdlib-only installs must not read the broken block as valid
        saved = enrich.yaml
        enrich.yaml = None
        try:
            rec = self._record(self._skill('name: broken\n' + BROKEN_LINE))
            self.assertEqual(rec['parser'], 'fallback')
            self.assertIs(rec['frontmatter_ok'], False)
            self.assertEqual(rec['missing_fields'], [])
            self.assertEqual((rec['parse_error']['line'],
                              rec['parse_error']['column']), (3, 24))
        finally:
            enrich.yaml = saved

    def test_without_pyyaml_valid_values_stay_valid(self):
        saved = enrich.yaml
        enrich.yaml = None
        try:
            rec = self._record(self._skill(
                'name: fine\ndescription: "Use when: asked for a demo"'))
            self.assertIs(rec['frontmatter_ok'], True)
            self.assertEqual(rec['missing_fields'], [])
            rec = self._record(self._skill(
                'name: links\ndescription: See https://example.com/docs'))
            self.assertIs(rec['frontmatter_ok'], True)
            # a colon not followed by a space is plain text (a URL)
            self.assertIsNone(rec['parse_error'])
        finally:
            enrich.yaml = saved

    def test_gate_finding_carries_the_error_position(self):
        p = self._skill('name: broken\n' + BROKEN_LINE)
        skills = {'entries': [{'name': 'broken', 'path': str(p), 'desc_len': 0,
                               'has_triggers': True, 'md5': 'x', 'location': 'x'}],
                  'duplicates': [], 'locations_checked': ['x: y'],
                  'coverage': {'checked': ['x'], 'failed': [], 'truncated': []}}
        extra = enrich.skills_frontmatter(skills['entries'])
        rep = {'skills': skills, 'skills_extra': extra}
        gs, findings = gates.evaluate(rep)
        hits = _by_check({'findings_detailed': findings}, 'SKL_FRONTMATTER_INVALID')
        self.assertEqual(len(hits), 1)
        ev = hits[0]['evidence'][0]
        self.assertEqual((ev['error_line'], ev['error_column']), (3, 24))
        self.assertIn('line 3, column 24', hits[0]['title'])
        self.assertNotIn('prepare a short report', json.dumps(findings))
        self.assertEqual(_rule(_gate({'gates': gs}, 'G5'), 'frontmatter')['status'],
                         'fail')


if __name__ == '__main__':
    unittest.main()
