"""Cursor adapter. Models the documented rule system of Cursor
(https://docs.cursor.com/context/rules) as a loading model, not a
verified runtime:

- markers          .cursor/ and .cursorrules at the project root. The
                   global state lives inside the Cursor app directory,
                   which is not a reliable marker, so home_markers
                   stays empty.
- rules            .cursor/rules/**/*.mdc and *.md. The YAML frontmatter
                   classifies each rule:
                   alwaysApply: true -> always on
                   globs set      -> auto-attached to matching paths
                   description only -> agent-requested, the model
                                       decides when to read it
                   none of the three -> manual, never auto-applied
- legacy           .cursorrules at the project root: always loaded, but
                   below .cursor/rules/ in precedence; coexisting with
                   .cursor/rules/ is reported as a conflict
- config           .cursor/mcp.json (mcpServers key)

Glob semantics are approximated: fnmatch on the relative POSIX path,
plus a directory-prefix rule for 'dir/**' forms and wildcard-free
directory names. See known_limitations.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
from pathlib import Path
from typing import Optional

from ..base import (AdapterFinding, HarnessAdapter, HarnessContext,
                    InstructionChain, InstructionLink, InstructionSource)
from .. import register

RULES_DIR_PARTS = ('.cursor', 'rules')
RULE_SUFFIXES = ('.mdc', '.md')
LEGACY_FILENAME = '.cursorrules'
MCP_RELPATH = ('.cursor', 'mcp.json')
WORKSPACE_SCAN_CAP = 5000        # paths max when testing glob applicability
_PRUNE_DIRS = {'.git'}           # never count as glob scope


# ----------------------------------------------------- frontmatter
def _strip_quotes(value: str) -> str:
    v = value.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
        return v[1:-1]
    return v


def _parse_frontmatter(text: str) -> Optional[dict]:
    """Minimal YAML frontmatter parser for the keys Cursor rules use
    (description, globs, alwaysApply). Supports 'key: value', quoted
    values, inline lists [a, b] and block lists. None when the file has
    no closed '---' block; a strict YAML parser is not a dependency
    here, so exotic syntax may silently degrade to empty values."""
    lines = text.lstrip('\ufeff').splitlines()
    if not lines or lines[0].strip() != '---':
        return None
    data: dict = {}
    i, n = 1, len(lines)
    closed = False
    while i < n:
        s = lines[i].strip()
        if s in ('---', '...'):
            closed = True
            break
        i += 1
        if not s or s.startswith('#') or ':' not in s:
            continue
        key, _, value = s.partition(':')
        key, value = key.strip(), value.strip()
        if value == '':
            # block list: following '- item' lines belong to this key
            items = []
            while i < n:
                nxt = lines[i].strip()
                if nxt.startswith('- '):
                    items.append(_strip_quotes(nxt[2:]))
                elif nxt == '-':
                    items.append('')
                else:
                    break
                i += 1
            data[key] = items
        elif value.startswith('[') and value.endswith(']'):
            data[key] = [_strip_quotes(p) for p in value[1:-1].split(',')
                         if p.strip()]
        else:
            data[key] = _strip_quotes(value)
    return data if closed else None


def _to_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ('true', 'yes', 'on', '1')


def _split_globs(value) -> list:
    """globs frontmatter value -> list of patterns. Accepts a YAML list
    or a string with comma/space separators. A value that is only
    separators degrades to [''] so the empty glob stays visible for
    CURSOR_GLOB_INVALID instead of silently dropping the rule scope."""
    if isinstance(value, list):
        return [str(v).strip() for v in value]
    if isinstance(value, str):
        if value.strip() == '':
            return ['']
        parts = [p for p in re.split(r'[,\s]+', value.strip()) if p]
        return parts or ['']
    return []


def _classify(fm: Optional[dict]) -> tuple:
    """Frontmatter -> (kind, description, globs, always_apply) where
    kind is 'always' | 'auto' | 'agent' | 'manual'."""
    if fm is None:
        return 'manual', '', [], False
    desc = str(fm.get('description', '') or '').strip()
    raw_globs = fm.get('globs')
    globs = _split_globs(raw_globs) if raw_globs is not None else []
    always = _to_bool(fm.get('alwaysApply', False))
    if always:
        return 'always', desc, globs, True
    if globs:
        return 'auto', desc, globs, False
    if desc:
        return 'agent', desc, [], False
    return 'manual', desc, [], False


def _read_frontmatter(path: Path) -> Optional[dict]:
    try:
        return _parse_frontmatter(
            path.read_text(encoding='utf-8', errors='replace'))
    except OSError:
        return None


# ----------------------------------------------------- glob model
def _dir_prefix(glob: str) -> Optional[str]:
    """'src/**' and 'src/**/*' -> 'src' (matches the directory itself
    and everything under it); '**' -> '' (matches everything)."""
    g = glob.strip()
    for tail in ('/**/*', '/**'):
        if g.endswith(tail):
            return g[:-len(tail)]
    if g == '**':
        return ''
    return None


def _glob_matches(rel: str, glob: str) -> bool:
    """Approximated Cursor glob match for a relative POSIX path."""
    g = glob.strip()
    if g == '':
        return False
    prefix = _dir_prefix(g)
    if prefix is not None:
        return rel == prefix or rel.startswith(prefix + '/')
    if not any(c in g for c in '*?['):
        # wildcard-free name: the path itself or a directory prefix
        return rel == g or rel.startswith(g + '/')
    return fnmatch.fnmatch(rel, g)


def _glob_invalid_reason(glob: str) -> Optional[str]:
    """Heuristic glob syntax check: '**' is only valid as a complete
    path segment ('src/**', '**/*.py'), never glued inside one
    ('a**b')."""
    g = glob.strip()
    if g == '':
        return 'empty glob'
    for seg in g.split('/'):
        if '**' in seg and seg != '**':
            return ("'**' must be a complete path segment, got %r" % seg)
    return None


def _workspace_relpaths(root: Path, cap: int = WORKSPACE_SCAN_CAP) -> list:
    """Relative POSIX paths of files and directories under root
    (pruning .git), capped — used to test whether a glob has any
    applicable scope at all."""
    out: list = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in _PRUNE_DIRS)
        for name in dirnames + filenames:
            p = os.path.join(dirpath, name)
            try:
                rel = os.path.relpath(p, root)
            except ValueError:
                continue
            out.append(rel.replace(os.sep, '/'))
            if len(out) >= cap:
                return out
    return out


@register
class CursorAdapter(HarnessAdapter):
    harness_id = 'cursor'
    display_name = 'Cursor'
    spec_source = 'https://docs.cursor.com/context/rules'
    spec_verified = '2026-11-17'
    supported_versions = 'current (unverified)'
    known_limitations = [
        'glob semantics approximated with fnmatch + dir-prefix; '
        'nested .mdc referencing not modelled',
    ]

    # --- conformance: honesty status per capability.
    # No runtime verification exists for this adapter, so
    # 'runtime-tested' never appears: claims trace to the Cursor docs
    # (spec_source) or to a known_limitations entry.
    CAPABILITY_STATUS = {
        # .cursor/ and .cursorrules are documented project artifacts
        'detection': 'documented',
        # global Cursor state lives in the app directory, not in a
        # stable home path: home_markers is deliberately empty
        'user_settings': 'unsupported',
        # the always/auto/agent/manual classification plus the legacy
        # file follows the documented frontmatter semantics
        'instruction_hierarchy': 'documented',
        # activation semantics per docs, but the precedence values
        # (30/20/10) and the legacy-below-rules ordering are model
        # decisions the docs do not spell out
        'loading_order': 'approximated',
        # nested .mdc referencing is not modelled (known_limitations)
        'imports': 'unsupported',
        # fnmatch + dir-prefix approximation (known_limitations)
        'glob_matching': 'approximated',
        # Cursor has no per-directory instruction files: scoping is
        # glob-based only, so there is nothing to model here
        'nested_instructions': 'unsupported',
        # Cursor's rule system has no skills mechanism;
        # skills_locations() stays empty
        'skills': 'unsupported',
        # .cursor/mcp.json with the mcpServers key is documented
        'mcp': 'documented',
        # no Cursor permission model knowledge has been collected;
        # nothing implemented, not even an approximation
        'permissions': 'unknown',
        # no budget knowledge at all; not even listed in
        # known_limitations
        'context_budget': 'unknown',
        # the app version is not discoverable offline from the project;
        # detect_version never guesses
        'version_detect': 'unsupported',
        # spec_source re-verified on spec_verified (2026-11-17)
        'spec_freshness': 'documented',
    }

    # ------------------------------------------------- detection
    def project_markers(self, ctx: HarnessContext) -> list:
        return ['.cursor', '.cursorrules']

    def home_markers(self, ctx: HarnessContext) -> list:
        # global Cursor state sits in the app directory — unreliable
        return []

    def detect_version(self, ctx: HarnessContext) -> Optional[str]:
        return None

    # ------------------------------------------------- instructions
    def _rule_records(self, ctx: HarnessContext) -> list:
        """One record per .mdc/.md rule under .cursor/rules/ with the
        parsed frontmatter and its classification."""
        records = []
        rules_dir = ctx.root_path(*RULES_DIR_PARTS)
        if not ctx.exists(rules_dir):
            return records
        try:
            entries = sorted(rules_dir.rglob('*'))
        except OSError:
            return records
        for p in entries:
            try:
                if not p.is_file() or p.suffix.lower() not in RULE_SUFFIXES:
                    continue
            except OSError:
                continue
            kind, desc, globs, always = _classify(_read_frontmatter(p))
            records.append({'path': p, 'kind': kind, 'description': desc,
                            'globs': globs, 'always_apply': always})
        return records

    def instruction_sources(self, ctx: HarnessContext) -> list:
        srcs = [InstructionSource(
                    r['path'], 'path_scoped', r['description'],
                    globs=r['globs'], always_apply=r['always_apply'])
                for r in self._rule_records(ctx)]
        legacy = ctx.root_path(LEGACY_FILENAME)
        if ctx.exists(legacy):
            srcs.append(InstructionSource(
                legacy, 'project', 'legacy .cursorrules (project root)'))
        return srcs

    @staticmethod
    def _source_kind(source: InstructionSource) -> str:
        if source.scope != 'path_scoped':
            return 'legacy'
        if source.always_apply:
            return 'always'
        if source.globs:
            return 'auto'
        if source.description:
            return 'agent'
        return 'manual'

    def resolve_chain(self, ctx: HarnessContext,
                      target_dir: Optional[Path] = None) -> InstructionChain:
        target = target_dir or ctx.root
        chain = InstructionChain(harness_id=self.harness_id,
                                 target_dir=target)
        rel = ctx.rel(target)
        if rel == '.':        # ctx.rel() of the root itself
            rel = ''
        for s in self.instruction_sources(ctx):
            kind = self._source_kind(s)
            if kind == 'always':
                chain.links.append(InstructionLink(
                    s, precedence=30,
                    reason='alwaysApply: true'))
            elif kind == 'auto':
                hit = next((g for g in s.globs
                            if _glob_matches(rel, g)), None)
                if hit is not None:
                    chain.links.append(InstructionLink(
                        s, precedence=20, reason='glob match: %s' % hit))
                else:
                    chain.unloaded.append((
                        s, "globs %s do not match target '%s'"
                        % (s.globs, rel or '.')))
            elif kind == 'agent':
                chain.links.append(InstructionLink(
                    s, precedence=20, active=False,
                    reason='agent-requested: model decides'))
            elif kind == 'manual':
                chain.links.append(InstructionLink(
                    s, precedence=20, active=False,
                    reason='manual rule: never auto-applied'))
            else:  # legacy .cursorrules
                chain.links.append(InstructionLink(
                    s, precedence=10,
                    reason='legacy .cursorrules: always loaded'))
        return chain

    # ------------------------------------------------- configs
    def config_files(self, ctx: HarnessContext) -> list:
        mcp = ctx.root_path(*MCP_RELPATH)
        return [mcp] if ctx.exists(mcp) else []

    def mcp_config_files(self, ctx: HarnessContext) -> list:
        return self.config_files(ctx)

    # ------------------------------------------------- validation
    def validate(self, ctx: HarnessContext) -> list:
        findings: list = []
        records = self._rule_records(ctx)

        # CURSOR_MDC_FRONTMATTER: .mdc without frontmatter/description
        bad_fm = []
        for r in records:
            if r['path'].suffix.lower() != '.mdc':
                continue
            if not r['description']:
                fm = _read_frontmatter(r['path'])
                detail = ('no YAML frontmatter block' if fm is None
                          else 'frontmatter has no description')
                bad_fm.append({'file': str(r['path']), 'detail': detail})
        if bad_fm:
            findings.append(AdapterFinding(
                check_id='CURSOR_MDC_FRONTMATTER',
                category='instructions', severity='medium', status='warn',
                title='Cursor .mdc rule missing frontmatter or description',
                description=(
                    '%d .mdc rule(s) under .cursor/rules/ have no YAML '
                    'frontmatter or no description; Cursor shows the '
                    'description when deciding whether to load the rule, '
                    'so without it the rule is effectively invisible.'
                    % len(bad_fm)),
                evidence=bad_fm,
                recommendation=(
                    'add a frontmatter block with a description to each '
                    '.mdc rule (---\\ndescription: ...\\n---).'),
                confidence=0.9))

        # CURSOR_GLOB_INVALID: malformed glob patterns
        bad_globs = []
        for r in records:
            for g in r['globs']:
                why = _glob_invalid_reason(g)
                if why:
                    bad_globs.append({'file': str(r['path']), 'glob': g,
                                      'detail': why})
        if bad_globs:
            findings.append(AdapterFinding(
                check_id='CURSOR_GLOB_INVALID',
                category='instructions', severity='medium', status='warn',
                title='Cursor rule has invalid glob syntax',
                description=(
                    'globs values that are empty or glue ** inside a path '
                    'segment do not match the intended files and may make '
                    'the rule silently dead.'),
                evidence=bad_globs,
                recommendation=(
                    "use ** only as a full path segment ('src/**', "
                    "'**/*.py') and remove empty glob entries."),
                confidence=0.8))

        # CURSOR_GLOB_NOMATCH: auto-attached rule matching no path
        auto_records = [r for r in records if r['kind'] == 'auto']
        dead = []
        if auto_records:
            paths = _workspace_relpaths(ctx.root)
            for r in auto_records:
                if not any(_glob_matches(p, g)
                           for p in paths for g in r['globs']):
                    dead.append({'file': str(r['path']),
                                 'globs': list(r['globs']),
                                 'detail': 'no applicable scope: no '
                                           'workspace path matches'})
        if dead:
            findings.append(AdapterFinding(
                check_id='CURSOR_GLOB_NOMATCH',
                category='instructions', severity='medium', status='warn',
                title='Cursor auto-attached rule has no applicable scope',
                description=(
                    'auto-attached rule(s) whose globs match no file in '
                    'the workspace: the rule is dead and never loads'),
                evidence=dead,
                recommendation=(
                    'fix the globs to cover existing paths, or delete the '
                    'rule.'),
                confidence=0.85))

        # CURSOR_LEGACY_AND_RULES: .cursorrules + .cursor/rules/ both
        legacy = ctx.root_path(LEGACY_FILENAME)
        rules_dir = ctx.root_path(*RULES_DIR_PARTS)
        if ctx.exists(legacy) and ctx.exists(rules_dir):
            findings.append(AdapterFinding(
                check_id='CURSOR_LEGACY_AND_RULES',
                category='compatibility', severity='medium', status='warn',
                title='Legacy .cursorrules coexists with .cursor/rules/',
                description=(
                    'both the legacy .cursorrules file and the .cursor/'
                    'rules/ directory are present; instructions may '
                    'overlap or conflict, and the legacy format cannot '
                    'express scoping'),
                evidence=[
                    {'file': str(legacy),
                     'detail': 'legacy root-level rule file'},
                    {'file': str(rules_dir),
                     'detail': 'structured rules directory also present'},
                ],
                recommendation=(
                    'migrate .cursorrules content into .cursor/rules/*.mdc '
                    'with explicit frontmatter and delete the legacy '
                    'file.'),
                confidence=0.9))

        # CURSOR_RULES_DUPLICATE_DESC: same description on two rules
        by_desc: dict = {}
        for r in records:
            if r['description']:
                by_desc.setdefault(r['description'], []).append(r['path'])
        dupes = [{'description': d, 'files': [str(p) for p in ps]}
                 for d, ps in sorted(by_desc.items()) if len(ps) > 1]
        if dupes:
            findings.append(AdapterFinding(
                check_id='CURSOR_RULES_DUPLICATE_DESC',
                category='instructions', severity='low', status='info',
                title='Cursor rules share an identical description',
                description=(
                    'rules with identical descriptions are hard to tell '
                    'apart for the model and for maintainers'),
                evidence=dupes,
                recommendation=(
                    'give each rule a description that says what it is '
                    'for.'),
                confidence=0.9))

        # CURSOR_RULE_NO_SCOPE: manual rules (no frontmatter metadata)
        manual = [r for r in records if r['kind'] == 'manual']
        if manual:
            findings.append(AdapterFinding(
                check_id='CURSOR_RULE_NO_SCOPE',
                category='instructions', severity='low', status='info',
                title='Cursor rule without scope metadata (manual only)',
                description=(
                    'rule(s) with no description, globs or alwaysApply '
                    'are manual: Cursor never applies them automatically'),
                evidence=[{'file': str(r['path']),
                           'detail': 'no description/globs/alwaysApply in '
                                     'frontmatter'} for r in manual],
                recommendation=(
                    'add alwaysApply, globs or at least a description so '
                    'the rule can be activated without manual steps.'),
                confidence=0.9))

        # CURSOR_MCP_PARSE: .cursor/mcp.json syntax and shape
        mcp = ctx.root_path(*MCP_RELPATH)
        if ctx.exists(mcp):
            parse_error = None
            data = None
            try:
                data = json.loads(mcp.read_text(encoding='utf-8',
                                                errors='replace'))
            except (ValueError, OSError) as exc:
                parse_error = str(exc)
            if parse_error is not None:
                findings.append(AdapterFinding(
                    check_id='CURSOR_MCP_PARSE',
                    category='config', severity='high', status='fail',
                    title='Cursor MCP config is not valid JSON',
                    description=('.cursor/mcp.json cannot be parsed; '
                                 'MCP servers defined there do not load'),
                    evidence=[{'file': str(mcp),
                               'detail': parse_error}],
                    recommendation='fix the JSON syntax in mcp.json.',
                    confidence=0.95))
            elif not isinstance(data, dict) or 'mcpServers' not in data:
                findings.append(AdapterFinding(
                    check_id='CURSOR_MCP_PARSE',
                    category='config', severity='medium', status='warn',
                    title='Cursor MCP config has no mcpServers key',
                    description=('.cursor/mcp.json parses but defines no '
                                 'mcpServers object; no MCP servers will '
                                 'be configured'),
                    evidence=[{'file': str(mcp),
                               'detail': 'mcpServers key missing'}],
                    recommendation=(
                        'define servers under the mcpServers key, or '
                        'remove the file.'),
                    confidence=0.9))

        return findings
