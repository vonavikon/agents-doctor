"""Windsurf adapter. Models the documented rule system of Windsurf
(https://docs.windsurf.com/windsurf/cascade/rules) as a loading
model, not a verified runtime:

- markers          .windsurf/ and .windsurfrules at the project root.
                   Windsurf keeps memories and global state inside its
                   app data, which is not a reliable marker, so
                   home_markers stays empty.
- rules            .windsurf/rules/**/*.md. The YAML frontmatter
                   classifies each rule via the trigger key:
                   trigger: always         -> always on
                   trigger: glob (+ glob)  -> auto-attached to matching
                                              paths
                   trigger: manual         -> never auto-applied
                   trigger: model_decision -> agent-requested, the
                                              model decides when to
                                              read it
                   missing or unknown trigger -> the rule cannot
                   activate; reported by validate()
- legacy           .windsurfrules at the project root: always loaded,
                   below .windsurf/rules/ in precedence; coexisting
                   with .windsurf/rules/ is reported as a conflict
- config           .windsurf/mcp_config.json (mcpServers key)
- workflows        .windsurf/workflows is a skills-like location for
                   workflow files; their internals are not modelled

Glob semantics are shared with the Cursor adapter: fnmatch on the
relative POSIX path plus a directory-prefix rule. See
known_limitations.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from ..base import (AdapterFinding, HarnessAdapter, HarnessContext,
                    InstructionChain, InstructionLink, InstructionSource)
from .. import register
from .cursor import (_glob_matches, _read_frontmatter, _split_globs,
                     _workspace_relpaths)

RULES_DIR_PARTS = ('.windsurf', 'rules')
RULE_SUFFIX = '.md'
LEGACY_FILENAME = '.windsurfrules'
MCP_RELPATH = ('.windsurf', 'mcp_config.json')
WORKFLOWS_PARTS = ('.windsurf', 'workflows')
VALID_TRIGGERS = ('always', 'glob', 'manual', 'model_decision')


# ----------------------------------------------------- frontmatter
def _classify(fm: Optional[dict]) -> tuple:
    """Frontmatter -> (kind, trigger, description, globs) where kind is
    'always' | 'glob' | 'glob_missing' | 'manual' | 'model_decision' |
    'no_trigger' | 'unknown'."""
    if fm is None:
        return 'no_trigger', None, '', []
    desc = str(fm.get('description', '') or '').strip()
    trigger = fm.get('trigger')
    if isinstance(trigger, list):
        trigger = ', '.join(str(t).strip() for t in trigger
                            if str(t).strip())
    trigger = str(trigger or '').strip()
    if trigger == '':
        return 'no_trigger', None, desc, []
    if trigger not in VALID_TRIGGERS:
        return 'unknown', trigger, desc, []
    if trigger == 'always':
        return 'always', trigger, desc, []
    if trigger == 'glob':
        raw = fm.get('glob')
        missing = (raw is None
                   or (isinstance(raw, str) and raw.strip() == '')
                   or (isinstance(raw, list) and not raw))
        if missing:
            return 'glob_missing', trigger, desc, []
        return 'glob', trigger, desc, _split_globs(raw)
    return trigger, trigger, desc, []      # manual | model_decision


@register
class WindsurfAdapter(HarnessAdapter):
    harness_id = 'windsurf'
    display_name = 'Windsurf'
    spec_source = 'https://docs.windsurf.com/windsurf/cascade/rules'
    spec_verified = '2026-11-17'
    supported_versions = 'current (unverified)'
    known_limitations = [
        'memories and workflows internals not modelled',
        'glob semantics approximated with fnmatch + dir-prefix',
    ]

    # --- conformance: how we know each capability.
    # No runtime verification exists for this adapter, so 'runtime-tested'
    # never appears; every entry cites where the knowledge comes from.
    CAPABILITY_STATUS = {
        # .windsurf/ and .windsurfrules are the documented project
        # markers; home markers stay empty by design (app data is an
        # unreliable installation signal)
        'detection': 'documented',
        # global state (memories, app settings) lives in Windsurf app
        # data — known to exist, deliberately not modelled (unreliable
        # marker, no documented offline layout)
        'user_settings': 'unsupported',
        # rules/*.md trigger classification (always/glob/manual/
        # model_decision) plus the legacy .windsurfrules layer follow
        # the documented rules system
        'instruction_hierarchy': 'documented',
        # precedence numbers (always 30, glob 20, legacy 10) are this
        # adapter's model of the documented activation order, not
        # runtime-verified
        'loading_order': 'approximated',
        # Windsurf rules document no @import-style indirection; there
        # is nothing to parse, so none is modelled
        'imports': 'unsupported',
        # trigger globs are documented, but matching rides the
        # fnmatch + dir-prefix heuristic shared with the cursor adapter
        'glob_matching': 'approximated',
        # Windsurf has no per-subdirectory rule files; scoping is
        # glob-trigger based, so nested loading is not modelled
        'nested_instructions': 'unsupported',
        # .windsurf/workflows is exposed as a location, but workflow
        # internals are deliberately not modelled (known limitation)
        'skills': 'unsupported',
        # .windsurf/mcp_config.json and its mcpServers key are
        # documented; the file is parsed fully as JSON
        'mcp': 'documented',
        # Windsurf has no repo-level permission config; guards live in
        # app settings, deliberately not modelled
        'permissions': 'unsupported',
        # no instruction-size budget in the docs; budget stays None
        'context_budget': 'unknown',
        # detect_version always returns None — never guess offline
        'version_detect': 'unsupported',
        # spec_verified refreshed against docs.windsurf.com rules page
        'spec_freshness': 'documented',
    }

    # ------------------------------------------------- detection
    def project_markers(self, ctx: HarnessContext) -> list:
        return ['.windsurf', '.windsurfrules']

    def home_markers(self, ctx: HarnessContext) -> list:
        # global Windsurf state sits in app data — unreliable marker
        return []

    def detect_version(self, ctx: HarnessContext) -> Optional[str]:
        return None

    # ------------------------------------------------- instructions
    def _rule_records(self, ctx: HarnessContext) -> list:
        """One record per .md rule under .windsurf/rules/ with the
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
                if not p.is_file() or p.suffix.lower() != RULE_SUFFIX:
                    continue
            except OSError:
                continue
            kind, trigger, desc, globs = _classify(_read_frontmatter(p))
            records.append({'path': p, 'kind': kind, 'trigger': trigger,
                            'description': desc, 'globs': globs})
        return records

    def instruction_sources(self, ctx: HarnessContext) -> list:
        srcs = [InstructionSource(
                    r['path'], 'path_scoped', r['description'],
                    globs=r['globs'],
                    always_apply=r['kind'] == 'always')
                for r in self._rule_records(ctx)]
        legacy = ctx.root_path(LEGACY_FILENAME)
        if ctx.exists(legacy):
            srcs.append(InstructionSource(
                legacy, 'project', 'legacy .windsurfrules (project root)'))
        return srcs

    def resolve_chain(self, ctx: HarnessContext,
                      target_dir: Optional[Path] = None) -> InstructionChain:
        target = target_dir or ctx.root
        chain = InstructionChain(harness_id=self.harness_id,
                                 target_dir=target)
        rel = ctx.rel(target)
        if rel == '.':        # ctx.rel() of the root itself
            rel = ''
        for r in self._rule_records(ctx):
            src = InstructionSource(
                r['path'], 'path_scoped', r['description'],
                globs=r['globs'], always_apply=r['kind'] == 'always')
            kind = r['kind']
            if kind == 'always':
                chain.links.append(InstructionLink(
                    src, precedence=30, reason='trigger: always'))
            elif kind == 'glob':
                hit = next((g for g in r['globs']
                            if _glob_matches(rel, g)), None)
                if hit is not None:
                    chain.links.append(InstructionLink(
                        src, precedence=20, reason='glob match: %s' % hit))
                else:
                    chain.unloaded.append((
                        src, "glob %s does not match target '%s'"
                        % (r['globs'], rel or '.')))
            elif kind == 'glob_missing':
                chain.links.append(InstructionLink(
                    src, precedence=20, active=False,
                    reason='trigger: glob but no glob field: rule is '
                           'broken and never activates'))
            elif kind == 'model_decision':
                chain.links.append(InstructionLink(
                    src, precedence=20, active=False,
                    reason='model_decision: model decides'))
            elif kind == 'manual':
                chain.links.append(InstructionLink(
                    src, precedence=20, active=False,
                    reason='manual rule: never auto-applied'))
            elif kind == 'no_trigger':
                chain.links.append(InstructionLink(
                    src, precedence=20, active=False,
                    reason='no trigger in frontmatter'))
            else:  # unknown trigger value
                chain.links.append(InstructionLink(
                    src, precedence=20, active=False,
                    reason='unknown trigger: %s' % r['trigger']))
        legacy = ctx.root_path(LEGACY_FILENAME)
        if ctx.exists(legacy):
            chain.links.append(InstructionLink(
                InstructionSource(
                    legacy, 'project',
                    'legacy .windsurfrules (project root)'),
                precedence=10,
                reason='legacy .windsurfrules: always loaded'))
        return chain

    # ------------------------------------------------- capabilities
    def skills_locations(self, ctx: HarnessContext) -> list:
        # workflow files live here; internals are not modelled
        return [ctx.root_path(*WORKFLOWS_PARTS)]

    def config_files(self, ctx: HarnessContext) -> list:
        mcp = ctx.root_path(*MCP_RELPATH)
        return [mcp] if ctx.exists(mcp) else []

    def mcp_config_files(self, ctx: HarnessContext) -> list:
        return self.config_files(ctx)

    def context_budget_bytes(self) -> Optional[int]:
        return None

    # ------------------------------------------------- validation
    def validate(self, ctx: HarnessContext) -> list:
        findings: list = []
        records = self._rule_records(ctx)

        # WINDSURF_RULE_NO_TRIGGER: rule without a trigger
        no_trigger = []
        for r in records:
            if r['kind'] == 'no_trigger':
                fm = _read_frontmatter(r['path'])
                detail = ('no YAML frontmatter block' if fm is None
                          else 'frontmatter has no trigger key')
                no_trigger.append({'file': str(r['path']), 'detail': detail})
        if no_trigger:
            findings.append(AdapterFinding(
                check_id='WINDSURF_RULE_NO_TRIGGER',
                category='instructions', severity='medium', status='warn',
                title='Windsurf rule has no trigger',
                description=(
                    '%d rule(s) under .windsurf/rules/ have no trigger '
                    'in their frontmatter; Windsurf cannot classify '
                    'them and they never activate.' % len(no_trigger)),
                evidence=no_trigger,
                recommendation=(
                    'add a trigger key (always, glob, manual or '
                    'model_decision) to each rule\'s frontmatter.'),
                confidence=0.9))

        # WINDSURF_TRIGGER_UNKNOWN: trigger outside the documented set
        unknown = [{'file': str(r['path']), 'trigger': r['trigger'],
                    'detail': 'trigger value outside always/glob/manual/'
                              'model_decision'}
                   for r in records if r['kind'] == 'unknown']
        if unknown:
            findings.append(AdapterFinding(
                check_id='WINDSURF_TRIGGER_UNKNOWN',
                category='instructions', severity='medium', status='warn',
                title='Windsurf rule has an unknown trigger value',
                description=(
                    'rule(s) whose trigger is not one of the documented '
                    'values cannot be classified and never activate'),
                evidence=unknown,
                recommendation=(
                    'use one of: always, glob, manual, model_decision.'),
                confidence=0.85))

        # WINDSURF_GLOB_MISSING: trigger: glob without a glob field
        missing = [{'file': str(r['path']),
                    'detail': 'trigger: glob but no glob field in '
                              'frontmatter'}
                   for r in records if r['kind'] == 'glob_missing']
        if missing:
            findings.append(AdapterFinding(
                check_id='WINDSURF_GLOB_MISSING',
                category='instructions', severity='medium', status='fail',
                title='Windsurf glob rule has no glob field',
                description=(
                    'rule(s) with trigger: glob but no glob pattern in '
                    'the frontmatter; the rule is broken and never '
                    'activates'),
                evidence=missing,
                recommendation=(
                    'add a glob field with the pattern(s) the rule '
                    'should attach to, or switch the trigger to '
                    'always/manual.'),
                confidence=0.9))

        # WINDSURF_GLOB_NOMATCH: glob rule matching no path
        glob_records = [r for r in records if r['kind'] == 'glob']
        dead = []
        if glob_records:
            paths = _workspace_relpaths(ctx.root)
            for r in glob_records:
                if not any(_glob_matches(p, g)
                           for p in paths for g in r['globs']):
                    dead.append({'file': str(r['path']),
                                 'globs': list(r['globs']),
                                 'detail': 'no applicable scope: no '
                                           'workspace path matches'})
        if dead:
            findings.append(AdapterFinding(
                check_id='WINDSURF_GLOB_NOMATCH',
                category='instructions', severity='low', status='warn',
                title='Windsurf glob rule has no applicable scope',
                description=(
                    'glob rule(s) whose patterns match no file in the '
                    'workspace: the rule is dead and never loads'),
                evidence=dead,
                recommendation=(
                    'fix the glob to cover existing paths, or delete '
                    'the rule.'),
                confidence=0.85))

        # WINDSURF_LEGACY_AND_RULES: .windsurfrules + .windsurf/rules/
        legacy = ctx.root_path(LEGACY_FILENAME)
        rules_dir = ctx.root_path(*RULES_DIR_PARTS)
        if ctx.exists(legacy) and ctx.exists(rules_dir):
            findings.append(AdapterFinding(
                check_id='WINDSURF_LEGACY_AND_RULES',
                category='compatibility', severity='medium', status='warn',
                title='Legacy .windsurfrules coexists with '
                      '.windsurf/rules/',
                description=(
                    'both the legacy .windsurfrules file and the '
                    '.windsurf/rules/ directory are present; '
                    'instructions may overlap or conflict, and the '
                    'legacy format cannot express scoping'),
                evidence=[
                    {'file': str(legacy),
                     'detail': 'legacy root-level rule file'},
                    {'file': str(rules_dir),
                     'detail': 'structured rules directory also present'},
                ],
                recommendation=(
                    'migrate .windsurfrules content into .windsurf/'
                    'rules/*.md with explicit trigger frontmatter and '
                    'delete the legacy file.'),
                confidence=0.9))

        # WINDSURF_MCP_PARSE: mcp_config.json syntax
        mcp = ctx.root_path(*MCP_RELPATH)
        if ctx.exists(mcp):
            try:
                json.loads(mcp.read_text(encoding='utf-8',
                                         errors='replace'))
            except (ValueError, OSError) as exc:
                findings.append(AdapterFinding(
                    check_id='WINDSURF_MCP_PARSE',
                    category='config', severity='high', status='fail',
                    title='Windsurf MCP config is not valid JSON',
                    description=(
                        '.windsurf/mcp_config.json cannot be parsed; '
                        'MCP servers defined there do not load'),
                    evidence=[{'file': str(mcp), 'detail': str(exc)}],
                    recommendation=(
                        'fix the JSON syntax in mcp_config.json.'),
                    confidence=0.95))

        return findings
