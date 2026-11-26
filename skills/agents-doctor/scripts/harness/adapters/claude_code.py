"""Claude Code adapter.

Offline model of the documented Claude Code loading behaviour
(memory files, path-scoped rules, @imports, settings), based on
https://docs.anthropic.com/en/docs/claude-code. Not verified against
a runtime: every resolved chain keeps approximated=True.

- project markers   .claude, CLAUDE.md, .mcp.json, .claude/settings.json
- home markers      ~/.claude
- instructions      ~/.claude/CLAUDE.md (user), ./CLAUDE.md (project),
                    CLAUDE.local.md (project, deprecated), nested
                    <subdir>/CLAUDE.md (loaded when the target is inside
                    that subtree), .claude/rules/*.md (frontmatter:
                    globs -> path-scoped, alwaysApply -> always, only a
                    description -> agent-requested), AGENTS.md at the
                    project root (Claude Code >= 2.1.296), and @path.md
                    imports expanded recursively (max 5 hops)
- precedence        rules 40 > nested 30 > project 20 > user 10;
                    an import inherits parent precedence + 1
- config            .claude/settings.json, .claude/settings.local.json,
                    ~/.claude/settings.json; .mcp.json defines MCP servers
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

IMPORT_MAX_DEPTH = 5            # @import hops beyond this are not loaded
RULES_GLOB_SCAN_CAP = 5000      # files scanned to prove a glob matches nothing
VALID_HOOK_EVENTS = {
    'PreToolUse', 'PostToolUse', 'UserPromptSubmit', 'Notification',
    'Stop', 'SubagentStop', 'PreCompact', 'SessionStart', 'SessionEnd',
}
_BASH_FULL_WILDCARD = ('Bash(*)', 'Bash(*:*)')
_DANGEROUS_FLAGS = ('dangerouslySkipPermissions', 'bypassPermissionsMode')
# walked but never a source of nested instructions
_SKIP_DIRS = {'.git', 'node_modules', '.claude'}

# @docs/foo.md at line start or after whitespace; stop at .md not
# followed by a word char (so a.mdown does not half-match).
_IMPORT_RE = re.compile(r'(?:^|\s)@(\S+?\.md)(?!\w)')


def _norm(path: Path) -> str:
    """Comparable string for a path (resolve symlinks / relative junk)."""
    try:
        return str(path.resolve())
    except OSError:
        return str(path)


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return ''


def _is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:
        return False


# placeholder location for an import target that exists outside the
# audited area: the real path is neither read nor reported
_OUTSIDE_AREA = Path('<outside audit area>')


def _inside_area(ctx: HarnessContext, path: Path) -> bool:
    """True when path lies inside the workspace root or the home
    directory, compared on resolved paths (symlinks included)."""
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path
    for area in (ctx.root, ctx.home):
        try:
            area = area.resolve()
        except OSError:
            pass
        if resolved == area or area in resolved.parents:
            return True
    return False


def _load_json(path: Path):
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _parse_frontmatter(text: str) -> dict:
    """Minimal YAML frontmatter: scalar `key: value` pairs plus
    `- item` lists under the last key. Good enough for rules and
    agent files; full YAML is out of scope for stdlib-only code."""
    meta = {}
    lines = text.lstrip('\ufeff').splitlines()
    if not lines or lines[0].strip() != '---':
        return meta
    last_key = None
    for line in lines[1:]:
        s = line.strip()
        if s == '---':
            break
        if s.startswith('- ') and last_key is not None:
            current = meta.get(last_key)
            if isinstance(current, list):
                current.append(s[2:].strip().strip('\'"'))
            continue
        if ':' in s:
            key, _, value = s.partition(':')
            last_key = key.strip()
            value = value.strip()
            meta[last_key] = value.strip('\'"') if value else []
    return meta


def _norm_globs(value) -> list:
    """globs frontmatter value -> list of patterns. Accepts a YAML list
    or a scalar with comma/space separators."""
    if not value:
        return []
    items = value if isinstance(value, list) else re.split(r'[,\s]+', str(value))
    return [g for g in (str(i).strip().strip('\'"') for i in items) if g]


def _truthy(value) -> bool:
    return isinstance(value, str) and value.strip().lower() in ('true', 'yes', '1')


def _glob_match_path(rel: str, pattern: str) -> bool:
    """fnmatch-based glob check with `**/<subpath>` semantics: a pattern
    ending in /** or /* also matches the directory itself."""
    p = pattern.strip()
    if not p or rel in ('', '.'):
        return False
    if fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(rel, '**/' + p):
        return True
    for suffix in ('/**', '/*'):
        if p.endswith(suffix):
            base = p[: -len(suffix)]
            return rel == base or rel.startswith(base + '/')
    return False


@register
class ClaudeCodeAdapter(HarnessAdapter):
    harness_id = 'claude_code'
    display_name = 'Claude Code'
    spec_source = 'https://docs.anthropic.com/en/docs/claude-code'
    spec_verified = '2026-11-17'
    supported_versions = '2.x (loading model, unverified against runtime)'
    known_limitations = [
        'subdirectory CLAUDE.md lazy loading modelled as path-based '
        'inclusion: a nested file is active only when the target '
        'directory lies inside its subtree',
        'enterprise managed policies not modelled (no offline source)',
        'AGENTS.md support depends on version >= 2.1.296; when both '
        'CLAUDE.md and AGENTS.md exist, both are reported as project '
        'sources',
        'no documented instruction context budget',
    ]

    # --- conformance (TZ 3.0 section 5): honesty status per capability.
    # Nothing in this adapter runs against a real Claude Code, so
    # 'runtime-tested' never appears: every claim traces to the
    # Anthropic docs (spec_source) or to a known_limitations entry.
    CAPABILITY_STATUS = {
        # .claude/, CLAUDE.md and .mcp.json are documented project
        # artifacts; the detection engine just combines them
        'detection': 'documented',
        # settings.json / settings.local.json at the three documented
        # locations (project, project-local, user home)
        'user_settings': 'documented',
        # memory/rules layers are documented, but the numeric precedence
        # (rules 40 > nested 30 > project 20 > user 10) and the
        # collision model are ours; enterprise policies not modelled
        'instruction_hierarchy': 'approximated',
        # offline model: every chain keeps approximated=True, and the
        # documented lazy loading is modelled as path-based inclusion
        'loading_order': 'approximated',
        # the 5-hop cap is documented; regex @path extraction and the
        # importer-dir-then-root fallback are approximations
        'imports': 'approximated',
        # fnmatch plus a **/-suffix directory rule, not the real matcher
        'glob_matching': 'approximated',
        # documented lazy loading modelled as path-based inclusion
        # (first known_limitations entry)
        'nested_instructions': 'approximated',
        # .claude/skills, .claude/commands and ~/.claude/plugins are
        # documented locations (locations only; no skill parsing)
        'skills': 'documented',
        # .mcp.json plus mcpServers in settings are documented
        'mcp': 'documented',
        # permissions.allow rule syntax and the bypass flags per docs
        'permissions': 'documented',
        # docs define no instruction budget (known_limitations), so
        # context_budget_bytes() deliberately returns None
        'context_budget': 'unsupported',
        # no offline version source exists; detect_version never guesses
        'version_detect': 'unsupported',
        # spec_source re-verified on spec_verified (2026-11-17)
        'spec_freshness': 'documented',
    }

    # ------------------------------------------------- detection
    def project_markers(self, ctx: HarnessContext) -> list:
        return ['.claude', 'CLAUDE.md', '.mcp.json', '.claude/settings.json']

    def dir_conflict_map(self, ctx: HarnessContext) -> list:
        return ['.claude']

    def home_markers(self, ctx: HarnessContext) -> list:
        return [ctx.home_path('.claude')]

    def detect_version(self, ctx: HarnessContext) -> Optional[str]:
        # no offline source (no version file or lockfile); never guess
        return None

    # ------------------------------------------------- instructions
    def instruction_sources(self, ctx: HarnessContext) -> list:
        base, entries, _missing = self._gather(ctx)
        return base + [e['source'] for e in entries if e['loaded']]

    def resolve_chain(self, ctx: HarnessContext,
                      target_dir: Optional[Path] = None
                      ) -> InstructionChain:
        target = Path(target_dir) if target_dir is not None else ctx.root
        if not target.is_absolute():
            target = ctx.root / target
        chain = InstructionChain(harness_id=self.harness_id, target_dir=target)
        rel = ctx.rel(target)
        base, entries, _missing = self._gather(ctx)

        index = {}          # normalized path -> InstructionLink
        for s in base:
            prec, active, reason = 0, True, ''
            if s.scope == 'path_scoped':
                prec = 40
                if s.always_apply:
                    reason = 'alwaysApply rule'
                elif s.globs:
                    if any(_glob_match_path(rel, g) for g in s.globs):
                        reason = 'globs match target'
                    else:
                        active, reason = False, 'globs do not match target'
                else:
                    active, reason = False, 'agent-requested: model decides'
            elif s.scope == 'nested':
                prec = 30
                rule_dir = s.path.parent.resolve()
                target_resolved = target.resolve()
                on_path = (rule_dir == target_resolved
                           or rule_dir in target_resolved.parents)
                if on_path:
                    reason = 'on path to target'
                else:
                    active, reason = False, 'outside target path'
            elif s.scope == 'project':
                prec = 20
            elif s.scope == 'user':
                prec = 10
            link = InstructionLink(s, precedence=prec, active=active,
                                   reason=reason)
            chain.links.append(link)
            index[_norm(s.path)] = link

        for e in entries:
            src = e['source']
            parent_link = index.get(_norm(e['parent'])) if e['parent'] else None
            if parent_link is None:
                prec, active, reason = 1, False, 'parent not loaded'
            else:
                prec = parent_link.precedence + 1
                active = parent_link.active
                reason = '' if active else 'parent not loaded'
            if not e['loaded']:
                chain.unloaded.append((src, e['reason']))
                continue
            link = InstructionLink(src, precedence=prec, active=active,
                                   reason=reason)
            chain.links.append(link)
            index[_norm(src.path)] = link

        # strongest first; stable within one precedence level
        chain.links.sort(key=lambda l: -l.precedence)
        return chain

    # ------------------------------------------------- capabilities
    def skills_locations(self, ctx: HarnessContext) -> list:
        return [
            ctx.root_path('.claude', 'skills'),
            ctx.home_path('.claude', 'skills'),
            # commands are a separate entity but live in a skills-like spot
            ctx.root_path('.claude', 'commands'),
            ctx.home_path('.claude', 'plugins'),
        ]

    def config_files(self, ctx: HarnessContext) -> list:
        candidates = [
            ctx.root_path('.claude', 'settings.json'),
            ctx.root_path('.claude', 'settings.local.json'),
            ctx.home_path('.claude', 'settings.json'),
        ]
        return [f for f in candidates if ctx.exists(f)]

    def mcp_config_files(self, ctx: HarnessContext) -> list:
        mcp = ctx.root_path('.mcp.json')
        return [mcp] if ctx.exists(mcp) else []

    def context_budget_bytes(self) -> Optional[int]:
        return None  # no documented instruction budget

    # ------------------------------------------------- validation
    def validate(self, ctx: HarnessContext) -> list:
        findings = []
        findings.extend(self._check_local_deprecated(ctx))
        findings.extend(self._check_imports(ctx))
        settings = [(f, _load_json(f)) for f in self.config_files(ctx)]
        settings = [(f, d) for f, d in settings if isinstance(d, dict)]
        findings.extend(self._check_permissions(ctx, settings))
        findings.extend(self._check_hooks(ctx, settings))
        findings.extend(self._check_dangerous(ctx, settings))
        findings.extend(self._check_mcp_duplicates(ctx, settings))
        findings.extend(self._check_agents_frontmatter(ctx))
        findings.extend(self._check_rules_glob_scope(ctx))
        return findings

    # ------------------------------------------------- internals
    def _nested_claude_md(self, ctx: HarnessContext) -> list:
        out = []
        for dirpath, dirnames, filenames in os.walk(ctx.root):
            dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
            if Path(dirpath) == ctx.root:
                continue
            if 'CLAUDE.md' in filenames:
                out.append(Path(dirpath) / 'CLAUDE.md')
        return sorted(out, key=lambda p: (len(p.relative_to(ctx.root).parts),
                                          p.as_posix()))

    def _collect_rules(self, ctx: HarnessContext) -> list:
        rules_dir = ctx.root_path('.claude', 'rules')
        sources = []
        if not rules_dir.is_dir():
            return sources
        for md in sorted(rules_dir.glob('*.md')):
            meta = _parse_frontmatter(_read_text(md))
            globs = _norm_globs(meta.get('globs'))
            always = _truthy(meta.get('alwaysApply'))
            description = str(meta.get('description') or '').strip()
            if globs:
                # explicit globs make the rule path-scoped, even with
                # alwaysApply set alongside
                always = False
            elif not description:
                # nothing to request on demand: load always
                always = True
            sources.append(InstructionSource(
                md, 'path_scoped', description or md.stem,
                globs=globs, always_apply=always))
        return sources

    def _base_sources(self, ctx: HarnessContext) -> list:
        srcs = []
        user_md = ctx.home_path('.claude', 'CLAUDE.md')
        if ctx.exists(user_md):
            srcs.append(InstructionSource(
                user_md, 'user', 'user memory (~/.claude/CLAUDE.md)'))
        proj_md = ctx.root_path('CLAUDE.md')
        if ctx.exists(proj_md):
            srcs.append(InstructionSource(
                proj_md, 'project', 'project CLAUDE.md'))
        agents_md = ctx.root_path('AGENTS.md')
        if ctx.exists(agents_md):
            srcs.append(InstructionSource(
                agents_md, 'project', 'AGENTS.md (Claude Code >= 2.1.296)'))
        local_md = ctx.root_path('CLAUDE.local.md')
        if ctx.exists(local_md):
            srcs.append(InstructionSource(
                local_md, 'project', 'CLAUDE.local.md (deprecated)'))
        for p in self._nested_claude_md(ctx):
            srcs.append(InstructionSource(
                p, 'nested', 'subdirectory CLAUDE.md'))
        srcs.extend(self._collect_rules(ctx))
        return srcs

    @staticmethod
    def _import_target(ctx: HarnessContext, origin: Path, raw: str):
        """Where one @import points.

        Returns (path, state); state is one of
          'found'   - the file exists inside the audited area
                      (workspace root or home) and is loaded,
          'outside' - the file exists but lies outside the audited area:
                      named, never read,
          'missing' - no such file where the import can point to.
        path is None only for 'missing'.

        '@~/x' resolves against the user's home as the scanner sees it
        (ctx.home, so an isolated --home works), an absolute path is
        taken as is; anything else is relative to the importing file,
        then to the workspace root.
        """
        spec = raw.replace('\\', '/')
        if spec.startswith('~/'):
            candidates = [ctx.home_path(*spec[2:].split('/'))]
        elif os.path.isabs(spec) or re.match(r'^[A-Za-z]:/', spec):
            candidates = [Path(spec)]
        else:
            candidates = [origin.parent.joinpath(*spec.split('/')),
                          ctx.root.joinpath(*spec.split('/'))]
        for cand in candidates:
            if ctx.exists(cand) and _is_file(cand):
                return cand, ('found' if _inside_area(ctx, cand) else 'outside')
        return None, 'missing'

    def _expand_imports(self, ctx: HarnessContext, base_files: list):
        """Walk @path.md imports starting from the CLAUDE.md files.
        Returns (entries, missing): entries are dicts with source/parent/
        depth/loaded/reason, missing are dead @references.

        An import whose target lies outside the audited area is an entry
        with outside=True and loaded=False (reason says so): it is neither
        dead nor read."""
        entries, missing = [], []
        seen = {_norm(f) for f in base_files}
        seen_outside = set()

        def expand(origin: Path, depth: int):
            for raw in _IMPORT_RE.findall(_read_text(origin)):
                candidate, state = self._import_target(ctx, origin, raw)
                if state == 'missing':
                    missing.append({'file': str(origin), 'import': raw})
                    continue
                if state == 'outside':
                    if raw not in seen_outside:
                        seen_outside.add(raw)
                        entries.append({
                            'source': InstructionSource(
                                _OUTSIDE_AREA / Path(raw.replace('\\', '/')).name,
                                'imported',
                                'imported from %s (outside the audited area)'
                                % origin.name),
                            'parent': origin, 'depth': depth + 1,
                            'loaded': False, 'outside': True,
                            'reason': 'outside the audited area '
                                      '(workspace root and home)'})
                    continue
                key = _norm(candidate)
                if key in seen:
                    continue
                seen.add(key)
                src = InstructionSource(
                    candidate, 'imported',
                    'imported from %s' % origin.name)
                hop = depth + 1
                if hop > IMPORT_MAX_DEPTH:
                    entries.append({'source': src, 'parent': origin,
                                    'depth': hop, 'loaded': False,
                                    'reason': 'import chain deeper than %d hops'
                                              % IMPORT_MAX_DEPTH})
                    continue
                entries.append({'source': src, 'parent': origin,
                                'depth': hop, 'loaded': True, 'reason': ''})
                expand(candidate, hop)

        for f in base_files:
            expand(f, 0)
        return entries, missing

    def _gather(self, ctx: HarnessContext):
        """Single pass shared by instruction_sources / resolve_chain /
        validate so all three see the same model."""
        base = self._base_sources(ctx)
        import_files = []
        user_md = ctx.home_path('.claude', 'CLAUDE.md')
        if ctx.exists(user_md):
            import_files.append(user_md)
        proj_md = ctx.root_path('CLAUDE.md')
        if ctx.exists(proj_md):
            import_files.append(proj_md)
        import_files.extend(self._nested_claude_md(ctx))
        entries, missing = self._expand_imports(ctx, import_files)
        return base, entries, missing

    # ------------------------------------------------- checks
    def _check_local_deprecated(self, ctx: HarnessContext) -> list:
        local = ctx.root_path('CLAUDE.local.md')
        if not ctx.exists(local):
            return []
        return [AdapterFinding(
            check_id='CLAUDE_LOCAL_DEPRECATED',
            category='compatibility', severity='medium', status='warn',
            title='CLAUDE.local.md is deprecated',
            description=('CLAUDE.local.md is deprecated; newer Claude Code '
                         'versions discourage it and it is not meant to be '
                         'committed.'),
            evidence=[{'file': str(local)}],
            recommendation=('move the content into CLAUDE.md or a '
                            '.claude/rules/ rule and delete the file.'),
            confidence=0.9)]

    def _check_imports(self, ctx: HarnessContext) -> list:
        findings = []
        _base, entries, missing = self._gather(ctx)
        over = [e for e in entries if not e['loaded'] and not e.get('outside')]
        if over:
            findings.append(AdapterFinding(
                check_id='CLAUDE_IMPORT_DEPTH',
                category='instructions', severity='low', status='warn',
                title='CLAUDE.md import chain deeper than %d hops'
                      % IMPORT_MAX_DEPTH,
                description=('Claude Code expands @imports up to %d hops; '
                             'files reachable only deeper are not loaded.'
                             % IMPORT_MAX_DEPTH),
                evidence=[{'file': str(e['source'].path), 'depth': e['depth']}
                          for e in over],
                recommendation='flatten the @import chain.',
                confidence=0.8))
        # targets that exist but lie outside the audited area: not dead,
        # and not verified either
        outside = [e for e in entries if e.get('outside')]
        if outside:
            findings.append(AdapterFinding(
                check_id='CLAUDE_IMPORT_OUTSIDE',
                category='instructions', severity='low', status='unknown',
                title='CLAUDE.md imports files outside the audited area',
                description=('%d @import target(s) exist but lie outside the '
                             'workspace and the home directory; their content '
                             'was not read, so they are unverified.' % len(outside)),
                evidence=[{'file': str(e['source'].path),
                           'imported_from': e['parent'].name if e['parent'] else ''}
                          for e in outside],
                recommendation='Nothing to fix unless the import is a mistake: '
                               'audit that folder separately to check the file.',
                confidence=0.9))
        if missing:
            findings.append(AdapterFinding(
                check_id='CLAUDE_IMPORT_MISSING',
                category='instructions', severity='medium', status='fail',
                title='CLAUDE.md imports a missing file',
                description=('An @path.md import points to a file that does '
                             'not exist (dead import); the reference loads '
                             'nothing.'),
                evidence=[{'file': m['file'], 'import': m['import']}
                          for m in missing],
                recommendation='fix or remove the dead @import.',
                confidence=0.9))
        return findings

    def _check_permissions(self, ctx, settings) -> list:
        findings = []
        for path, data in settings:
            perms = data.get('permissions')
            allow = perms.get('allow') if isinstance(perms, dict) else None
            if not isinstance(allow, list):
                continue
            rules = [r for r in allow if isinstance(r, str)]
            bash_full = [r for r in rules if r.strip() in _BASH_FULL_WILDCARD]
            others = [r for r in rules
                      if '*' in r and r.strip() not in _BASH_FULL_WILDCARD]
            if not (bash_full or others):
                continue
            evidence = [{'file': str(path), 'rule': r}
                        for r in bash_full + others]
            if bash_full:
                status, severity = 'fail', 'high'
                title = 'Wildcard Bash permission in Claude Code settings'
                description=('permissions.allow grants Bash(*) or '
                             'Bash(*:*): any shell command runs without '
                             'confirmation.')
            else:
                status, severity = 'warn', 'medium'
                title = 'Wildcard permission in Claude Code settings'
                description=('permissions.allow contains wildcard rules; '
                             'they cover more tools or hosts than intended.')
            findings.append(AdapterFinding(
                check_id='CLAUDE_SETTINGS_PERMISSIONS_WILDCARD',
                category='security', severity=severity, status=status,
                title=title, description=description, evidence=evidence,
                recommendation=('replace wildcards with the narrowest tool '
                                'or host pattern that is actually needed.'),
                confidence=0.9))
        return findings

    def _check_hooks(self, ctx, settings) -> list:
        findings = []
        for path, data in settings:
            hooks = data.get('hooks')
            if not isinstance(hooks, dict):
                continue
            evidence = []
            for event, groups in hooks.items():
                if event not in VALID_HOOK_EVENTS:
                    evidence.append({'file': str(path), 'event': event,
                                     'detail': 'unknown hook event'})
                if not isinstance(groups, list):
                    continue
                for group in groups:
                    if not isinstance(group, dict):
                        continue
                    cmds = group.get('hooks')
                    has_command = (isinstance(cmds, list) and any(
                        isinstance(h, dict) and str(h.get('command', '')).strip()
                        for h in cmds))
                    if not has_command:
                        evidence.append({'file': str(path), 'event': event,
                                         'detail': 'hook without command'})
            if evidence:
                findings.append(AdapterFinding(
                    check_id='CLAUDE_HOOKS_INVALID',
                    category='config', severity='medium', status='warn',
                    title='Invalid hooks in Claude Code settings',
                    description=('hooks reference an unknown event or a '
                                 'group without a command; such a '
                                 'hook never fires.'),
                    evidence=evidence,
                    recommendation=('use a documented event and give every '
                                    'group a command. A matcher is only '
                                    'needed to filter tool events and is '
                                    'optional everywhere.'),
                    confidence=0.8))
        return findings

    def _check_dangerous(self, ctx, settings) -> list:
        def walk(obj, found):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if key in _DANGEROUS_FLAGS and value:
                        found.append({'flag': key, 'value': value})
                    walk(value, found)
            elif isinstance(obj, list):
                for item in obj:
                    walk(item, found)

        findings = []
        for path, data in settings:
            found = []
            walk(data, found)
            if found:
                findings.append(AdapterFinding(
                    check_id='CLAUDE_SETTINGS_DANGEROUS',
                    category='security', severity='high', status='fail',
                    title='Permission bypass enabled in Claude Code settings',
                    description=('settings enable dangerouslySkipPermissions '
                                 'or bypassPermissionsMode: the agent acts '
                                 'without any permission prompts.'),
                    evidence=[dict(f, file=str(path)) for f in found],
                    recommendation=('remove the bypass flag and grant the '
                                    'specific permissions instead.'),
                    confidence=0.9))
        return findings

    def _check_mcp_duplicates(self, ctx, settings) -> list:
        mcp = _load_json(ctx.root_path('.mcp.json'))
        names = set()
        if isinstance(mcp, dict) and isinstance(mcp.get('mcpServers'), dict):
            names = set(mcp['mcpServers'])
        findings = []
        if not names:
            return findings
        for path, data in settings:
            servers = data.get('mcpServers')
            if not isinstance(servers, dict):
                continue
            dup = sorted(names & set(servers))
            if dup:
                findings.append(AdapterFinding(
                    check_id='CLAUDE_MCP_DUPLICATE_SERVERS',
                    category='config', severity='medium', status='warn',
                    title='MCP server defined twice',
                    description=('the same server name is defined in '
                                 '.mcp.json and in settings; Claude Code '
                                 'resolves only one of them.'),
                    evidence=[{'file': str(ctx.root_path('.mcp.json'))},
                              {'file': str(path), 'servers': dup}],
                    recommendation=('keep the server in one place, prefer '
                                    '.mcp.json for project servers.'),
                    confidence=0.8))
        return findings

    def _check_agents_frontmatter(self, ctx) -> list:
        agents_dir = ctx.root_path('.claude', 'agents')
        if not agents_dir.is_dir():
            return []
        bad = []
        for md in sorted(agents_dir.glob('*.md')):
            meta = _parse_frontmatter(_read_text(md))
            if not str(meta.get('name') or '').strip() or \
                    not str(meta.get('description') or '').strip():
                bad.append(md)
        if not bad:
            return []
        return [AdapterFinding(
            check_id='CLAUDE_AGENTS_FRONTMATTER',
            category='structure', severity='medium', status='warn',
            title='Subagent file missing frontmatter',
            description=('.claude/agents/*.md needs a name and description '
                         'in the frontmatter; without them the subagent '
                         'cannot be selected.'),
            evidence=[{'file': str(md)} for md in bad],
            recommendation=('add name: and description: to the frontmatter '
                            'of each agent file.'),
            confidence=0.9)]

    def _check_rules_glob_scope(self, ctx) -> list:
        rules = [s for s in self._base_sources(ctx)
                 if s.scope == 'path_scoped' and s.globs]
        if not rules:
            return []
        files = []
        cap_hit = False
        for dirpath, dirnames, filenames in os.walk(ctx.root):
            dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
            for name in filenames:
                files.append(ctx.rel(Path(dirpath) / name))
                if len(files) >= RULES_GLOB_SCAN_CAP:
                    cap_hit = True
                    break
            if cap_hit:
                break
        dead = []
        for rule in rules:
            if cap_hit:
                break   # cannot prove a no-match on a truncated scan
            if not any(_glob_match_path(f, g) for f in files
                       for g in rule.globs):
                dead.append(rule)
        if not dead:
            return []
        return [AdapterFinding(
            check_id='CLAUDE_RULES_GLOB_NOMATCH',
            category='instructions', severity='low', status='warn',
            title='Rule glob matches no file in the workspace',
            description=('a .claude/rules glob has no applicable scope: '
                         'the rule never activates.'),
            evidence=[{'file': str(r.path), 'globs': list(r.globs)}
                      for r in dead],
            recommendation=('fix the glob so it matches real paths, or '
                            'delete the rule.'),
            confidence=0.7)]
