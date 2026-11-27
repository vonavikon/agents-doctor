"""Gemini CLI adapter. Models the documented instruction system of
Google's Gemini CLI (https://docs.gemini-cli, source at
https://github.com/google-gemini/gemini-cli) as a loading model, not a
verified runtime:

- markers      .gemini/ and GEMINI.md at the project root; ~/.gemini in
               the user home. The version cannot be determined offline.
- instructions ~/.gemini/GEMINI.md (user layer), ./GEMINI.md (project
               root), <subdir>/GEMINI.md (nested: loaded while the
               agent works inside that subtree, the one closest to the
               working directory wins) and @path imports: an imported
               file inherits the precedence of its importer +1, at
               most 5 hops deep; the 6th hop is not loaded
- configs      ~/.gemini/settings.json and .gemini/settings.json; MCP
               servers live under mcpServers in the same files
- skills       .gemini/extensions (each extension folder may carry its
               own GEMINI.md) and .gemini/commands (toml commands)
- budget       not documented for the instruction chain

The hierarchical AI memory the real CLI keeps under
~/.gemini/tmp/<hash>/memories/ is not modelled (see known_limitations).
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Optional

from ..base import (AdapterFinding, HarnessAdapter, HarnessContext,
                    InstructionChain, InstructionLink, InstructionSource)
from .. import register

try:
    import tomllib                     # Python 3.11+
except ImportError:                    # Python 3.10: no stdlib TOML
    tomllib = None

USER_PRECEDENCE = 10
PROJECT_PRECEDENCE = 20
NESTED_PRECEDENCE = 30                 # closest nested layer to the target
IMPORT_MAX_HOPS = 5                    # documented import depth limit
NESTED_SCAN_CAP = 2000                 # dirs max when discovering nested

# @path tokens in a GEMINI.md body; approximated with a regex, fenced
# code blocks are not excluded
_IMPORT_RE = re.compile(r'(?:^|\s)@([\w./\\-]+)', re.MULTILINE)


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return ''


def _import_tokens(text: str) -> list:
    """@path tokens in a GEMINI.md body. Trailing sentence punctuation
    is trimmed; tokens without a path separator or a dot (plain @name
    mentions) are ignored — they are not file imports."""
    out = []
    for raw in _IMPORT_RE.findall(text):
        token = raw.rstrip('.,;:!?')
        if token and any(c in token for c in './\\'):
            out.append(token)
    return out


def _resolve_import(token: str, importer: Path,
                    home: Path) -> Optional[Path]:
    """Resolve an @token: relative tokens resolve against the importing
    file's directory, ~-prefixed against the user home, absolute tokens
    as-is. None when the target is not an existing regular file."""
    if token.startswith('~'):
        rest = token[1:].replace('\\', '/').lstrip('/')
        candidate = home.joinpath(*rest.split('/')) if rest else home
    else:
        candidate = importer.parent / token
    try:
        if candidate.is_file():
            return candidate.resolve()
    except (OSError, ValueError):
        pass
    return None


def _nested_gemini_dirs(root: Path, cap: int = NESTED_SCAN_CAP) -> list:
    """Directories below root that contain a GEMINI.md (hidden dirs are
    pruned, the walk is capped for cost). The root itself is not
    included: its GEMINI.md is the project layer."""
    out = []
    root_res = root.resolve()
    walked = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith('.'))
        walked += 1
        if walked > cap:
            break
        here = Path(dirpath)
        if 'GEMINI.md' in filenames and here.resolve() != root_res:
            out.append(here)
    return out


def _walk_imports(ctx: HarnessContext, base_files: list) -> list:
    """Follow @imports from every base GEMINI.md (breadth-first, cycles
    cut). Returns records {token, importer, resolved, hop}; hop 1 is a
    direct import of the base file. Files beyond IMPORT_MAX_HOPS are
    recorded but not descended into: the CLI never loads them, so their
    own imports do not matter."""
    records = []
    for base in base_files:
        visited = {base.resolve()}
        queue = [(base, 0)]
        while queue:
            importer, hop = queue.pop(0)
            for token in _import_tokens(_read_text(importer)):
                resolved = _resolve_import(token, importer, ctx.home)
                records.append({'token': token, 'importer': importer,
                                'resolved': resolved, 'hop': hop + 1})
                if (resolved is not None
                        and hop + 1 <= IMPORT_MAX_HOPS
                        and resolved not in visited):
                    visited.add(resolved)
                    queue.append((resolved, hop + 1))
    return records


@register
class GeminiCliAdapter(HarnessAdapter):
    harness_id = 'gemini_cli'
    display_name = 'Gemini CLI'
    spec_source = ('https://docs.gemini-cli / '
                   'https://github.com/google-gemini/gemini-cli')
    spec_verified = '2026-11-17'
    supported_versions = 'current (unverified)'
    known_limitations = [
        'hierarchical GEMINI.md loading modelled as documented, not '
        'runtime-verified',
        'AI memories under ~/.gemini/tmp/<hash>/memories/ are not '
        'modelled',
        'import depth limit of 5 hops taken from documentation',
        '@import token extraction approximated with a regex; fenced '
        'code blocks are not excluded',
    ]

    # --- conformance: honesty status per capability.
    # No runtime verification exists for this adapter, so
    # 'runtime-tested' never appears: claims trace to the Gemini CLI
    # docs (spec_source) or to a known_limitations entry.
    CAPABILITY_STATUS = {
        # .gemini/, GEMINI.md and ~/.gemini are documented artifacts
        'detection': 'documented',
        # ~/.gemini/settings.json is the documented user config
        'user_settings': 'documented',
        # the GEMINI.md layers themselves are documented, but the
        # hierarchical AI memories are an instruction source the adapter
        # does not see (known_limitations)
        'instruction_hierarchy': 'approximated',
        # user/project/nested chain with closest-to-target-wins per
        # docs; modelled as documented, not runtime-verified
        'loading_order': 'documented',
        # the 5-hop limit is documented, but token extraction is a
        # regex that does not exclude fenced code blocks
        # (known_limitations)
        'imports': 'approximated',
        # GEMINI.md files have no path-scoped rules; nothing to model
        'glob_matching': 'unsupported',
        # subtree GEMINI.md loaded while working inside it, per docs
        'nested_instructions': 'documented',
        # .gemini/extensions and .gemini/commands are documented
        # locations
        'skills': 'documented',
        # mcpServers inside settings.json is documented
        'mcp': 'documented',
        # the sandbox/yolo approval mode is known to exist but no
        # permission model has been collected or implemented
        'permissions': 'unknown',
        # no chain budget is documented for the instruction chain
        # (module docstring); nothing to assert
        'context_budget': 'unknown',
        # no offline version source; detect_version never guesses
        'version_detect': 'unsupported',
        # spec_source re-verified on spec_verified (2026-11-17)
        'spec_freshness': 'documented',
    }

    # ------------------------------------------------- detection
    def project_markers(self, ctx: HarnessContext) -> list:
        return ['.gemini', 'GEMINI.md']

    def home_markers(self, ctx: HarnessContext) -> list:
        return [ctx.home_path('.gemini')]

    def detect_version(self, ctx: HarnessContext) -> Optional[str]:
        return None                   # offline there is no reliable source

    # ------------------------------------------------- instructions
    def instruction_sources(self, ctx: HarnessContext) -> list:
        srcs = []
        user_md = ctx.home_path('.gemini', 'GEMINI.md')
        if ctx.exists(user_md):
            srcs.append(InstructionSource(
                user_md, 'user', 'user-level GEMINI.md (~/.gemini)'))
        root_md = ctx.root_path('GEMINI.md')
        if ctx.exists(root_md):
            srcs.append(InstructionSource(
                root_md, 'project', 'project root GEMINI.md'))
        for d in _nested_gemini_dirs(ctx.root):
            srcs.append(InstructionSource(
                d / 'GEMINI.md', 'nested',
                'subtree GEMINI.md, loaded while the agent works '
                'inside this directory'))
        return srcs

    def resolve_chain(self, ctx: HarnessContext,
                      target_dir: Optional[Path] = None
                      ) -> InstructionChain:
        target = target_dir or ctx.root
        chain = InstructionChain(harness_id=self.harness_id,
                                 target_dir=target)
        root_res = ctx.root.resolve()
        tgt_res = target.resolve()
        # directories on the root->target path (target included)
        on_path = set()
        try:
            rel = tgt_res.relative_to(root_res)
        except ValueError:
            rel = None
        if rel is not None:
            cur = root_res
            for part in rel.parts:
                cur = cur / part
                on_path.add(cur)

        base_links: list = []
        for s in self.instruction_sources(ctx):
            if s.scope == 'user':
                link = InstructionLink(
                    s, precedence=USER_PRECEDENCE,
                    reason='user layer (~/.gemini/GEMINI.md)')
            elif s.scope == 'project':
                link = InstructionLink(
                    s, precedence=PROJECT_PRECEDENCE,
                    reason='project root layer')
            else:                              # nested
                ndir = s.path.resolve().parent
                if ndir in on_path:
                    depth = len(tgt_res.relative_to(ndir).parts)
                    reason = ('nested layer at the target directory'
                              if depth == 0 else
                              'nested layer, %d level(s) above target'
                              % depth)
                    link = InstructionLink(
                        s, precedence=NESTED_PRECEDENCE - depth,
                        reason=reason)
                else:
                    link = InstructionLink(
                        s, precedence=0, active=False,
                        reason='outside target path')
            chain.links.append(link)
            if link.active:
                base_links.append(link)

        self._expand_imports(ctx, chain, base_links)
        return chain

    def _expand_imports(self, ctx: HarnessContext,
                        chain: InstructionChain, base_links: list) -> None:
        """Turn the @imports of the active layers into imported links
        (precedence = importer +1, max 5 hops). Missing targets and
        hop-6+ files land in chain.unloaded."""
        seen: set = set()
        for base in base_links:
            queue = [(base.source.path, 0, base.precedence)]
            while queue:
                importer, hop, prec = queue.pop(0)
                for token in _import_tokens(_read_text(importer)):
                    resolved = _resolve_import(token, importer, ctx.home)
                    if resolved is None:
                        chain.unloaded.append((
                            InstructionSource(
                                importer.parent / token, 'imported',
                                'import in %s' % ctx.rel(importer)),
                            'import target not found'))
                        continue
                    if resolved in seen:
                        continue
                    seen.add(resolved)
                    if hop + 1 > IMPORT_MAX_HOPS:
                        chain.unloaded.append((
                            InstructionSource(
                                resolved, 'imported',
                                'imported by %s' % ctx.rel(importer)),
                            'import chain deeper than %d hops: not loaded'
                            % IMPORT_MAX_HOPS))
                        continue
                    source = InstructionSource(
                        resolved, 'imported',
                        'imported by %s' % ctx.rel(importer))
                    chain.links.append(InstructionLink(
                        source, precedence=prec + 1,
                        reason='import of %s (hop %d)'
                               % (ctx.rel(importer), hop + 1)))
                    queue.append((resolved, hop + 1, prec + 1))

    # ------------------------------------------------- capabilities
    def skills_locations(self, ctx: HarnessContext) -> list:
        return [ctx.root_path('.gemini', 'extensions'),
                ctx.root_path('.gemini', 'commands')]

    def config_files(self, ctx: HarnessContext) -> list:
        files = [ctx.home_path('.gemini', 'settings.json'),
                 ctx.root_path('.gemini', 'settings.json')]
        return [f for f in files if ctx.exists(f)]

    def mcp_config_files(self, ctx: HarnessContext) -> list:
        # mcpServers lives in the same settings.json files
        return self.config_files(ctx)

    def context_budget_bytes(self) -> Optional[int]:
        return None

    # ------------------------------------------------- validation
    def validate(self, ctx: HarnessContext) -> list:
        findings: list = []
        sources = self.instruction_sources(ctx)

        # GEMINI_IMPORT_MISSING / GEMINI_IMPORT_DEPTH
        records = _walk_imports(ctx, [s.path for s in sources])
        missing = [{'file': str(r['importer']), 'import': r['token'],
                    'detail': 'hop %d: target not found or not a '
                              'regular file' % r['hop']}
                   for r in records if r['resolved'] is None]
        if missing:
            findings.append(AdapterFinding(
                check_id='GEMINI_IMPORT_MISSING',
                category='instructions', severity='medium', status='fail',
                title='GEMINI.md import points to a missing file',
                description=(
                    '%d @import(s) in GEMINI.md files resolve to no '
                    'regular file; Gemini CLI loads the instructions '
                    'without them, so the referenced rules silently '
                    'disappear.' % len(missing)),
                evidence=missing,
                recommendation=('fix the @path or create the file; '
                                'relative paths resolve against the '
                                'directory of the importing file.'),
                confidence=0.9))
        deep = [r for r in records if r['hop'] > IMPORT_MAX_HOPS]
        if deep:
            findings.append(AdapterFinding(
                check_id='GEMINI_IMPORT_DEPTH',
                category='instructions', severity='medium', status='warn',
                title='GEMINI.md import chain deeper than 5 hops',
                description=('Gemini CLI follows @imports at most %d '
                             'hops; everything below hop %d is not '
                             'loaded.' % (IMPORT_MAX_HOPS,
                                          IMPORT_MAX_HOPS)),
                evidence=[{'file': str(r['importer']),
                           'import': r['token'],
                           'detail': 'hop %d' % r['hop']} for r in deep],
                recommendation='flatten the import chain to %d hops or '
                               'less.' % IMPORT_MAX_HOPS,
                confidence=0.8))

        # GEMINI_SETTINGS_PARSE
        for f in self.config_files(ctx):
            parse_error = None
            data = None
            try:
                data = json.loads(_read_text(f))
            except ValueError as exc:
                parse_error = str(exc)
            if parse_error is not None:
                findings.append(AdapterFinding(
                    check_id='GEMINI_SETTINGS_PARSE',
                    category='config', severity='high', status='fail',
                    title='Gemini settings.json is not valid JSON',
                    description=('settings.json cannot be parsed; Gemini '
                                 'CLI falls back to defaults and every '
                                 'setting in the file (tools, MCP '
                                 'servers) is ignored.'),
                    evidence=[{'file': str(f), 'detail': parse_error}],
                    recommendation='fix the JSON syntax in settings.json.',
                    confidence=0.95))
                continue
            if not isinstance(data, dict):
                findings.append(AdapterFinding(
                    check_id='GEMINI_SETTINGS_PARSE',
                    category='config', severity='high', status='fail',
                    title='Gemini settings.json is not a JSON object',
                    description=('settings.json parses to %s, expected '
                                 'an object; the file is ignored.'
                                 % type(data).__name__),
                    evidence=[{'file': str(f),
                               'detail': 'parses to %s'
                                         % type(data).__name__}],
                    recommendation=('wrap the settings in a top-level '
                                    'JSON object.'),
                    confidence=0.9))
                continue
            bad_tools = [{'file': str(f), 'key': key,
                          'detail': '%s is %s, expected a list'
                                    % (key, type(data[key]).__name__)}
                         for key in ('excludeTools', 'coreTools')
                         if key in data and not isinstance(data[key], list)]
            if bad_tools:
                findings.append(AdapterFinding(
                    check_id='GEMINI_SETTINGS_PARSE',
                    category='config', severity='medium', status='warn',
                    title='Gemini settings.json tool filters are not '
                          'lists',
                    description=('excludeTools/coreTools must be lists '
                                 'of tool names; a scalar value makes '
                                 'the filter ineffective.'),
                    evidence=bad_tools,
                    recommendation=('write the tool filters as arrays, '
                                    'e.g. "excludeTools": '
                                    '["run_shell_command"].'),
                    confidence=0.85))

        # GEMINI_COMMANDS_FRONTMATTER
        commands_dir = ctx.root_path('.gemini', 'commands')
        toml_files = []
        if ctx.exists(commands_dir):
            try:
                toml_files = sorted(p for p in commands_dir.iterdir()
                                    if p.is_file()
                                    and p.suffix.lower() == '.toml')
            except OSError:
                toml_files = []
        if toml_files and tomllib is None:
            findings.append(AdapterFinding(
                check_id='GEMINI_COMMANDS_FRONTMATTER',
                category='config', severity='info', status='unknown',
                title='Gemini custom commands not checked',
                description=('tomllib is unavailable on this python; '
                             'the .toml command files were not parsed '
                             'and the description check did not run.'),
                evidence=[{'file': str(p), 'detail': 'not parsed'}
                          for p in toml_files],
                recommendation=('rerun the scan on Python 3.11+ where '
                                'tomllib is available.'),
                confidence=0.3))
        else:
            no_desc, bad_toml = [], []
            for p in toml_files:
                try:
                    data = tomllib.loads(_read_text(p))
                except ValueError as exc:
                    bad_toml.append({'file': str(p),
                                     'detail': str(exc)[:200]})
                    continue
                desc = data.get('description')
                if not (isinstance(desc, str) and desc.strip()):
                    no_desc.append({'file': str(p),
                                    'detail': 'no description key'})
            if bad_toml:
                findings.append(AdapterFinding(
                    check_id='GEMINI_COMMANDS_FRONTMATTER',
                    category='config', severity='medium', status='fail',
                    title='Gemini custom command is not valid TOML',
                    description=('a .toml file under .gemini/commands/ '
                                 'fails to parse; Gemini CLI cannot '
                                 'load the command.'),
                    evidence=bad_toml,
                    recommendation='fix the TOML syntax in the command '
                                   'file.',
                    confidence=0.9))
            if no_desc:
                findings.append(AdapterFinding(
                    check_id='GEMINI_COMMANDS_FRONTMATTER',
                    category='config', severity='low', status='warn',
                    title='Gemini custom command without description',
                    description=('command .toml files without a '
                                 'description are hard to pick: the '
                                 'description is what the model sees '
                                 'when choosing between commands.'),
                    evidence=no_desc,
                    recommendation=('add a description key to each '
                                    'command file.'),
                    confidence=0.9))

        # GEMINI_NESTED_ORPHAN
        nested = [s for s in sources if s.scope == 'nested']
        has_root_md = ctx.exists(ctx.root_path('GEMINI.md'))
        if nested and not has_root_md:
            findings.append(AdapterFinding(
                check_id='GEMINI_NESTED_ORPHAN',
                category='structure', severity='low', status='info',
                title='Nested GEMINI.md without a project root GEMINI.md',
                description=('documented hierarchical loading treats the '
                             'root GEMINI.md as the main entry; nested '
                             'files load only inside their own subtree, '
                             'so project-wide rules have no home'),
                evidence=[{'file': str(s.path),
                           'detail': 'nested GEMINI.md; root GEMINI.md '
                                     'missing'} for s in nested],
                recommendation=('move shared rules into a root GEMINI.md '
                                'or accept the subtree-only scope.'),
                confidence=0.85))

        # GEMINI_EXTENSION_LAYOUT
        ext_dir = ctx.root_path('.gemini', 'extensions')
        if ctx.exists(ext_dir):
            try:
                subs = sorted(p for p in ext_dir.iterdir() if p.is_dir())
            except OSError:
                subs = []
            bad_ext = [{'file': str(sub),
                        'detail': 'no GEMINI.md inside the extension '
                                  'folder'}
                       for sub in subs
                       if not ctx.exists(sub / 'GEMINI.md')]
            if bad_ext:
                findings.append(AdapterFinding(
                    check_id='GEMINI_EXTENSION_LAYOUT',
                    category='structure', severity='low', status='warn',
                    title='Gemini extension folder without GEMINI.md',
                    description=('every folder under .gemini/extensions/ '
                                 'is treated as an extension through its '
                                 'GEMINI.md; a folder without one is '
                                 'dead weight the CLI cannot load'),
                    evidence=bad_ext,
                    recommendation=('add a GEMINI.md to the extension '
                                    'folder or remove the folder.'),
                    confidence=0.85))

        return findings
