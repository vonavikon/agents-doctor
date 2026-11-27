"""OpenCode adapter. Model of the documented OpenCode behaviour:

- project markers  .opencode, opencode.json, opencode.jsonc, AGENTS.md
- home dir         ~/.config/opencode (global config + global AGENTS.md)
- instructions     ~/.config/opencode/AGENTS.md (global base layer),
                   ./AGENTS.md (project root),
                   custom file from the `instruction` config key
                   (project scope, wins over the root AGENTS.md),
                   nested <subdir>/AGENTS.md loaded while the agent works
                   inside that subtree
- merge model      all layers load together; the nearer a layer is to
                   the working directory, the higher its precedence on
                   rule collisions (modelled, not runtime-verified)
- skills           .opencode/command, .opencode/agent, .opencode/plugin
- config           opencode.json / opencode.jsonc (project; jsonc is
                   JSON with // line comments),
                   ~/.config/opencode/opencode.json (global)
- MCP servers      `mcp` (or legacy `mcpServers`) key of the same files
- budget           not documented -> None
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from ..base import (AdapterFinding, HarnessAdapter, HarnessContext,
                    InstructionChain, InstructionLink, InstructionSource)
from .. import register

try:
    import content_quality
except ImportError:                     # harness imported outside scripts/
    content_quality = None

DRIFT_WINDOW_LINES = 3                  # duplicate block size, mirrors
                                        # DUPLICATE_BLOCK_LINES in conflicts
DRIFT_MAX_BLOCKS = 2000                 # cap windows hashed per file


def _normalize_line(line: str) -> str:
    """content_quality._normalize, with a same-semantics fallback when
    the module is not importable (lowercase, keep word chars)."""
    if content_quality is not None:
        return content_quality._normalize(line)
    return ' '.join(re.findall(r'\w+', line.lower()))


def _strip_jsonc_comments(text: str) -> str:
    """Remove // line comments, string-aware so 'https://...' inside a
    JSON string survives. Block comments are not handled (heuristic)."""
    out = []
    i, n = 0, len(text)
    in_string = False
    while i < n:
        c = text[i]
        if in_string:
            out.append(c)
            if c == '\\' and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_string = False
            i += 1
        elif c == '"':
            in_string = True
            out.append(c)
            i += 1
        elif c == '/' and i + 1 < n and text[i + 1] == '/':
            while i < n and text[i] != '\n':   # skip to end of line
                i += 1
        else:
            out.append(c)
            i += 1
    return ''.join(out)


def _load_config(path: Path):
    """Parse an opencode config. Returns (data, error): data is a dict
    on success, None on any parse failure with error explaining why."""
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except OSError as e:
        return None, str(e)
    if path.suffix == '.jsonc':
        text = _strip_jsonc_comments(text)
        stage = 'not valid JSON after stripping // comments'
    else:
        stage = 'not valid JSON'
    try:
        data = json.loads(text)
    except ValueError as e:
        return None, '%s: %s' % (stage, str(e)[:200])
    if not isinstance(data, dict):
        return None, ('top-level value is %s, not an object'
                      % type(data).__name__)
    return data, None


def _read_lines(path: Path) -> list:
    try:
        return path.read_text(
            encoding='utf-8', errors='replace').splitlines()
    except OSError:
        return []


def _windows(lines: list):
    """(start, normalized 3-line window, raw window) for one file."""
    for start in range(0, max(0, len(lines) - DRIFT_WINDOW_LINES + 1)):
        if start >= DRIFT_MAX_BLOCKS:
            break
        window = lines[start:start + DRIFT_WINDOW_LINES]
        norm = tuple(_normalize_line(w) for w in window)
        if not any(norm):
            continue
        yield start, norm, window


def _first_duplicate_block(path_a: Path, path_b: Path):
    """First 3-line block (normalized) present in both files, as
    evidence dicts, or None when the files share no block."""
    seen = {}
    for start, norm, _w in _windows(_read_lines(path_a)):
        seen.setdefault(norm, start)
    for start, norm, window in _windows(_read_lines(path_b)):
        if norm in seen:
            preview = ' / '.join(w.strip() for w in window
                                 if w.strip())[:200]
            return [
                {'file': str(path_a), 'line': seen[norm] + 1,
                 'detail': 'duplicated block starts here'},
                {'file': str(path_b), 'line': start + 1,
                 'detail': 'same %d lines: %s'
                           % (DRIFT_WINDOW_LINES, preview)},
            ]
    return None


def _frontmatter_has_description(text: str):
    """(ok, detail) for an agent markdown file: ok when it opens with a
    closed --- block that carries a non-empty description key."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != '---':
        return False, 'no frontmatter block'
    end = None
    for i in range(1, min(len(lines), 60)):
        if lines[i].strip() == '---':
            end = i
            break
    if end is None:
        return False, 'frontmatter block is not closed'
    for line in lines[1:end]:
        if re.match(r'^\s*description\s*:\s*\S', line):
            return True, ''
    return False, 'frontmatter has no description'


@register
class OpencodeAdapter(HarnessAdapter):
    harness_id = 'opencode'
    display_name = 'OpenCode'
    spec_source = 'https://opencode.ai/docs/config/'
    spec_verified = '2026-11-17'
    supported_versions = 'current (unverified)'
    known_limitations = [
        'jsonc comment stripping is heuristic (string-aware // line '
        'comments only; /* */ block comments are not handled)',
        'AGENTS.md merge order and the `instruction` file precedence are '
        'modelled from the docs, not runtime-verified',
    ]

    # --- conformance: how we know each capability.
    # No runtime verification exists for this adapter, so 'runtime-tested'
    # never appears; every entry cites where the knowledge comes from.
    CAPABILITY_STATUS = {
        # marker files (.opencode, opencode.json[c], AGENTS.md) and
        # ~/.config/opencode are the documented discovery surface
        'detection': 'documented',
        # ~/.config/opencode/opencode.json + global AGENTS.md: documented
        # locations, discovered and parsed by this adapter
        'user_settings': 'documented',
        # global -> project root -> `instruction` override -> nested
        # layers follow the documented rules layout
        'instruction_hierarchy': 'documented',
        # precedence numbers (1/10/15, 10*(depth+1)) are this adapter's
        # model of the documented merge order, not runtime-verified
        'loading_order': 'approximated',
        # OpenCode documents no @import-style indirection for AGENTS.md;
        # there is nothing to parse, so none is modelled
        'imports': 'unsupported',
        # OpenCode instruction files carry no path-scoped glob rules;
        # no glob engine is needed or implemented
        'glob_matching': 'unsupported',
        # subdir AGENTS.md loaded while the agent works inside that
        # subtree: documented mechanism, discovered and resolved
        'nested_instructions': 'documented',
        # .opencode/command|agent|plugin are the documented locations;
        # only the locations are exposed, no skill parsing
        'skills': 'documented',
        # the `mcp`/`mcpServers` keys are documented, but reading them
        # rides the heuristic jsonc stripper (see known_limitations)
        'mcp': 'approximated',
        # permission model (bash/edit/write allow-ask-deny) per docs;
        # checked by OPENCODE_PERMISSIONS_DANGEROUS
        'permissions': 'documented',
        # no instruction-size budget in the docs; budget stays None
        'context_budget': 'unknown',
        # detect_version always returns None — never guess offline
        'version_detect': 'unsupported',
        # spec_verified refreshed against opencode.ai/docs/config/
        'spec_freshness': 'documented',
    }

    # ------------------------------------------------- detection
    def project_markers(self, ctx: HarnessContext) -> list:
        return ['.opencode', 'opencode.json', 'opencode.jsonc', 'AGENTS.md']

    def dir_conflict_map(self, ctx: HarnessContext) -> list:
        return ['.opencode']

    def home_markers(self, ctx: HarnessContext) -> list:
        return [ctx.home_path('.config', 'opencode')]

    def detect_version(self, ctx: HarnessContext) -> Optional[str]:
        return None                       # never guess

    # ------------------------------------------------- paths
    def _global_config(self, ctx: HarnessContext) -> Path:
        return ctx.home_path('.config', 'opencode', 'opencode.json')

    def _project_configs(self, ctx: HarnessContext) -> list:
        return [ctx.root_path('opencode.json'),
                ctx.root_path('opencode.jsonc')]

    def config_files(self, ctx: HarnessContext) -> list:
        files = [self._global_config(ctx)] + self._project_configs(ctx)
        return [f for f in files if ctx.exists(f)]

    def mcp_config_files(self, ctx: HarnessContext) -> list:
        # servers live in the `mcp` (or `mcpServers`) key of the same files
        return self.config_files(ctx)

    # ------------------------------------------------- instructions
    def _global_agents_md(self, ctx: HarnessContext) -> Path:
        return ctx.home_path('.config', 'opencode', 'AGENTS.md')

    def _instruction_entry(self, ctx: HarnessContext):
        """(config, raw value, resolved path) for the first project
        config that sets `instruction`; None when none does. The path is
        returned even when it does not exist (callers check)."""
        for cfg in self._project_configs(ctx):
            if not ctx.exists(cfg):
                continue
            data, _err = _load_config(cfg)
            if not isinstance(data, dict):
                continue
            val = data.get('instruction')
            if not isinstance(val, str) or not val.strip():
                continue
            p = Path(val).expanduser()
            if not p.is_absolute():
                p = ctx.root_path(val)
            return cfg, val, p
        return None

    def _instruction_file(self, ctx: HarnessContext) -> Optional[Path]:
        entry = self._instruction_entry(ctx)
        return entry[2] if entry else None

    def _nested_sources(self, ctx: HarnessContext,
                        target: Optional[Path] = None) -> list:
        """AGENTS.md in first-level subdirectories plus, when target is
        given, every AGENTS.md on the root->target path at any depth.
        Hidden directories (.git, .opencode, ...) are skipped."""
        dirs, seen = [], set()

        def _add(d: Path) -> None:
            if d not in seen:
                seen.add(d)
                dirs.append(d)

        try:
            first = sorted(ctx.root.iterdir())
        except OSError:
            first = []
        for e in first:
            if e.is_dir() and not e.name.startswith('.'):
                _add(e.resolve())
        if target is not None:
            try:
                rel = target.resolve().relative_to(ctx.root.resolve())
            except ValueError:
                rel = None               # target outside root: path empty
            if rel is not None:
                cur = ctx.root.resolve()
                for part in rel.parts:
                    cur = cur / part
                    _add(cur)
        out = []
        for d in dirs:
            md = d / 'AGENTS.md'
            if ctx.exists(md):
                out.append(InstructionSource(
                    md, 'nested',
                    'subtree AGENTS.md, loaded while the agent works '
                    'inside this directory'))
        return out

    def instruction_sources(self, ctx: HarnessContext) -> list:
        srcs = []
        global_md = self._global_agents_md(ctx)
        if ctx.exists(global_md):
            srcs.append(InstructionSource(
                global_md, 'global', 'user-level global AGENTS.md'))
        root_md = ctx.root_path('AGENTS.md')
        if ctx.exists(root_md):
            srcs.append(InstructionSource(
                root_md, 'project', 'project root AGENTS.md'))
        inst = self._instruction_file(ctx)
        if inst is not None and ctx.exists(inst):
            if not any(s.path.resolve() == inst.resolve() for s in srcs):
                srcs.append(InstructionSource(
                    inst, 'project',
                    'custom instruction file from the `instruction` '
                    'config key, wins over the root AGENTS.md'))
        srcs.extend(self._nested_sources(ctx))
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

        sources = self.instruction_sources(ctx)
        # instruction_sources only walks first-level dirs; add deeper
        # AGENTS.md found on the root->target path
        known_nested = {s.path.resolve() for s in sources
                        if s.scope == 'nested'}
        for s in self._nested_sources(ctx, target):
            if s.path.resolve() not in known_nested:
                sources.append(s)
                known_nested.add(s.path.resolve())

        inst = self._instruction_file(ctx)
        inst_res = inst.resolve() if inst is not None else None

        for s in sources:
            if s.scope == 'global':
                chain.links.append(InstructionLink(
                    s, precedence=1, active=True,
                    reason='global base layer'))
            elif inst_res is not None and s.path.resolve() == inst_res:
                chain.links.append(InstructionLink(
                    s, precedence=15, active=True,
                    reason='custom instruction file from config, wins '
                           'over the root AGENTS.md'))
            elif s.scope == 'project':
                chain.links.append(InstructionLink(
                    s, precedence=10, active=True,
                    reason='project root layer'))
            else:                          # nested
                ndir = s.path.resolve().parent
                if tgt_res == root_res or ndir in on_path:
                    depth = len(ndir.relative_to(root_res).parts)
                    chain.links.append(InstructionLink(
                        s, precedence=10 * (depth + 1), active=True,
                        reason='nested layer %d level(s) below root'
                               % depth))
                else:
                    chain.links.append(InstructionLink(
                        s, precedence=0, active=False,
                        reason='outside target path'))
        return chain

    # ------------------------------------------------- capabilities
    def skills_locations(self, ctx: HarnessContext) -> list:
        return [ctx.root_path('.opencode', 'command'),
                ctx.root_path('.opencode', 'agent'),
                ctx.root_path('.opencode', 'plugin')]

    def context_budget_bytes(self) -> Optional[int]:
        return None

    # ------------------------------------------------- validation
    def validate(self, ctx: HarnessContext) -> list:
        findings = []

        # ---- parse every config once; OPENCODE_CONFIG_PARSE on failure
        parsed = []
        for f in self.config_files(ctx):
            data, err = _load_config(f)
            if data is None:
                findings.append(AdapterFinding(
                    check_id='OPENCODE_CONFIG_PARSE',
                    category='config', severity='high', status='fail',
                    title='opencode config fails to parse',
                    description=('%s is %s, so OpenCode cannot read it '
                                 'and every config-dependent check is '
                                 'blind.' % (f.name, err)),
                    evidence=[{'file': str(f), 'detail': err}],
                    recommendation=('fix the JSON syntax; for jsonc keep '
                                    'comments on their own // lines.'),
                    confidence=0.9))
            else:
                parsed.append((f, data))

        # ---- OPENCODE_INSTRUCTION_MISSING
        entry = self._instruction_entry(ctx)
        if entry is not None and not ctx.exists(entry[2]):
            cfg, val, p = entry
            findings.append(AdapterFinding(
                check_id='OPENCODE_INSTRUCTION_MISSING',
                category='config', severity='medium', status='fail',
                title='instruction file from opencode config is missing',
                description=('The `%s` config names "%s" as the custom '
                             'instruction file, but that file does not '
                             'exist; the instruction layer it should '
                             'provide silently never loads.'
                             % (cfg.name, val)),
                evidence=[{'file': str(cfg),
                           'detail': 'instruction = "%s"' % val},
                          {'file': str(p), 'detail': 'not found'}],
                recommendation=('create the file or fix the instruction '
                                'path in the config.'),
                confidence=0.9))

        # ---- OPENCODE_PERMISSIONS_DANGEROUS
        for f, data in parsed:
            perm = data.get('permission')
            if not isinstance(perm, dict):
                perm = data.get('permissions')
            if isinstance(perm, dict):
                self._check_permissions(f, perm, findings)

        # ---- OPENCODE_MCP_PARSE
        for f, data in parsed:
            bad = [key for key in ('mcp', 'mcpServers')
                   if key in data and not isinstance(data[key], dict)]
            if bad:
                findings.append(AdapterFinding(
                    check_id='OPENCODE_MCP_PARSE',
                    category='config', severity='medium', status='warn',
                    title='mcp section in opencode config is not an object',
                    description=('The %s key(s) in %s do not hold an '
                                 'object; OpenCode cannot read server '
                                 'definitions from them, so MCP tools '
                                 'silently stay unavailable.'
                                 % (', '.join(bad), f.name)),
                    evidence=[{'file': str(f),
                               'detail': '%s = %s' % (key,
                                                      type(data[key])
                                                      .__name__)
                               } for key in bad],
                    recommendation=('make the mcp section an object of '
                                    'server definitions: "mcp": {"name": '
                                    '{"command": ...}}.'),
                    confidence=0.8))

        # ---- OPENCODE_AGENT_FRONTMATTER
        agent_dir = ctx.root_path('.opencode', 'agent')
        if agent_dir.is_dir():
            try:
                entries = sorted(agent_dir.iterdir())
            except OSError:
                entries = []
            for e in entries:
                if not (e.is_file() and e.suffix == '.md'):
                    continue
                try:
                    text = e.read_text(encoding='utf-8', errors='replace')
                except OSError:
                    continue
                ok, detail = _frontmatter_has_description(text)
                if not ok:
                    findings.append(AdapterFinding(
                        check_id='OPENCODE_AGENT_FRONTMATTER',
                        category='structure', severity='medium',
                        status='warn',
                        title='OpenCode agent file lacks a description',
                        description=('%s has %s; without a description '
                                     'the agent cannot say when to pick '
                                     'this agent over the default one.'
                                     % (e.name, detail)),
                        evidence=[{'file': str(e), 'detail': detail}],
                        recommendation=('add a frontmatter block with a '
                                        'one-line description:\n---\n'
                                        'description: ...\n---'),
                        confidence=0.8))

        # ---- OPENCODE_GLOBAL_LOCAL_DRIFT
        global_md = self._global_agents_md(ctx)
        root_md = ctx.root_path('AGENTS.md')
        if ctx.exists(global_md) and ctx.exists(root_md):
            hit = _first_duplicate_block(global_md, root_md)
            if hit is not None:
                findings.append(AdapterFinding(
                    check_id='OPENCODE_GLOBAL_LOCAL_DRIFT',
                    category='instructions', severity='low', status='warn',
                    title=('global and project AGENTS.md duplicate '
                           'each other'),
                    description=('The global AGENTS.md and the project '
                                 'AGENTS.md share at least %d consecutive '
                                 'lines; every OpenCode session loads '
                                 'them twice, and the two copies drift '
                                 'apart on the next edit.'
                                 % DRIFT_WINDOW_LINES),
                    evidence=hit,
                    recommendation=('keep the shared lines in one file: '
                                    'project-specific rules in the '
                                    'project AGENTS.md, machine-wide '
                                    'habits in the global one.'),
                    confidence=0.7))
        return findings

    @staticmethod
    def _check_permissions(f: Path, perm: dict, findings: list) -> None:
        """OPENCODE_PERMISSIONS_DANGEROUS on one permissions object:
        bash wildcard allow -> fail/high; edit/write unrestricted or no
        deny fencing rm -rf -> warn/medium."""
        # bash: every command allowed
        bash = perm.get('bash')
        bash_wildcard = bash == '*'
        if isinstance(bash, dict) and bash.get('*') == 'allow':
            bash_wildcard = True
        if bash_wildcard:
            findings.append(AdapterFinding(
                check_id='OPENCODE_PERMISSIONS_DANGEROUS',
                category='security', severity='high', status='fail',
                title='OpenCode bash permissions allow every command',
                description=('permissions.bash allows the "*" pattern: '
                             'the agent may run any shell command, '
                             'including destructive ones, without a '
                             'deny rule or a confirmation.'),
                evidence=[{'file': str(f), 'detail': 'bash: "*" -> allow'}],
                recommendation=('replace the wildcard with allow entries '
                                'for the commands the agent needs and '
                                'deny the rest.'),
                confidence=0.9))
        elif isinstance(bash, dict):
            allows = [k for k, v in bash.items() if v == 'allow']
            fenced = any(v == 'deny' and ('rm' in str(k).lower()
                                          or k == '*')
                         for k, v in bash.items())
            if allows and not fenced:
                findings.append(AdapterFinding(
                    check_id='OPENCODE_PERMISSIONS_DANGEROUS',
                    category='security', severity='medium', status='warn',
                    title='No deny rule fences rm -rf style commands',
                    description=('permissions.bash lists allow rules but '
                                 'no deny pattern covers rm -rf style '
                                 'commands; a prompt that talks the '
                                 'agent into rm -rf meets no fence.'),
                    evidence=[{'file': str(f),
                               'detail': '%d bash rule(s), none denies rm'
                                         % len(bash)}],
                    recommendation=('add "rm -rf *": "deny" (and '
                                    '"rm -fr *": "deny") before the '
                                    'allow rules.'),
                    confidence=0.7))

        # edit / write: unrestricted file changes
        for key in ('edit', 'write'):
            sec = perm.get(key)
            if sec in ('allow', '*'):
                unrestricted, detail = True, '%s: "%s"' % (key, sec)
            elif isinstance(sec, dict):
                denies = [v for v in sec.values() if v == 'deny']
                unrestricted = (sec.get('*') == 'allow' and not denies)
                detail = '%s: "*" -> allow, no deny' % key
            else:
                unrestricted = False
                detail = ''
            if unrestricted:
                findings.append(AdapterFinding(
                    check_id='OPENCODE_PERMISSIONS_DANGEROUS',
                    category='security', severity='medium', status='warn',
                    title='OpenCode %s permissions unrestricted' % key,
                    description=('permissions.%s allows every file change '
                                 'without a deny rule or a confirmation; '
                                 'the agent can rewrite anything in the '
                                 'workspace, including files it was only '
                                 'asked to read.' % key),
                    evidence=[{'file': str(f), 'detail': detail}],
                    recommendation=('switch to "ask", or list the paths '
                                    'the agent may change and deny the '
                                    'rest.'),
                    confidence=0.75))
