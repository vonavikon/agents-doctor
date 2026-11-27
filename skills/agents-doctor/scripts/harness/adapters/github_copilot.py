"""GitHub Copilot adapter (repo instructions model).

Offline model of the documented repo-level instruction behaviour,
based on https://docs.github.com/en/copilot. Not verified against a
runtime: every resolved chain keeps approximated=True.

- markers     .github/copilot-instructions.md, .github/instructions/,
              .github/prompts/. No home markers: global ("personal")
              instructions live in the editor settings UI, not in a
              file the scanner could see (known limitation).
- instructions
              .github/copilot-instructions.md — main project file,
              always loaded;
              .github/instructions/*.md — path-scoped instruction
              files: frontmatter `applyTo: <globs>` decides which
              files they apply to; without applyTo the file never
              applies (warn);
              .github/prompts/*.md — prompt files used on demand
              (e.g. chat participants / slash prompts), never
              auto-instructions.
- chain       main file precedence 20; instructions/*.md precedence 30
              when an applyTo glob matches the target directory
              (fnmatch + dir-prefix glob semantics as in cursor),
              otherwise inactive; prompts always inactive.
              approximated=True.
- configs     .github/copilot-mcp.yml (YAML; no PyYAML dependency, so
              validated only heuristically: the file must expose at
              least one plausible top-level `key:` line), and
              .github/mcp.json (JSON, parsed fully). Both are
              mcp_config_files.
- skills      .github/prompts, .github/agents (when present).
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

MAIN_INSTRUCTIONS = ('.github', 'copilot-instructions.md')
INSTRUCTIONS_DIR = ('.github', 'instructions')
PROMPTS_DIR = ('.github', 'prompts')
AGENTS_DIR = ('.github', 'agents')
MCP_YML = ('.github', 'copilot-mcp.yml')
MCP_JSON = ('.github', 'mcp.json')

MAIN_INSTRUCTION_MAX_BYTES = 25 * 1024   # Copilot trims/ignores bloated
                                         # main instructions; documented
                                         # guidance is to keep it short
APPLYTO_SCAN_CAP = 5000                  # paths max when proving that an
                                         # applyTo glob matches nothing
_PRUNE_DIRS = {'.git'}                   # never glob scope

_YAML_TOP_KEY_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_-]*\s*:')


# ----------------------------------------------------- text helpers
def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return ''


def _strip_quotes(value: str) -> str:
    v = value.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
        return v[1:-1]
    return v


def _parse_frontmatter(text: str) -> Optional[dict]:
    """Minimal YAML frontmatter parser for the keys Copilot files use
    (description, applyTo). Scalar `key: value` pairs, quoted values
    and `- item` block lists; None when there is no closed '---'
    block. A strict YAML parser is not a dependency here."""
    lines = text.lstrip('\ufeff').splitlines()
    if not lines or lines[0].strip() != '---':
        return None
    data: dict = {}
    last_key = None
    closed = False
    for line in lines[1:]:
        s = line.strip()
        if s == '---':
            closed = True
            break
        if s.startswith('- ') and last_key is not None:
            current = data.get(last_key)
            if isinstance(current, list):
                current.append(_strip_quotes(s[2:]))
            continue
        if ':' in s:
            key, _, value = s.partition(':')
            last_key = key.strip()
            value = value.strip()
            data[last_key] = _strip_quotes(value) if value else []
    return data if closed else None


def _split_applyto(value) -> list:
    """applyTo frontmatter value -> list of glob patterns. GitHub
    separates multiple patterns with a comma; YAML block lists and
    inline [a, b] lists are accepted too."""
    if not value:
        return []
    if isinstance(value, list):
        items = [str(i) for i in value]
    else:
        s = str(value).strip()
        if s.startswith('[') and s.endswith(']'):
            s = s[1:-1]
        items = re.split(r'[,\s]+', s)
    return [g for g in (_strip_quotes(i).strip() for i in items) if g]


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
    """Approximated glob match for a relative POSIX path: fnmatch plus
    a directory-prefix rule, same semantics as the cursor adapter."""
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


def _workspace_relpaths(root: Path, cap: int = APPLYTO_SCAN_CAP) -> list:
    """Relative POSIX paths of files and directories under root
    (pruning .git), capped — used to test whether an applyTo glob has
    any applicable scope at all."""
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


def _yaml_has_top_key(text: str) -> bool:
    """Heuristic stand-in for a YAML parser: does the file expose at
    least one plausible top-level `key:` line? Comments, blanks,
    indented (nested) lines and list items do not count."""
    for line in text.splitlines():
        s = line.rstrip('\r')
        if not s or s[:1] in (' ', '\t', '#', '-'):
            continue
        if _YAML_TOP_KEY_RE.match(s):
            return True
    return False


@register
class GithubCopilotAdapter(HarnessAdapter):
    harness_id = 'github_copilot'
    display_name = 'GitHub Copilot'
    spec_source = 'https://docs.github.com/en/copilot'
    spec_verified = '2026-11-17'
    supported_versions = 'current (unverified)'
    known_limitations = [
        'global instructions live in editor settings, not the repo; '
        'they cannot be detected or validated offline',
        'YAML mcp config validated heuristically (no top-level key '
        'check only, no full YAML parse)',
    ]

    # --- conformance: how we know each capability.
    # No runtime verification exists for this adapter, so 'runtime-tested'
    # never appears; every entry cites where the knowledge comes from.
    CAPABILITY_STATUS = {
        # .github/copilot-instructions.md, instructions/, prompts/ are
        # the documented repo-level markers; no home markers exist by
        # design (see user_settings)
        'detection': 'documented',
        # global ("personal") instructions are edited in the editor
        # settings UI, not stored as a scannable file — no data offline
        'user_settings': 'unknown',
        # main file + applyTo-scoped instructions/*.md + on-demand
        # prompts follow the documented repo-instructions model
        'instruction_hierarchy': 'documented',
        # precedence numbers (main 20, scoped 30) and root-level glob
        # matching are this adapter's model, not runtime-verified
        'loading_order': 'approximated',
        # Copilot instruction files document no @import indirection;
        # there is nothing to parse, so none is modelled
        'imports': 'unsupported',
        # applyTo globs are documented, but matching rides the
        # fnmatch + dir-prefix heuristic shared with the cursor adapter
        'glob_matching': 'approximated',
        # Copilot has no per-subdirectory instruction files; path
        # scoping is glob-based (applyTo), so nesting is not modelled
        'nested_instructions': 'unsupported',
        # .github/prompts and .github/agents are the documented
        # locations; frontmatter expectations checked by validate()
        'skills': 'documented',
        # mcp.json is parsed fully, but copilot-mcp.yml only gets the
        # heuristic top-level-key check (no full YAML parse)
        'mcp': 'approximated',
        # Copilot has no repo-level permission config; permission
        # toggles live in editor settings, deliberately not modelled
        'permissions': 'unsupported',
        # Copilot trims bloated main instructions, but the exact 25KB
        # threshold is this adapter's approximation of "keep it short"
        'context_budget': 'approximated',
        # detect_version always returns None — never guess offline
        'version_detect': 'unsupported',
        # spec_verified refreshed against docs.github.com/en/copilot
        'spec_freshness': 'documented',
    }

    # ------------------------------------------------- detection
    def project_markers(self, ctx: HarnessContext) -> list:
        return ['.github/copilot-instructions.md', '.github/instructions',
                '.github/prompts']

    def home_markers(self, ctx: HarnessContext) -> list:
        # global Copilot instructions are edited in the UI settings,
        # not stored as a scannable file
        return []

    def detect_version(self, ctx: HarnessContext) -> Optional[str]:
        return None

    # ------------------------------------------------- instructions
    def _instruction_records(self, ctx: HarnessContext) -> list:
        """One record per instruction-ish file: kind is 'main' |
        'scoped' | 'prompt'; carries the parsed frontmatter and the
        applyTo globs so sources, chain and validate share one model."""
        records = []
        main = ctx.root_path(*MAIN_INSTRUCTIONS)
        if ctx.exists(main):
            records.append({
                'kind': 'main',
                'source': InstructionSource(
                    main, 'project', 'main instruction file'),
                'globs': [], 'fm': None, 'has_fm': False,
            })
        instr_dir = ctx.root_path(*INSTRUCTIONS_DIR)
        if ctx.exists(instr_dir):
            for md in sorted(instr_dir.glob('*.md')):
                fm = _parse_frontmatter(_read_text(md))
                globs = _split_applyto(fm.get('applyTo')) if fm else []
                desc = str((fm or {}).get('description') or '').strip()
                records.append({
                    'kind': 'scoped',
                    'source': InstructionSource(
                        md, 'path_scoped', desc or md.stem, globs=globs),
                    'globs': globs, 'fm': fm, 'has_fm': fm is not None,
                })
        prompts_dir = ctx.root_path(*PROMPTS_DIR)
        if ctx.exists(prompts_dir):
            for md in sorted(prompts_dir.glob('*.md')):
                fm = _parse_frontmatter(_read_text(md))
                desc = str((fm or {}).get('description') or '').strip()
                records.append({
                    'kind': 'prompt',
                    'source': InstructionSource(
                        md, 'project', desc or md.stem),
                    'globs': [], 'fm': fm, 'has_fm': fm is not None,
                })
        return records

    def instruction_sources(self, ctx: HarnessContext) -> list:
        return [r['source'] for r in self._instruction_records(ctx)]

    def resolve_chain(self, ctx: HarnessContext,
                      target_dir: Optional[Path] = None
                      ) -> InstructionChain:
        target = Path(target_dir) if target_dir is not None else ctx.root
        if not target.is_absolute():
            target = ctx.root / target
        chain = InstructionChain(harness_id=self.harness_id,
                                 target_dir=target)
        rel = ctx.rel(target)
        if rel == '.':        # ctx.rel() of the root itself
            rel = ''
        for rec in self._instruction_records(ctx):
            src = rec['source']
            if rec['kind'] == 'main':
                chain.links.append(InstructionLink(
                    src, precedence=20,
                    reason='main instruction file: always loaded'))
            elif rec['kind'] == 'scoped':
                if not rec['globs']:
                    chain.links.append(InstructionLink(
                        src, precedence=30, active=False,
                        reason='no applyTo in frontmatter: never applied'))
                elif any(_glob_matches(rel, g) for g in rec['globs']):
                    chain.links.append(InstructionLink(
                        src, precedence=30,
                        reason='applyTo matches target'))
                else:
                    chain.links.append(InstructionLink(
                        src, precedence=30, active=False,
                        reason='glob does not match target'))
            else:  # prompt file
                chain.links.append(InstructionLink(
                    src, precedence=0, active=False,
                    reason='prompt file: used on demand'))
        # strongest first; stable within one precedence level
        chain.links.sort(key=lambda l: -l.precedence)
        return chain

    # ------------------------------------------------- capabilities
    def skills_locations(self, ctx: HarnessContext) -> list:
        out = []
        for parts in (PROMPTS_DIR, AGENTS_DIR):
            d = ctx.root_path(*parts)
            if ctx.exists(d):
                out.append(d)
        return out

    def config_files(self, ctx: HarnessContext) -> list:
        candidates = [ctx.root_path(*MCP_YML), ctx.root_path(*MCP_JSON)]
        return [f for f in candidates if ctx.exists(f)]

    def mcp_config_files(self, ctx: HarnessContext) -> list:
        return self.config_files(ctx)

    def context_budget_bytes(self) -> Optional[int]:
        return None  # no documented instruction budget

    # ------------------------------------------------- validation
    def validate(self, ctx: HarnessContext) -> list:
        findings: list = []
        records = self._instruction_records(ctx)
        findings.extend(self._check_missing_applyto(records))
        findings.extend(self._check_applyto_nomatch(ctx, records))
        findings.extend(self._check_prompt_frontmatter(records))
        findings.extend(self._check_main_too_big(ctx))
        findings.extend(self._check_mcp_json(ctx))
        findings.extend(self._check_mcp_yaml(ctx))
        findings.extend(self._check_agent_files(ctx))
        return findings

    # ------------------------------------------------- checks
    def _check_missing_applyto(self, records) -> list:
        bad = [r for r in records
               if r['kind'] == 'scoped' and not r['globs']]
        if not bad:
            return []
        return [AdapterFinding(
            check_id='COPILOT_INSTRUCTIONS_MISSING_APPLYTO',
            category='instructions', severity='medium', status='warn',
            title='Instruction file without applyTo',
            description=('instruction file(s) under .github/instructions/ '
                         'have no applyTo in the frontmatter: Copilot '
                         'never applies them to any file'),
            evidence=[{'file': str(r['source'].path),
                       'detail': 'no applyTo key in frontmatter'}
                      for r in bad],
            recommendation=('add an applyTo glob (e.g. applyTo: "**/*.py") '
                            'or move the content into copilot-instructions.md.'),
            confidence=0.9)]

    def _check_applyto_nomatch(self, ctx, records) -> list:
        scoped = [r for r in records
                  if r['kind'] == 'scoped' and r['globs']]
        if not scoped:
            return []
        paths = _workspace_relpaths(ctx.root)
        cap_hit = len(paths) >= APPLYTO_SCAN_CAP
        dead = []
        for r in scoped:
            if cap_hit:
                break   # cannot prove a no-match on a truncated scan
            if not any(_glob_matches(p, g) for p in paths
                       for g in r['globs']):
                dead.append(r)
        if not dead:
            return []
        return [AdapterFinding(
            check_id='COPILOT_APPLYTO_NOMATCH',
            category='instructions', severity='low', status='warn',
            title='applyTo glob has no applicable scope',
            description=('instruction file(s) whose applyTo globs match no '
                         'file in the workspace: no applicable scope, the '
                         'instruction never loads'),
            evidence=[{'file': str(r['source'].path),
                       'globs': list(r['globs'])} for r in dead],
            recommendation=('fix the applyTo globs so they match real '
                            'paths, or delete the instruction file.'),
            confidence=0.7)]

    def _check_prompt_frontmatter(self, records) -> list:
        bad = []
        for r in records:
            if r['kind'] != 'prompt':
                continue
            desc = str((r['fm'] or {}).get('description') or '').strip()
            if not desc:
                detail = ('no YAML frontmatter block' if not r['has_fm']
                          else 'frontmatter has no description')
                bad.append({'file': str(r['source'].path),
                            'detail': detail})
        if not bad:
            return []
        return [AdapterFinding(
            check_id='COPILOT_PROMPT_FRONTMATTER',
            category='structure', severity='low', status='info',
            title='Prompt file without frontmatter',
            description=('prompt file(s) under .github/prompts/ have no '
                         'frontmatter or no description; the description '
                         'is what Copilot shows when the prompt is picked'),
            evidence=bad,
            recommendation=('add a frontmatter block with a description '
                            'to each prompt file.'),
            confidence=0.9)]

    def _check_main_too_big(self, ctx) -> list:
        main = ctx.root_path(*MAIN_INSTRUCTIONS)
        if not ctx.exists(main):
            return []
        try:
            size = main.stat().st_size
        except OSError:
            return []
        if size <= MAIN_INSTRUCTION_MAX_BYTES:
            return []
        return [AdapterFinding(
            check_id='COPILOT_MAIN_TOO_BIG',
            category='instructions', severity='medium', status='warn',
            title='copilot-instructions.md exceeds %d KB'
                  % (MAIN_INSTRUCTION_MAX_BYTES // 1024),
            description=('the main instruction file is %d bytes; Copilot '
                         'trims or ignores bloated instruction files, so '
                         'rules near the end may silently drop out'
                         % size),
            evidence=[{'file': str(main), 'size': size,
                       'limit': MAIN_INSTRUCTION_MAX_BYTES}],
            recommendation=('keep copilot-instructions.md under %d KB and '
                            'move file-specific rules into .github/'
                            'instructions/*.md with applyTo.'
                            % (MAIN_INSTRUCTION_MAX_BYTES // 1024)),
            confidence=0.8)]

    def _check_mcp_json(self, ctx) -> list:
        mcp = ctx.root_path(*MCP_JSON)
        if not ctx.exists(mcp):
            return []
        try:
            with open(mcp, 'r', encoding='utf-8') as fh:
                json.load(fh)
        except (OSError, ValueError) as exc:
            return [AdapterFinding(
                check_id='COPILOT_MCP_JSON_PARSE',
                category='config', severity='high', status='fail',
                title='.github/mcp.json is not valid JSON',
                description=('.github/mcp.json cannot be parsed; MCP '
                             'servers defined there do not load'),
                evidence=[{'file': str(mcp), 'detail': str(exc)}],
                recommendation='fix the JSON syntax in mcp.json.',
                confidence=0.95)]
        return []

    def _check_mcp_yaml(self, ctx) -> list:
        yml = ctx.root_path(*MCP_YML)
        if not ctx.exists(yml):
            return []
        if _yaml_has_top_key(_read_text(yml)):
            return []
        return [AdapterFinding(
            check_id='COPILOT_MCP_YAML_HEURISTIC',
            category='config', severity='medium', status='warn',
            title='copilot-mcp.yml looks unparseable',
            description=('heuristic YAML check found no top-level `key:` '
                         'line in .github/copilot-mcp.yml; the file is '
                         'probably broken and its servers do not load'),
            evidence=[{'file': str(yml),
                       'detail': 'no top-level key found by heuristic'}],
            recommendation=('check the YAML syntax of copilot-mcp.yml '
                            '(keys like servers: at the top level).'),
            confidence=0.6)]

    def _check_agent_files(self, ctx) -> list:
        agents_dir = ctx.root_path(*AGENTS_DIR)
        if not ctx.exists(agents_dir):
            return []
        bad = []
        for md in sorted(agents_dir.glob('*.md')):
            fm = _parse_frontmatter(_read_text(md))
            desc = str((fm or {}).get('description') or '').strip()
            if not desc:
                bad.append(md)
        if not bad:
            return []
        return [AdapterFinding(
            check_id='COPILOT_AGENT_FILES',
            category='structure', severity='low', status='warn',
            title='Agent file without description',
            description=('.github/agents/*.md needs a description in the '
                         'frontmatter; without it the agent cannot be '
                         'selected in the agent list'),
            evidence=[{'file': str(md)} for md in bad],
            recommendation=('add a description: to the frontmatter of '
                            'each agent file.'),
            confidence=0.9)]
