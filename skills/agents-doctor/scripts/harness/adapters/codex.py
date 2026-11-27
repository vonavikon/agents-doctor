"""OpenAI Codex adapter. Model of the documented Codex CLI behaviour,
now the single source for everything the core scanner used to hardcode
for Codex (CHAIN_BUDGET in audit_scan.py):

- project markers  .codex, AGENTS.md, AGENTS.override.md, .agents
- home state dir   ~/.codex (version file, config.toml, global AGENTS.md)
- instructions     ~/.codex/AGENTS.md (global base layer),
                   ./AGENTS.md (project root),
                   ./AGENTS.override.md (root override, wins over all),
                   nested <subdir>/AGENTS.md loaded while the agent works
                   inside that subtree
- merge model      all layers root->target load together (concat); the
                   nearer a layer is to the working directory, the higher
                   its precedence on rule collisions
- skills           .agents/skills (project); never an instruction source
- config           ~/.codex/config.toml, .codex/config.toml (project)
- MCP servers      [mcp_servers.*] tables inside the same config.toml
- budget           32768 bytes for the global+project+nested AGENTS.md
                   chain
"""
from __future__ import annotations

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

CHAIN_BUDGET_BYTES = 32768             # mirrors CHAIN_BUDGET in audit_scan.py


def _looks_like_secret(value: str) -> bool:
    """True when a literal env value looks like a live credential.
    ${VAR} / $VAR templates are indirection, not secrets."""
    v = value.strip()
    if not v or v.startswith('$'):
        return False
    if v.lower().startswith('bearer '):
        return len(v) - len('bearer ') >= 20
    if v.startswith('sk-'):
        return len(v) >= 20
    if len(v) >= 40 and re.fullmatch(r'[A-Za-z0-9+/=]+', v):
        return True                     # long base64-ish blob
    return False


def _secret_kind(value: str) -> str:
    v = value.strip()
    if v.lower().startswith('bearer '):
        return 'bearer token'
    if v.startswith('sk-'):
        return 'sk- style key'
    return 'base64 blob'


@register
class CodexAdapter(HarnessAdapter):
    harness_id = 'codex'
    display_name = 'OpenAI Codex'
    spec_source = 'https://developers.openai.com/codex'
    spec_verified = '2026-11-17'
    supported_versions = 'current CLI (unverified)'
    known_limitations = [
        'AGENTS.md merge order modelled as documented, not runtime-verified',
        'project .codex/config.toml support varies by version',
    ]

    # --- conformance: honesty status per capability.
    # No runtime verification exists for this adapter, so
    # 'runtime-tested' never appears: claims trace to the Codex docs
    # (spec_source) or to a known_limitations entry.
    CAPABILITY_STATUS = {
        # .codex/, AGENTS.md and AGENTS.override.md are documented
        # project artifacts; the engine just combines the markers
        'detection': 'documented',
        # ~/.codex/config.toml is the documented user config; only the
        # project-level .codex/config.toml varies by version
        # (known_limitations)
        'user_settings': 'documented',
        # global -> project -> override -> nested layering per docs;
        # the override file is a documented mechanism
        'instruction_hierarchy': 'documented',
        # concat merge with nearer-to-target-wins per docs; modelled as
        # documented, not runtime-verified (known_limitations)
        'loading_order': 'documented',
        # the AGENTS.md format defines no @import indirection, so none
        # is modelled
        'imports': 'unsupported',
        # AGENTS.md has no path-scoped rules; nothing to model
        'glob_matching': 'unsupported',
        # modelled with a deviation: first-level subdir AGENTS.md are
        # active even for the root target, deeper ones only on the
        # root->target path — the runtime reads them lazily instead
        'nested_instructions': 'approximated',
        # only the shared .agents/skills dir is listed; native Codex
        # skill discovery has not been verified against the docs
        'skills': 'unknown',
        # [mcp_servers.*] tables inside config.toml are documented
        'mcp': 'documented',
        # sandbox_mode / approval_policy semantics per docs
        'permissions': 'documented',
        # the 32768-byte chain budget is carried from the legacy scanner
        # constant ("Codex truncation budget", docs/gates.md); not
        # re-verified against the current official docs
        'context_budget': 'approximated',
        # sniffs ~/.codex/version and config.toml keys — a heuristic
        # over state files, not a documented interface
        'version_detect': 'approximated',
        # spec_source re-verified on spec_verified (2026-11-17)
        'spec_freshness': 'documented',
    }

    # ------------------------------------------------- detection
    def project_markers(self, ctx: HarnessContext) -> list:
        return ['.codex', 'AGENTS.md', 'AGENTS.override.md', '.agents']

    def dir_conflict_map(self, ctx: HarnessContext) -> list:
        return ['.codex']

    def home_markers(self, ctx: HarnessContext) -> list:
        return [ctx.home_path('.codex')]

    def detect_version(self, ctx: HarnessContext) -> Optional[str]:
        ver_file = ctx.home_path('.codex', 'version')
        if ctx.exists(ver_file):
            try:
                text = ver_file.read_text(
                    encoding='utf-8', errors='replace').strip()
            except OSError:
                text = ''
            if text:
                return text
        cfg = ctx.home_path('.codex', 'config.toml')
        if ctx.exists(cfg) and tomllib is not None:
            try:
                data = tomllib.loads(
                    cfg.read_text(encoding='utf-8', errors='replace'))
            except (tomllib.TOMLDecodeError, OSError, ValueError):
                return None
            for key in ('codex_version', 'version'):
                val = data.get(key)
                if isinstance(val, str) and val.strip():
                    return val.strip()
        return None                       # never guess

    # ------------------------------------------------- instructions
    def _nested_sources(self, ctx: HarnessContext,
                        target: Optional[Path] = None) -> list:
        """AGENTS.md in first-level subdirectories plus, when target is
        given, every AGENTS.md on the root->target path at any depth.
        Hidden directories (.git, .agents, ...) are skipped."""
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
                rel = None               # target outside root: path set empty
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
        global_md = ctx.home_path('.codex', 'AGENTS.md')
        if ctx.exists(global_md):
            srcs.append(InstructionSource(
                global_md, 'global', 'user-level global AGENTS.md'))
        root_md = ctx.root_path('AGENTS.md')
        if ctx.exists(root_md):
            srcs.append(InstructionSource(
                root_md, 'project', 'project root AGENTS.md'))
        override_md = ctx.root_path('AGENTS.override.md')
        if ctx.exists(override_md):
            srcs.append(InstructionSource(
                override_md, 'project',
                'root override layer, wins over every other source'))
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

        for s in sources:
            if s.scope == 'global':
                chain.links.append(InstructionLink(
                    s, precedence=1, active=True,
                    reason='global base layer'))
            elif s.path.name == 'AGENTS.override.md':
                chain.links.append(InstructionLink(
                    s, precedence=100, active=True,
                    reason='override layer at root, wins over all layers'))
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
        return [ctx.root_path('.agents', 'skills')]

    def config_files(self, ctx: HarnessContext) -> list:
        files = [ctx.home_path('.codex', 'config.toml'),
                 ctx.root_path('.codex', 'config.toml')]
        return [f for f in files if ctx.exists(f)]

    def mcp_config_files(self, ctx: HarnessContext) -> list:
        # MCP servers live in [mcp_servers.*] tables of the same files
        return self.config_files(ctx)

    def context_budget_bytes(self) -> Optional[int]:
        return CHAIN_BUDGET_BYTES

    # ------------------------------------------------- validation
    def validate(self, ctx: HarnessContext) -> list:
        findings = []

        # CODEX_OVERRIDE_IGNORED: override without a base file
        has_override = ctx.exists(ctx.root_path('AGENTS.override.md'))
        has_root_md = ctx.exists(ctx.root_path('AGENTS.md'))
        if has_override and not has_root_md:
            findings.append(AdapterFinding(
                check_id='CODEX_OVERRIDE_IGNORED',
                category='structure', severity='medium', status='warn',
                title='AGENTS.override.md without a base AGENTS.md',
                description=(
                    'The override file is designed to patch a project '
                    'AGENTS.md. With no base file present it silently '
                    'becomes the only project instruction layer, and its '
                    'overrides may refer to rules that do not exist.'),
                evidence=[{'file': ctx.root_path('AGENTS.override.md'),
                           'detail': 'override present, base AGENTS.md '
                                     'missing'}],
                recommendation=('add a root AGENTS.md or delete the '
                                'override file.'),
                confidence=0.9))

        # CODEX_CHAIN_BUDGET: global + project + nested sizes vs budget
        total, per_file = 0, []
        for s in self.instruction_sources(ctx):
            if s.path.name != 'AGENTS.md':
                continue
            try:
                size = s.path.stat().st_size
            except OSError:
                continue
            total += size
            per_file.append({'file': str(s.path),
                             'detail': '%d bytes' % size})
        if total > CHAIN_BUDGET_BYTES:
            findings.append(AdapterFinding(
                check_id='CODEX_CHAIN_BUDGET',
                category='instructions', severity='medium', status='warn',
                title='AGENTS.md chain over the Codex context budget',
                description=(
                    'global + project + nested AGENTS.md total %d bytes, '
                    'over the %d-byte budget. Codex loads the whole chain '
                    'into context, so the bloat displaces working context.'
                    % (total, CHAIN_BUDGET_BYTES)),
                evidence=per_file,
                recommendation=('shorten the files or move subtree-specific '
                                'rules into nested AGENTS.md so only the '
                                'active subtree pays for them.'),
                confidence=0.85))

        # config.toml checks
        parsed = []
        unavailable = False
        for f in self.config_files(ctx):
            if tomllib is None:
                unavailable = True
                continue
            try:
                data = tomllib.loads(
                    f.read_text(encoding='utf-8', errors='replace'))
            except (tomllib.TOMLDecodeError, OSError, ValueError) as e:
                findings.append(AdapterFinding(
                    check_id='CODEX_TOML_PARSE',
                    category='config', severity='high', status='fail',
                    title='Codex config.toml fails to parse',
                    description=('config.toml is not valid TOML and Codex '
                                 'cannot read it: %s' % str(e)[:200]),
                    evidence=[{'file': str(f),
                               'detail': str(e)[:200]}],
                    recommendation=('fix the TOML syntax; validate with '
                                    'python -c "import tomllib;'
                                    ' tomllib.load(...)"'),
                    confidence=0.9))
                continue
            parsed.append((f, data))
        if unavailable:
            findings.append(AdapterFinding(
                check_id='CODEX_TOML_PARSE',
                category='config', severity='info', status='unknown',
                title='Codex config.toml not checked',
                description=('tomllib unavailable on this python; the '
                             'config.toml files were not parsed and the '
                             'sandbox/approval/MCP checks did not run.'),
                evidence=[{'file': str(f), 'detail': 'not parsed'}
                          for f in self.config_files(ctx)],
                recommendation=('rerun the scan on Python 3.11+ where '
                                'tomllib is available.'),
                confidence=0.3))

        for f, data in parsed:
            danger = data.get('sandbox_mode') == 'danger-full-access'
            never = data.get('approval_policy') == 'never'
            if danger:
                desc = ("sandbox_mode = 'danger-full-access' disables the "
                        "Codex sandbox: the agent runs with full host "
                        "filesystem and network access.")
                if never:
                    desc += (" The same file also sets approval_policy = "
                             "'never', so no confirmation is ever "
                             "requested: the agent can take any action "
                             "unattended.")
                findings.append(AdapterFinding(
                    check_id='CODEX_SANDBOX_DANGER',
                    category='security', severity='critical',
                    status='fail',
                    title='Codex sandbox fully disabled',
                    description=desc,
                    evidence=[{'file': str(f),
                               'detail': "sandbox_mode = "
                                         "'danger-full-access'"
                                         + (" + approval_policy = 'never'"
                                            if never else '')}],
                    recommendation=("use sandbox_mode = 'workspace-write' "
                                    "or stricter and keep an approval "
                                    "policy that asks before acting "
                                    "outside the workspace."),
                    confidence=0.95))
            elif never:
                findings.append(AdapterFinding(
                    check_id='CODEX_APPROVAL_NEVER',
                    category='security', severity='high', status='fail',
                    title='Codex agent acts without confirmations',
                    description=("approval_policy = 'never': the agent "
                                 "executes commands and applies changes "
                                 "without ever asking the user."),
                    evidence=[{'file': str(f),
                               'detail': "approval_policy = 'never'"}],
                    recommendation=("switch to 'on-request' or another "
                                    "policy that asks before risky steps."),
                    confidence=0.9))

            # CODEX_MCP_ENV_SECRETS: literal credentials in MCP env
            servers = data.get('mcp_servers')
            if not isinstance(servers, dict):
                continue
            hits = []
            for name, block in servers.items():
                if not isinstance(block, dict):
                    continue
                env = block.get('env')
                if not isinstance(env, dict):
                    continue
                for key, val in env.items():
                    if isinstance(val, str) and _looks_like_secret(val):
                        # evidence is masked: kind and length only
                        hits.append({'file': str(f), 'detail':
                                     'mcp_servers.%s.env.%s: literal %s '
                                     '(%d chars)'
                                     % (name, key, _secret_kind(val),
                                        len(val))})
            if hits:
                findings.append(AdapterFinding(
                    check_id='CODEX_MCP_ENV_SECRETS',
                    category='security', severity='high', status='fail',
                    title='Literal secrets in Codex MCP server env',
                    description=('env values under [mcp_servers.*] contain '
                                 'literal credentials; anyone who can read '
                                 'the config gets live keys. ${VAR} '
                                 'templates are fine, literal values are '
                                 'not.'),
                    evidence=hits,
                    recommendation=('move the values into environment '
                                    'variables and reference them as '
                                    '${VAR}; rotate the exposed keys.'),
                    confidence=0.85))
        return findings
