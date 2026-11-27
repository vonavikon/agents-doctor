"""Harness adapter contract.

Every supported AI-agent environment (Claude Code, Codex, Cursor, ...)
is described by one adapter class. The adapter is the single place that
knows the environment's markers, instruction-loading rules, config files
and structure expectations. The core scanner and the gates ask the
registry; they never hardcode a harness again.

Design rules:
- adapters FEED the existing nine gates, they do not replace them;
- every claim carries evidence and confidence;
- when a behaviour cannot be confirmed against the real runtime, the
  adapter reports it as a model (`approximated=True`), never as fact;
- an absent optional file is never an error by itself.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# --- conformance vocabulary -------------------------------------------
# Every adapter capability carries one of these honesty statuses. They
# describe HOW WE KNOW something, separate from whether it works.
CAPABILITY_STATUSES = (
    'documented',        # confirmed against official documentation
    'runtime-tested',    # verified experimentally on a real runtime
    'approximated',      # an approximate model (documented deviations)
    'unsupported',       # deliberately not modelled yet
    'unknown',           # not enough data — the default
)

# The capability names every adapter is graded on.
CAPABILITY_KEYS = (
    'detection',              # project + home discovery
    'user_settings',          # user-level configuration discovery
    'instruction_hierarchy',  # instruction sources + precedence model
    'loading_order',          # what loads for a target directory
    'imports',                # @import-style indirection
    'glob_matching',          # path-scoped rules semantics
    'nested_instructions',    # subdirectory instruction loading
    'skills',                 # skill locations and parsing
    'mcp',                    # MCP configuration knowledge
    'permissions',            # permission/sandbox model
    'context_budget',         # documented budget limits
    'version_detect',         # installed-version detection
    'spec_freshness',         # how recent the doc verification is
)


@dataclass
class HarnessContext:
    """Resolved paths and cheap helpers handed to every adapter call."""
    root: Path                      # workspace root (resolved)
    home: Path                      # user home (resolved; --home flag)

    def rel(self, path: Path) -> str:
        """Path relative to root with forward slashes, for evidence."""
        try:
            return path.resolve().relative_to(self.root.resolve()).as_posix()
        except ValueError:
            return str(path)

    def root_path(self, *parts: str) -> Path:
        return self.root.joinpath(*parts)

    def home_path(self, *parts: str) -> Path:
        return self.home.joinpath(*parts)

    def exists(self, path: Path) -> bool:
        try:
            return path.exists()
        except OSError:
            return False


@dataclass
class Detection:
    """Result of harness detection for one adapter.

    status: 'detected'  - project-level markers present
            'possible'  - only weak/global signals
            'not_found' - no signals at all
    confidence: 'high' | 'medium' | 'low'. A single file is never proof
    of active use: high confidence needs markers AND activity.
    """
    harness_id: str
    status: str = 'not_found'
    confidence: str = 'low'
    evidence: list = field(default_factory=list)   # human-readable strings
    activity: str = 'unknown'   # active | occasional | abandoned | unknown
    version: Optional[str] = None
    markers: list = field(default_factory=list)    # found marker rel-paths


@dataclass
class InstructionSource:
    """One instruction file the harness may load."""
    path: Path
    scope: str          # global | user | project | nested | path_scoped | imported
    description: str = ''
    # for path_scoped rules: the glob patterns from frontmatter, if any
    globs: list = field(default_factory=list)
    always_apply: bool = False

    def to_dict(self):
        return {'path': str(self.path), 'scope': self.scope,
                'description': self.description, 'globs': list(self.globs),
                'always_apply': self.always_apply}


@dataclass
class InstructionLink:
    """One source resolved for a specific target directory."""
    source: InstructionSource
    precedence: int = 0    # higher wins when rules collide
    active: bool = True    # False = present but not loaded for this target
    reason: str = ''       # why inactive / why this precedence


@dataclass
class InstructionChain:
    """Effective instruction set for a target directory.

    approximated=True means the chain follows the documented loading
    model, not a verified runtime harness.
    """
    harness_id: str
    target_dir: Path
    links: list = field(default_factory=list)         # InstructionLink
    conflicts: list = field(default_factory=list)     # dicts with paths+detail
    unloaded: list = field(default_factory=list)      # (source, reason)
    approximated: bool = True

    @property
    def loaded(self) -> list:
        return [l for l in self.links if l.active]

    def to_dict(self):
        return {
            'harness': self.harness_id,
            'target_dir': str(self.target_dir),
            'approximated': self.approximated,
            'loaded': [
                {'path': str(l.source.path), 'scope': l.source.scope,
                 'precedence': l.precedence, 'reason': l.reason}
                for l in self.loaded],
            'overridden': [
                {'path': str(l.source.path), 'precedence': l.precedence,
                 'reason': l.reason}
                for l in self.links if not l.active],
            'unloaded': [{'path': str(s.path), 'reason': r}
                         for s, r in self.unloaded],
            'conflicts': list(self.conflicts),
        }


@dataclass
class AdapterFinding:
    """A harness-specific finding in adapter shape.

    check_id is the STABLE identifier (e.g. CLAUDE_INSTRUCTION_CONFLICT);
    the report fid stays a per-scan counter. The gate engine maps
    AdapterFinding into the report finding model.
    """
    check_id: str
    category: str            # structure | instructions | config | security | compatibility
    severity: str            # critical | high | medium | low | info
    status: str              # fail | warn | pass | unknown | not_applicable
    title: str
    description: str
    evidence: list = field(default_factory=list)   # dicts {file,line?,detail}
    recommendation: str = ''
    confidence: float = 0.8

    def to_dict(self):
        return {
            'check_id': self.check_id, 'category': self.category,
            'severity': self.severity, 'status': self.status,
            'title': self.title, 'description': self.description,
            'evidence': list(self.evidence),
            'recommendation': self.recommendation,
            'confidence': self.confidence,
        }


class HarnessAdapter:
    """Base class. Subclasses set the identity fields and override the
    methods they can honestly implement. Defaults are conservative: no
    markers, no instructions, no findings — a harness that reports
    nothing changes nothing."""

    harness_id: str = ''            # 'claude_code'
    display_name: str = ''          # 'Claude Code'
    # adapter version, independent of the product version:
    # bump only when THIS adapter's behaviour or checks change
    adapter_version: str = '1.0.0'
    # --- spec provenance: keep honest, update when re-verified
    spec_source: str = ''           # URL of the official documentation
    spec_verified: str = ''         # 'YYYY-MM-DD' of the last check
    supported_versions: str = ''    # free text, '' = unverified
    known_limitations: list = []    # human-readable strings
    # --- conformance: per-capability honesty status.
    # Keys are capability names from CAPABILITY_KEYS; values from
    # CAPABILITY_STATUSES. A capability absent here reads as 'unknown'
    # downstream — never as pass.
    CAPABILITY_STATUS: dict = {}

    # ------------------------------------------------- detection
    def project_markers(self, ctx: HarnessContext) -> list:
        """Relative paths whose presence in a project marks this harness
        (e.g. ['.claude/settings.json']). Existence only; the detection
        engine combines them with activity and never treats one file as
        proof of active use."""
        return []

    def dir_conflict_map(self, ctx: HarnessContext) -> list:
        """Project markers that imply EXCLUSIVE ownership of a directory
        for the G1 harness-env-conflict rule (first adapter to claim a
        marker wins, registry order). Only set this for directories the
        harness alone owns; '.agents' belongs to zcode there."""
        return []

    def home_markers(self, ctx: HarnessContext) -> list:
        """Absolute paths in the user home that mark an installation
        (e.g. ['~/.claude']). Weaker than project markers."""
        return []

    def detect_version(self, ctx: HarnessContext) -> Optional[str]:
        """Best-effort version; None when it cannot be determined
        reliably. Never guess."""
        return None

    # ------------------------------------------------- instructions
    def instruction_sources(self, ctx: HarnessContext) -> list:
        """All instruction sources this harness may read."""
        return []

    def resolve_chain(self, ctx: HarnessContext,
                      target_dir: Optional[Path] = None
                      ) -> Optional[InstructionChain]:
        """Effective instruction set for target_dir (root when None).
        Follows the documented loading model of THIS harness; sets
        approximated=True unless verified against a runtime."""
        return None

    # ------------------------------------------------- capabilities
    def skills_locations(self, ctx: HarnessContext) -> list:
        """Directories that may contain skills (SKILL.md)."""
        return []

    def config_files(self, ctx: HarnessContext) -> list:
        """Config files to parse-validate for G2 (JSON/TOML)."""
        return []

    def mcp_config_files(self, ctx: HarnessContext) -> list:
        """Files that may define MCP servers (subset of config_files)."""
        return []

    def context_budget_bytes(self) -> Optional[int]:
        """Harness instruction-size budget in bytes, if documented."""
        return None

    # ------------------------------------------------- validation
    def validate(self, ctx: HarnessContext) -> list:
        """Harness-specific structure and config checks. Return
        AdapterFinding list; unknown territory must yield status
        'unknown', never a pass."""
        return []

    def spec_info(self) -> dict:
        statuses = {}
        for key in CAPABILITY_KEYS:
            raw = self.CAPABILITY_STATUS.get(key, 'unknown')
            statuses[key] = raw if raw in CAPABILITY_STATUSES else 'unknown'
        return {
            'harness_id': self.harness_id,
            'display_name': self.display_name,
            'adapter_version': self.adapter_version,
            'spec_source': self.spec_source,
            'spec_verified': self.spec_verified,
            'supported_versions': self.supported_versions,
            'known_limitations': list(self.known_limitations),
            'capability_status': statuses,
        }

    def adapter_quality(self) -> dict:
        """Diagnostic quality of THIS adapter — deliberately
        separate from workspace health. Statuses map to evidence
        weights; the score is a simple mean, printed with the formula
        so nobody has to trust a bare number. unsupported/unknown
        score 0 — they are gaps, not achievements."""
        weights = {'runtime-tested': 1.0, 'documented': 0.75,
                   'approximated': 0.4, 'unsupported': 0.0,
                   'unknown': 0.0}
        statuses = self.spec_info()['capability_status']
        per = {k: weights[v] for k, v in statuses.items()}
        score = round(sum(per.values()) / len(per), 2) if per else 0.0
        return {'score': score, 'weights': weights,
                'per_capability': statuses}
