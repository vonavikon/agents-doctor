"""Gate engine: turns scanner facts into the nine gates and typed findings.

Input is the rep dict from audit_scan.scan() plus the optional stage-2
fact sections: config_integrity, heavy_outside_git, junk_classified and
skills_extra (or the same fields merged into skills.entries). Every
section is optional: a section that is entirely absent yields unknown
rules, never a silent pass. A section that is present but empty is data:
it passes when nothing is wrong, except where the spec says absence
itself matters (configuration files, secret prevention) -- there it
warns, because absence of evidence must not read as a pass.

Thresholds live in GATE_POLICY so the scanner and the tests import one
source of truth. This module deliberately does not import audit_scan
(circular); audit_scan.py keeps its own PROJECT_BENCH / CHAIN_BUDGET /
SKILL_DESC_LIMIT copies for now and will switch to importing GATE_POLICY
when the stage-2 integration lands.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import glossary  # noqa: E402
import report_model  # noqa: E402

# --- single source of truth for thresholds --------------------------------

GATE_POLICY = {
    # total size of junk files + junk/build dirs that fails G9
    'JUNK_FAIL_BYTES': 500 * 1024 * 1024,
    # more empty dirs than this turns the info-level observation into a warn
    'EMPTY_WARN_COUNT': 10,
    # a tracked file at or over this size fails G7
    'TRACKED_BIG_BYTES': 5 * 1024 * 1024,
    # skill description limit; above it the harness refuses to load the skill
    'DESC_LIMIT': 1024,
    # project instruction file benchmark (audit_scan.PROJECT_BENCH)
    'PROJECT_BENCH': 16 * 1024,
    # AGENTS.md chain budget, root + nested (audit_scan.CHAIN_BUDGET)
    'CHAIN_BUDGET': 32768,
    # An instruction file smaller than this is a pointer or a stub: its
    # signal ratio is a hint to look, never a warning. Size is judged in
    # bytes, not in lines: a file of two very long lines is not short.
    'SHORT_INSTRUCTION_BYTES': 2048,
    # what counts as a secret-prevention mechanism for G6
    'SECRET_PREVENTION_HINTS': {
        # only these hooks count as prevention when they run a secret scan
        'hook_names': ('pre-commit', 'pre-push'),
        # key inside hook flags set by the scanner
        'scan_flag': 'secret_scan',
        # patterns a .gitignore must cover; contents are not in the facts
        # yet, so a hook is the only verifiable proof today
        'gitignore_patterns': ('.env', '.mcp.json'),
    },
}

# --- declarative gate definitions -------------------------------------------

GATE_DEFS = [
    {
        'gid': 'G1', 'n': 1, 'name': 'Workspace structure',
        'description': 'Workspace layout sanity: one instruction source per level, '
                       'no unexpected nesting, no conflicting agent environments.',
        'pass_when': 'no drifted AGENTS.md/CLAUDE.md pairs, no nested repositories, '
                     'project directories match the harnesses in use',
        'fail_when': 'an AGENTS.md/CLAUDE.md pair at one level is neither identical '
                     'nor a pointer',
        'warn_when': 'a repository is nested inside another repository; project '
                     'directories exist for several harnesses while at most one is active',
        'recommendation': 'Fix the layout: one instruction source per level, no nested '
                          'repositories, project dirs only for harnesses in use.',
        'doc_ref': 'README.md#the-nine-gates',
    },
    {
        'gid': 'G2', 'n': 2, 'name': 'Configuration integrity',
        'description': 'Configuration files parse and have no duplicate keys.',
        'pass_when': 'every configuration file parses and each key occurs once',
        'fail_when': 'a configuration file has a syntax error or duplicate keys',
        'warn_when': 'no configuration files were found at all',
        'recommendation': 'Fix or remove broken config files; keep one key per setting.',
        'doc_ref': 'README.md#the-nine-gates',
    },
    {
        'gid': 'G3', 'n': 3, 'name': 'Rules consistency',
        'description': 'Instruction files resolve, agree and stay within budgets.',
        'pass_when': 'no dead references, no drifted pairs, no boilerplate, '
                     'files within the 16 KB benchmark and the 32768-byte chain budget',
        'fail_when': 'dead links, paths or commands; a drifted AGENTS.md/CLAUDE.md pair',
        'warn_when': 'generic boilerplate in auto-loaded context; an instruction file '
                     'over 16 KB; the AGENTS.md chain over 32768 bytes',
        'recommendation': 'Repair dead references, merge drifted pairs, replace '
                          'boilerplate with project-specific rules.',
        'doc_ref': 'README.md#the-nine-gates',
    },
    {
        'gid': 'G4', 'n': 4, 'name': 'Directory ownership and discoverability',
        'description': 'Every directory has a decided fate; valuable data sits under version control.',
        'pass_when': 'no heavy data directories outside git, no loose top-level folders',
        'fail_when': 'a heavy non-build directory sits outside every git repository',
        'warn_when': 'other top-level folders outside version control',
        'recommendation': 'Give every folder a fate: version control, archive or deletion.',
        'doc_ref': 'README.md#the-nine-gates',
    },
    {
        'gid': 'G5', 'n': 5, 'name': 'Skills and agent capabilities',
        'description': 'Skills have valid frontmatter, usable descriptions and synced copies.',
        'pass_when': 'frontmatter parses with the required fields, descriptions are under '
                     '1024 chars with triggers, copies are identical, references resolve',
        'fail_when': 'missing name or description, unparseable frontmatter, a description '
                     'over 1024 chars, diverged copies of one skill',
        'warn_when': 'no trigger phrase in a description; a skill references a missing file; '
                     'frontmatter parsed with the fallback parser (unknown)',
        'recommendation': 'Repair skill frontmatter, shorten descriptions, sync or remove '
                          'diverged copies.',
        'doc_ref': 'README.md#the-nine-gates',
    },
    {
        'gid': 'G6', 'n': 6, 'name': 'Secrets and Git security',
        'description': 'No secrets in files, index or remote URLs; a secret scan guards commits.',
        'pass_when': 'no secrets in worktree files, git index or remote URLs, and a '
                     'pre-commit/pre-push hook runs a secret scan',
        'fail_when': 'an exposed, staged or tracked secret; credentials in a remote URL',
        'warn_when': 'no secret-prevention mechanism exists (absence of prevention is never a pass)',
        'recommendation': 'Rotate exposed secrets, remove them from files and history, '
                          'add a pre-commit secret scan.',
        'doc_ref': 'README.md#security-model',
    },
    {
        'gid': 'G7', 'n': 7, 'name': 'Git hygiene',
        'description': 'Repositories are clean, ignored properly and free of oversized files.',
        'pass_when': 'clean worktrees, .gitignore present, no tracked file over 5 MB, '
                     'one checkout per remote',
        'fail_when': 'a tracked file over 5 MB',
        'warn_when': 'uncommitted or untracked work; a repo without .gitignore; '
                     'several checkouts of one remote',
        'recommendation': 'Commit or stash local work, add .gitignore, move big files '
                          'out of git, keep one checkout per remote.',
        'doc_ref': 'README.md#the-nine-gates',
    },
    {
        'gid': 'G8', 'n': 8, 'name': 'Agent environment governance',
        'description': 'One owner per rule; no instructions for dead harnesses; clean MCP config.',
        'pass_when': 'no dead-harness instructions, drifted pairs owned by G1/G3 '
                     '(cross-referenced here), no duplicate keys in MCP configs',
        'fail_when': 'instructions maintained for a dead harness; duplicate keys in an '
                     'MCP configuration',
        'warn_when': 'nothing (cross-references are informational)',
        'recommendation': 'Retire instructions for dead harnesses; keep one owner per rule '
                          'and one key per MCP server.',
        'doc_ref': 'README.md#the-nine-gates',
    },
    {
        'gid': 'G9', 'n': 9, 'name': 'Workspace health and maintainability',
        'description': 'Junk, build artifacts and oversized files stay within healthy limits.',
        'pass_when': 'no classified junk, total junk+build under 500 MB, few empty dirs, '
                     'no occasional harnesses, no large files outside git',
        'fail_when': 'junk and build artifacts together exceed 500 MB',
        'warn_when': 'confirmed or potentially unused junk; more than 10 empty dirs; an '
                     'occasional harness; a file over 5 MB outside git',
        'recommendation': 'Delete or archive junk, watch the total size, keep occasional '
                          'harnesses as a deliberate choice.',
        'doc_ref': 'README.md#limits-and-thresholds',
    },
]

# --- engine internals --------------------------------------------------------

_STATUS_RANK = {'not_applicable': 0, 'pass': 1, 'unknown': 2, 'warn': 3, 'fail': 4}

CATEGORY_BY_PREFIX = {
    'SEC': 'secrets', 'CFG': 'config', 'RUL': 'rules', 'DIR': 'dirs',
    'SKL': 'skills', 'GIT': 'git', 'GOV': 'governance', 'HLTH': 'health',
}

# project-dir marker -> harness tool it belongs to ('.agents' is the
# Z Code project skills dir, so it maps to the zcode harness).
# Derived from the harness registry (adapter.dir_conflict_map); the
# literal below is the fallback when the registry cannot be imported.
_DIR_TO_TOOL_FALLBACK = {'.claude': 'claude', '.codex': 'codex',
                         '.zcode/config.json': 'zcode', '.agents': 'zcode'}
_DIR_TO_TOOL = None


def _dir_to_tool():
    global _DIR_TO_TOOL
    if _DIR_TO_TOOL is None:
        mapping = dict(_DIR_TO_TOOL_FALLBACK)
        try:
            from harness import HarnessContext, iter_adapters
            ctx = HarnessContext(root=Path('.'), home=Path('.'))
            for adapter in iter_adapters():
                for marker in adapter.dir_conflict_map(ctx):
                    # first adapter to claim a marker wins (registry
                    # order), preserving the legacy zcode claim on
                    # '.agents'
                    mapping.setdefault(marker, adapter.harness_id)
        except Exception:
            pass
        _DIR_TO_TOOL = mapping
    return _DIR_TO_TOOL

_REQUIRED_SKILL_FIELDS = ('name', 'description')

# folders the tool itself creates under the audited root
_TOOL_OWN_DIRS = ('.agents-doctor', '.agents-doctor-trash')


def is_short_instruction(analysis):
    """True for a pointer-sized instruction file (smaller than
    GATE_POLICY['SHORT_INSTRUCTION_BYTES']). A report without the size
    (made before it was recorded) counts as not short."""
    size = analysis.get('size_bytes')
    return isinstance(size, int) and 0 <= size < GATE_POLICY['SHORT_INSTRUCTION_BYTES']


def worst_status(statuses):
    """Worst of the given statuses; fail > warn > unknown > pass > not_applicable."""
    if not statuses:
        return 'unknown'
    return max(statuses, key=lambda s: _STATUS_RANK.get(s, 0))


def _norm(path):
    return str(path).replace('\\', '/')


def _kb(n):
    return '%d KB' % ((n or 0) // 1024)


def _mb(n):
    return '%d MB' % ((n or 0) // (1024 * 1024))


class _Counter:
    """Per-prefix finding counters: SEC-001, CFG-001, ..."""

    def __init__(self):
        self._n = {p: 0 for p in CATEGORY_BY_PREFIX}

    def next_id(self, prefix):
        self._n[prefix] += 1
        return '%s-%03d' % (prefix, self._n[prefix])


class _GateRun:
    """Collects rule results, evidence lines and findings for one gate."""

    def __init__(self, gid, counter, findings, ctx):
        self.gid = gid
        self.counter = counter
        self.findings = findings
        self.ctx = ctx
        self.checks = []
        self.evidence = []

    def rule(self, name, status, evidence=(), reason=None, why=None, count=None):
        """One rule result.

        why is a code from glossary.REASONS saying why the rule is
        unknown or not_applicable (count feeds its text); the English
        reason is derived from it. A rule left unknown without a reason
        is a rule whose facts were not collected. reason and why are
        what the reports and the summary print instead of a bare status.
        """
        check = {'rule': name, 'status': status}
        if status in ('unknown', 'not_applicable'):
            if why:
                check['why'] = why
                if count is not None:
                    check['count'] = count
                reason = reason or glossary.reason_text(why, 'en', count)
            elif status == 'unknown' and not reason:
                check['why'] = 'facts_missing'
                reason = glossary.reason_text('facts_missing', 'en')
            if reason:
                check['reason'] = reason
        self.checks.append(check)
        lines = list(evidence) or ['%s: %s' % (name, status)]
        self.evidence.extend(lines)

    def finding(self, prefix, severity, status, title, description, evidence,
                confidence, recommendation, autofix_available=False,
                check_id=None):
        f = report_model.make_finding(
            fid=self.counter.next_id(prefix), gate=self.gid,
            category=CATEGORY_BY_PREFIX[prefix], severity=severity,
            status=status, title=title, description=description,
            evidence=evidence, confidence=confidence,
            recommendation=recommendation,
            autofix_available=autofix_available)
        if check_id:
            # stable identifier of the finding type (same role as the
            # adapters' check_id); the report fid is a per-scan counter
            f['check_id'] = check_id
        self.findings.append(f)
        return f


def _missing(run, prefix, title, section):
    run.finding(prefix, 'low', 'unknown', title,
                'Facts section %r is absent, so this check did not run; '
                'the gate cannot pass on missing data.' % section,
                [{'detail': 'facts section missing: %s' % section}], 0.5,
                'Re-run the scanner with the current version and pass the full facts dict.',
        check_id='FACTS_SECTION_MISSING')


def _skill_meta(entry, skills_extra):
    """frontmatter facts from the merged entry keys, else from skills_extra.

    skills_frontmatter keys records by name when it parsed one and by file
    path when it could not (a malformed block yields no name); match both
    ways so malformed skills still reach their facts."""
    meta = {}
    for key in ('frontmatter_ok', 'missing_fields', 'fields_checked',
                'parse_error', 'dead_refs', 'parser'):
        if key in entry:
            meta[key] = entry[key]
    extra = skills_extra.get(entry.get('name'))
    if extra is None:
        entry_path = str(entry.get('path', ''))
        for rec in skills_extra.values():
            if isinstance(rec, dict) and rec.get('path') == entry_path:
                extra = rec
                break
    for key, val in (extra or {}).items():
        meta.setdefault(key, val)
    return meta


# --- G1: workspace structure -------------------------------------------------

def _g1(facts, run):
    drift = facts.get('context_drift')
    if drift is None:
        _missing(run, 'DIR', 'Instruction pair drift not verified', 'context_drift')
        run.rule('drifted-config-pairs', 'unknown')
    else:
        for d in drift:
            f = run.finding(
                'DIR', 'high', 'fail',
                'Drifted AGENTS.md/CLAUDE.md pair in %s' % d.get('path', '?'),
                'AGENTS.md and CLAUDE.md at the same level are neither identical '
                'nor linked by a pointer; two rule sources diverge over time.',
                [{'location': d.get('path'), 'jaccard': d.get('jaccard')}],
                0.9, 'Keep one file as the source and turn the other into a pointer to it.',
                check_id='DIR_INSTRUCTION_PAIR_DRIFT')
            run.ctx.setdefault('drift_fids', []).append(f['fid'])
        run.rule('drifted-config-pairs', 'fail' if drift else 'pass',
                 ['drifted config pairs: %d' % len(drift)])

    top = facts.get('top_level')
    if top is None:
        _missing(run, 'DIR', 'Nested repositories not verified', 'top_level')
        run.rule('nested-repos', 'unknown')
    else:
        # a repository that .gitignore keeps out is a layout its owner
        # chose: not an accident to report
        labels = {t.get('name'): _repo_label(t) for t in top}
        nested = [(t.get('name'), rel)
                  for t in top
                  for rel in ((t.get('extra') or {}).get('nested_repos') or [])
                  if _norm(rel) not in {
                      _norm(x) for x in
                      ((t.get('extra') or {}).get('nested_repos_ignored') or [])}]
        for repo, rel in nested:
            run.finding(
                'DIR', 'medium', 'warn',
                'Nested repository in %s: %s' % (labels.get(repo, repo), rel),
                'A git repository lives inside another repository; the outer one '
                'sees it as embedded untracked content and sync tools mis-handle it.',
                [{'repo': repo, 'nested': rel}], 0.85,
                'Register it as a submodule or move it out to the workspace top level.',
                check_id='DIR_NESTED_REPOSITORY')
        run.rule('nested-repos', 'warn' if nested else 'pass',
                 ['nested repositories: %d' % len(nested)])

    h = facts.get('harness')
    if not isinstance(h, dict) or 'tools' not in h or 'project_dirs' not in h:
        _missing(run, 'DIR', 'Agent environment conflict not verified', 'harness')
        run.rule('harness-env-conflict', 'unknown')
    else:
        states = {t.get('tool'): t.get('state') for t in (h.get('tools') or [])}
        present = {}
        for pd in h.get('project_dirs') or []:
            tool = _dir_to_tool().get(_norm(pd.get('name', '')))
            if tool and pd.get('exists') and tool not in present:
                present[tool] = pd.get('name')
        active = sorted(t for t in present if states.get(t) == 'active')
        if len(present) > 1 and len(active) <= 1:
            detail = ', '.join('%s (%s, %s)' % (name, tool, states.get(tool, 'unknown'))
                               for tool, name in sorted(present.items()))
            run.finding(
                'DIR', 'low', 'warn',
                'Project dirs for several harnesses, at most one active',
                'Directories exist for %d harnesses but only %d active one(s); '
                'the idle ones still load their context and drift.' % (len(present), len(active)),
                [{'detail': detail}], 0.8,
                'Remove the directories of harnesses you no longer use, or accept '
                'the extra context deliberately.',
                check_id='DIR_MULTI_HARNESS_PROJECT_DIRS')
            run.rule('harness-env-conflict', 'warn',
                     ['harness dirs present: %d, active: %d' % (len(present), len(active))])
        else:
            run.rule('harness-env-conflict', 'pass',
                     ['harness dirs present: %d, active among them: %d'
                      % (len(present), len(active))])


# --- G2: configuration integrity ----------------------------------------------

def _g2(facts, run):
    cfg = facts.get('config_integrity')
    if cfg is None:
        _missing(run, 'CFG', 'Configuration integrity not verified', 'config_integrity')
        run.rule('config-parse', 'unknown')
        return
    if not cfg:
        run.finding(
            'CFG', 'info', 'warn', 'No configuration files found',
            'The scanner found no configuration files to parse. Absence of data is '
            'not a pass: nobody confirmed the workspace really has no configs.',
            [{'detail': 'no configuration files found'}], 0.9,
            'If the workspace should have configs (MCP, harness settings), find out '
            'why none were discovered.',
            check_id='CFG_NO_CONFIG_FILES')
        run.rule('config-parse', 'warn', ['no configuration files found'])
        return
    broken = 0
    for e in cfg:
        if not e.get('ok', True):
            broken += 1
            run.finding(
                'CFG', 'high', 'fail',
                'Configuration file does not parse: %s' % e.get('path', '?'),
                'The %s file failed to parse (%s); tools reading it fall back to '
                'defaults or fail outright.' % (e.get('format', 'config'),
                                                e.get('error') or 'syntax error'),
                [{'file': e.get('path'), 'format': e.get('format'),
                  'error': e.get('error')}],
                0.95, 'Fix the syntax error, then re-run the audit.',
                check_id='CFG_FILE_UNPARSEABLE')
        for key in e.get('dup_keys') or []:
            broken += 1
            run.finding(
                'CFG', 'medium', 'fail',
                'Duplicate key %r in %s' % (key, e.get('path', '?')),
                'Duplicate keys in a %s file resolve silently to the last '
                'occurrence; what is written stops matching what runs.'
                % e.get('format', 'config'),
                [{'file': e.get('path'), 'key': key}], 0.9,
                'Remove the duplicate key and keep one deliberate value.',
                check_id='CFG_DUPLICATE_KEY')
    run.rule('config-parse', 'fail' if broken else 'pass',
             ['config files parsed: %d, broken: %d' % (len(cfg), broken)])


# --- G3: rules consistency ------------------------------------------------------

def _g3(facts, run):
    cf = facts.get('context_files')
    if cf is None:
        _missing(run, 'RUL', 'Instruction file checks not verified', 'context_files')
        run.rule('dead-references', 'unknown')
        run.rule('generic-markers', 'unknown')
        run.rule('instruction-size', 'unknown')
    else:
        dead = 0
        for e in cf:
            for kind, label in (('dead_links', 'link'), ('dead_paths', 'path'),
                                ('dead_commands', 'command')):
                for ref in e.get(kind) or []:
                    dead += 1
                    run.finding(
                        'RUL', 'medium', 'fail',
                        'Dead %s in %s: %s' % (label, e.get('path', '?'), ref),
                        'The instruction file points to %r which does not exist; '
                        'an agent following it fails or improvises.' % ref,
                        [{'file': e.get('path'), 'ref': ref, 'kind': label}],
                        0.9, 'Fix or remove the reference.',
                        check_id='RUL_DEAD_REFERENCE')
        run.rule('dead-references', 'fail' if dead else 'pass',
                 ['instruction files checked: %d, dead references: %d' % (len(cf), dead)])

        markers = [(e.get('path'), m) for e in cf for m in (e.get('generic_markers') or [])]
        for p, m in markers:
            run.finding(
                'RUL', 'low', 'warn', 'Generic boilerplate in %s: %r' % (p, m),
                'Template or overview text inside auto-loaded context spends the '
                'context budget without giving the agent rules.',
                [{'file': p, 'marker': m}], 0.7,
                'Replace the boilerplate with project-specific rules or drop it.',
                check_id='RUL_GENERIC_BOILERPLATE')
        run.rule('generic-markers', 'warn' if markers else 'pass',
                 ['generic markers: %d' % len(markers)])

        big = [e for e in cf if (e.get('size_bytes') or 0) > GATE_POLICY['PROJECT_BENCH']]
        for e in big:
            run.finding(
                'RUL', 'low', 'warn',
                'Instruction file over %s: %s' % (_kb(GATE_POLICY['PROJECT_BENCH']), e.get('path')),
                'The file is %s; the project-instruction benchmark is %s, everything '
                'above it taxes every session.'
                % (_kb(e.get('size_bytes') or 0), _kb(GATE_POLICY['PROJECT_BENCH'])),
                [{'file': e.get('path'), 'size': _kb(e.get('size_bytes') or 0)}],
                0.85, 'Split the file: keep rules auto-loaded, move the rest to linked docs.',
                check_id='RUL_FILE_TOO_BIG')
        run.rule('instruction-size', 'warn' if big else 'pass',
                 ['instruction files over benchmark: %d' % len(big)])

    cq = facts.get('content_quality')
    if cq is None:
        # section absent (facts from an older scanner or a fabricated
        # report): the check did not run and records no rule, so the
        # verdicts of the other G3 rules stand unchanged
        pass
    elif not cq:
        run.rule('content-quality', 'not_applicable',
                 ['no project instruction files to analyze'])
    else:
        # collect worst scores across all project instruction files
        worst_ratio = 1.0
        long_ratio = 1.0     # worst ratio among files big enough to judge
        total_generic = 0
        total_contradictions = 0
        total_redundant = 0
        for path, analysis in cq.items():
            ratio = analysis.get('signal_ratio', 1.0)
            worst_ratio = min(worst_ratio, ratio)
            if not is_short_instruction(analysis):
                long_ratio = min(long_ratio, ratio)
            total_generic += len(analysis.get('generic_phrases', []))
            total_contradictions += len(analysis.get('contradictions', []))
            total_redundant += len(analysis.get('redundant_pairs', []))

        # contradictions are hard failures
        for path, analysis in cq.items():
            for c in analysis.get('contradictions', []):
                run.finding(
                    'RUL', 'high', 'fail',
                    'Contradictory instructions in %s' % path,
                    'One line says "%s" while another says "%s" — the agent '
                    'gets conflicting rules.'
                    % (c.get('line_a', '')[:60], c.get('line_b', '')[:60]),
                    [{'file': path, 'line_a': c.get('line_a'),
                      'line_b': c.get('line_b')}],
                    0.9, 'Remove one of the contradictory lines or reconcile '
                         'them into one rule.',
                    check_id='RUL_CONTRADICTIONS')

        # generic phrases are warnings
        if total_generic > 0:
            run.finding(
                'RUL', 'low', 'warn',
                '%d generic phrases across instruction files' % total_generic,
                'These lines could apply to any project (e.g. "write clean '
                'code", "follow best practices") — the agent already knows '
                'this. They waste context budget.',
                [{'count': total_generic}], 0.8,
                'Remove generic advice; keep only rules specific to THIS project.',
                check_id='RUL_GENERIC_PHRASES')

        # low signal ratio: a warning for a file big enough to judge, a
        # hint for a pointer-sized one (it holds few rules by design).
        # Every such file gets a line of its own: one line for the worst
        # file left the others without a place to look
        for path, analysis in sorted(cq.items()):
            ratio = analysis.get('signal_ratio', 1.0)
            if ratio >= 0.3:
                continue
            short = is_short_instruction(analysis)
            run.finding(
                'RUL', 'info' if short else 'medium',
                'pass' if short else 'warn',
                ('Short instruction file, few concrete rules (signal ratio %.0f%%)'
                 if short else
                 'Instruction file is mostly noise (signal ratio %.0f%%)')
                % (ratio * 100),
                'Less than 30% of the non-blank lines are actionable '
                'instructions. The rest is narrative, descriptions, or filler.',
                [{'file': path, 'ratio': round(ratio, 2),
                  'bytes': analysis.get('size_bytes')}], 0.85,
                ('A short pointer file is fine as it is; check it only if it '
                 'was meant to hold rules.' if short else
                 'Trim to actionable rules: what to run, what to avoid, '
                 'where files are.'),
                check_id='RUL_SHORT_FILE_HINT' if short else 'RUL_MOSTLY_NOISE')

        # redundancy is info
        if total_redundant > 0:
            run.finding(
                'RUL', 'info', 'warn',
                '%d redundant rule pairs' % total_redundant,
                'Near-duplicate instructions were found; each costs tokens '
                'in every session.',
                [{'count': total_redundant}], 0.7,
                'Merge duplicate rules into single, precise instructions.',
                check_id='RUL_REDUNDANT_RULES')

        status = 'fail' if total_contradictions > 0 else (
            'warn' if total_generic > 5 or long_ratio < 0.3 else 'pass')
        run.rule('content-quality', status,
                 ['files analyzed: %d, worst signal ratio: %.2f, '
                  'generic phrases: %d, contradictions: %d, redundant pairs: %d'
                  % (len(cq), worst_ratio, total_generic, total_contradictions,
                     total_redundant)])

    drift = facts.get('context_drift')
    if drift is None:
        _missing(run, 'RUL', 'Rule pair drift not verified', 'context_drift')
        run.rule('pair-drift', 'unknown')
    else:
        for d in drift:
            f = run.finding(
                'RUL', 'high', 'fail', 'Two rule sources at %s' % d.get('path', '?'),
                'AGENTS.md and CLAUDE.md at the same level disagree (similarity %s); '
                'each edit widens the gap.' % d.get('jaccard'),
                [{'location': d.get('path'), 'jaccard': d.get('jaccard')}],
                0.9, 'Keep one file as the source and make the other a pointer '
                     '(structure view: G1).',
                check_id='RUL_TWO_RULE_SOURCES')
            run.ctx.setdefault('drift_fids', []).append(f['fid'])
        run.rule('pair-drift', 'fail' if drift else 'pass',
                 ['drifted pairs: %d' % len(drift)])

    if 'chain_budget_over' not in facts:
        _missing(run, 'RUL', 'AGENTS.md chain budget not verified', 'chain_budget_over')
        run.rule('chain-budget', 'unknown')
    elif facts.get('chain_budget_over'):
        over = [c for c in (facts.get('context_budget') or []) if c.get('over')]
        run.finding(
            'RUL', 'medium', 'warn',
            'AGENTS.md chain over %d bytes' % GATE_POLICY['CHAIN_BUDGET'],
            'The root plus nested AGENTS.md chain exceeds the Codex budget; '
            'the tail is truncated silently.',
            [{'chain': c.get('root'), 'bytes': c.get('total_bytes')} for c in over]
            or [{'detail': 'chain over budget'}],
            0.9, 'Trim the chain or split nested instructions into linked files.',
            check_id='RUL_CHAIN_OVER_BUDGET')
        run.rule('chain-budget', 'warn', ['chains over budget: %d' % max(len(over), 1)])
    else:
        run.rule('chain-budget', 'pass',
                 ['AGENTS.md chains within %d bytes' % GATE_POLICY['CHAIN_BUDGET']])


# --- G4: directory ownership -----------------------------------------------------

def _g4(facts, run):
    heavy = facts.get('heavy_outside_git')
    if heavy is None:
        _missing(run, 'DIR', 'Heavy directories outside git not verified',
                 'heavy_outside_git')
        run.rule('heavy-outside-git', 'unknown')
        heavy = None
    else:
        for h in heavy:
            run.finding(
                'DIR', 'medium', 'fail',
                'Heavy directory outside git: %s' % h.get('path', '?'),
                'The directory holds %s of data, is not a build artifact and sits '
                'outside every git repository; its fate is undecided.'
                % _kb(h.get('size_bytes')),
                [{'path': h.get('path'), 'size': _kb(h.get('size_bytes')),
                  'depth': h.get('depth')}],
                0.9, 'Move it under version control, archive it, or delete it.',
                check_id='DIR_HEAVY_OUTSIDE_GIT')
        run.rule('heavy-outside-git', 'fail' if heavy else 'pass',
                 ['heavy dirs outside git: %d' % len(heavy)])

    top = facts.get('top_level')
    if top is None:
        _missing(run, 'DIR', 'Top-level layout not verified', 'top_level')
        run.rule('unowned-top-dirs', 'unknown')
    else:
        heavy_paths = {_norm(h.get('path', '')) for h in (heavy or [])}
        # the audited folder as a repository: its top-level folders hold
        # tracked files unless git lists them as a whole (untracked or
        # ignored by .gitignore)
        root_ex = next((t.get('extra') or {} for t in top
                        if t.get('kind') == 'repo'
                        and _norm(t.get('name', '')) == '.'), {})
        top_status = root_ex.get('top_status')
        loose = []
        for t in top:
            if t.get('kind') != 'dir':
                continue
            name = _norm(t.get('name', ''))
            if name in _TOOL_OWN_DIRS:
                # the tool's own working folder and its trash: not the
                # user's data, never a finding
                continue
            if any(p == name or p.startswith(name + '/') for p in heavy_paths):
                continue
            if top_status is not None and name not in top_status['untracked']:
                continue
            loose.append(t)
        if loose:
            in_root_repo = top_status is not None
            run.finding(
                'DIR', 'low', 'warn',
                '%d top-level folders outside version control' % len(loose),
                ('These folders sit in the audited folder\'s repository but '
                 'none of their files is tracked: no history and no backup.'
                 if in_root_repo else
                 'These folders are not git repositories; their content has no '
                 'history and no backup.'),
                [{'path': t.get('name'), 'size': _kb(t.get('size_bytes'))}
                 for t in loose],
                0.9,
                'Add the folders to the repository, or to .gitignore if they '
                'are not meant to be saved.' if in_root_repo else
                'Decide for each folder: make it a repo, move it into one, or '
                'remove it.',
                check_id='DIR_LOOSE_TOP_FOLDERS')
        run.rule('unowned-top-dirs', 'warn' if loose else 'pass',
                 ['top-level dirs outside git: %d' % len(loose)])


# --- G5: skills -----------------------------------------------------------------

_SKILL_RULES = ('frontmatter', 'description-length', 'triggers',
                'skill-dead-refs', 'duplicate-copies')


def _skills_coverage(skills):
    """How much of the skill folders the scan actually looked at.

    Returns (checked, failed, truncated): checked = number of folders
    read, failed = [{'location', 'reason'}] for folders that exist but
    could not be read, truncated = [{'location', 'scanned', 'found'}]
    where a per-folder cap cut the search. Reports made before coverage
    was recorded fall back to the checked-folder list.
    """
    cov = skills.get('coverage')
    if not isinstance(cov, dict):
        return len(skills.get('locations_checked') or []), [], []
    return (len(cov.get('checked') or []), list(cov.get('failed') or []),
            list(cov.get('truncated') or []))


def _skill_folder_unreadable(run, folder):
    """One finding for a skill folder that exists but could not be read."""
    run.finding(
        'SKL', 'medium', 'unknown',
        'Skill folder %s could not be checked' % folder.get('location'),
        'The folder exists but the scanner could not read it (%s), '
        'so skills inside it were not checked.' % folder.get('reason'),
        [{'location': folder.get('location'), 'reason': folder.get('reason')}],
        0.9, 'Fix the folder access (permissions or folder type), '
             'then re-run the audit.',
        check_id='SKL_FOLDER_UNREADABLE')


def _g5(facts, run):
    skills = facts.get('skills')
    if not isinstance(skills, dict) or 'entries' not in skills:
        _missing(run, 'SKL', 'Skills not verified', 'skills')
        for name in _SKILL_RULES:
            run.rule(name, 'unknown', why='skills_facts_missing')
        return
    entries = skills.get('entries') or []
    extra = facts.get('skills_extra') or {}
    checked, failed, truncated = _skills_coverage(skills)
    # a skill search that missed part of a folder leaves every rule short
    # of a verdict: rules that would pass read unknown instead
    incomplete = ([t.get('location') for t in truncated]
                  + [f.get('location') for f in failed])

    def settle(status, evidence, affected=True):
        """(status, evidence, why) of one rule, capped at unknown when
        the search did not cover every folder the rule depends on."""
        if affected and incomplete and status == 'pass':
            return ('unknown', list(evidence) + ['search incomplete in: '
                                                  + ', '.join(str(x) for x in incomplete)],
                    'skills_search_incomplete')
        return (status, evidence, None)

    if not entries:
        # nothing was found to check: never a pass. What the rules say
        # depends on whether the search could run at all.
        if failed:
            status, why, count = 'unknown', 'skills_folders_unreadable', len(failed)
        elif checked:
            status, why, count = 'not_applicable', 'no_skills_found', checked
        else:
            status, why, count = 'not_applicable', 'no_skill_folders', None
        for name in _SKILL_RULES:
            run.rule(name, status,
                     ['skills found: 0, folders checked: %d, unreadable: %d'
                      % (checked, len(failed))],
                     why=why, count=count)
        for f in failed:
            _skill_folder_unreadable(run, f)
        return

    fm_fail = fm_unknown = verified = over_desc = no_triggers = dead_refs = 0
    for e in entries:
        meta = _skill_meta(e, extra)
        name = e.get('name') or e.get('path') or '?'
        fm_ok = meta.get('frontmatter_ok')
        if fm_ok is None:
            fm_unknown += 1
            reason = ('fallback parser' if meta.get('parser') == 'fallback' or not meta
                      else 'no frontmatter facts')
            run.finding(
                'SKL', 'low', 'unknown',
                'Skill %r: frontmatter checks skipped (%s)' % (name, reason),
                'Frontmatter facts are missing or the file was parsed with the '
                'fallback parser, so the field checks for this skill did not run.',
                [{'file': e.get('path'), 'parser': meta.get('parser', 'unknown')}],
                0.6, 'Fix the frontmatter so it parses as YAML, then re-run the audit.',
                check_id='SKL_FRONTMATTER_UNKNOWN')
            continue
        if fm_ok is False:
            fm_fail += 1
            ev = [{'file': e.get('path'), 'parser': meta.get('parser')}]
            err = meta.get('parse_error') or {}
            if err.get('line'):
                # position of the syntax error inside SKILL.md; the
                # parser's own wording only, never a quote of the line
                ev[0].update({'error_line': err['line'],
                              'error_column': err.get('column'),
                              'error': err.get('problem')})
                where = ' (line %s, column %s)' % (err['line'], err.get('column'))
                title = 'Frontmatter of skill %r does not parse%s' % (name, where)
                rec = ('Fix the frontmatter syntax in SKILL.md at line %s, '
                       'column %s (%s).' % (err['line'], err.get('column'),
                                            err.get('problem')))
            elif meta.get('fields_checked'):
                # parsed far enough to know: there is no frontmatter block
                where = ''
                title = 'Skill %r has no frontmatter block' % name
                rec = 'Add a frontmatter block (name and description) at the top of SKILL.md.'
            else:
                where = ''
                title = 'Frontmatter of skill %r does not parse' % name
                rec = 'Fix the frontmatter syntax in SKILL.md.'
            run.finding(
                'SKL', 'high', 'fail', title,
                'The frontmatter could not be parsed (parser: %s); the skill may '
                'not load at all.' % meta.get('parser', 'yaml'),
                ev, 0.9, rec, check_id='SKL_FRONTMATTER_INVALID')
            continue
        missing = [f for f in (meta.get('missing_fields') or [])
                   if f in _REQUIRED_SKILL_FIELDS]
        if e.get('desc_len') is None and 'description' not in missing:
            missing.append('description')
        if missing:
            fm_fail += 1
            run.finding(
                'SKL', 'high', 'fail',
                'Skill %r misses required fields: %s' % (name, ', '.join(missing)),
                'A SKILL.md without %s is not a valid skill; harnesses skip or '
                'mis-load it.' % ' and '.join(missing),
                [{'file': e.get('path'), 'missing': missing}], 0.95,
                'Add the missing field(s) to the frontmatter.',
                check_id='SKL_REQUIRED_FIELD_MISSING')
            continue
        verified += 1
        if (e.get('desc_len') or 0) > GATE_POLICY['DESC_LIMIT']:
            over_desc += 1
            run.finding(
                'SKL', 'high', 'fail',
                'Description of skill %r is %d chars, limit %d'
                % (name, e['desc_len'], GATE_POLICY['DESC_LIMIT']),
                'The harness refuses to load a skill whose description exceeds the limit.',
                [{'file': e.get('path'), 'desc_len': e['desc_len']}], 0.95,
                'Shorten the description; move details into the skill body.',
                check_id='SKL_DESCRIPTION_TOO_LONG')
        if not e.get('has_triggers'):
            no_triggers += 1
            run.finding(
                'SKL', 'low', 'warn',
                'No triggers in the description of skill %r' % name,
                'Without a "use when"-style phrase the harness rarely picks the skill.',
                [{'file': e.get('path')}], 0.8,
                'Add a trigger phrase ("use when ...") to the description.',
                check_id='SKL_NO_TRIGGERS')
        for ref in meta.get('dead_refs') or []:
            dead_refs += 1
            run.finding(
                'SKL', 'medium', 'warn',
                'Skill %r references missing file: %s' % (name, ref),
                'The SKILL.md points to %r which does not exist next to it.' % ref,
                [{'file': e.get('path'), 'ref': ref}], 0.9,
                'Restore the file or drop the reference.',
                check_id='SKL_DEAD_REFERENCE')

    if fm_fail:
        fm_status = 'fail'
    elif fm_unknown:
        fm_status = 'unknown'
    else:
        fm_status = 'pass'
    status, evidence, why = settle(
        fm_status,
        ['skills checked: %d, frontmatter failures: %d, unverified: %d'
         % (len(entries), fm_fail, fm_unknown)])
    run.rule('frontmatter', status, evidence, why=why)

    if verified == 0:
        detail_status = 'unknown'
    else:
        detail_status = None
    detail_rules = (
        ('description-length',
         detail_status or ('fail' if over_desc else 'pass'),
         ['descriptions over %d chars: %d' % (GATE_POLICY['DESC_LIMIT'], over_desc)],
         'descriptions'),
        ('triggers',
         detail_status or ('warn' if no_triggers else 'pass'),
         ['skills without triggers: %d' % no_triggers],
         'triggers'),
        ('skill-dead-refs',
         detail_status or ('warn' if dead_refs else 'pass'),
         ['dead skill references: %d' % dead_refs],
         'references'),
    )
    for rule, status, evidence, what in detail_rules:
        status, evidence, why = settle(status, evidence)
        if detail_status:
            why = 'frontmatter_unverified'
        run.rule(rule, status, evidence, why=why)

    dups = skills.get('duplicates')
    if dups is None:
        _missing(run, 'SKL', 'Skill copy sync not verified', 'skills.duplicates')
        run.rule('duplicate-copies', 'unknown', why='skills_copies_not_compared')
    else:
        diverged = [d for d in dups if d.get('sync') != 'identical']
        for d in diverged:
            run.finding(
                'SKL', 'high', 'fail', 'Diverged copies of skill %r' % d.get('name'),
                '%s copies of the skill exist and their content differs; edits land '
                'in one copy while the harness loads another.' % d.get('copies'),
                [{'name': d.get('name'), 'copies': d.get('copies'),
                  'paths': (d.get('paths') or [])[:10]}],
                0.95, 'Pick one canonical location and delete or sync the rest.',
                check_id='SKL_COPIES_DIVERGED')
        # copies are compared outside the plugin cache (the CLI keeps
        # several versions there on purpose), so a cap inside the cache
        # does not shorten this rule
        status, evidence, why = settle(
            'fail' if diverged else 'pass',
            ['skill name collisions: %d, diverged: %d' % (len(dups), len(diverged))],
            affected=any(x != 'plugins-cache' for x in incomplete))
        run.rule('duplicate-copies', status, evidence, why=why)

    # a partial search is not a pass: say what was left out
    for t in truncated:
        run.finding(
            'SKL', 'medium', 'unknown',
            'Skills check incomplete in %s' % t.get('location'),
            'Only the first %d of %d skills in this folder were checked '
            '(per-folder limit %d); the rest are unverified.'
            % (t.get('scanned'), t.get('found'), t.get('cap')),
            [{'location': t.get('location'), 'scanned': t.get('scanned'),
              'found': t.get('found'), 'cap': t.get('cap')}],
            0.9, 'Narrow the folder, then re-run.',
            check_id='SKL_CHECK_INCOMPLETE')
    for f in failed:
        _skill_folder_unreadable(run, f)


_NO_GIT_WHY = 'no_git'   # glossary.REASONS code: nothing to hook or index


def _repo_label(t):
    """Name of a repository for titles: the audited folder itself is
    listed under '.'."""
    return 'the audited folder' if _norm(t.get('name', '')) == '.' \
        else t.get('name')


def _unchecked_repos(facts, top):
    """Repositories the git-side checks never reach.

    The audited folder itself (when it is a repository, listed as '.')
    and the repositories sitting directly in it get their index,
    history and hooks read. The walk lists every folder holding a .git
    (facts['git_roots']); the ones that are neither, or that sit inside
    one of them, come back here. Reports made before the list was
    recorded know only the top level, so they report none."""
    top_names = {_norm(t.get('name', '')) for t in top if t.get('kind') == 'repo'}
    return [g for g in (facts.get('git_roots') or [])
            if _norm(g) not in top_names
            and _norm(g).split('/')[0] not in top_names]


# --- G6: secrets and git security --------------------------------------------------

def _g6(facts, run):
    sec = facts.get('secrets')
    if sec is None:
        _missing(run, 'SEC', 'Exposed secrets not verified', 'secrets')
        run.rule('exposed-secrets', 'unknown')
    else:
        for s in sec:
            state = s.get('git')
            spot = '%s:%s' % (s.get('path', '?'), s.get('line', '?'))
            evidence = [{'file': s.get('path'), 'line': s.get('line'),
                         'kind': s.get('kind'), 'mask': s.get('mask'),
                         'fingerprint': s.get('fingerprint'), 'git': state}]
            if state == 'ignored':
                # kept out of git on purpose (.gitignore): the normal
                # place for local settings, at risk only when shared
                run.finding(
                    'SEC', 'medium', 'warn',
                    'Credential in a git-ignored file %s' % spot,
                    'A %s sits in a file that .gitignore keeps out of git. That '
                    'is where local settings live; the key is at risk only if the '
                    'file itself is shared.' % s.get('kind', 'secret'),
                    evidence, s.get('confidence', 0.9),
                    'Keep the file out of archives, shared folders and mail. '
                    'Rotate the key if the file was shared.',
                    check_id='SEC_EXPOSED_SECRET')
                continue
            tracked = state == 'tracked'
            run.finding(
                'SEC', 'critical', 'fail',
                'Exposed secret in %s' % spot,
                (('A %s was detected in a file tracked by git: it leaves the '
                  'machine with every clone. The value is redacted, only the '
                  'mask and fingerprint are recorded.'
                  if tracked else
                  'A %s was detected in a workspace file; the value is redacted, '
                  'only the mask and fingerprint are recorded.')
                 % s.get('kind', 'secret')),
                evidence, s.get('confidence', 0.9),
                ('Rotate the secret at its provider, `git rm --cached` the file '
                 'and purge it from history.' if tracked else
                 'Add the file to .gitignore so the next `git add` does not take '
                 'it. Rotate the secret at its provider if the file was ever '
                 'shared.' if state == 'untracked' else
                 'Rotate the secret at its provider, remove it from the file and '
                 'purge it from history.'),
                check_id='SEC_EXPOSED_SECRET')
        failing = [s for s in sec if s.get('git') != 'ignored']
        run.rule('exposed-secrets',
                 'fail' if failing else ('warn' if sec else 'pass'),
                 ['secrets found in workspace files: %d' % len(sec)])

    top = facts.get('top_level')
    if top is None:
        _missing(run, 'SEC', 'Git-side secret checks not verified', 'top_level')
        run.rule('tracked-secrets', 'unknown')
        run.rule('secret-prevention', 'unknown')
        return
    top_repos = [t for t in top if t.get('kind') == 'repo']
    unchecked_repos = _unchecked_repos(facts, top)
    # nothing to hook, index or search when there is no git at all
    no_git = not top_repos and not unchecked_repos

    # a key already reported where it lies (in a tracked file) is not
    # reported a second time from the index
    exposed_tracked = {(_norm(s.get('path', '')), s.get('line'))
                       for s in (sec or []) if s.get('git') == 'tracked'}

    git_hits = 0
    maybe_hits = 0
    for t in top:
        ex = t.get('extra') or {}
        prefix = '' if _norm(t.get('name', '')) == '.' else _norm(t.get('name')) + '/'
        for ts in ex.get('tracked_secrets') or []:
            if (prefix + _norm(ts.get('file', '')), ts.get('line')) in exposed_tracked:
                continue
            if ts.get('in_bundle'):
                # a keyword literal in a tracked file of 1 MB or more:
                # bundles and minified libraries hold examples; the
                # worktree scan does not read such files either
                maybe_hits += 1
                run.finding(
                    'SEC', 'low', 'warn',
                    'Possible secret in a large tracked file %s: %s:%s'
                    % (_repo_label(t), ts.get('file'), ts.get('line')),
                    'A %s was matched in a tracked file of 1 MB or more. Such '
                    'files are bundles and libraries, and their values are '
                    'usually examples; the line was not judged.'
                    % ts.get('kind', 'secret'),
                    [{'repo': t.get('name'), 'file': ts.get('file'),
                      'line': ts.get('line'), 'kind': ts.get('kind'),
                      'fingerprint': ts.get('fingerprint')}],
                    0.5,
                    'Look at the line by hand. Rotate the key only if it is '
                    'a real one.',
                    check_id='SEC_TRACKED_SECRET_BUNDLE')
                continue
            git_hits += 1
            run.finding(
                'SEC', 'critical', 'fail',
                'Secret tracked in git at %s: %s:%s'
                % (_repo_label(t), ts.get('file'), ts.get('line')),
                'A %s sits in a tracked or staged file; it leaves the machine with '
                'the next push.' % ts.get('kind', 'secret'),
                [{'repo': t.get('name'), 'file': ts.get('file'), 'line': ts.get('line'),
                  'kind': ts.get('kind'), 'fingerprint': ts.get('fingerprint')}],
                ts.get('confidence', 0.9),
                'Rotate the secret, `git rm --cached` the file and purge the history.',
                check_id='SEC_TRACKED_SECRET')
        if ex.get('credentials_in_remote'):
            git_hits += 1
            run.finding(
                'SEC', 'critical', 'fail',
                'Credentials in the remote URL of %s' % _repo_label(t),
                'The origin URL embeds a login:password pair; it is in .git/config '
                'and shows up in every `git remote -v`. The stored form is '
                'sanitized; rotate the credential — it has already been in a file.',
                [{'repo': t.get('name')}], 0.95,
                'Move auth to a credential helper and rotate the credential: '
                'the current one already sat in plain text.',
                check_id='SEC_CREDENTIALS_IN_REMOTE')
        for hs in ex.get('history_secrets') or []:
            git_hits += 1
            run.finding(
                'SEC', 'critical', 'fail',
                'Secret in git history of %s: %s:%s'
                % (_repo_label(t), hs.get('file'), hs.get('line')),
                'A %s lives in a historical commit; cloning or pushing '
                're-ships it every time.' % hs.get('kind', 'secret'),
                [{'repo': t.get('name'), 'file': hs.get('file'),
                  'line': hs.get('line'), 'commit': hs.get('commit'),
                  'kind': hs.get('kind'), 'fingerprint': hs.get('fingerprint')}],
                hs.get('confidence', 0.9),
                'Rotate the secret, then purge it from history '
                '(git filter-repo or BFG).',
                check_id='SEC_SECRET_IN_HISTORY')
    if unchecked_repos:
        # known repositories whose git side was not read
        run.finding(
            'SEC', 'medium', 'unknown',
            '%d repositor%s inside the audited area not checked for secrets'
            % (len(unchecked_repos), 'y' if len(unchecked_repos) == 1 else 'ies'),
            'The audited folder itself and the repositories sitting directly '
            'in it get their git index, history and hooks read. These lie '
            'deeper, so their git side is unverified.',
            [{'repositories': len(unchecked_repos),
              'paths': unchecked_repos[:10]}],
            0.9, 'Audit each of these repository folders separately to check '
                 'its git side (index, history, hooks).',
            check_id='SEC_GIT_SIDE_UNVERIFIED')
    # a clean result covers only the repositories that were read: with
    # deeper ones left unread the rule is "unknown", never "pass"
    unverified = bool(unchecked_repos)
    if no_git:
        run.rule('tracked-secrets', 'not_applicable',
                 ['secret hits in git: not applicable, no repositories'],
                 why=_NO_GIT_WHY)
    elif not top_repos:
        # repositories exist, but their index was not read
        run.rule('tracked-secrets', 'unknown',
                 ['secret hits in git: not verified for %d repositor%s'
                  % (len(unchecked_repos),
                     'y' if len(unchecked_repos) == 1 else 'ies')],
                 why='git_index_unverified', count=len(unchecked_repos))
    elif git_hits:
        run.rule('tracked-secrets', 'fail',
                 ['secret hits in git (index, remote URLs, history): %d' % git_hits])
    elif unverified:
        run.rule('tracked-secrets', 'unknown',
                 ['secret hits in git (index, remote URLs, history): 0; '
                  'deeper repositories not read: %d' % len(unchecked_repos)],
                 why='git_index_unverified', count=len(unchecked_repos))
    elif maybe_hits:
        # nothing certain, one line to look at by hand
        run.rule('tracked-secrets', 'warn',
                 ['secret hits in git (index, remote URLs, history): 0; '
                  'possible hits in large tracked files: %d' % maybe_hits])
    else:
        run.rule('tracked-secrets', 'pass',
                 ['secret hits in git (index, remote URLs, history): 0'])

    # deep-scan coverage: an incomplete history scan must never read as pass
    coverages = [(t.get('name'), (t.get('extra') or {}).get('history_coverage'))
                 for t in top]
    coverages = [(name, c) for name, c in coverages if c]
    if no_git:
        run.rule('history-coverage', 'not_applicable',
                 ['git history: not applicable, no repositories'],
                 why=_NO_GIT_WHY)
    elif not top_repos:
        run.rule('history-coverage', 'unknown',
                 ['git history: not verified for %d repositor%s'
                  % (len(unchecked_repos),
                     'y' if len(unchecked_repos) == 1 else 'ies')],
                 why='git_nested_unverified', count=len(unchecked_repos))
    elif coverages:
        labels = {_norm(t.get('name', '')): _repo_label(t) for t in top_repos}
        incomplete = [(n, c) for n, c in coverages if not c.get('complete')]
        for name, c in incomplete:
            run.finding(
                'SEC', 'medium', 'unknown',
                'Git history scan incomplete for %s'
                % labels.get(_norm(name), name),
                'Scanned %s of %s commits%s: findings below the cap are not '
                'excluded, but the rest of the history is unverified.'
                % (c.get('commits_scanned'), c.get('commits_total'),
                   ' (all refs)' if c.get('all_refs') else ''),
                [{'repo': name, 'scanned': c.get('commits_scanned'),
                  'total': c.get('commits_total'),
                  'all_refs': c.get('all_refs')}], 0.9,
                'Re-run with a higher --history-depth or without a cap to '
                'verify the full history.',
                check_id='SEC_HISTORY_SCAN_INCOMPLETE')
        if incomplete:
            run.rule('history-coverage', 'unknown',
                     ['repos with history scanned: %d, incomplete: %d'
                      % (len(coverages), len(incomplete))],
                     why='history_partially_scanned')
        elif unverified:
            run.rule('history-coverage', 'unknown',
                     ['repos with history scanned: %d, incomplete: 0; deeper '
                      'repositories not read: %d'
                      % (len(coverages), len(unchecked_repos))],
                     why='git_nested_unverified', count=len(unchecked_repos))
        else:
            run.rule('history-coverage', 'pass',
                     ['repos with history scanned: %d, incomplete: 0'
                      % len(coverages)])
    else:
        run.rule('history-coverage', 'unknown',
                 ['deep scan not requested: history unchecked (not a pass)'],
                 why='history_not_scanned')

    hints = GATE_POLICY['SECRET_PREVENTION_HINTS']
    repos_scanned = len(top_repos)
    hooks = []
    for t in top_repos:
        for h in (t.get('extra') or {}).get('hooks') or []:
            if (h.get('name') in hints['hook_names']
                    and (h.get('flags') or {}).get(hints['scan_flag'])):
                hooks.append('%s: %s' % (_repo_label(t), h.get('name')))
    if hooks:
        run.rule('secret-prevention', 'pass',
                 ['secret scan hooks: ' + '; '.join(hooks)])
    elif no_git:
        # no repository, so no commit to guard: nothing to install
        run.rule('secret-prevention', 'not_applicable',
                 ['secret scan hooks: not applicable, no repositories'],
                 why=_NO_GIT_WHY)
    else:
        if top_repos:
            run.finding(
                'SEC', 'medium', 'warn', 'No secret-prevention mechanism found',
                'No %s hook runs a secret scan in any of the %d repositories. A '
                '.gitignore alone is not proof: coverage of %s is not derivable from '
                'the collected facts, so absence of a hook is treated as no prevention.'
                % ('/'.join(hints['hook_names']), repos_scanned,
                   ', '.join(hints['gitignore_patterns'])),
                [{'detail': 'no %s hook with secret scan in any repository'
                            % '/'.join(hints['hook_names']),
                  'repositories scanned': repos_scanned}],
                0.85,
                'Install a pre-commit secret scan (gitleaks or equivalent) in every '
                'active repository.',
                check_id='SEC_PREVENTION_ABSENT')
        if unverified:
            # repositories exist, but their hooks were not read
            run.finding(
                'SEC', 'medium', 'unknown',
                'Secret prevention not verified for %d repositor%s'
                % (len(unchecked_repos),
                   'y' if len(unchecked_repos) == 1 else 'ies'),
                'No %s hook runs a secret scan in the audited folder or in the '
                'repositories sitting directly in it, and the hooks of these %d '
                'deeper ones were not read. Prevention is unverified, not absent.'
                % ('/'.join(hints['hook_names']), len(unchecked_repos)),
                [{'detail': 'hooks of nested repositories are not scanned',
                  'repositories unverified': len(unchecked_repos),
                  'paths': unchecked_repos[:10]}],
                0.85, 'Audit each of these repository folders separately to see '
                      'whether a secret-scan hook is installed.',
                check_id='SEC_PREVENTION_UNVERIFIED')
        if not top_repos:
            run.rule('secret-prevention', 'unknown',
                     ['secret scan hooks found: 0 (repositories scanned: 0, '
                      'unverified: %d)' % len(unchecked_repos)],
                     why='git_nested_unverified', count=len(unchecked_repos))
        else:
            run.rule('secret-prevention', 'warn',
                     ['secret scan hooks found: 0 (repositories scanned: %d)'
                      % repos_scanned])


# --- G7: git hygiene ------------------------------------------------------------------

def _g7(facts, run):
    top = facts.get('top_level')
    if top is None:
        _missing(run, 'GIT', 'Git hygiene not verified', 'top_level')
        for name in ('worktree-clean', 'gitignore-present', 'tracked-big-files',
                     'single-checkout'):
            run.rule(name, 'unknown')
        return
    repos = [t for t in top if t.get('kind') == 'repo']
    if not repos:
        deeper = _unchecked_repos(facts, top)
        if deeper:
            # repositories exist, but not where their hygiene is read
            status, why, count = 'unknown', 'git_nested_unverified', len(deeper)
            evidence = ['top-level repositories: 0, unverified: %d' % len(deeper)]
        else:
            status, why, count = 'not_applicable', _NO_GIT_WHY, None
            evidence = ['no git repositories at the top level']
        for name in ('worktree-clean', 'gitignore-present', 'tracked-big-files',
                     'single-checkout'):
            run.rule(name, status, evidence, why=why, count=count)
        return

    deeper = _unchecked_repos(facts, top)

    def hygiene_rule(name, status, evidence):
        # a clean result covers only the repositories that were read
        if deeper and status == 'pass':
            run.rule(name, 'unknown',
                     evidence + ['deeper repositories not read: %d' % len(deeper)],
                     why='git_nested_unverified', count=len(deeper))
        else:
            run.rule(name, status, evidence)

    dirty = 0
    for t in repos:
        g = t.get('git') or {}
        nd = len(g.get('dirty') or [])
        nu = len(g.get('untracked') or [])
        if nd or nu:
            dirty += 1
            run.finding(
                'GIT', 'low', 'warn', 'Uncommitted work in %s' % _repo_label(t),
                '%d modified and %d untracked paths; local-only work is one disk '
                'failure away from loss.' % (nd, nu),
                [{'repo': t.get('name'), 'dirty': nd, 'untracked': nu}], 0.9,
                'Commit or stash the changes; push if the repo has a remote.',
                check_id='GIT_UNCOMMITTED_WORK')
    hygiene_rule('worktree-clean', 'warn' if dirty else 'pass',
                 ['repos with uncommitted work: %d of %d' % (dirty, len(repos))])

    noign = [t for t in repos if not (t.get('extra') or {}).get('gitignore', False)]
    for t in noign:
        run.finding(
            'GIT', 'low', 'warn', 'No .gitignore in %s' % _repo_label(t),
            'Without .gitignore, build artifacts and local config land in commits.',
            [{'repo': t.get('name')}], 0.9,
            'Add a .gitignore covering build dirs and local config files.',
            check_id='GIT_NO_GITIGNORE')
    hygiene_rule('gitignore-present', 'warn' if noign else 'pass',
                 ['repos without .gitignore: %d' % len(noign)])

    lf = facts.get('large_files')
    if lf is None:
        _missing(run, 'GIT', 'Large tracked files not verified', 'large_files')
        run.rule('tracked-big-files', 'unknown')
    else:
        repo_names = {_norm(t.get('name', '')) for t in repos}
        big = 0
        for f in lf:
            size = f.get('size_bytes') or 0
            if size < GATE_POLICY['TRACKED_BIG_BYTES']:
                continue
            inside = _norm(f.get('path', '')).split('/')[0] in repo_names
            tracked = f.get('tracked', inside)
            if not tracked:
                continue
            big += 1
            run.finding(
                'GIT', 'medium', 'fail',
                'Tracked file over %s: %s' % (_mb(GATE_POLICY['TRACKED_BIG_BYTES']),
                                              f.get('path')),
                'A %s file lives in git; every clone pays for it and the history '
                'keeps it forever.' % _mb(size),
                [{'file': f.get('path'), 'size': _kb(size)}], 0.9,
                'Move the file out of git (or into git-lfs) and rewrite history '
                'if it already spread.',
                check_id='GIT_TRACKED_FILE_TOO_BIG')
        hygiene_rule('tracked-big-files', 'fail' if big else 'pass',
                     ['tracked files over %s: %d'
                      % (_mb(GATE_POLICY['TRACKED_BIG_BYTES']), big)])

    dup = facts.get('dup_checkouts')
    if dup is None:
        _missing(run, 'GIT', 'Duplicate checkouts not verified', 'dup_checkouts')
        run.rule('single-checkout', 'unknown')
    else:
        dups = [(url, names) for url, names in sorted(dup.items()) if len(names) > 1]
        for url, names in dups:
            run.finding(
                'GIT', 'low', 'warn',
                'Multiple checkouts of one remote: %s' % ', '.join(names),
                'The same repository is checked out %d times; edits in one copy do '
                'not reach the others.' % len(names),
                [{'remote': url, 'checkouts': names}], 0.9,
                'Keep one checkout or make the others deliberate worktrees.',
                check_id='GIT_MULTIPLE_CHECKOUTS')
        hygiene_rule('single-checkout', 'warn' if dups else 'pass',
                     ['remotes with several checkouts: %d' % len(dups)])


# --- G8: agent environment governance --------------------------------------------

def _g8(facts, run):
    h = facts.get('harness')
    notes = h.get('notes') if isinstance(h, dict) else None
    if notes is None:
        _missing(run, 'GOV', 'Agent environment governance not verified', 'harness')
        run.rule('dead-harness-instructions', 'unknown')
    else:
        for note in notes:
            run.finding(
                'GOV', 'medium', 'fail',
                'Instructions maintained for a dead harness',
                'An instruction file is kept for a harness that has been idle: %s'
                % note,
                [{'detail': note}], 0.85,
                'Remove the file or convert it to a pointer under the harness '
                'actually in use.',
                check_id='GOV_DEAD_HARNESS_INSTRUCTIONS')
        run.rule('dead-harness-instructions', 'fail' if notes else 'pass',
                 ['governance notes: %d' % len(notes)])

    drift = facts.get('context_drift')
    if drift is None:
        run.rule('drift-ownership', 'unknown')
    elif drift:
        refs = sorted(run.ctx.get('drift_fids', []))
        run.rule('drift-ownership', 'pass',
                 ['drifted pairs: %d, owned by G1/G3 findings (%s)'
                  % (len(drift), ', '.join(refs) or 'n/a')])
    else:
        run.rule('drift-ownership', 'pass', ['drifted pairs: 0'])

    cfg = facts.get('config_integrity')
    if cfg is None:
        _missing(run, 'GOV', 'MCP configuration not verified', 'config_integrity')
        run.rule('mcp-duplicate-keys', 'unknown')
    else:
        mcp_bad = 0
        for e in cfg:
            if 'mcp' not in _norm(e.get('path', '')).lower():
                continue
            for key in e.get('dup_keys') or []:
                mcp_bad += 1
                run.finding(
                    'GOV', 'medium', 'fail',
                    'Duplicate key %r in MCP config %s' % (key, e.get('path')),
                    'Two blocks in the MCP configuration share a key; one silently '
                    'wins and the running setup diverges from what is written.',
                    [{'file': e.get('path'), 'key': key}], 0.9,
                    'Rename or remove the duplicate block so each key maps to one server.',
                    check_id='GOV_MCP_DUPLICATE_KEY')
        run.rule('mcp-duplicate-keys', 'fail' if mcp_bad else 'pass',
                 ['MCP configs with duplicate keys: %d' % mcp_bad])


# --- G9: workspace health ----------------------------------------------------------

def _g9(facts, run):
    jc = facts.get('junk_classified')
    if jc is None:
        _missing(run, 'HLTH', 'Junk classification not verified', 'junk_classified')
        run.rule('classified-junk', 'unknown')
    else:
        actionable = [j for j in jc
                      if j.get('cls') in ('confirmed_unused', 'potentially_unused')]
        for j in actionable:
            conf = j.get('confidence')
            if not isinstance(conf, (int, float)) or isinstance(conf, bool):
                conf = 0.7
            run.finding(
                'HLTH', 'low', 'warn',
                'Unused data (%s): %s' % (j.get('cls'), j.get('path', '?')),
                'Classified as %s (confidence %s): %s.'
                % (j.get('cls'), conf, j.get('reason')),
                [{'path': j.get('path'), 'reason': j.get('reason'),
                  'size': _kb(j.get('size_bytes')), 'class': j.get('cls')}],
                conf, 'Review, then archive or delete.',
                autofix_available=(j.get('cls') == 'confirmed_unused'),
                check_id='HLTH_UNUSED_DATA')
        run.rule('classified-junk', 'warn' if actionable else 'pass',
                 ['classified junk items: %d' % len(actionable)])

    j = facts.get('junk')
    if j is None:
        _missing(run, 'HLTH', 'Junk volume not verified', 'junk')
        run.rule('junk-volume', 'unknown')
        run.rule('empty-dirs', 'unknown')
    else:
        files = j.get('files') or []
        dirs = j.get('dirs') or []
        total = (sum(f.get('size_bytes', 0) for f in files)
                 + sum(d.get('size_bytes', 0) for d in dirs))
        if total > GATE_POLICY['JUNK_FAIL_BYTES']:
            run.finding(
                'HLTH', 'medium', 'fail',
                'Junk and build artifacts over %s' % _mb(GATE_POLICY['JUNK_FAIL_BYTES']),
                'The workspace carries %s of junk files and build directories; '
                'scans, backups and disk suffer.' % _mb(total),
                [{'detail': 'total junk+build size: %d bytes' % total}], 0.95,
                'Delete build dirs (they regenerate) and archive or remove the rest.',
                check_id='HLTH_JUNK_OVER_LIMIT')
        run.rule('junk-volume',
                 'fail' if total > GATE_POLICY['JUNK_FAIL_BYTES'] else 'pass',
                 ['junk+build total: %s across %d files and %d dirs'
                  % (_mb(total), len(files), len(dirs))])
        empty = j.get('empty_dirs') or []
        if len(empty) > GATE_POLICY['EMPTY_WARN_COUNT']:
            run.finding(
                'HLTH', 'info', 'warn', '%d empty directories' % len(empty),
                'More than %d empty dirs: usually debris from moves and deletes.'
                % GATE_POLICY['EMPTY_WARN_COUNT'],
                [{'path': p} for p in empty[:50]], 0.9,
                'Remove the empty directories.',
                check_id='HLTH_EMPTY_DIRS')
            run.rule('empty-dirs', 'warn', ['empty dirs: %d' % len(empty)])
        elif empty:
            run.finding(
                'HLTH', 'info', 'pass', '%d empty directories' % len(empty),
                'A few empty dirs are harmless; recorded as an observation.',
                [{'path': p} for p in empty[:50]], 0.9,
                'Optional: remove the empty directories.',
                check_id='HLTH_EMPTY_DIRS')
            run.rule('empty-dirs', 'pass',
                     ['empty dirs: %d (at or below %d)'
                      % (len(empty), GATE_POLICY['EMPTY_WARN_COUNT'])])
        else:
            run.rule('empty-dirs', 'pass', ['empty dirs: 0'])

    h = facts.get('harness')
    tools = h.get('tools') if isinstance(h, dict) else None
    if tools is None:
        run.rule('occasional-harness', 'unknown')
    else:
        occ = [t for t in tools if t.get('state') == 'occasional']
        for t in occ:
            run.finding(
                'HLTH', 'info', 'warn',
                'Harness %s used occasionally' % t.get('tool'),
                'Last activity %s days ago: between fresh and abandoned; decide '
                'which way it goes.' % t.get('last_activity_days_ago'),
                [{'tool': t.get('tool'), 'days': t.get('last_activity_days_ago')}],
                0.8, 'Keep it maintained or retire its config files.',
                check_id='HLTH_HARNESS_OCCASIONAL')
        run.rule('occasional-harness', 'warn' if occ else 'pass',
                 ['occasional harnesses: %d' % len(occ)])

    lf = facts.get('large_files')
    top = facts.get('top_level')
    if lf is None or top is None:
        run.rule('large-untracked-files', 'unknown',
                 ['skipped: large_files or top_level facts missing'])
    else:
        repo_names = {_norm(t.get('name', '')) for t in top if t.get('kind') == 'repo'}
        if '.' in repo_names and any('tracked' in f for f in lf):
            # the audited folder is a repository and git said which large
            # files it holds; the rest have no history behind them
            outside = [f for f in lf if f.get('tracked') is False]
        else:
            outside = [f for f in lf
                       if _norm(f.get('path', '')).split('/')[0] not in repo_names]
        for f in outside:
            run.finding(
                'HLTH', 'low', 'warn',
                'File over %s outside git: %s'
                % (_mb(GATE_POLICY['TRACKED_BIG_BYTES']), f.get('path')),
                'Large files outside version control; check whether they are data '
                'worth keeping.',
                [{'path': f.get('path'), 'size': _kb(f.get('size_bytes'))}], 0.9,
                'Move under version control (git-lfs if needed) or delete.',
                check_id='HLTH_LARGE_FILE_OUTSIDE_GIT')
        run.rule('large-untracked-files', 'warn' if outside else 'pass',
                 ['large files outside git: %d' % len(outside)])


_BUILDERS = {'G1': _g1, 'G2': _g2, 'G3': _g3, 'G4': _g4, 'G5': _g5,
             'G6': _g6, 'G7': _g7, 'G8': _g8, 'G9': _g9}


def evaluate(facts):
    """Evaluate all nine gates over the facts dict.

    Returns (gates, findings): gates in GATE_DEFS order, findings in
    creation order with stable <PREFIX>-<counter> ids (SEC-001, CFG-001,
    ...). A gate's status is the worst status among its rules; a gate
    whose rules all lack data is unknown, never pass.

    facts['harness_findings_raw'] (adapter findings + instruction
    conflicts, see harness/collect.py) join the gate they are mapped
    to: their status counts into the gate worst-status and their ids
    come from the same counters, with the stable harness/check_id
    fields riding along.
    """
    facts = facts or {}
    counter = _Counter()
    findings = []
    ctx = {}
    gates_out = []
    raw_by_gate = {}
    for raw in facts.get('harness_findings_raw') or []:
        raw_by_gate.setdefault(raw.get('gate'), []).append(raw)
    for gd in GATE_DEFS:
        run = _GateRun(gd['gid'], counter, findings, ctx)
        _BUILDERS[gd['gid']](facts, run)
        extra = raw_by_gate.get(gd['gid'], [])
        appended = []
        for raw in extra:
            evidence = raw.get('evidence') or []
            status = raw.get('status', 'unknown')
            if not evidence and status != 'unknown':
                status = 'unknown'   # no proof, no verdict
            try:
                f = report_model.make_finding(
                    fid=counter.next_id(raw.get('prefix', 'GOV')),
                    gate=gd['gid'], category=raw.get('category', 'governance'),
                    severity=raw.get('severity', 'info'),
                    status=status,
                    title=raw.get('title', ''),
                    description=raw.get('description', ''),
                    evidence=evidence,
                    confidence=raw.get('confidence', 0.5),
                    recommendation=raw.get('recommendation', ''))
            except ValueError:
                continue   # malformed adapter finding: drop, never crash
            f['harness'] = raw.get('harness', '')
            f['check_id'] = raw.get('check_id', '')
            findings.append(f)
            appended.append(f)
        statuses = ([c['status'] for c in run.checks]
                    + [f['status'] for f in appended])
        status = worst_status(statuses)
        conf = min((f['confidence'] for f in findings if f['gate'] == gd['gid']),
                   default=0.95)
        gate = report_model.make_gate(
            gid=gd['gid'], n=gd['n'], name=gd['name'],
            description=gd['description'], checks=run.checks,
            pass_when=gd['pass_when'], fail_when=gd['fail_when'],
            warn_when=gd['warn_when'], status=status,
            evidence=run.evidence, confidence=round(conf, 2),
            recommendation=gd['recommendation'], doc_ref=gd['doc_ref'])
        if status in ('unknown', 'not_applicable'):
            # why the gate did not pass or did not apply: the reason of
            # its first rule carrying that status
            cause = next((c for c in run.checks
                          if c['status'] == status and c.get('reason')), None)
            if cause:
                gate['status_reason'] = cause['reason']
                if cause.get('why'):
                    gate['status_why'] = cause['why']
                if cause.get('count') is not None:
                    gate['status_count'] = cause['count']
        gates_out.append(gate)
    return gates_out, findings
