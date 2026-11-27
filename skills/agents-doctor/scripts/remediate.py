#!/usr/bin/env python3
"""Guarded remediation engine for agents-doctor.

Turns one typed finding from a scan.json into a plan of small, reversible
steps and executes the plan only after explicit confirmation. Supported
in v1 (deliberately conservative):

- HLTH "<N> empty directories"            -> rmdir every empty dir in the evidence
- GIT "No .gitignore in <repo>"           -> write a small .gitignore template
- HLTH "Unused data (confirmed_unused)" with autofix_available
                                          -> move the path into
                                             <root>/.agents-doctor-trash/
                                             <timestamp>-<opid>/
                                             keeping its relative path

Every other finding raises UnsupportedError; no command of any kind is
built for an unsupported finding.

Safety model:
- no step touches anything outside the audited root: every target is
  resolve()d and containment-checked when the plan is built and again
  before the first step runs;
- an empty plan touches nothing and never prompts;
- the trash directory name is the constant TRASH_DIR_NAME
  ('.agents-doctor-trash'); the generated .gitignore template lists
  it, and trash moves never overwrite an existing destination (a taken
  name gets an '.__N__' suffix, see trashops.py);
- every mutating step is journaled through trashops (move_to_trash,
  record_rmdir, record_create_file): per-run operation id, write-ahead
  manifest.json in the run directory, crash-recovery detection of
  interrupted earlier runs. Undo a whole run -- moved files, removed
  empty directories, written .gitignore files -- with
  `safe_clean.py restore <run_dir>`;
- every planned target carries a plan-time TOCTOU snapshot {size,
  mtime_ns, type}; immediately before each mutation (after the user
  confirmed) trashops._pre_operation_check re-verifies canonical
  containment under the root, a symlink-free literal path chain, the
  expected type and the snapshot; a drifted target is skipped as
  'changed', a swapped symlink or an escape raises
  trashops.SecurityRefusal and is recorded as a failed step;
- the .gitignore write creates the file with os.open(O_CREAT|O_EXCL):
  a name that appears (or a link planted) between the check and the
  write can never be overwritten or written through;
- rmdir goes through os.rmdir (a non-empty directory fails loudly) and
  is journaled, so restore can recreate the empty directory;
- a failing step is recorded and the run continues with the next step;
- no network access, no git mutations, no overwrites.

apply_plan(assume_yes=True) skips the interactive prompt; it exists for
tests and automation and is never passed by the CLI.

Also provides fingerprint_diff(old, new) -> {new, resolved, persisting,
changed}, the same diff the scanner's --baseline computes plus a CHANGED
section (same section+path, different fingerprint), and reaudit() for
the before/after report.

Harness-aware fixes: findings raised by harness adapters carry a
stable check_id; CHECK_ID_FIXES maps the supported ones to a plan.
CLAUDE_LOCAL_DEPRECATED moves the file into the trash run
(autofix, risk review: the file may hold something worth merging
first), CURSOR_LEGACY_AND_RULES / WINDSURF_LEGACY_AND_RULES and
INSTR_DUPLICATION get display-only plans (autofix_available=False,
nothing executes). A check_id without a registry entry is
UnsupportedError, like every unsupported finding.

Risk levels: every step carries risk 'safe' | 'review' | 'high' |
'manual'. Steps without a risk field are 'safe' (plans from older
callers keep working). safe steps run after the single global 'yes';
review and high steps additionally ask per step ("step N risk=REVIEW:
<target> -- apply this step? [yes/no]"; a 'no' or EOF skips the step
with reason 'declined-risk'); manual steps are advice only and never
execute (recorded skipped, reason 'manual').
New step types: fix_dead_link (manual: the reference is checked or
removed by hand, the md text is never rewritten automatically),
normalize_config (review: a JSON file with duplicate keys is rewritten
keeping the FIRST occurrence of every key and indent 2; the original
lands in the trash run as the backup; an mtime/size drift between plan
and apply skips the step as changed), dedupe_instructions (manual:
which blocks repeat in which files, extract-them-once advice) and
context_tax_hint (manual: shrink advice for an oversized instruction
file).

Operation journal: every apply appends one line to
<root>/.agents-doctor/operations.jsonl -- {ts, fid, check_id, root,
steps: [{action, target, risk, result}]} -- paths and verdicts only,
never file contents, so no secret can leak into it. Journal failures
print a warning and never fail the apply.

Concurrency and crash recovery: apply_plan runs under the
trash lock (.agents-doctor-trash/.lock, O_EXCL) and refuses cleanly
with RemediateBusy while another run holds it; trashops.find_incomplete
/ trashops.recover roll back write-ahead entries an interrupted run
left in flight.

CLI:
    python remediate.py <scan.json> <fid> [--apply] [--root R] [--reaudit]

Exit codes: 0 ok (dry run, declined confirmation or clean apply), 1 IO
or safety error or failed steps (including RemediateBusy), 3 no
supported automatic fix.
"""
import argparse
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import audit_scan  # noqa: E402  (BUILD_DIRS for the template, scan for reaudit)
import trashops  # noqa: E402  (shared trash-run machinery)

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

PROG = 'remediate'

# where moved junk lands:
# <root>/<TRASH_DIR_NAME>/<YYYYmmdd-HHMMSS>-<opid>/<rel path> (trashops.py)
TRASH_DIR_NAME = trashops.TRASH_DIR_NAME

SKIPPED = 'skipped'
# _execute_step sentinels: the target changed between plan() and apply
# (the step is skipped, the disk is left alone for it), and a manual
# step (advice only; nothing ever executes)
CHANGED = 'changed'
MANUAL = 'manual'

# --- risk levels ------------------------------------------------------------------

RISK_SAFE = 'safe'   # runs after the single global confirmation
RISK_REVIEW = 'review'  # additionally asks per step; the user sees the target
RISK_HIGH = 'high'   # same per-step gate as review; reserved for riskier fixes
RISK_MANUAL = 'manual'  # advice only; never executes, recorded skipped
RISKS = (RISK_SAFE, RISK_REVIEW, RISK_HIGH, RISK_MANUAL)

# operation journal: <root>/<OPS_DIR_NAME>/<OPS_JOURNAL_NAME>
OPS_DIR_NAME = '.agents-doctor'
OPS_JOURNAL_NAME = 'operations.jsonl'

_LOCAL_IGNORE_LINES = ('.env', '.mcp.json', 'settings.local.json')


def step_risk(step):
    """Risk of one plan step; steps without a valid risk field are
    'safe' (plans built before the field existed keep working)."""
    risk = (step or {}).get('risk')
    return risk if risk in RISKS else RISK_SAFE


class UnsupportedError(Exception):
    """The finding has no supported automatic fix."""


# clean refusal when another trash run holds the lock;
# trashops.LockBusy under its remediate-facing name
RemediateBusy = trashops.LockBusy


# --- harness check_id registry -----------------------------------------------------

# Adapter findings carry a stable check_id (harness/adapters/*); the
# registry maps the ones with a supported fix to a plan builder spec:
# 'autofix' entries build a trash_move step for evidence[0].file;
# manual entries list (command, note) migration steps that are printed
# but never executed (apply_plan records them as skipped/manual); a
# 'builder' entry is a function (root, fid, check_id, evidence) ->
# steps for findings whose steps depend on the evidence. 'risk' is the
# risk level the built steps carry.
CHECK_ID_FIXES = {
    'CLAUDE_LOCAL_DEPRECATED': {
        'autofix': True,
        'risk': RISK_REVIEW,   # the user looks first: the file may be needed
        'note': 'CLAUDE.local.md is deprecated; the file moves into the '
                'trash run -- merge anything worth keeping into CLAUDE.md '
                'or .claude/rules/ before deleting the trash',
    },
    'CURSOR_LEGACY_AND_RULES': {
        'autofix': False,
        'risk': RISK_MANUAL,
        'manual': [
            ('migrate .cursorrules content -> .cursor/rules/legacy.md',
             'the legacy format cannot express scoping; frontmatter '
             '(description, globs) has to be written by hand'),
            ('delete .cursorrules once the migrated rule is confirmed '
             'to load',
             'both sources present can overlap or conflict, so removal '
             'follows the migration, not the other way round'),
        ],
    },
    'WINDSURF_LEGACY_AND_RULES': {
        'autofix': False,
        'risk': RISK_MANUAL,
        'manual': [
            ('migrate .windsurfrules content -> .windsurf/rules/legacy.md',
             'the legacy format cannot express triggers; frontmatter has '
             'to be written by hand'),
            ('delete .windsurfrules once the migrated rule is confirmed '
             'to load',
             'both sources present can overlap or conflict, so removal '
             'follows the migration, not the other way round'),
        ],
    },
    # instruction blocks duplicated across sources: the plan
    # names both files and lines; the extraction into one shared file
    # is a hand edit, never an automatic rewrite
    'INSTR_DUPLICATION': {
        'autofix': False,
        'risk': RISK_MANUAL,
        'builder': lambda root, fid, check_id, evidence: _plan_instr_duplication(
            root, fid, check_id, evidence),
    },
}


def gitignore_template():
    """Small .gitignore template: build dirs + local config files."""
    lines = ['# generated by agents-doctor remediate.py', '# build artifacts']
    lines += sorted(d + '/' for d in audit_scan.BUILD_DIRS)
    lines += ['', '# local config files (may hold secrets)']
    lines += list(_LOCAL_IGNORE_LINES)
    lines += ['', '# agents-doctor remediation trash (review, then delete)',
              TRASH_DIR_NAME + '/']
    return '\n'.join(lines) + '\n'


# --- helpers -----------------------------------------------------------------

def _require_inside(root, target):
    """Resolve + containment check, like the scanner's boundary guard:
    target must be the root itself or live below it."""
    root = Path(root).resolve()
    try:
        resolved = Path(target).resolve()
    except OSError as exc:
        raise ValueError('cannot resolve target %s: %s' % (target, exc))
    if resolved != root and root not in resolved.parents:
        # TOCTOU defence: a target that planned inside but now
        # resolves outside is an attack diagnosis, not a usage
        # error; SecurityRefusal subclasses ValueError so plan-
        # time callers see the same clean message as before
        raise trashops.SecurityRefusal(
            'target escapes the workspace root: %s' % target)


def _rel_under(target, root):
    """Display form of target's path relative to root (posix slashes)."""
    try:
        return Path(target).resolve().relative_to(Path(root).resolve()).as_posix()
    except ValueError:
        return str(target)


def _exists_quiet(p):
    """exists() that treats permission errors as absent."""
    try:
        return Path(p).exists()
    except OSError:
        return False


def _find_ref_line(path, ref):
    """1-based line number of the first line containing ref, or None
    (plan-time read only; used to point the user at the dead
    reference)."""
    try:
        text = Path(path).read_text(encoding='utf-8', errors='replace')
    except OSError:
        return None
    for num, line in enumerate(text.splitlines(), 1):
        if ref in line:
            return num
    return None


def _dedupe_json(raw):
    """Parse a JSON document keeping the FIRST occurrence of every
    duplicate key (at every nesting level, matching the duplicate
    detection in enrich._json_dup_keys; the stdlib parser alone keeps
    the LAST one). Returns (model, sorted duplicate key names);
    raises ValueError when the text is not valid JSON."""
    dups = set()

    def hook(pairs):
        obj = {}
        seen = set()
        for key, value in pairs:
            if key in seen:
                dups.add(key)
            else:
                seen.add(key)
                obj[key] = value
        return obj

    model = json.loads(raw, object_pairs_hook=hook)
    return model, sorted(dups)


def after_path(scan_path):
    """Where reaudit() writes the fresh scan: <stem>.after.json."""
    p = Path(scan_path)
    return p.with_name(p.stem + '.after.json')


# --- fingerprint diff ----------------------------------------------------------

def fingerprint_diff(old_findings, new_findings):
    """Diff two rep['findings'] fingerprint lists ({fp, section, path}).

    Sections: new (fingerprint appeared), resolved (fingerprint gone),
    persisting (same fingerprint in both), changed (fingerprint is new
    but its section+path existed in the old scan with another
    fingerprint -- the same problem reshaped). Changed entries also
    count as new.
    """
    old = [f for f in (old_findings or [])
           if isinstance(f, dict) and f.get('fp')]
    new = [f for f in (new_findings or [])
           if isinstance(f, dict) and f.get('fp')]
    old_fps = {f['fp'] for f in old}
    new_fps = {f['fp'] for f in new}
    old_by_key = {}
    for f in old:
        old_by_key.setdefault((f.get('section'), f.get('path')), set()).add(f['fp'])
    changed, changed_keys = [], set()
    for f in new:
        key = (f.get('section'), f.get('path'))
        fps = old_by_key.get(key)
        if fps and f['fp'] not in fps and key not in changed_keys:
            changed.append(f)
            changed_keys.add(key)
    return {
        'new': [f for f in new if f['fp'] not in old_fps],
        'resolved': [f for f in old if f['fp'] not in new_fps],
        'persisting': [f for f in new if f['fp'] in old_fps],
        'changed': changed,
    }


# --- planning ------------------------------------------------------------------

def plan(rep, fid):
    """Plan the fix for one finding.

    Returns a list of step dicts {action, target, command, reversible,
    note}; 'command' is a shell-style string for display only. An empty
    list means "nothing to do right now" (targets already gone). Raises
    UnsupportedError (message names the fid and the reason) for anything
    without a supported automatic fix, and ValueError when a target
    would leave the audited root. No destructive command is ever
    generated for an unsupported finding.

    Findings that carry a check_id registered in CHECK_ID_FIXES
    (harness adapters, the adapter contract) are planned through that
    registry: a registered autofix becomes a trash_move step, a
    registered manual entry becomes display-only steps with
    autofix_available=False.
    Every finding carries a check_id (gate findings too, it names the
    finding type); one the registry does not know falls through to the
    gate routes below, which plan by the shape of the evidence.
    """
    finding = None
    for f in rep.get('findings_detailed') or []:
        if f.get('fid') == fid:
            finding = f
            break
    if finding is None:
        raise UnsupportedError(
            'finding %s not found in this scan; re-run the audit or check the '
            'id with "agents_doctor.py explain <scan.json> %s"' % (fid, fid))
    root = Path(rep.get('root') or '.').resolve()
    title = str(finding.get('title') or '')
    evidence = finding.get('evidence') or []
    prefix = str(fid).split('-', 1)[0]

    # 0) harness-adapter findings carry a stable check_id (the adapter
    # contract): the registry decides. Gate findings carry a check_id as
    # well; one the registry does not know is planned by the gate routes below
    check_id = str(finding.get('check_id') or '')
    if check_id and check_id in CHECK_ID_FIXES:
        return _plan_check_id(root, fid, check_id, evidence)

    # 1) confirmed-unused junk -> move into the trash dir
    if prefix == 'HLTH' and title.startswith('Unused data (confirmed_unused'):
        if not finding.get('autofix_available'):
            raise UnsupportedError(
                '%s: confirmed-unused finding without autofix_available; '
                're-run the audit, then fix it by hand' % fid)
        steps = []
        for ev in evidence:
            rel = ev.get('path')
            if not rel:
                continue
            target = root / rel
            _require_inside(root, target)
            if not target.exists():
                continue  # already gone since the scan: nothing to plan
            steps.append({
                'action': 'trash_move',
                'target': str(target),
                'command': 'move "%s" -> "%s"' % (
                    target,
                    root / TRASH_DIR_NAME / '<timestamp>-<opid>'
                    / _rel_under(target, root)),
                'reversible': True,
                'risk': RISK_SAFE,
                'note': 'lands under %s/<timestamp>-<opid>/ with the relative '
                        'path kept; undo with safe_clean.py restore' % TRASH_DIR_NAME,
                'snapshot': trashops.snapshot(target),
            })
        return steps

    # 2) repo without .gitignore -> write the small template
    if prefix == 'GIT' and title.startswith('No .gitignore in'):
        repo_name = None
        for ev in evidence:
            if ev.get('repo'):
                repo_name = ev['repo']
                break
        if repo_name is None:
            m = re.match(r'No \.gitignore in (\S+)', title)
            repo_name = m.group(1) if m else None
        if not repo_name:
            raise UnsupportedError(
                '%s: cannot tell which repository the finding is about' % fid)
        target = root / repo_name / '.gitignore'
        _require_inside(root, target)
        if target.exists():
            note = '.gitignore already exists; nothing will be written'
        else:
            note = ('template: build dirs, .env, .mcp.json, settings.local.json, '
                    + TRASH_DIR_NAME + '/')
        return [{
            'action': 'write_gitignore',
            'target': str(target),
            'command': 'write template .gitignore -> "%s"' % target,
            'reversible': True,
            'risk': RISK_SAFE,
            'note': note,
        }]

    # 3) the empty-directories observation -> rmdir each evidence dir
    if prefix == 'HLTH' and re.match(r'^\d+\s+empty directories\b', title):
        steps = []
        for ev in evidence:
            rel = ev.get('path')
            if not rel:
                continue
            target = root / rel
            _require_inside(root, target)
            if not target.is_dir():
                continue
            if any(target.iterdir()):
                continue  # no longer empty: refuse, os.rmdir would too
            steps.append({
                'action': 'rmdir',
                'target': str(target),
                'command': 'rmdir "%s"' % target,
                'reversible': True,
                'risk': RISK_SAFE,
                'note': 'directory is empty; removing it loses no content',
                'snapshot': trashops.snapshot(target),
            })
        return steps

    # 4) dead references in instruction files: one manual
    # step per reference -- verify the path or remove it by hand; the
    # markdown text is deliberately never rewritten automatically
    if prefix == 'RUL' and re.match(r'^Dead (link|path|command) in ', title):
        steps = []
        for ev in evidence:
            rel_file = ev.get('file')
            ref = ev.get('ref')
            kind = ev.get('kind') or 'reference'
            if not rel_file or not ref:
                continue
            target = root / rel_file
            _require_inside(root, target)
            if not _exists_quiet(target):
                continue  # the instruction file itself is gone since the scan
            line = _find_ref_line(target, ref)
            # display in posix form whatever the platform separator is
            where = '%s:%s' % (Path(rel_file).as_posix(),
                               line if line else '?')
            steps.append({
                'action': 'fix_dead_link',
                'target': str(target),
                'command': 'verify the path or remove the dead %s %r in %s'
                           % (kind, ref, where),
                'reversible': False,
                'risk': RISK_MANUAL,
                'autofix_available': False,
                'note': 'the instruction file points at %r which does not '
                        'exist; check whether the path moved, then fix or '
                        'remove the reference by hand -- rewriting the text '
                        'automatically could discard a rule worth keeping'
                        % ref,
                'ref': ref,
                'kind': kind,
                'line': line,
            })
        return steps

    # 5) oversized instruction file: shrink advice, manual
    if prefix == 'RUL' and title.startswith('Instruction file over'):
        steps = []
        for ev in evidence:
            rel_file = ev.get('file')
            if not rel_file:
                continue
            target = root / rel_file
            _require_inside(root, target)
            if not _exists_quiet(target):
                continue
            size = ev.get('size') or 'over the benchmark'
            steps.append({
                'action': 'context_tax_hint',
                'target': str(target),
                'command': 'shrink the instruction file %s (%s over the '
                           'auto-load benchmark)' % (rel_file, size),
                'reversible': False,
                'risk': RISK_MANUAL,
                'autofix_available': False,
                'note': 'the file is auto-loaded into every session, so its '
                        'size is a per-session tax: keep only rules in it, '
                        'move reference material into documents the agent '
                        'reads on demand and link them',
            })
        return steps

    # 6) duplicate keys in a JSON config: the plan shows the
    # duplicates; the rewrite is one review-gated step -- first
    # occurrence wins, key order kept, indent 2, original backed up in
    # the trash run
    if prefix == 'CFG' and title.startswith('Duplicate key'):
        ev0 = (evidence or [{}])[0] if evidence else {}
        rel_file = ev0.get('file')
        if not rel_file:
            raise UnsupportedError(
                '%s: duplicate-key finding carries no file to fix' % fid)
        target = root / rel_file
        _require_inside(root, target)
        if not _exists_quiet(target):
            return []            # already gone since the scan: nothing to plan
        try:
            raw = Path(target).read_text(encoding='utf-8', errors='replace')
            model, dups = _dedupe_json(raw)
        except ValueError as exc:
            raise UnsupportedError(
                '%s: %s is not valid JSON (%s); normalize supports JSON '
                'files only -- fix it by hand' % (fid, rel_file, exc))
        if not dups:
            return []            # duplicates already gone: nothing to rewrite
        return [{
            'action': 'normalize_config',
            'target': str(target),
            'command': 'rewrite %s without the duplicate key(s) %s -- first '
                       'occurrence wins, key order kept, indent 2'
                       % (rel_file, ', '.join(repr(k) for k in dups)),
            'reversible': True,
            'risk': RISK_REVIEW,
            'autofix_available': True,
            'note': 'the original file moves into the trash run as the '
                    'backup, then the deduplicated text is written in its '
                    'place (json model, indent 2 -- a source formatted '
                    'otherwise will show a whitespace diff); undo with '
                    'safe_clean.py restore',
            'snapshot': trashops.snapshot(target),
            'dup_keys': dups,
        }]

    raise UnsupportedError(
        '%s: no supported automatic fix for this finding (title %r, gate %s, '
        'category %s%s); apply its recommendation by hand'
        % (fid, title, finding.get('gate'), finding.get('category'),
           ', check_id %s' % check_id if check_id else ''))


def _trash_step(root, target, note, risk=RISK_SAFE):
    """One trash_move step dict for an absolute target under root."""
    return {
        'action': 'trash_move',
        'target': str(target),
        'command': 'move "%s" -> "%s"' % (
            target,
            root / TRASH_DIR_NAME / '<timestamp>-<opid>'
            / _rel_under(target, root)),
        'reversible': True,
        'risk': risk,
        'note': note,
        'snapshot': trashops.snapshot(target),
    }


def _plan_instr_duplication(root, fid, check_id, evidence):
    """dedupe_instructions steps for an INSTR_DUPLICATION finding.

    The adapter evidence carries both sides of the duplicated block:
    [{'file': a, 'line': la, 'detail': text}, {'file': b, 'line': lb,
    ...}]. The plan restates both spots and recommends extracting the
    block into one shared file; the edit itself is manual -- merging
    instruction text automatically could silently change what agents
    load. A first file that is already gone since the scan plans
    nothing."""
    steps = []
    for i, ev in enumerate(evidence or []):
        rel_file = ev.get('file')
        if not rel_file:
            continue
        target = Path(rel_file)
        if not target.is_absolute():
            target = root / target
        _require_inside(root, target)
        if not _exists_quiet(target):
            continue
        others = ['%s:%s' % (o.get('file'), o.get('line'))
                  for j, o in enumerate(evidence or [])
                  if j != i and o.get('file')]
        steps.append({
            'action': 'dedupe_instructions',
            'target': str(target),
            'command': 'extract the duplicated block at %s:%s into one '
                       'shared file and import/reference it from %s'
                       % (rel_file, ev.get('line'),
                          ', '.join(others) or 'the other sources'),
            'reversible': False,
            'risk': RISK_MANUAL,
            'autofix_available': False,
            'note': 'the same block appears in %s and %s ("%s..."); two '
                    'copies drift apart and both are paid for in every '
                    'session -- keep one copy and reference it'
                    % ('%s:%s' % (rel_file, ev.get('line')),
                       ', '.join(others) or 'the other source',
                       (ev.get('detail') or '')[:60]),
            'check_id': check_id,
        })
    return steps


def _plan_check_id(root, fid, check_id, evidence):
    """Plan the fix for a harness-adapter finding keyed by check_id.

    The target comes from evidence[0] ('file', as the adapters write
    it; 'path' accepted too), absolute or root-relative. Registered
    autofix entries build a trash_move step (the risk comes from the
    registry entry); manual entries build display-only steps with
    autofix_available=False that apply_plan records as skipped
    (nothing executes); a spec with a 'builder' plans straight from
    the evidence. A target that is already gone since the scan plans
    nothing. Unregistered check_ids raise UnsupportedError naming the
    check_id."""
    spec = CHECK_ID_FIXES.get(check_id)
    if spec is None:
        raise UnsupportedError(
            '%s: no supported automatic fix for check_id %s; apply its '
            'recommendation by hand' % (fid, check_id))
    if spec.get('builder'):
        return spec['builder'](root, fid, check_id, evidence)
    ev = (evidence or [{}])[0] if evidence else {}
    raw = ev.get('file') or ev.get('path')
    if not raw:
        raise UnsupportedError(
            '%s: check_id %s evidence carries no file to fix'
            % (fid, check_id))
    target = Path(raw)
    if not target.is_absolute():
        target = root / target
    _require_inside(root, target)
    if not _exists_quiet(target):
        return []            # already gone since the scan: nothing to plan
    if spec.get('autofix'):
        step = _trash_step(root, target, spec.get('note') or '',
                           risk=spec.get('risk') or RISK_SAFE)
        step['check_id'] = check_id
        step['autofix_available'] = True
        return [step]
    steps = []
    for command, note in spec.get('manual') or []:
        steps.append({
            'action': 'manual',
            'target': str(target),
            'command': command,
            'reversible': False,   # no automatic undo for a hand migration
            'risk': spec.get('risk') or RISK_MANUAL,
            'note': note,
            'autofix_available': False,
            'check_id': check_id,
        })
    return steps


def print_plan(fid, steps):
    """Print a plan the way the CLIs show a dry run (risk per step)."""
    print('fix plan for %s:' % fid)
    if not steps:
        print('  (nothing to do: no target from this finding is present)')
        return
    for i, st in enumerate(steps, 1):
        print('  %d. [%s] (risk: %s) %s'
              % (i, st.get('action'), step_risk(st), st.get('command')))
        print('     reversible: %s' % ('yes' if st.get('reversible') else 'no'))
        if st.get('note'):
            print('     note: %s' % st['note'])


# --- execution -----------------------------------------------------------------

# manual-risk action types: never dispatched even when a
# legacy caller hands them to _execute_step directly
MANUAL_ACTIONS = ('manual', 'fix_dead_link', 'dedupe_instructions',
                  'context_tax_hint')


def _execute_step(step, root, get_run):
    """Run one step; returns an executed-record dict, SKIPPED or
    CHANGED. get_run() lazily creates the shared trash run (opid +
    manifest) the first time a step needs it. Every mutating action --
    trash_move, rmdir, write_gitignore, normalize_config -- is
    journaled in that run's write-ahead manifest, so the whole plan is
    one undoable unit.

    Every mutating action runs trashops._pre_operation_check
    immediately before it touches the disk (after the user confirmed):
    canonical containment under root, no symlink anywhere in the
    literal path chain, expected type and the plan-time snapshot must
    all hold. A drifted target returns CHANGED; a swapped symlink or
    an escape raises trashops.SecurityRefusal and the step is recorded
    as failed."""
    action = step.get('action')
    target = Path(step.get('target', ''))
    cur = None
    if action in MANUAL_ACTIONS or step_risk(step) == RISK_MANUAL:
        return MANUAL       # advice only; apply_plan records it skipped
    if action in ('rmdir', 'trash_move'):
        # pre-operation gate: the symlink walk runs first, so a swapped
        # link is diagnosed as an attack, not as ordinary drift; then
        # containment; then the snapshot comparison
        ok, reason = trashops._pre_operation_check(
            root, target, step.get('snapshot'),
            expected_type=('dir' if action == 'rmdir' else None))
        if not ok:
            if reason == 'changed':
                return CHANGED   # drifted since plan(): skip, disk untouched
            if reason == 'missing' and action == 'rmdir':
                return CHANGED   # vanished since plan(): nothing to remove
            if reason == 'missing':
                raise OSError('source missing: %s' % target)
            raise trashops.SecurityRefusal(
                '%s refused (%s): %s' % (action, reason, target))
        cur = trashops.snapshot(target)
    if action == 'rmdir':
        with os.scandir(str(target)) as it:
            if next(it, None) is not None:
                return CHANGED   # no longer empty: skip, os.rmdir would too
        rel = target.resolve().relative_to(root).as_posix()
        run = get_run()
        # os.rmdir inside: loud failure when not empty or missing
        trashops.record_rmdir(run, target, rel, cur)
        return {'action': action, 'target': str(target), 'result': 'removed',
                'trash_run': str(run.run_dir), 'opid': run.opid}
    if action == 'write_gitignore':
        if target.exists():
            return SKIPPED  # never overwrite an existing .gitignore
        if os.path.islink(str(target)):
            raise trashops.SecurityRefusal(
                'write_gitignore refused (symlink): %s' % target)
        if not target.parent.is_dir():
            raise OSError('parent directory missing: %s' % target.parent)
        ok, reason = trashops._pre_operation_check(
            root, target.parent, expected_type='dir')
        if not ok:
            raise trashops.SecurityRefusal(
                'write_gitignore refused (%s): %s' % (reason, target.parent))
        rel = target.resolve().relative_to(root).as_posix()
        run = get_run()
        # O_CREAT|O_EXCL inside: a name planted between the checks and
        # the write can neither be written through nor overwritten
        trashops.record_create_file(run, target, rel, gitignore_template())
        return {'action': action, 'target': str(target), 'result': 'created',
                'trash_run': str(run.run_dir), 'opid': run.opid}
    if action == 'trash_move':
        src = target
        rel = src.resolve().relative_to(root).as_posix()
        snap = step.get('snapshot') or {}
        run = get_run()
        dst, _idx = trashops.move_to_trash(
            run, src, rel, snap.get('size') or 0, snap.get('mtime_ns'),
            snap.get('type'))
        return {'action': action, 'target': str(src),
                'result': 'moved', 'moved_to': str(dst),
                'trash_run': str(run.run_dir), 'opid': run.opid}
    if action == 'normalize_config':
        # rewrite a JSON config without duplicate keys. The
        # mtime/size snapshot from plan time gates the TOCTOU window;
        # a drifted or vanished file is skipped as changed, never
        # rewritten. The original bytes move into the trash run as the
        # backup BEFORE the deduplicated text is written in their
        # place (json model, first occurrence wins, key order kept,
        # indent 2), so restore always has the exact original.
        ok, reason = trashops._pre_operation_check(
            root, target, step.get('snapshot'), expected_type='file')
        if not ok:
            if reason in ('changed', 'missing'):
                return CHANGED   # drifted/vanished since plan(): skip
            raise trashops.SecurityRefusal(
                'normalize_config refused (%s): %s' % (reason, target))
        try:
            raw = Path(target).read_text(encoding='utf-8',
                                         errors='replace')
            model, dups = _dedupe_json(raw)
        except OSError as exc:
            raise OSError('cannot read %s: %s' % (target, exc))
        except ValueError as exc:
            raise ValueError('%s no longer parses as JSON (%s); normalize '
                             'refused' % (target, exc))
        if not dups:
            return SKIPPED       # duplicates gone since the scan: no rewrite
        new_text = json.dumps(model, ensure_ascii=False, indent=2) + '\n'
        rel = target.resolve().relative_to(root).as_posix()
        cur = trashops.snapshot(target)
        run = get_run()
        dst, _idx = trashops.move_to_trash(
            run, target, rel, cur.get('size') or 0,
            cur.get('mtime_ns'), cur.get('type'))
        trashops.record_create_file(run, target, rel, new_text)
        return {'action': action, 'target': str(target),
                'result': 'normalized', 'removed_dup_keys': dups,
                'moved_to': str(dst),
                'trash_run': str(run.run_dir), 'opid': run.opid}
    raise ValueError('unknown action: %r' % (action,))


def _log_operation(root, fid, steps, journal_steps):
    """Append one operations.jsonl line for an applied plan.

    The journal records what was attempted -- {ts, fid, check_id, root,
    steps: [{action, target, risk, result}]} -- and nothing else:
    no file contents, no refs, no notes, so no secret can leak into
    it. Journal failures print a warning to stderr and never fail the
    apply."""
    try:
        check_id = next((s.get('check_id') for s in steps
                         if isinstance(s, dict) and s.get('check_id')),
                        None)
        line = {'ts': datetime.now().isoformat(timespec='seconds'),
                'fid': fid, 'check_id': check_id, 'root': str(root),
                'steps': journal_steps}
        ops_dir = Path(root) / OPS_DIR_NAME
        ops_dir.mkdir(parents=True, exist_ok=True)
        with (ops_dir / OPS_JOURNAL_NAME).open('a', encoding='utf-8') as fh:
            fh.write(json.dumps(line, ensure_ascii=False) + '\n')
    except Exception as exc:
        print('%s: operations journal not written: %s: %s'
              % (PROG, type(exc).__name__, exc), file=sys.stderr)


def _journal_step(st, risk, result):
    """One journal step record: action/target/risk/result, no content."""
    return {'action': (st or {}).get('action'),
            'target': (st or {}).get('target'),
            'risk': risk, 'result': result}


def apply_plan(steps, root, assume_yes=False, reaudit=False, home=None,
               before_findings=None, fid=None, confirm=None):
    """Execute planned steps after an explicit confirmation.

    Interactive by default: the plan is printed and the caller must
    answer exactly 'yes' to the prompt (confirm=callable replaces
    input for tests; it is asked for the global prompt and for every
    per-step risk prompt). assume_yes=True skips the prompt and every
    per-step risk prompt (tests and automation only; the CLI never
    passes it). Every target is containment-checked against the
    resolved root before anything runs. A failing step is recorded and
    the run continues with the next step; a step whose target changed
    since plan() is skipped as {'reason': 'changed'}; a manual step
    (risk 'manual') is recorded as skipped with reason
    'manual' and never touches the disk. Every mutating step -- trash
    moves, rmdirs, written .gitignore files, config normalizations --
    is journaled in one trash run directory (timestamp + opid) with a
    write-ahead manifest, so the whole plan is undoable in one
    `safe_clean.py restore <run_dir>`.

    Risk levels: safe steps run after the single global 'yes'.
    review and high steps additionally prompt per step --
    'step N risk=REVIEW: <target> -- apply this step? [yes/no]' -- and
    a 'no' or EOF skips that step with reason 'declined-risk' (the
    rest of the plan still runs). manual steps never execute. Steps
    without a risk field are 'safe', so plans from older callers keep
    working.

    Concurrency: the first mutating step takes the trash lock
    (<root>/<TRASH_DIR_NAME>/.lock, O_EXCL); while another run holds
    it apply_plan refuses with RemediateBusy (alias of
    trashops.LockBusy) instead of racing it. The lock is released in a
    finally; a plan whose every step was skipped or manual never takes
    it and never creates the trash directory.

    fid rides into the operations journal
    (<root>/.agents-doctor/operations.jsonl, one line per apply: ts,
    fid, check_id, root, per-step action/target/risk/result -- never
    file contents); journal failures never fail the apply.

    reaudit=True re-runs audit_scan.scan(root, home) after a
    successful apply (home defaults to Path.home(); pass the scan's
    rep['home']) and adds report['reaudit'] = {'before': n, 'after': m}
    -- before from the before_findings list (e.g. rep['findings']),
    after from the fresh scan. The key only exists when reaudit was
    requested.

    Returns {'executed': [...], 'failed': [...], 'skipped': [...],
    'declined': bool, 'trash_run': str|None, 'opid': str|None};
    declined=True means the confirmation was refused and nothing ran.
    Raises RemediateBusy when the trash lock is held by another run
    (nothing of this plan has executed at that point -- the lock is
    taken before the first mutation).
    """
    root = Path(root).resolve()
    ask = confirm if confirm is not None else input
    report = {'executed': [], 'failed': [], 'skipped': [], 'declined': False,
              'trash_run': None, 'opid': None}
    steps = list(steps or [])
    if not steps:
        print('nothing to do: the plan is empty')
        return report
    # pre-flight containment: a step whose target escapes the root
    # (e.g. swapped for an outside symlink between plan and apply) is
    # recorded as a refused step, not raised -- the caller gets the
    # same {executed: [], failed: [SecurityRefusal...]} report as an
    # in-flight refusal
    refused = []
    for st in steps:
        try:
            _require_inside(root, st.get('target', ''))
        except trashops.SecurityRefusal as exc:
            refused.append((st, exc))
    if refused:
        for st, exc in refused:
            report['failed'].append({
                'action': st.get('action'), 'target': st.get('target'),
                'error': 'SecurityRefusal: %s' % exc})
        print('refused: %d step(s) fail the containment check '
              '(target escaped the workspace root); nothing executed'
              % len(refused))
        refused_targets = {st.get('target') for st, _exc in refused}
        _log_operation(root, fid, steps, [
            _journal_step(st, step_risk(st),
                          'refused' if st.get('target') in refused_targets
                          else 'skipped')
            for st in steps])
        return report
    print('plan to apply:')
    for i, st in enumerate(steps, 1):
        print('  %d. [%s] (risk: %s) %s'
              % (i, st.get('action'), step_risk(st), st.get('command')))
        if st.get('note'):
            print('     note: %s' % st['note'])
    if not assume_yes:
        try:
            answer = ask('apply? [yes/no] ')
        except EOFError:
            answer = ''
        if answer.strip() != 'yes':
            report['declined'] = True
            print('declined; nothing executed')
            _log_operation(root, fid, steps,
                           [_journal_step(st, step_risk(st), 'skipped:declined')
                            for st in steps])
            return report

    state = {'run': None, 'lock': None}
    journal = []

    def get_run():
        if state['run'] is None:
            # take the trash lock before the run directory is
            # created; LockBusy escapes as RemediateBusy (the alias)
            lock = trashops.TrashLock(root)
            lock.acquire()
            state['lock'] = lock
            try:
                state['run'] = trashops.TrashRun(
                    root, 'remediate',
                    interrupted=trashops.find_interrupted(root))
            except Exception:
                lock.release()
                state['lock'] = None
                raise
            report['trash_run'] = str(state['run'].run_dir)
            report['opid'] = state['run'].opid
        return state['run']

    try:
        for num, st in enumerate(steps, 1):
            risk = step_risk(st)
            # manual steps never execute; review/high steps
            # need their own yes (EOF or a refusal skips the step)
            if risk == RISK_MANUAL:
                report['skipped'].append({'action': st.get('action'),
                                          'target': st.get('target'),
                                          'reason': 'manual'})
                journal.append(_journal_step(st, risk, 'skipped:manual'))
                continue
            if risk in (RISK_REVIEW, RISK_HIGH) and not assume_yes:
                try:
                    answer = ask('step %d risk=%s: %s -- apply this step? '
                                 '[yes/no] ' % (num, risk.upper(),
                                                st.get('target')))
                except EOFError:
                    answer = ''
                if answer.strip() != 'yes':
                    report['skipped'].append({
                        'action': st.get('action'),
                        'target': st.get('target'),
                        'reason': 'declined-risk'})
                    journal.append(_journal_step(
                        st, risk, 'skipped:declined-risk'))
                    continue
            try:
                outcome = _execute_step(st, root, get_run)
            except trashops.LockBusy:
                # concurrency refusal: not a per-step failure, the
                # whole apply refuses (nothing has mutated -- the lock
                # precedes the first mutation of every action)
                raise
            except Exception as exc:  # recorded, then the run continues
                report['failed'].append(
                    {'action': st.get('action'), 'target': st.get('target'),
                     'error': '%s: %s' % (type(exc).__name__, exc)})
                journal.append(_journal_step(st, risk, 'failed'))
                print('%s: step failed, continuing: [%s] %s: %s'
                      % (PROG, st.get('action'), st.get('target'), exc),
                      file=sys.stderr)
                continue
            if outcome == SKIPPED:
                report['skipped'].append({'action': st.get('action'),
                                          'target': st.get('target')})
                journal.append(_journal_step(st, risk, 'skipped'))
            elif outcome == CHANGED:
                report['skipped'].append({'action': st.get('action'),
                                          'target': st.get('target'),
                                          'reason': 'changed'})
                journal.append(_journal_step(st, risk, 'skipped:changed'))
            elif outcome == MANUAL:
                report['skipped'].append({'action': st.get('action'),
                                          'target': st.get('target'),
                                          'reason': 'manual'})
                journal.append(_journal_step(st, risk, 'skipped:manual'))
            else:
                report['executed'].append(outcome)
                journal.append(_journal_step(
                    st, risk, outcome.get('result') or 'executed'))
        if state['run'] is not None:
            state['run'].finish(
                planned=len(steps),
                moved=sum(1 for e in report['executed']
                          if e.get('action') == 'trash_move'),
                failed=len(report['failed']), skipped=len(report['skipped']),
                removed_dirs=sum(1 for e in report['executed']
                                 if e.get('action') == 'rmdir'),
                created=sum(1 for e in report['executed']
                            if e.get('action') == 'write_gitignore'),
                normalized=sum(1 for e in report['executed']
                               if e.get('action') == 'normalize_config'))
    finally:
        if state['lock'] is not None:
            state['lock'].release()

    _log_operation(root, fid, steps, journal)

    if reaudit and not report['declined']:
        home_path = Path(home).resolve() if home else Path.home()
        new_rep = audit_scan.scan(root, home_path)
        report['reaudit'] = {
            'before': (len(before_findings)
                       if before_findings is not None else None),
            'after': len(new_rep.get('findings') or []),
        }
    return report


# --- re-audit --------------------------------------------------------------------

def reaudit(root, home, old_scan_path, deep=False):
    """Re-scan the workspace and diff against the old report.

    Runs audit_scan.scan in-process, writes <scan>.after.json next to
    the old scan file and returns (new_rep, diff) with the four
    fingerprint sections from fingerprint_diff(). Used after apply_plan
    for the before/after report.
    """
    root = Path(root).resolve()
    home = Path(home).resolve()
    old_rep = json.loads(Path(old_scan_path).read_text(encoding='utf-8'))
    new_rep = audit_scan.scan(root, home, deep)
    after_path(old_scan_path).write_text(
        json.dumps(new_rep, ensure_ascii=False, indent=2), encoding='utf-8')
    return new_rep, fingerprint_diff(old_rep.get('findings') or [],
                                     new_rep.get('findings') or [])


# --- CLI ---------------------------------------------------------------------------

def _load_scan(path):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        print('%s: cannot read scan %s: %s' % (PROG, path, exc), file=sys.stderr)
        return None


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog='remediate.py',
        description='Guarded fix engine for agents-doctor findings: plan '
                    'small reversible steps for one finding, apply them only '
                    'after explicit confirmation, optionally re-audit.',
        epilog='Supported fixes: empty-dir rmdir; .gitignore template for '
               'a repo missing one; confirmed-unused junk moved into '
               '%s/<timestamp>-<opid>/ (write-ahead manifest; undo with '
               'safe_clean.py restore <run_dir>); harness check_id fixes '
               '(CLAUDE_LOCAL_DEPRECATED moves the file into the trash run; '
               'CURSOR/WINDSURF_LEGACY_AND_RULES print a manual migration '
               'plan; INSTR_DUPLICATION prints a dedupe plan); dead '
               'references in instruction files get manual verify-or-remove '
               'steps; a JSON config with duplicate keys is rewritten '
               'keeping the first occurrence (normalize_config, per-step '
               'confirmation); an oversized instruction file gets shrink '
               'advice. Steps carry a risk level: safe runs after the one '
               'global yes, review/high additionally asks per step, manual '
               'never executes. Applies append an audit line to '
               '%s/operations.jsonl. Everything else is refused '
               'with exit code 3. No network, no git mutations, nothing '
               'outside the audited root. Dry run by default; --apply still '
               'asks for the word "yes". Runs hold the trash lock '
               '(%s/.lock); a concurrent run is refused cleanly.' % (
                   TRASH_DIR_NAME, OPS_DIR_NAME, TRASH_DIR_NAME))
    ap.add_argument('scan', help='scan.json from a previous audit')
    ap.add_argument('fid', help='finding id to fix (see agents_doctor.py explain)')
    ap.add_argument('--apply', action='store_true',
                    help='execute the plan after an interactive confirmation '
                         '(default: dry run, print the plan only)')
    ap.add_argument('--root', default=None, metavar='R',
                    help='workspace root (default: the root recorded in scan.json)')
    ap.add_argument('--reaudit', action='store_true',
                    help='afterwards re-run the scan and print the fingerprint '
                         'diff (writes <scan>.after.json)')
    a = ap.parse_args(argv)

    rep = _load_scan(a.scan)
    if rep is None:
        return 1
    root = a.root or rep.get('root')
    if not root:
        print('%s: scan has no root and --root was not given' % PROG,
              file=sys.stderr)
        return 1
    root = str(Path(root).resolve())
    if a.root:  # --root overrides the scan for planning too
        rep = dict(rep, root=root)

    try:
        steps = plan(rep, a.fid)
    except UnsupportedError as exc:
        print('%s: %s' % (PROG, exc), file=sys.stderr)
        return 3
    except ValueError as exc:
        print('%s: %s' % (PROG, exc), file=sys.stderr)
        return 1

    print_plan(a.fid, steps)
    failed_count = 0
    if not a.apply:
        print('%s %s: %d step(s) planned, nothing changed (dry run; add '
              '--apply and confirm to execute)' % (PROG, a.fid, len(steps)))
    else:
        try:
            report = apply_plan(steps, root, fid=a.fid)
        except RemediateBusy as exc:
            print('%s: %s' % (PROG, exc), file=sys.stderr)
            return 1
        except ValueError as exc:
            print('%s: %s' % (PROG, exc), file=sys.stderr)
            return 1
        if report['declined']:
            print('%s %s: declined, nothing executed' % (PROG, a.fid))
        else:
            print('%s %s: executed %d, skipped %d, failed %d'
                  % (PROG, a.fid, len(report['executed']),
                     len(report['skipped']), len(report['failed'])))
            if report.get('trash_run'):
                print('trash run: %s (opid %s); undo with: safe_clean.py '
                      'restore "%s"'
                      % (report['trash_run'], report.get('opid'),
                         report['trash_run']))
            for fail in report['failed']:
                print('  failed [%s] %s: %s'
                      % (fail.get('action'), fail.get('target'), fail.get('error')),
                      file=sys.stderr)
            failed_count = len(report['failed'])

    if a.reaudit:
        home = rep.get('home') or str(Path.home())
        try:
            _new_rep, diff = reaudit(root, home, a.scan)
        except (OSError, ValueError) as exc:
            print('%s: reaudit failed: %s' % (PROG, exc), file=sys.stderr)
            return 1
        print('reaudit: %d new, %d resolved, %d persisting, %d changed '
              '(report: %s)'
              % (len(diff['new']), len(diff['resolved']),
                 len(diff['persisting']), len(diff['changed']),
                 after_path(a.scan)))
    return 1 if failed_count else 0


if __name__ == '__main__':
    sys.exit(main())
