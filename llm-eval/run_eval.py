#!/usr/bin/env python3
"""End-to-end runner for the LLM layer of agents-doctor.

    python llm-eval/run_eval.py --model offline
    python llm-eval/run_eval.py --model my-model --api https://api.example.com/v1 \
        --key-env OPENAI_API_KEY --out runs/my-model/

Pipeline per fixture: build the prompt exactly as the agent gets it in
the skill (make_report_prompt: the user's request, the SKILL.md
instructions and the digest the audit command prints), get the chat
answer - from the model (any OpenAI-compatible /chat/completions endpoint
via urllib), from a pre-written/replayed answer (--pregenerated), or from
the shipped samples (offline mode) - then grade it deterministically with
grade_answer.py's checks (A1-A12) and write a verdict.json per answer
plus a combined summary.md and report.json.

Modes:
  offline (default, --model offline): no network at all. Grades the shipped
      sample answers (llm-eval/samples: good-chaos, bad-chaos, good-clean),
      builds the adversarial fixtures locally and checks INPUT_VALIDATION on
      the malformed one. This is the CI contract: exit 0 iff every 'good'
      sample passes all critical checks (A1, A2, A3, A6, A7, A8) with >= 6
      of 7 rubric checks passing, every 'bad' sample is caught (a critical
      fails, <= 3 of 7 pass), and the malformed fixture is rejected.
  online (--api <base-url> --model <name>): calls <api>/chat/completions with
      a Bearer key from the env var named by --key-env (default
      OPENAI_API_KEY), 120 s timeout, one retry. Model runs are opt-in only:
      without a non-empty key in the named env var the runner prints an
      'opt-in only' error and exits 2 before touching the network. Exit 0
      iff all critical checks pass on the generated answers and
      INPUT_VALIDATION holds.
  replay (--pregenerated <dir>, no --api): grades existing answers instead
      of calling a model. File name convention per fixture stem S: good-S.md
      (or S.md) is expected to pass, bad-S.md is expected to fail - both
      are graded when both exist.

Artifacts land in --out (default llm-eval/runs/<timestamp>-<model>/): one
directory per graded answer with verdict.json, report.md and prompt.txt, the
raw model response (response.json, online mode), the generated adversarial
fixtures under fixtures/, summary.md, and a run-level report.json split into
deterministic (scanner-side facts: verdicts, aggregated checks, matrix entry)
and llm_interpretation (the model layer: model id, api base, prompt version,
latency, token usage, harness='none'; null with an explanation when no model
was called). Every run also appends an entry to the benchmark matrix
(--matrix, default llm-eval/results/matrix.json): {model, mode,
prompt_version, harness, ts, scores A1-A12, latency_ms, tokens,
spot_mentions, result}. On a repeat online run of the same model and prompt
version, A12 (reproducibility) is graded as the jaccard of the findings
whose place the answer names against the previous run (pass >= 0.8).
Python 3.9+, stdlib only.
"""
import argparse
import importlib.util
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SKILL_MD = REPO / 'skills' / 'agents-doctor' / 'SKILL.md'
DEFAULT_SAMPLES = HERE / 'samples'
DEFAULT_FIXTURES = [HERE / 'fixtures' / 'clean.json',
                    HERE / 'fixtures' / 'chaos.json']
CRITICAL_CHECKS = ('A1', 'A2', 'A3', 'A6', 'A7', 'A8')
RUBRIC_CHECKS = ('A1', 'A2', 'A3', 'A4', 'A5', 'A9', 'A10')
ALL_CHECKS = tuple(f'A{i}' for i in range(1, 13))  # A1-A12
# the language of the user request the model answers in
ANSWER_LANG = 'ru'
TIMEOUT_S = 120

# Bump when skills/agents-doctor/SKILL.md (Workflow/Rules) or the prompt
# built by make_report_prompt.py changes shape: the benchmark matrix and A12
# comparisons key off it, so a prompt change must not silently mix with old
# runs of the "same" prompt.
PROMPT_VERSION = '2026-11-25'

DEFAULT_MATRIX = HERE / 'results' / 'matrix.json'


def _load(name):
    spec = importlib.util.spec_from_file_location(f'llm_eval_{name}', HERE / f'{name}.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


grade_report = _load('grade_report')
grade_answer = _load('grade_answer')
make_report_prompt = _load('make_report_prompt')
adversarial = _load('adversarial')


# ---------------------------------------------------------------- model layer

def chat_completion(api_base, model, prompt, key_env='OPENAI_API_KEY',
                    timeout=TIMEOUT_S):
    """One chat completion against an OpenAI-compatible endpoint, one retry."""
    key = os.environ.get(key_env, '')
    url = api_base.rstrip('/') + '/chat/completions'
    body = json.dumps({
        'model': model,
        'temperature': 0,
        'messages': [{'role': 'user', 'content': prompt}],
    }).encode('utf-8')
    last = None
    for attempt in (1, 2):
        req = urllib.request.Request(
            url, data=body, method='POST',
            headers={'Content-Type': 'application/json',
                     'Authorization': f'Bearer {key}'})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode('utf-8'))
            return payload['choices'][0]['message']['content'], payload
        except (urllib.error.URLError, OSError, KeyError, IndexError,
                ValueError) as e:
            last = e
            if attempt == 1:
                continue
    raise RuntimeError(f'model call failed after retry ({url}): {last}')


def call_model(api_base, model, prompt, key_env='OPENAI_API_KEY',
               timeout=TIMEOUT_S):
    """chat_completion plus the run facts fixed into results: latency and
    token usage (usage is None when the endpoint does not report it)."""
    t0 = time.perf_counter()
    content, payload = chat_completion(api_base, model, prompt,
                                       key_env=key_env, timeout=timeout)
    latency_ms = round((time.perf_counter() - t0) * 1000, 1)
    usage = payload.get('usage') if isinstance(payload, dict) else None
    if isinstance(usage, dict):
        usage = {k: usage[k] for k in ('prompt_tokens', 'completion_tokens',
                                       'total_tokens')
                 if isinstance(usage.get(k), int)} or None
    return {'content': content, 'payload': payload,
            'latency_ms': latency_ms, 'usage': usage}


# ------------------------------------------------------------------- plumbing

def resolve_fixture(path_str):
    p = Path(path_str)
    candidates = [p] if p.is_absolute() else [
        Path.cwd() / p, HERE / p, REPO / p]
    for c in candidates:
        if c.exists():
            return c
    tried = ', '.join(str(c) for c in candidates)
    raise SystemExit(f'fixture not found: {path_str} (tried {tried})')


def _sample_candidates(sample_dir, stem):
    """(label, path) pairs for a fixture stem: good-S.md/S.md then bad-S.md."""
    found = []
    for tag, name in (('good', f'good-{stem}.md'), ('good', f'{stem}.md'),
                      ('bad', f'bad-{stem}.md')):
        p = Path(sample_dir) / name
        if p.exists() and p not in [f for _, f in found]:
            found.append((tag, p))
    return found


def _checks_dict(results):
    return {rid: {'status': status.lower(), 'evidence': detail}
            for rid, _label, status, detail in results}


def load_matrix(path):
    """Benchmark matrix entries; a corrupt file self-heals to []."""
    p = Path(path)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding='utf-8'))
    except ValueError:
        return []
    return data if isinstance(data, list) else []


def append_matrix(path, entry):
    """Append one run entry to the matrix JSON (creates the directory)."""
    p = Path(path)
    entries = load_matrix(p)
    entries.append(entry)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(entries, indent=2, ensure_ascii=False) + '\n',
                 encoding='utf-8')
    return p


def aggregate_scores(verdicts):
    """Worst-case A1-A12 status across the run's verdicts."""
    scores = {}
    for rid in ALL_CHECKS:
        statuses = [v['checks'].get(rid, {}).get('status', 'na')
                    for v in verdicts if isinstance(v.get('checks'), dict)]
        if any(s == 'fail' for s in statuses):
            scores[rid] = 'fail'
        elif statuses and all(s == 'na' for s in statuses):
            scores[rid] = 'na'
        else:
            scores[rid] = 'pass'
    return scores


def _sum_usage(metas):
    """Sum token usage across model calls; None when nothing reported."""
    total = {}
    for m in metas:
        for k, v in (m.get('usage') or {}).items():
            total[k] = total.get(k, 0) + v
    return total or None


def compute_r12(current_spots, matrix_entries, model, prompt_version):
    """A12 vs the latest previous online run of the same model+prompt.

    Returns None when there is nothing to compare with yet (status stays NA).
    """
    prevs = [e for e in matrix_entries
             if e.get('model') == model
             and e.get('prompt_version') == prompt_version
             and e.get('mode') == 'online']
    if not prevs:
        return None
    prev = prevs[-1]
    j = grade_report.jaccard(current_spots, prev.get('spot_mentions') or [])
    status = 'pass' if j >= grade_answer.A12_JACCARD_MIN else 'fail'
    return {'status': status,
            'evidence': f'finding-mention jaccard {j:.2f} vs run '
                        f'{prev.get("ts", "?")} (threshold '
                        f'{grade_answer.A12_JACCARD_MIN})'}


def grade_report_into_verdict(fixture, scan, report_text, report_source,
                              model, expect, sample_based, model_meta=None,
                              r12=None, digest=None):
    """Grade one chat answer against its scan and digest."""
    if digest is None:
        digest = grade_answer.digest_of(scan, ANSWER_LANG)
    results = grade_answer.grade(report_text, scan, digest, ANSWER_LANG)
    checks = _checks_dict(results)
    if r12 is not None:
        checks['A12'] = r12
    checks['INPUT_VALIDATION'] = {
        'status': 'na', 'evidence': 'scan passed input validation'}
    # a check the scan makes not applicable did not fail: it counts
    # with the passes (a clean folder has no critical finding to name)
    rubric_passes = sum(1 for r in RUBRIC_CHECKS
                        if checks[r]['status'] in ('pass', 'na'))
    critical_ok = all(checks[c]['status'] in ('pass', 'na')
                      for c in CRITICAL_CHECKS)
    verdict = {
        'fixture': str(fixture),
        'report': str(report_source),
        'model': model,
        'expect': expect,
        'sample_based': sample_based,
        'prompt_version': PROMPT_VERSION,
        'model_meta': model_meta,
        'checks': checks,
        'totals': {
            'pass': sum(1 for v in checks.values() if v['status'] == 'pass'),
            'fail': sum(1 for v in checks.values() if v['status'] == 'fail'),
            'na': sum(1 for v in checks.values() if v['status'] == 'na'),
        },
        'rubric_passes': rubric_passes,
        'critical_ok': critical_ok,
    }
    return verdict


def write_verdict(out_root, tag, verdict, report_text, prompt, raw_payload=None):
    vdir = out_root / tag
    vdir.mkdir(parents=True, exist_ok=True)
    (vdir / 'report.md').write_text(report_text, encoding='utf-8')
    if prompt is not None:
        (vdir / 'prompt.txt').write_text(prompt, encoding='utf-8')
    if raw_payload is not None:
        (vdir / 'response.json').write_text(
            json.dumps(raw_payload, indent=2, ensure_ascii=False) + '\n',
            encoding='utf-8')
    (vdir / 'verdict.json').write_text(
        json.dumps(verdict, indent=2, ensure_ascii=False) + '\n',
        encoding='utf-8')
    return vdir


def check_input_validation(malformed_path, out_root, model):
    """The grader must reject the malformed fixture; returns (ok, verdict)."""
    scan = json.loads(malformed_path.read_text(encoding='utf-8'))
    problems = grade_report.validate_scan(scan)
    if problems:
        evidence = 'invalid report input: ' + '; '.join(problems[:3])
        status = 'pass'
    else:
        evidence = 'malformed fixture was not rejected by validate_scan'
        status = 'fail'
    checks = {
        rid: {'status': 'na',
              'evidence': 'not graded: input rejected before grading'}
        for rid in list(ALL_CHECKS)
    }
    checks['INPUT_VALIDATION'] = {'status': status, 'evidence': evidence}
    verdict = {
        'fixture': str(malformed_path),
        'report': None,
        'model': model,
        'expect': 'input',
        'sample_based': True,
        'prompt_version': PROMPT_VERSION,
        'model_meta': None,
        'checks': checks,
        'totals': {
            'pass': sum(1 for v in checks.values() if v['status'] == 'pass'),
            'fail': sum(1 for v in checks.values() if v['status'] == 'fail'),
            'na': sum(1 for v in checks.values() if v['status'] == 'na'),
        },
        'rubric_passes': 0,
        'critical_ok': status == 'pass',
    }
    write_verdict(out_root, 'malformed-input', verdict,
                  report_text=malformed_path.read_text(encoding='utf-8'),
                  prompt=None)
    return status == 'pass', verdict


def write_summary(out_root, model, mode, verdicts):
    cols = list(ALL_CHECKS) + ['INPUT']
    lines = [
        f'# LLM eval summary',
        '',
        f'model: {model} | mode: {mode} | ran: {datetime.now().isoformat(timespec="seconds")}',
        '',
        '| fixture | answer | ' + ' | '.join(cols) + ' | A-pass | expect | ok |',
        '|---|---|' + '---|' * (len(cols) + 3),
    ]
    for v in verdicts:
        cells = []
        for c in cols:
            key = 'INPUT_VALIDATION' if c == 'INPUT' else c
            cells.append(v['checks'].get(key, {}).get('status', '-'))
        report = Path(v['report']).name if v['report'] else '-'
        report = 'chat answer' if 'api' in report else report
        if v['expect'] == 'good':
            ok = v['critical_ok'] and (not v['sample_based']
                                       or v['rubric_passes'] >= 6)
        elif v['expect'] == 'bad':
            ok = (not v['critical_ok']) and (not v['sample_based']
                                             or v['rubric_passes'] <= 3)
        else:
            ok = v['checks']['INPUT_VALIDATION']['status'] == 'pass'
        lines.append(
            f"| {Path(v['fixture']).name} | {report} | "
            + ' | '.join(cells)
            + f" | {v['rubric_passes']}/7 | {v['expect']} | {'ok' if ok else 'BAD'} |")
    lines += ['', f'total verdicts: {len(verdicts)}', '']
    (out_root / 'summary.md').write_text('\n'.join(lines), encoding='utf-8')
    return lines


def verdict_ok(v):
    if v['expect'] == 'good':
        return v['critical_ok'] and (not v['sample_based']
                                     or v['rubric_passes'] >= 6)
    if v['expect'] == 'bad':
        return (not v['critical_ok']) and (not v['sample_based']
                                           or v['rubric_passes'] <= 3)
    return v['checks']['INPUT_VALIDATION']['status'] == 'pass'


def run(argv=None):
    ap = argparse.ArgumentParser(description='run the LLM-layer evaluation')
    ap.add_argument('--model', default='offline',
                    help='model name, or "offline" (default) to skip generation')
    ap.add_argument('--api', default=None,
                    help='OpenAI-compatible base URL, e.g. https://api.openai.com/v1 '
                         'or http://localhost:8000/v1; enables online mode')
    ap.add_argument('--key-env', default='OPENAI_API_KEY',
                    help='env var holding the Bearer key (default OPENAI_API_KEY)')
    ap.add_argument('--fixture', action='append', default=None,
                    help='scan JSON to evaluate; repeatable. Default: '
                         'llm-eval/fixtures/clean.json + chaos.json')
    ap.add_argument('--pregenerated', default=None,
                    help='directory with pre-written reports per fixture stem '
                         '(good-<stem>.md / <stem>.md / bad-<stem>.md); '
                         'replaces model generation for fixtures it covers')
    ap.add_argument('--out', default=None,
                    help='output directory (default: llm-eval/runs/<ts>-<model>/)')
    ap.add_argument('--matrix', default=str(DEFAULT_MATRIX),
                    help='benchmark matrix JSON to append this run to '
                         '(default: llm-eval/results/matrix.json)')
    a = ap.parse_args(argv)

    offline = a.model == 'offline'
    if offline and a.api:
        ap.error('--model offline cannot be combined with --api')
    online = bool(a.api)
    if online and offline:
        ap.error('pass a real --model name together with --api')
    mode = 'online' if online else ('offline' if offline else 'replay')

    # Model runs are opt-in only: no key, no network, clean exit before any
    # artifact is written (CI stays on the offline contract).
    if online and not os.environ.get(a.key_env, '').strip():
        print(f'model runs are opt-in only: env var {a.key_env} is not set; '
              f'export the key (or pass --key-env <VAR>) or use --model '
              f'offline', file=sys.stderr)
        return 2

    matrix_path = Path(a.matrix)
    matrix_entries = load_matrix(matrix_path)

    ts = datetime.now().strftime('%Y%m%d-%H%M%S')
    out_root = Path(a.out) if a.out else HERE / 'runs' / f'{ts}-{a.model}'
    out_root.mkdir(parents=True, exist_ok=True)

    # Always: adversarial set + INPUT_VALIDATION on the malformed fixture.
    adv_paths = adversarial.build_all(out_root / 'fixtures')
    malformed_path = out_root / 'fixtures' / 'malformed.json'
    input_ok, input_verdict = check_input_validation(malformed_path, out_root,
                                                     a.model)

    fixture_paths = ([resolve_fixture(f) for f in a.fixture]
                     if a.fixture else DEFAULT_FIXTURES)
    sample_dir = Path(a.pregenerated) if a.pregenerated else (
        DEFAULT_SAMPLES if (offline or not online) else None)

    online_meta = {}     # fixture stem -> call_model result (online only)
    interp_reports = []  # llm_interpretation entries for report.json
    verdicts = [input_verdict]
    for fixture in fixture_paths:
        stem = fixture.stem
        scan = json.loads(fixture.read_text(encoding='utf-8'))
        problems = grade_report.validate_scan(scan)
        if problems:
            # A chosen fixture that violates the schema is an input test, not
            # a model test: record rejection, do not call the model.
            checks = {rid: {'status': 'na',
                            'evidence': 'not graded: input rejected'}
                      for rid in list(ALL_CHECKS)}
            checks['INPUT_VALIDATION'] = {
                'status': 'pass',
                'evidence': 'invalid report input: ' + '; '.join(problems[:3])}
            v = {
                'fixture': str(fixture),
                'report': None,
                'model': a.model,
                'expect': 'input',
                'sample_based': True,
                'prompt_version': PROMPT_VERSION,
                'model_meta': None,
                'checks': checks,
                'totals': {
                    'pass': sum(1 for c in checks.values()
                                if c['status'] == 'pass'),
                    'fail': sum(1 for c in checks.values()
                                if c['status'] == 'fail'),
                    'na': sum(1 for c in checks.values() if c['status'] == 'na'),
                },
                'rubric_passes': 0,
                'critical_ok': True,
            }
            write_verdict(out_root, f'{stem}-input', v,
                          report_text=fixture.read_text(encoding='utf-8'),
                          prompt=None)
            verdicts.append(v)
            print(f'{stem}: rejected as invalid input (INPUT_VALIDATION pass)')
            continue

        prompt = make_report_prompt.build_prompt(fixture, SKILL_MD,
                                                 ANSWER_LANG)
        _scan, digest, _digest_text = make_report_prompt.build_digest(
            fixture, ANSWER_LANG)
        reports = []  # (tag, source, text, sample_based, raw_payload)

        if sample_dir is not None:
            for tag, path in _sample_candidates(sample_dir, stem):
                reports.append((tag, path, path.read_text(encoding='utf-8'),
                                True, None))
        if not reports and not online:
            where = sample_dir if sample_dir else DEFAULT_SAMPLES
            raise SystemExit(
                f'no report for fixture {fixture.name} in {where} and no --api; '
                f'pass --pregenerated or --api')
        if not reports and online:
            print(f'{stem}: calling model {a.model} ...')
            res = call_model(a.api, a.model, prompt, key_env=a.key_env)
            reports.append(('good', f'{a.model} (api)', res['content'],
                            False, res['payload']))
            online_meta[stem] = res

        for tag, source, text, sample_based, raw in reports:
            model_meta, r12 = None, None
            if online and not sample_based and stem in online_meta:
                cur_spots = grade_answer.spot_mentions(
                text, scan, make_report_prompt.build_digest(
                    fixture, ANSWER_LANG)[1])
                r12 = compute_r12(cur_spots, matrix_entries, a.model,
                                  PROMPT_VERSION)
                model_meta = dict(online_meta[stem],
                                  model=a.model, api_base=a.api,
                                  prompt_version=PROMPT_VERSION,
                                  harness='none',
                                  spot_mentions=sorted(cur_spots))
            v = grade_report_into_verdict(fixture, scan, text, source,
                                          a.model, tag, sample_based,
                                          model_meta=model_meta, r12=r12,
                                          digest=digest)
            suffix = '' if len(reports) == 1 else f'-{tag}'
            vdir = write_verdict(out_root, f'{stem}{suffix}', v, text,
                                 prompt, raw)
            verdicts.append(v)
            if model_meta is not None:
                interp_reports.append({
                    'fixture': stem,
                    'report_path': str(vdir / 'report.md'),
                    'prompt_path': str(vdir / 'prompt.txt'),
                    'latency_ms': model_meta['latency_ms'],
                    'spot_mentions': model_meta['spot_mentions'],
                    'A12': v['checks']['A12'],
                })
            crit = ', '.join(
                f"{c}={v['checks'][c]['status']}" for c in CRITICAL_CHECKS)
            print(f'{stem}{suffix}: expect {tag}, {v["rubric_passes"]}/7 '
                  f'rubric checks pass ({crit})')

    summary_lines = write_summary(out_root, a.model, mode, verdicts)
    ok = input_ok and all(verdict_ok(v) for v in verdicts
                          if v is not input_verdict)
    result = 'PASS' if ok else 'FAIL'

    # Benchmark matrix: one entry per run, offline included (model='offline').
    gen_metas = [m for m in online_meta.values()]
    entry = {
        'model': a.model,
        'mode': mode,
        'prompt_version': PROMPT_VERSION,
        'harness': 'none',
        'ts': ts,
        'api_base': a.api if online else None,
        'scores': aggregate_scores(verdicts),
        'latency_ms': (round(sum(m['latency_ms'] for m in gen_metas), 1)
                       if gen_metas else None),
        'tokens': _sum_usage(gen_metas) if gen_metas else None,
        'spot_mentions': (sorted(set().union(*(
            r['spot_mentions'] for r in interp_reports)))
            if interp_reports else []),
        'result': result,
    }
    append_matrix(matrix_path, entry)

    # Run-level report.json: deterministic facts strictly separated from the
    # LLM interpretation layer.
    if online and interp_reports:
        llm_section = {
            'model': a.model,
            'api_base': a.api,
            'prompt_version': PROMPT_VERSION,
            'harness': 'none',
            'latency_ms': entry['latency_ms'],
            'token_usage': entry['tokens'],
            'reports': interp_reports,
        }
        note = ('model-written reports; graded by the deterministic checks '
                'recorded in report.json -> deterministic')
    else:
        llm_section = None
        if mode == 'offline':
            note = ('offline mode: llm interpretation is opt-in only '
                    '(--api with --key-env); the graded reports are shipped '
                    'samples, not model output')
        else:
            note = ('replay mode: reports were pre-written (--pregenerated); '
                    'no model interpretation was generated')
    report_doc = {
        'run': {
            'ts': ts,
            'model': a.model,
            'mode': mode,
            'prompt_version': PROMPT_VERSION,
            'harness': 'none',
            'api_base': a.api if online else None,
            'key_env': a.key_env if online else None,
        },
        'deterministic': {
            'fixtures': [str(p) for p in fixture_paths],
            'input_validation_ok': input_ok,
            'verdicts': verdicts,
            'scores': entry['scores'],
            'result': result,
            'matrix': {'path': str(matrix_path), 'appended': True},
        },
        'llm_interpretation': llm_section,
        'llm_interpretation_note': note,
    }
    (out_root / 'report.json').write_text(
        json.dumps(report_doc, indent=2, ensure_ascii=False) + '\n',
        encoding='utf-8')

    print('\n'.join(summary_lines))
    print(f'artifacts: {out_root}')
    print(f'matrix: {matrix_path} (entry #{len(load_matrix(matrix_path))})')
    if ok:
        print('result: PASS')
        return 0
    bad = [f"{Path(v['fixture']).name}({v['expect']})" for v in verdicts
           if v is not input_verdict and not verdict_ok(v)]
    if not input_ok:
        bad.append('malformed(input)')
    print(f'result: FAIL ({", ".join(bad) if bad else "unexpected"})')
    return 1


def main(argv=None):
    sys.exit(run(argv))


if __name__ == '__main__':
    main()
