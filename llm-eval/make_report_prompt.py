#!/usr/bin/env python3
"""Build the exact prompt a real agent gets in the agents-doctor skill.

    python llm-eval/make_report_prompt.py --scan llm-eval/fixtures/chaos.json --out prompt.txt

Since the plain-language rework the agent never sees the scan JSON. It runs
one command, the command prints a short digest (summary.py) and the agent
writes the chat answer from that digest. The prompt mirrors exactly that:

  the user's request ("Audit my workspace"),
  the Workflow and Rules sections of skills/agents-doctor/SKILL.md,
  the digest the command prints for the scan (fenced),
  the order to write the chat answer now.

The same scan, language and SKILL.md always give byte-identical output, so
prompt, model reply and grade are reproducible together.

Secret and path safety: fixtures are redacted by construction, and the
digest carries neither secret values nor absolute paths. build_prompt
refuses to emit a prompt that contains a raw-looking token
(sk-[A-Za-z0-9_-]{16,}) or the absolute root/home of the scan anyway.
Python 3.9+, stdlib only.
"""
import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
DEFAULT_SKILL = REPO / 'skills' / 'agents-doctor' / 'SKILL.md'
SCRIPTS = REPO / 'skills' / 'agents-doctor' / 'scripts'

sys.path.insert(0, str(SCRIPTS))
import summary  # noqa: E402

RAW_TOKEN_RX = re.compile(r'sk-[A-Za-z0-9_-]{16,}')

# what the user typed, per answer language
USER_REQUEST = {
    'ru': 'Проведи аудит моего рабочего пространства.',
    'en': 'Audit my workspace.',
}
ORDER = {
    'ru': 'Напиши свой ответ в чате сейчас.',
    'en': 'Write your answer in the chat now.',
}
# the files the audit command leaves on disk, named as the digest names them
DIGEST_FILES = {'human': '.agents-doctor/REPORT.md',
                'report': '.agents-doctor/AUDIT.md',
                'scan': '.agents-doctor/scan.json'}


def _section(md, title):
    """Text of the '## <title>' section, up to the next '## ' heading or EOF."""
    lines = md.splitlines()
    start = None
    for i, ln in enumerate(lines):
        if ln.strip() == f'## {title}':
            start = i + 1
            break
    if start is None:
        raise ValueError(f'SKILL.md section not found: {title!r}')
    body = []
    for ln in lines[start:]:
        if ln.startswith('## '):
            break
        body.append(ln)
    text = '\n'.join(body).strip('\n')
    if not text.strip():
        raise ValueError(f'SKILL.md section is empty: {title!r}')
    return text


def build_digest_from_scan(scan, lang='ru'):
    """(digest dict, digest text) exactly as the audit command prints the
    digest for this scan dict."""
    digest = summary.build(scan, lang, files=DIGEST_FILES)
    return digest, summary.render(digest)


def build_digest(scan_json_path, lang='ru'):
    """(scan dict, digest dict, digest text) for a scan file on disk."""
    scan_text = Path(scan_json_path).read_text(encoding='utf-8')
    scan = json.loads(scan_text)  # a broken fixture must fail here
    digest, text = build_digest_from_scan(scan, lang)
    return scan, digest, text


def build_prompt(scan_json_path, skill_md_path, lang='ru'):
    """Deterministic prompt: user request + SKILL.md instructions + the
    digest of the scan + the order to answer."""
    if lang not in USER_REQUEST:
        raise ValueError(f'unsupported lang: {lang!r}')
    scan, _digest, digest_text = build_digest(scan_json_path, lang)
    skill_text = Path(skill_md_path).read_text(encoding='utf-8')
    workflow = _section(skill_text, 'Workflow')
    rules = _section(skill_text, 'Rules')

    prompt = (
        'You are the agent running the agents-doctor skill in a chat with a '
        'user.\n'
        'The user wrote:\n'
        '\n'
        f'> {USER_REQUEST[lang]}\n'
        '\n'
        'You ran the one audit command the skill prescribes. Everything it '
        'printed is reproduced below.\n'
        '\n'
        '## Skill instructions (from skills/agents-doctor/SKILL.md)\n'
        '\n'
        '### Workflow\n'
        '\n'
        + workflow + '\n'
        '\n'
        '### Rules\n'
        '\n'
        + rules + '\n'
        '\n'
        '## What the audit command printed\n'
        '\n'
        '```\n'
        + digest_text.rstrip('\n') + '\n'
        '```\n'
        '\n'
        + ORDER[lang] + '\n'
    )

    leaked = RAW_TOKEN_RX.findall(prompt)
    if leaked:
        raise ValueError(
            f'prompt would leak {len(leaked)} raw-looking secret token(s) '
            f'(e.g. {leaked[0][:5]}***); fix the fixture before evaluating')
    # the digest names files relative to the audited folder; an absolute
    # root or home reaching the prompt would be a leak. A root that is not
    # an absolute path may simply share a word with the instructions.
    for key in ('root', 'home'):
        value = str(scan.get(key) or '')
        if not re.match(r'^[A-Za-z]:[\\/]|^/', value.replace('\\', '/')):
            continue
        if value in prompt or value.replace('\\', '/') in prompt:
            raise ValueError(
                f'prompt would leak the absolute {key} of the scan; the '
                'digest must name files relative to the audited folder')
    return prompt


def main(argv=None):
    ap = argparse.ArgumentParser(description='build the skill answer prompt')
    ap.add_argument('--scan', default=str(HERE / 'fixtures' / 'chaos.json'),
                    help='scan JSON to digest (default: llm-eval/fixtures/chaos.json)')
    ap.add_argument('--skill', default=str(DEFAULT_SKILL),
                    help='SKILL.md to take the instructions from')
    ap.add_argument('--lang', choices=sorted(USER_REQUEST), default='ru',
                    help='language of the user request and the digest (default: ru)')
    ap.add_argument('--digest', action='store_true',
                    help='print only the digest instead of the full prompt')
    ap.add_argument('--out', default=None,
                    help='output file (default: print to stdout)')
    a = ap.parse_args(argv)

    if a.digest:
        _scan, _digest, text = build_digest(a.scan, a.lang)
    else:
        text = build_prompt(a.scan, a.skill, a.lang)
    if a.out:
        Path(a.out).write_text(text, encoding='utf-8')
        print(f'written: {a.out} ({len(text)} chars)')
    else:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stdout.write(text + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
