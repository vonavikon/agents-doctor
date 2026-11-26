#!/usr/bin/env python3
"""Generate skills/agents-doctor/references/glossary.md from glossary.py.

The glossary module is the single source of the plain-language names
(gates, finding types, reasons) used by the summary and the reports.
This tool renders it as the reference the agent reads, so the three can
never drift apart.

    python tools/gen_glossary.py            # write the file
    python tools/gen_glossary.py --check    # exit 1 when the file is stale
"""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'skills' / 'agents-doctor' / 'scripts'))

import glossary  # noqa: E402

TARGET = REPO / 'skills' / 'agents-doctor' / 'references' / 'glossary.md'


def _cell(text):
    return str(text).replace('|', '\\|')


def render():
    out = [
        '# Glossary: checks and findings in plain words',
        '',
        'Generated from `scripts/glossary.py` by `tools/gen_glossary.py`; '
        'do not edit by hand.',
        '',
        'Reports and summaries carry codes: `G5` for a check (gate), '
        '`SKL_FRONTMATTER_INVALID` for a kind of finding. Codes are for '
        'tools. People read the names below. In an answer to the user, '
        'name a check or a finding by its name and never by its code; the '
        'code is needed only for the `explain` and `fix` modes. When the '
        'user writes in Russian, answer with the Russian names.',
        '',
        '## Checks (gates)',
        '',
        '| Code | Name (ru) | Name (en) | What it checks |',
        '| --- | --- | --- | --- |',
    ]
    for gid in sorted(glossary.GATES):
        ru, en, about_ru, about_en = glossary.GATES[gid]
        out.append('| `%s` | %s | %s | %s / %s |' % (
            gid, _cell(ru), _cell(en), _cell(about_ru), _cell(about_en)))
    out += ['', '## Status of a check', '',
            '| Status | ru | en |', '| --- | --- | --- |']
    for status, words in glossary.GATE_STATUS.items():
        out.append('| `%s` | %s | %s |' % (status, words['ru'], words['en']))
    out += ['', '## Severity and status of a finding', '',
            '| Severity | ru | en | | Finding status | ru | en |',
            '| --- | --- | --- | --- | --- | --- | --- |']
    sevs = list(glossary.SEVERITY.items())
    stats = list(glossary.FINDING_STATUS.items())
    for i in range(max(len(sevs), len(stats))):
        s = sevs[i] if i < len(sevs) else ('', {})
        f = stats[i] if i < len(stats) else ('', {})
        out.append('| `%s` | %s | %s | | `%s` | %s | %s |' % (
            s[0], s[1].get('ru', ''), s[1].get('en', ''),
            f[0], f[1].get('ru', ''), f[1].get('en', '')))

    for lang, heading, name_col, action_col in (
            ('ru', '## Виды находок (ru)', 'Название', 'Что сделать'),
            ('en', '## Kinds of findings (en)', 'Name', 'What to do')):
        out += ['', heading, '',
                '| Code | %s | %s |' % (name_col, action_col),
                '| --- | --- | --- |']
        kinds = list(glossary.KINDS.items()) + list(glossary.ADAPTER_KINDS.items())
        for code, entry in sorted(kinds):
            out.append('| `%s` | %s | %s |' % (
                code, _cell(entry[lang]['title']), _cell(entry[lang]['action'])))
        # one kind whose name and advice depend on a fact of the case:
        # where the file of a key sits ('git' in the finding's evidence)
        out += ['', '`SEC_EXPOSED_SECRET` has three faces, by the `git` value '
                'of its evidence:', '',
                '| `git` | %s | %s |' % (name_col, action_col),
                '| --- | --- | --- |']
        for state, entry in sorted(glossary.SECRET_STATES.items()):
            out.append('| `%s` | %s | %s |' % (
                state, _cell(entry[lang]['title']), _cell(entry[lang]['action'])))

    out += ['', '## Why a check is "not checked" or "not applicable"', '',
            '| Code | ru | en |', '| --- | --- | --- |']
    for code, entry in sorted(glossary.REASONS.items()):
        out.append('| `%s` | %s | %s |' % (
            code, _cell(entry['ru'].replace('{n}', 'N')),
            _cell(entry['en'].replace('{n}', 'N'))))
    out.append('')
    return '\n'.join(out)


def main(argv=None):
    check = '--check' in (argv if argv is not None else sys.argv[1:])
    text = render()
    if check:
        current = TARGET.read_text(encoding='utf-8') if TARGET.exists() else ''
        if current.replace('\r\n', '\n') != text:
            print('STALE: %s differs from glossary.py; run '
                  'python tools/gen_glossary.py' % TARGET)
            return 1
        print('OK: %s is up to date' % TARGET.name)
        return 0
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text(text, encoding='utf-8', newline='\n')
    print('wrote %s' % TARGET)
    return 0


if __name__ == '__main__':
    sys.exit(main())
