"""summary: the short digest of a scan that goes to the model and to chat.

The scan JSON stays on disk: it is large (hundreds of KB on a real
workspace), holds absolute paths of the machine and every evidence
entry, including quotes from the user's files. What the agent reads
instead is this digest:

- gate statuses in plain words, with the reason wherever a check did
  not run or does not apply;
- the findings that matter, most serious first, each with what it is,
  where it sits and what to do;
- where to start.

Paths are printed as a person sees them from the audited folder:
relative to it, '~/' inside the home directory, or just a file name for
anything else. No absolute path, no quoted file line and no secret
value ever enters the digest.

Deterministic. The module reads no file content and opens no network
connection; its only filesystem call is the metadata lookup that
resolves a path (os.path.realpath in file_alias).
"""
import os
import re

try:
    import glossary
except ImportError:  # pragma: no cover - direct script use
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import glossary

MAX_ITEMS = 25          # findings listed one by one; the rest are counted
MAX_PER_KIND = 3        # findings of one kind spelled out one by one
MAX_START = 3           # steps in "where to start"
MAX_START_PLACES = 4    # places one step names when several findings share it
MAX_UNCHECKED = 12      # "not checked" lines listed one by one
MAX_PLACES = 5          # folders named in one "where" line
MAX_REST_FILES = 8      # files named in the "more keys" line

_SEV_RANK = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
_STATUS_RANK = {'fail': 0, 'unknown': 1, 'warn': 2, 'pass': 3,
                'not_applicable': 4}

_TEXT = {
    'ru': {
        'title': 'АУДИТ ПАПКИ «{name}»',
        'coverage': 'Проверено: файлов {files}; навыков {skills}; '
                    'папок с Git: {repos}.',
        'skills_partial': 'Навыки проверены не полностью: {why}.',
        'own_source': 'Собственные файлы самого инструмента ({n}) не '
                      'проверялись на ключи.',
        'folder_git': 'Сама папка хранится в Git.',
        'folder_git_nested': 'Сама папка не в Git; внутри есть папки с Git.',
        'repos_nested': 'Папок с Git, которые не проверялись (лежат глубже '
                        'первого уровня): {n}.',
        'history': 'История Git на ключи: {state}.',
        'history_scanned': 'проверена',
        'history_partial': 'проверена не полностью',
        'history_not': 'не проверялась (это медленная проверка, её включают '
                       'по отдельной просьбе, например «проверь и историю Git»)',
        'history_na': 'неприменима, папок с Git нет',
        'h_gates': 'БЛОКИ ПРОВЕРОК',
        'h_findings': 'ЧТО НАЙДЕНО',
        'findings_total': 'Всего находок: {total}. Подробно показаны {shown}, '
                          'остальные пересчитаны по типу.',
        'findings_all': 'Всего находок: {total}.',
        'findings_none': 'Находок нет.',
        'findings_rest': 'Ещё по типам: {rest}.',
        'findings_rest_plugins': 'В установленных плагинах (их файлы не ваши, '
                                'исправит только обновление плагина): {rest}.',
        'findings_rest_files': 'Ещё ключи в файлах: {files}.',
        'and_more_files': 'ещё в {n} файлах',
        'file_unknown': 'файл не назван',
        'h_improve': 'ЧТО МОЖНО УЛУЧШИТЬ (предложения по оптимизации)',
        'imp_tokens': 'Лишние токены: при каждом запуске агент получает '
                      'примерно {mid} лишних токенов инструкций и памяти. '
                      'Сократите файлы инструкций и файл памяти.',
        'imp_memory': 'Файл памяти агента больше лимита: всё, что сверх '
                      'лимита, агент не видит. Перенесите подробности '
                      'в отдельные файлы.',
        'imp_junk': 'Мусор: {size}. Безопасная уборка перенесёт его '
                    'в корзину с возможностью восстановить.',
        'imp_dup': 'Дубликаты файлов: {size}.',
        'imp_large': 'Большие файлы без резервной копии: {size}.',
        'imp_repeats': 'Одинаковый текст повторяется в {n} парах файлов '
                       'инструкций: оставьте его в одном месте.',
        'imp_short_file': 'Файл инструкций {file} короткий: если это ссылка '
                          'на другой файл с правилами, всё в порядке.',
        'imp_noise': 'В файле инструкций {file} мало конкретных правил '
                     '(только {pct}% строк): сократите его.',
        'imp_generic': 'В инструкциях {n} строк общих советов, которые '
                       'подойдут любому проекту.',
        'imp_tool_dir': 'Отчёты аудита лежат в папке .agents-doctor, и она не '
                        'исключена из Git. Добавьте её в .gitignore: в снимке '
                        'есть пути этого компьютера.',
        'where': 'где',
        'action': 'что сделать',
        'audited_folder': 'самой папки',
        'and_more': 'и ещё {n}',
        'chain_all': 'все файлы инструкций вместе ({size})',
        'size_kb': '{n} КБ',
        'size_mb': '{n} МБ',
        'unchecked': 'не проверено: {reason}',
        'h_unchecked': 'ЧТО НЕ ПРОВЕРЕНО',
        'h_na': 'ЧТО НЕ ПРИМЕНИМО',
        'h_start': 'С ЧЕГО НАЧАТЬ',
        'start_none': 'Исправлять нечего: красных и жёлтых находок нет.',
        'h_files': 'ФАЙЛЫ',
        'f_human': 'простой отчёт: {p}',
        'f_report': 'технический отчёт: {p}',
        'f_scan': 'снимок полностью: {p}',
        'note': 'Коды в скобках нужны только для команд explain и fix. '
                'В ответе пользователю называйте находки словами, без кодов.',
    },
    'en': {
        'title': 'AUDIT OF "{name}"',
        'coverage': 'Checked: {files} files; {skills} skills; '
                    '{repos} git folders.',
        'skills_partial': 'Skills were not all checked: {why}.',
        'own_source': "The tool's own files ({n}) were not checked for keys.",
        'folder_git': 'The folder itself is kept in Git.',
        'folder_git_nested': 'The folder itself is not in Git; there are '
                             'git folders inside it.',
        'repos_nested': 'Git folders that were not checked (they lie deeper '
                        'than the first level): {n}.',
        'history': 'Git history for keys: {state}.',
        'history_scanned': 'checked',
        'history_partial': 'partly checked',
        'history_not': 'not checked (a slow check, run on a separate request '
                       'such as "check the git history too")',
        'history_na': 'not applicable, there are no git folders',
        'h_gates': 'CHECKS',
        'h_findings': 'FINDINGS',
        'findings_total': 'Findings in all: {total}. {shown} are spelled '
                          'out, the rest are counted by type.',
        'findings_all': 'Findings in all: {total}.',
        'findings_none': 'No findings.',
        'findings_rest': 'More, by type: {rest}.',
        'findings_rest_plugins': 'In installed plugins (not your files; only a '
                                 'plugin update fixes them): {rest}.',
        'findings_rest_files': 'More keys in files: {files}.',
        'and_more_files': '{n} more files',
        'file_unknown': 'file not named',
        'h_improve': 'WHAT CAN BE MADE BETTER (optimization suggestions)',
        'imp_tokens': 'Extra tokens: at every start the agent gets about '
                      '{mid} extra tokens of instructions and memory. '
                      'Shorten the instruction files and the memory file.',
        'imp_memory': 'The agent memory file is over the limit, and the agent '
                      'never sees what lies beyond it. Move the details into '
                      'separate files.',
        'imp_junk': 'Junk: {size}. The safe cleanup moves it to a trash '
                    'folder it can be restored from.',
        'imp_dup': 'Duplicate files: {size}.',
        'imp_large': 'Large files without a backup: {size}.',
        'imp_repeats': 'The same text is repeated in {n} pairs of instruction '
                       'files: keep it in one place.',
        'imp_short_file': 'The instruction file {file} is short: a pointer to '
                          'another file with the rules is fine as it is.',
        'imp_noise': 'The instruction file {file} holds few concrete rules '
                     '(only {pct}% of the lines): shorten it.',
        'imp_generic': '{n} lines of the instructions are generic advice that '
                       'would fit any project.',
        'imp_tool_dir': 'The audit reports lie in the .agents-doctor folder, '
                        'and it is not kept out of Git. Add it to .gitignore: '
                        'the snapshot holds paths of this computer.',
        'where': 'where',
        'action': 'what to do',
        'audited_folder': 'the audited folder',
        'and_more': '{n} more',
        'chain_all': 'all instruction files together ({size})',
        'size_kb': '{n} KB',
        'size_mb': '{n} MB',
        'unchecked': 'not checked: {reason}',
        'h_unchecked': 'NOT CHECKED',
        'h_na': 'NOT APPLICABLE',
        'h_start': 'WHERE TO START',
        'start_none': 'Nothing to fix: no red or yellow findings.',
        'h_files': 'FILES',
        'f_human': 'plain report: {p}',
        'f_report': 'technical report: {p}',
        'f_scan': 'full snapshot: {p}',
        'note': 'The codes in brackets are only for the explain and fix '
                'commands. In the answer to the user, name findings in '
                'words, without codes.',
    },
}


def _is_abs(path):
    # called on the forward-slash spelling (file_alias normalizes first)
    return bool(re.match(r'^([A-Za-z]:/|/)', path))


def file_alias(path, root=None, home=None):
    """A path as a person sees it from the audited folder.

    Relative paths stay as they are. Absolute paths become relative to
    the audited folder, '~/...' inside the home directory, or just the
    file name with a marker when they lie elsewhere: an absolute path
    of the machine never leaves this function.
    """
    if not path or not isinstance(path, str):
        return ''
    p = path.replace('\\', '/')
    if not _is_abs(p):
        return p

    def rel_to(base):
        """Path of p relative to base, or None when p is outside base.
        Case is ignored for the test but kept in the result."""
        if not base:
            return None
        try:
            real = os.path.normcase(os.path.realpath(p))
            base_real = os.path.normcase(os.path.realpath(str(base)))
            rel = os.path.relpath(real, base_real)
        except (OSError, ValueError):
            return None
        if rel == '..' or rel.startswith('..' + os.sep):
            return None
        if rel == '.':
            return base_name(base)
        # take the tail of the original spelling, so the letter case of
        # the real path survives (normcase lowercases on Windows)
        depth = len(rel.replace('\\', '/').split('/'))
        return '/'.join(p.split('/')[-depth:])

    def base_name(base):
        return os.path.basename(str(base).rstrip('\\/')) or '.'

    inside = rel_to(root)
    if inside is not None:
        return inside
    inside_home = rel_to(home)
    if inside_home is not None:
        return '~/' + inside_home if inside_home != base_name(home) else '~/'
    return '<outside audit area>/' + p.rsplit('/', 1)[-1]


_SKILL_IN_TITLE = re.compile(r"[Ss]kill '([^']+)'")


def skill_name(finding):
    """Name of the skill a finding is about, or None."""
    m = _SKILL_IN_TITLE.search(str(finding.get('title') or ''))
    return m.group(1) if m else None


# evidence keys that name a place; 'detail', 'error', 'text' and the
# like may quote file content and are never read here, with one named
# exception below
_PLACE_KEYS = ('file', 'path')
_NAME_KEYS = ('repo', 'name', 'tool', 'ref', 'location')
_LIST_KEYS = ('checkouts', 'paths')
# findings whose place is the set of repositories, not one file
_REPO_WIDE_CHECKS = ('SEC_PREVENTION_ABSENT', 'SEC_PREVENTION_UNVERIFIED',
                     'SEC_GIT_SIDE_UNVERIFIED')
# the one finding whose 'detail' starts with a file path (it is the
# scanner's own note, not a quote from the file)
_DETAIL_PATH_CHECKS = ('GOV_DEAD_HARNESS_INSTRUCTIONS',)


def _repo_alias(name, root, home, lang=glossary.DEFAULT_LANG):
    """A repository as a person reads it: the audited folder itself is
    listed under '.' in the scan."""
    if str(name) in ('.', ''):
        return _TEXT[lang]['audited_folder']
    return file_alias(str(name), root, home)


def _size(n, lang=glossary.DEFAULT_LANG):
    """Bytes as one short number: 379 КБ, 2 МБ."""
    t = _TEXT[lang]
    if n >= 1024 * 1024:
        return t['size_mb'].format(n=int(round(n / (1024.0 * 1024))))
    return t['size_kb'].format(n=max(1, int(round(n / 1024.0))))


def where(finding, rep, lang=glossary.DEFAULT_LANG):
    """Where a finding sits, in aliases only: skill name, file:line,
    folder, repository. Quotes of file content are left out. Empty when
    the scan names no place: the digest then simply has no "where" line
    (it never falls back to the scanner's English title)."""
    if lang not in _TEXT:
        lang = glossary.DEFAULT_LANG
    t = _TEXT[lang]
    root = rep.get('root')
    home = rep.get('home')
    evidence = [e for e in (finding.get('evidence') or []) if isinstance(e, dict)]
    check = finding.get('check_id')
    parts = []
    skill = skill_name(finding)
    if skill:
        parts.append(skill)
    places = []
    for e in evidence[:3]:
        spot = None
        for key in _PLACE_KEYS:
            value = e.get(key)
            if isinstance(value, str) and value:
                spot = file_alias(value, root, home)
                # the line of a secret, or the line of a syntax error in
                # a skill header
                line = e.get('line') if isinstance(e.get('line'), int) \
                    else e.get('error_line')
                if isinstance(line, int):
                    spot += ':%d' % line
                break
        if spot is None:
            for key in _LIST_KEYS:
                value = e.get(key)
                if not isinstance(value, list):
                    continue
                for item in value[:MAX_PLACES]:
                    if isinstance(item, str) and item:
                        places.append(_repo_alias(item, root, home, lang)
                                      if key == 'paths' else item)
                # the scan lists the first folders only; the count says
                # how many there are in all
                total = e.get('repositories', e.get('repositories unverified'))
                if isinstance(total, int) and total > min(len(value), MAX_PLACES):
                    places.append(t['and_more'].format(
                        n=total - min(len(value), MAX_PLACES)))
            for key in _NAME_KEYS:
                value = e.get(key)
                if isinstance(value, str) and value and value != skill:
                    spot = (_repo_alias(value, root, home, lang)
                            if key == 'repo' else value)
                    break
        if spot is None and check == 'RUL_CHAIN_OVER_BUDGET' \
                and isinstance(e.get('chain'), str):
            # the place is every instruction file at once
            spot = t['chain_all'].format(size=_size(e.get('bytes') or 0, lang))
        if spot is None and check in _DETAIL_PATH_CHECKS:
            head = str(e.get('detail') or '').split(':', 1)[0].strip()
            if head and len(head) <= 200 and '\n' not in head:
                spot = file_alias(head, root, home)
        if spot:
            places.append(spot)
        # what a dead import points at: named next to the file that imports it
        imported = e.get('import')
        if isinstance(imported, str) and imported:
            places.append('@' + file_alias(imported, root, home))
    if not places and check in _REPO_WIDE_CHECKS:
        places = [_repo_alias(t_.get('name'), root, home, lang)
                  for t_ in rep.get('top_level') or []
                  if isinstance(t_, dict) and t_.get('kind') == 'repo'][:MAX_PLACES]
    parts.extend(dict.fromkeys(p for p in places if p))
    return ', '.join(parts)


def describe(finding, rep, lang=glossary.DEFAULT_LANG):
    """One finding as the digest lists it."""
    title = glossary.title_for(finding, lang)
    if title:
        action = glossary.action_for(finding, lang)
        if lang == 'ru':
            # the action follows a colon in the rendered digest
            action = action[0].lower() + action[1:]
    else:
        # a check the glossary does not know yet: fall back to what the
        # scanner wrote, which is still free of secrets
        title = str(finding.get('title') or '')
        action = str(finding.get('recommendation') or '')
    return {
        'id': finding.get('fid'),
        'code': finding.get('check_id') or '',
        'gate': finding.get('gate'),
        'title': title,
        'where': where(finding, rep, lang),
        'action': action,
        'severity': finding.get('severity'),
        'status': finding.get('status'),
    }


def _priority(f):
    return (_SEV_RANK.get(f.get('severity'), 9),
            _STATUS_RANK.get(f.get('status'), 9),
            str(f.get('fid')))


def _history_state(rep, lang):
    """How much of the git history was looked at, from the facts."""
    t = _TEXT[lang]
    cov = [(t_.get('extra') or {}).get('history_coverage')
           for t_ in rep.get('top_level') or [] if t_.get('kind') == 'repo']
    cov = [c for c in cov if c]
    has_git = bool(cov) or bool(rep.get('git_roots')) or any(
        t_.get('kind') == 'repo' for t_ in rep.get('top_level') or [])
    if not has_git:
        return t['history_na']
    if not cov:
        return t['history_not']
    if any(not c.get('complete') for c in cov):
        return t['history_partial']
    return t['history_scanned']


def root_repo(rep):
    """The scan's entry for the audited folder itself, when the folder is
    a git repository (it is listed first, under the name '.')."""
    for x in rep.get('top_level') or []:
        if isinstance(x, dict) and x.get('kind') == 'repo' \
                and str(x.get('name')) in ('.', ''):
            return x
    return None


def _coverage_lines(rep, lang):
    t = _TEXT[lang]
    stats = rep.get('stats') or {}
    skills = rep.get('skills') or {}
    top_repos = [x for x in rep.get('top_level') or []
                 if isinstance(x, dict) and x.get('kind') == 'repo']
    cov = skills.get('coverage') or {}
    git_roots = rep.get('git_roots') or []
    lines = [t['coverage'].format(
        files=stats.get('total_files', 0),
        skills=len(skills.get('entries') or []),
        repos=len(git_roots) or len(top_repos))]
    if cov.get('truncated') or cov.get('failed'):
        where_ = ', '.join(str(x.get('location')) for x in
                           (cov.get('truncated') or []) + (cov.get('failed') or []))
        lines.append(t['skills_partial'].format(why=where_))
    own_skipped = stats.get('own_source_skipped') or 0
    if own_skipped:
        # files of a copy of this plugin: left out of the key check on
        # purpose, and said here so that the gap is not silent
        lines.append(t['own_source'].format(n=own_skipped))
    # the agent needs no guesswork to apply the ".gitignore" rule of the
    # skill: the digest says whether the audited folder is in git
    if root_repo(rep) is not None:
        lines.append(t['folder_git'])
    elif git_roots:
        lines.append(t['folder_git_nested'])
    # git folders whose index, history and hooks were not read: all that
    # lie deeper than the first level
    top_names = {str(x.get('name')) for x in top_repos}
    nested = sum(1 for g in git_roots
                 if str(g).replace('\\', '/').split('/')[0] not in top_names)
    if nested:
        lines.append(t['repos_nested'].format(n=nested))
    lines.append(t['history'].format(state=_history_state(rep, lang)))
    return lines


def _improve_lines(rep, lang):
    """Suggestions for making the workspace leaner, computed the same way
    as in the plain-language report: extra tokens at every start, memory
    the agent cannot see, junk, duplicates, large files without a
    backup, repeated or generic instruction text."""
    t = _TEXT[lang]
    try:
        import gates
        import report_human as rh
    except ImportError:  # pragma: no cover - shipped together
        return []
    tips = []
    overhead = rh.session_overhead_bytes(rep)
    if overhead > 0:
        tips.append(t['imp_tokens'].format(
            mid=rh.fmt_int(rh.token_range(overhead)[1], lang)))
    if rh.memory_over_bytes(rep) > 0:
        tips.append(t['imp_memory'])
    if rh.junk_bytes(rep) >= rh.TIP_MIN_BYTES:
        tips.append(t['imp_junk'].format(size=rh.human_bytes(rh.junk_bytes(rep), lang)))
    if rh.duplicates_bytes(rep) >= rh.TIP_MIN_BYTES:
        tips.append(t['imp_dup'].format(
            size=rh.human_bytes(rh.duplicates_bytes(rep), lang)))
    if rh.large_files_bytes(rep):
        tips.append(t['imp_large'].format(
            size=rh.human_bytes(rh.large_files_bytes(rep), lang)))
    folder_repo = root_repo(rep)
    if folder_repo is not None \
            and (folder_repo.get('extra') or {}).get('tool_dir_ignored') is False:
        # the reports of this tool hold paths of the machine: the folder
        # must stay out of git
        tips.append(t['imp_tool_dir'])
    findings = rep.get('findings_detailed') or []
    repeats = sum(1 for f in findings if f.get('check_id') == 'INSTR_DUPLICATION')
    if repeats:
        tips.append(t['imp_repeats'].format(n=repeats))
    cq = rep.get('content_quality') or {}
    # a file that already has its "few concrete rules" line is not
    # repeated as a suggestion; the suggestion covers the rest (a short
    # file, or one between 30% and 50% rules)
    noise_files = {str((f.get('evidence') or [{}])[0].get('file'))
                   for f in findings
                   if f.get('check_id') == 'RUL_MOSTLY_NOISE'}
    cq_tips = []
    for path, analysis in sorted(cq.items()):
        ratio = analysis.get('signal_ratio', 1.0)
        if ratio >= 0.5:
            continue
        if gates.is_short_instruction(analysis):
            cq_tips.append(t['imp_short_file'].format(file=path))
        elif str(path) not in noise_files:
            cq_tips.append(t['imp_noise'].format(
                file=path, pct=int(round(ratio * 100))))
    tips.extend(cq_tips[:2])
    generic = sum(a.get('generic_count', 0) for a in cq.values())
    if generic > 0:
        tips.append(t['imp_generic'].format(n=generic))
    return tips


_PLUGIN_MARKERS = ('/.zcode/cli/plugins/', '/.claude/plugins/', '/.agents/plugins/')


def _scope(finding, rep):
    """0 = the audited folder, 1 = the user's home, 2 = an installed
    plugin's cache: the user cannot fix a plugin's files, so those
    findings come last and are counted rather than listed."""
    evidence = finding.get('evidence') or []
    first = evidence[0] if evidence and isinstance(evidence[0], dict) else {}
    path = str(first.get('file') or first.get('path') or '').replace('\\', '/')
    if any(marker in path for marker in _PLUGIN_MARKERS):
        return 2
    home = str(rep.get('home') or '').replace('\\', '/')
    if home and path.startswith(home):
        return 1
    return 0


def scope(finding, rep):
    """Where a finding sits, for reports that list the user's own files
    before the files of installed plugins: 0 = the audited folder,
    1 = the home folder, 2 = a plugin's cache."""
    return _scope(finding, rep)


def _sorted_findings(rep):
    """Open findings, most serious first; inside one severity and status
    the audited folder comes before the home folder and before plugins."""
    findings = [f for f in rep.get('findings_detailed') or []
                if f.get('status') != 'pass']

    def key(f):
        severity, status, fid = _priority(f)
        return (severity, status, _scope(f, rep), fid)

    findings.sort(key=key)
    return findings


def _kind_name(finding, lang):
    title = glossary.title_for(finding, lang)
    if title:
        return title
    return str(finding.get('title') or finding.get('check_id') or '')[:80]


def build(rep, lang=glossary.DEFAULT_LANG, files=None):
    """The digest of one scan report, as a dict."""
    if lang not in _TEXT:
        lang = glossary.DEFAULT_LANG
    t = _TEXT[lang]
    findings = _sorted_findings(rep)
    shown, rest, rest_plugins = [], {}, {}
    per_kind = {}
    key_files = {}       # file -> keys counted there, not spelled out
    for f in findings:
        area = _scope(f, rep)
        key = f.get('check_id') or str(f.get('title') or '')
        # findings inside plugins are never spelled out one by one
        if area != 2 and len(shown) < MAX_ITEMS \
                and per_kind.get(key, 0) < MAX_PER_KIND:
            per_kind[key] = per_kind.get(key, 0) + 1
            shown.append(describe(f, rep, lang))
            continue
        if key == 'SEC_EXPOSED_SECRET' and area != 2:
            # the user needs the places of the other keys, not forty
            # equal lines and not one number
            spot = where(f, rep, lang)
            name = re.sub(r':\d+$', '', spot) or t['file_unknown']
            key_files[name] = key_files.get(name, 0) + 1
            continue
        bucket = rest_plugins if area == 2 else rest
        name = _kind_name(f, lang)
        bucket[name] = bucket.get(name, 0) + 1

    gates = []
    unchecked = []
    not_applicable = []
    for g in rep.get('gates') or []:
        status = g.get('status')
        item = {
            'id': g.get('gid'),
            'name': glossary.gate_name(g.get('gid'), lang),
            'status': status,
            'status_word': glossary.gate_status(status, lang),
        }
        reason = glossary.reason_text(g.get('status_why'), lang,
                                      g.get('status_count'))
        if reason:
            item['reason'] = reason
        gates.append(item)  # the reason is printed in its own section
        if status in ('unknown', 'not_applicable'):
            target = unchecked if status == 'unknown' else not_applicable
            for c in g.get('checks') or []:
                if c.get('status') != status:
                    continue
                line = glossary.reason_text(c.get('why'), lang, c.get('count')) \
                    or c.get('reason') or ''
                if not line:
                    continue
                entry = (glossary.gate_name(g.get('gid'), lang), line)
                if entry not in target:
                    target.append(entry)

    # where to start: one step per kind of finding, naming every place
    # the listed findings of that kind point at
    start = []
    for item in shown:
        if item['status'] not in ('fail', 'warn'):
            continue
        if item['code'] == 'SEC_EXPOSED_SECRET' and item['status'] != 'fail':
            # a key in a file that git keeps out is a hint, not a step
            continue
        same = next((s for s in start if s['code'] == item['code']
                     and s['action'] == item['action']), None)
        if same is not None:
            if item['where'] and item['where'] not in same['places'] \
                    and len(same['places']) < MAX_START_PLACES:
                same['places'].append(item['where'])
            continue
        if len(start) >= MAX_START:
            break
        start.append({'code': item['code'], 'title': item['title'],
                      'action': item['action'],
                      'places': [item['where']] if item['where'] else []})

    root = rep.get('root') or '.'
    return {
        'lang': lang,
        'name': os.path.basename(str(root).rstrip('\\/')) or str(root),
        'coverage': _coverage_lines(rep, lang),
        'gates': gates,
        'findings': shown,
        'findings_total': len(rep.get('findings_detailed') or []),
        'rest': sorted(rest.items(), key=lambda kv: -kv[1]),
        'rest_plugins': sorted(rest_plugins.items(), key=lambda kv: -kv[1]),
        'rest_files': sorted(key_files.items(), key=lambda kv: (-kv[1], kv[0])),
        'improve': _improve_lines(rep, lang),
        'unchecked': unchecked,
        'not_applicable': not_applicable,
        'start': start,
        'files': dict(files or {}),
    }


def render(digest):
    """The digest as plain text: what the agent reads."""
    t = _TEXT[digest['lang']]
    out = [t['title'].format(name=digest['name']), '']
    out.extend(digest['coverage'])
    out.append('')
    out.append(t['h_gates'])
    for g in digest['gates']:
        out.append('  %-13s %s (%s)' % (g['status_word'], g['name'], g['id']))
    out.append('')
    out.append(t['h_findings'])
    counted = bool(digest['rest'] or digest['rest_plugins']
                   or digest.get('rest_files'))
    if not digest['findings'] and not counted:
        out.append('  ' + t['findings_none'])
    else:
        if counted:
            out.append('  ' + t['findings_total'].format(
                total=digest['findings_total'], shown=len(digest['findings'])))
        else:
            out.append('  ' + t['findings_all'].format(
                total=digest['findings_total']))
        for i, f in enumerate(digest['findings'], 1):
            out.append('  %d. [%s, %s] %s (%s)' % (
                i, glossary.severity(f['severity'], digest['lang']),
                glossary.finding_status(f['status'], digest['lang']),
                f['title'], f['id']))
            if f['where']:
                out.append('     %s: %s' % (t['where'], f['where']))
            if f['action']:
                out.append('     %s: %s' % (t['action'], f['action']))
        if digest['rest']:
            out.append('  ' + t['findings_rest'].format(
                rest='; '.join('%s x%d' % (name, n) for name, n in digest['rest'])))
        if digest.get('rest_files'):
            listed = digest['rest_files'][:MAX_REST_FILES]
            listing = '; '.join('%s (%d)' % (name, n) for name, n in listed)
            if len(digest['rest_files']) > len(listed):
                listing += '; ' + t['and_more_files'].format(
                    n=len(digest['rest_files']) - len(listed))
            out.append('  ' + t['findings_rest_files'].format(files=listing))
        if digest['rest_plugins']:
            out.append('  ' + t['findings_rest_plugins'].format(
                rest='; '.join('%s x%d' % (name, n)
                               for name, n in digest['rest_plugins'][:8])))
    out.append('')
    if digest['improve']:
        out.append(t['h_improve'])
        for tip in digest['improve']:
            out.append('  - %s' % tip)
        out.append('')
    if digest['unchecked']:
        out.append(t['h_unchecked'])
        for gate, line in digest['unchecked'][:MAX_UNCHECKED]:
            out.append('  - %s: %s' % (gate, line))
        out.append('')
    if digest['not_applicable']:
        out.append(t['h_na'])
        for gate, line in digest['not_applicable'][:MAX_UNCHECKED]:
            out.append('  - %s: %s' % (gate, line))
        out.append('')
    out.append(t['h_start'])
    if not digest['start']:
        out.append('  ' + t['start_none'])
    for i, s in enumerate(digest['start'], 1):
        action = s['action']
        if action and action[0].islower():
            # a numbered step starts with a capital, unlike the "what to
            # do" line that follows a colon
            action = action[0].upper() + action[1:]
        out.append('  %d. %s' % (i, action))
        if s['places']:
            out.append('     (%s)' % '; '.join(s['places']))
    out.append('')
    if digest['files']:
        out.append(t['h_files'])
        for key, label in (('human', 'f_human'), ('report', 'f_report'),
                           ('scan', 'f_scan')):
            if digest['files'].get(key):
                out.append('  ' + t[label].format(p=digest['files'][key]))
        out.append('')
    out.append(t['note'])
    return '\n'.join(out)


_CARD = {
    'ru': {'what': 'что', 'where': 'где', 'action': 'что сделать',
           'autofix_yes': 'автоматическое исправление: есть план (fix %s), '
                          'применяется только после подтверждения',
           'autofix_no': 'автоматическое исправление: нет, сделайте вручную',
           'confidence': 'уверенность'},
    'en': {'what': 'what', 'where': 'where', 'action': 'what to do',
           'autofix_yes': 'automatic fix: a plan exists (fix %s); it is applied '
                          'only after your confirmation',
           'autofix_no': 'automatic fix: none, do it by hand',
           'confidence': 'confidence'},
}


def explain_card(finding, rep, lang=glossary.DEFAULT_LANG):
    """One finding as a short card: the same digest fields, nothing raw.

    The evidence list of the scan (absolute paths, quoted lines, masks)
    is never printed; only the digest view of the finding is."""
    if lang not in _TEXT:
        lang = glossary.DEFAULT_LANG
    c = _CARD[lang]
    d = describe(finding, rep, lang)
    out = ['%s  [%s, %s]  %s (%s)' % (
        d['id'], glossary.severity(d['severity'], lang),
        glossary.finding_status(d['status'], lang),
        glossary.gate_name(d['gate'], lang), d['gate'])]
    out.append('%s: %s' % (c['what'], d['title']))
    if d['where']:
        out.append('%s: %s' % (c['where'], d['where']))
    if d['action']:
        out.append('%s: %s' % (c['action'], d['action']))
    if finding.get('autofix_available'):
        out.append(c['autofix_yes'] % d['id'])
    else:
        out.append(c['autofix_no'])
    out.append('%s: %s' % (c['confidence'], finding.get('confidence')))
    return '\n'.join(out)
