#!/usr/bin/env python3
"""Render a scan.json report as plain-language markdown for non-technical readers.

    python report_human.py <scan.json> [--lang en|ru] [--sessions 10]
                            [--after <scan2.json>] [--out HUMAN-REPORT.md]

English or Russian. With --after (a second scan made after cleanup) the
report gains a "What gets better after cleanup" section that compares the
two scans. The generator is pure formatting: it reads the report dict,
never the filesystem, and never touches secret values (counts, file
names and line numbers only).

Findings are named through glossary.py (the finding's check_id gives the
plain title and the "what to do" sentence); reports made before check
ids existed fall back to the category mapping in plain_sentence().

All token and cost figures are estimates; every assumption is printed
next to the numbers it feeds. Python 3.9+, stdlib only.
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

try:
    import gates
    import glossary
    import summary
except ImportError:  # direct script use from another folder
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import gates
    import glossary
    import summary

SEVERITY_RANK = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
OPEN_STATUSES = ('fail', 'warn')

PROJECT_BENCHMARK_DEFAULT = 16384
MEMORY_LIMIT_BYTES = 24985
DAYS_PER_MONTH = 30
DEFAULT_SESSIONS_PER_DAY = 10

KB = 1024
MB = 1024 ** 2
GB = 1024 ** 3
THIN = '\u202f'  # narrow no-break space: RU thousands separator, unit gap

MAX_WRONG_BULLETS = 6
MAX_SAME_KIND = 3       # bullets of one finding type before a count takes over
MAX_UNCHECKED_FINDINGS = 6   # checks that could not run, listed one by one
MAX_TODO = 3
# junk or duplicates below this are not worth a tip of their own
TIP_MIN_BYTES = 1024 * 1024

# Plain-language task for a still-failing gate, by gate id.
GID_PLAIN = {
    'G1': {'en': 'put the folder layout in order',
           'ru': 'навести порядок в структуре папок'},
    'G2': {'en': 'repair the settings files',
           'ru': 'починить файлы настроек'},
    'G3': {'en': 'fix the instruction files',
           'ru': 'исправить файлы инструкций'},
    'G4': {'en': 'decide the fate of the loose folders',
           'ru': 'решить судьбу свободных папок'},
    'G5': {'en': 'repair the helper skills',
           'ru': 'починить вспомогательные навыки'},
    'G6': {'en': 'rotate and hide the passwords',
           'ru': 'сменить и спрятать пароли'},
    'G7': {'en': 'save the unfinished work to history',
           'ru': 'сохранить незавершённую работу в историю изменений'},
    'G8': {'en': 'remove rules for tools nobody uses',
           'ru': 'убрать правила для неиспользуемых инструментов'},
    'G9': {'en': 'clear out the remaining junk',
           'ru': 'разобрать оставшийся мусор'},
}

STRINGS = {
    'en': {
        'title': 'What the audit found, in plain words',
        'subtitle': 'Folder checked: {root}',
        'h_short': 'The short version',
        'state_fail': 'Of {total} checks, {fail} are red and {warn} are yellow: the workspace '
             'still works, but the mess is big enough to slow every agent down.',
        'state_warn': 'Of {total} checks, none is red and {warn} are yellow: the workspace is '
             'in decent shape, with a few things to tidy up.',
        'state_ok': 'All {total} checks pass: the workspace is clean, and the agents carry '
             'no dead weight.',
        'state_fail_secret': 'Of {total} checks, {fail} are red and {warn} are yellow. The first '
             'thing to deal with: passwords or keys are sitting in files.',
        'main_problem': 'The main problem: {sentence}',
        'promise': 'Cleanup can make every agent start faster and waste less.',
        'start_secret': 'Start here: {action} ({where}).',
        'start_secret_generic': 'have the key reissued by whoever issued it, '
             'then remove it from the file',
        'start_here': 'Start with this:',
        'file_unknown': 'the file named in the scan',
        'then': 'Then:',
        'what_to_do': 'What to do',
        'rest_line': 'The rest ({n}): {list}.',
        'not_checked': 'Not checked ({n}): {list}. These checks could not run, '
             'so the audit says nothing about them.',
        'not_checked_parts': 'Inside the other checks, {n} could not run either: '
             'see the section below.',
        'not_checked_rest': 'And {n} more checks that could not run.',
        'h_not_checked': 'What could not be checked',
        'not_checked_item': '{gate}: {reason}',
        'not_checked_no_reason': 'the scan does not say why',
        'skill_at': 'skill {name}',
        'file_at': 'file {file}',
        'file_line_at': 'file {file}, line {line}',
        'import_of': 'import {ref}',
        'audited_folder': 'the audited folder itself',
        'and_more': '{n} more',
        'improve_tool_dir': 'Keep the audit reports out of Git: add the .agents-doctor folder '
             'to .gitignore. The snapshot holds paths of this computer.',
        'h_improve': 'What you can make better',
        'improve_tokens': 'Shorten the instruction files and the agent memory: right now the '
             'agent gets about {mid} extra tokens at every start.',
        'improve_memory': 'The agent memory file is over the limit and the agent never sees what '
             'lies beyond it: move the details into separate files and keep short '
             'pointers.',
        'improve_junk': 'Clear out the junk: it frees {size}.',
        'improve_dup': 'Remove the duplicate files: another {size}.',
        'improve_large': 'Decide what to do with the large files that have no backup ({size}): '
             'put them under version control or delete them.',
        'improve_repeats': 'The same text is repeated in {n} pairs of instruction files: keep it '
             'in one place.',
        'clean_only_if': 'Run the safe cleanup (`safe_clean.py`) for the junk: it works through '
             'the findings one at a time and asks before every change.',
        'h_costs': 'What this costs you',
        'cost_tokens': 'Every session starts with about {lo}–{hi} extra tokens of instructions '
             'and memory the agent does not need (best estimate: {mid}).',
        'cost_monthly': 'Over a month that makes roughly {mlo}–{mhi} extra tokens (best '
             'estimate: {mmid}).',
        'cost_assumption': 'The monthly figure assumes {sessions} agent sessions a day and {days} '
             'days a month.',
        'cost_tokens_zero': 'Instructions and memory fit within healthy sizes: no extra tokens are '
             'loaded at every start.',
        'cost_memory': 'The agent memory file is {kb} over the limit, and everything past the '
             'limit is cut off: that part of your notes the agent never sees.',
        'cost_junk': 'Junk files and folders take up {size}.',
        'cost_dup': 'Verified duplicate copies add another {size}.',
        'cost_large': 'Large files without a backup hold {size}.',
        'cost_disk_zero': 'No junk, duplicates or oversized files were found.',
        'cost_secrets': '{n} passwords or keys are left in plain sight, in files or in saved '
             'history; the values themselves are not shown here.',
        'cost_secrets_one': '{n} password or key is left in plain sight, in files or in saved '
             'history; the value itself is not shown here.',
        'cost_secrets_zero': 'No passwords or keys are lying in plain sight.',
        'cost_secrets_ignored': 'Keys in settings files that Git keeps out: {n} (the usual '
             'place for personal settings; a risk only if such a file is sent anywhere).',
        'plugins_line': 'In installed plugins ({n_word}; not your files, only a plugin update '
             'fixes them): {list}.',
        'foot_quality': 'Why it matters: with a long context, background noise measurably '
             'lowers the quality of the answers.',
        'foot_tokens': 'How tokens are counted: an estimate of 4 bytes per token; depending on '
             'the language of the text the real ratio sits between 3 and 5 bytes per '
             'token.',
        'h_wrong': 'What is wrong, in plain words',
        'wrong_none': 'Nothing serious: no checks failed.',
        'plain_secrets': 'A password/key is sitting in a file where it should not be',
        'plain_no_prevention': 'Nothing guards against passwords slipping into saved work',
        'plain_heavy': 'A folder with {size} of data has no backup and no history',
        'plain_heavy_nosize': 'A folder with a lot of data has no backup and no history',
        'plain_unowned': 'Some folders are outside any backup: their content has no history',
        'plain_nested': 'One project sits inside another project, which confuses backup and '
             'sync tools',
        'plain_drift': 'Two instruction files disagree — the agent gets conflicting rules',
        'plain_dead': "The agent's instructions point to things that do not exist",
        'plain_boiler': 'Part of the instructions is template text that gives the agent no '
             'useful rules',
        'plain_fat': 'The instructions have grown too big; the agent pays for the extra on '
             'every start',
        'plain_skills': 'A helper skill is set up wrong and never runs',
        'plain_git': 'Work is not saved to history yet',
        'plain_config': 'A settings file is broken',
        'plain_noconfig': 'No settings files were found, worth checking why',
        'plain_gov': 'Rules are kept for a tool nobody has used in months',
        'plain_health': 'Unused files and old copies are piling up in the workspace',
        'plain_cq_noise': 'Only {pct}% of the lines of the instruction file {file} are concrete '
             "rules; the rest only fills the agent's context",
        'cq_short_hint': 'The instruction file {file} is short and holds almost no rules. A '
             'pointer to another file with the rules is fine as it is.',
        'h_better': 'What gets better after cleanup',
        'better_gates': 'Red checks went from {f1} to {f2}, yellow from {w1} to {w2}.',
        'better_slim': 'Agent instructions slimmed from {x} to {y}, about {z} fewer tokens '
             'every session.',
        'better_tokens': 'Extra tokens per start went from about {a} to {b}.',
        'better_junk': 'Junk went from {a} to {b}.',
        'better_secrets': 'Secrets in plain sight went from {a} to {b}.',
        'better_secrets_zero': 'Secrets in plain sight went from {a} to none.',
        'still_todo': '**Still to do:**',
        'h_next': 'Next step',
        'next_2': 'Then run the audit again: the second report shows the "after" picture '
             'and what improved.',
        'next_3': 'This audit changed nothing: it only read files and counted.',
        'footer': 'Read-only audit: nothing was modified. Generated {ts}. The numbers are '
             'estimates, not bills: they show the order of magnitude.',
    },
    'ru': {
        'title': 'Что нашла проверка: простыми словами',
        'subtitle': 'Проверенная папка: {root}',
        'h_short': 'Коротко',
        'state_fail': 'Из {total} проверок {fail} {failw} и {warn} {warnw}: работать ещё '
             'можно, но беспорядка уже хватает, чтобы тормозить агента.',
        'state_warn': 'Из {total} проверок ни одна не красная, {warn} {warnw}: с рабочей '
             'папкой всё в порядке, хотя есть что прибрать.',
        'state_ok': 'Все {total} проверок зелёные: рабочая папка чистая, и агент не тащит '
             'за собой ничего лишнего.',
        'state_fail_secret': 'Из {total} проверок {fail} {failw} и {warn} {warnw}. Главное сейчас: в '
             'файлах лежат пароли или ключи.',
        'main_problem': 'Главная проблема: {sentence}',
        'promise': 'После уборки агент будет стартовать быстрее и тратить меньше.',
        'start_secret': 'Начните с этого: {action} ({where}).',
        'start_secret_generic': 'смените ключ у того, кто его выдал, затем уберите '
             'его из файла',
        'start_here': 'Начните с этого:',
        'file_unknown': 'файл, названный в проверке',
        'then': 'Дальше:',
        'what_to_do': 'Что сделать',
        'rest_line': 'Остальное ({n}): {list}.',
        'not_checked': 'Не проверено ({n}): {list}. Эти проверки не удалось '
             'выполнить, об их результате ничего не известно.',
        'not_checked_parts': 'Внутри остальных проверок тоже не удалось выполнить '
             '{n}: подробности в разделе ниже.',
        'not_checked_rest': 'И ещё {n} непроверенных.',
        'h_not_checked': 'Что не удалось проверить',
        'not_checked_item': '{gate}: {reason}',
        'not_checked_no_reason': 'причина не записана',
        'skill_at': 'навык {name}',
        'file_at': 'файл {file}',
        'file_line_at': 'файл {file}, строка {line}',
        'import_of': 'подключение {ref}',
        'audited_folder': 'самой папки',
        'and_more': 'ещё {n}',
        'improve_tool_dir': 'Не храните отчёты аудита в Git: добавьте папку .agents-doctor '
             'в .gitignore. В снимке есть пути этого компьютера.',
        'h_improve': 'Что можно улучшить',
        'improve_tokens': 'Сократите файлы инструкций и память агента: сейчас агент получает '
             'примерно {mid} лишних токенов при каждом запуске.',
        'improve_memory': 'Файл памяти агента больше лимита, и всё, что сверх лимита, агент не '
             'видит. Перенесите подробности в отдельные файлы и оставьте короткие '
             'ссылки.',
        'improve_junk': 'Разберите мусор: освободится {size}.',
        'improve_dup': 'Удалите дубликаты файлов: освободится ещё {size}.',
        'improve_large': 'Решите, что делать с большими файлами без резервной копии ({size}): '
             'сохраните их в историю или удалите.',
        'improve_repeats': 'Одинаковый текст повторяется в {n} парах файлов инструкций: оставьте '
             'его в одном месте.',
        'clean_only_if': 'Запустите безопасную уборку (`safe_clean.py`): она проходит находки по '
             'одной и спрашивает перед каждым изменением.',
        'h_costs': 'Во сколько это обходится',
        'cost_tokens': 'При каждом запуске агент получает примерно {lo}–{hi} лишних токенов '
             'инструкций и памяти, которые ему не нужны (лучшая оценка: {mid}).',
        'cost_monthly': 'За месяц набегает порядка {mlo}–{mhi} лишних токенов (лучшая оценка: '
             '{mmid}).',
        'cost_assumption': 'Месячная оценка исходит из {sessions} запусков агента в день и {days} '
             'дней в месяце.',
        'cost_tokens_zero': 'Инструкции и память укладываются в здоровые размеры: при запуске '
             'ничего лишнего не загружается.',
        'cost_memory': 'Файл памяти агента превышает лимит на {kb}, и всё сверх лимита '
             'обрезается: эту часть ваших заметок агент никогда не видит.',
        'cost_junk': 'Мусорные файлы и папки занимают {size}.',
        'cost_dup': 'Подтверждённые дубликаты добавляют ещё {size}.',
        'cost_large': 'Большие файлы без резервной копии занимают {size}.',
        'cost_disk_zero': 'Мусора, дубликатов и слишком больших файлов не нашлось.',
        'cost_secrets': 'На виду, в файлах или в сохранённой истории, осталось {n} {parols} и '
             '{keys}; сами значения здесь не показываем.',
        'cost_secrets_one': 'На виду, в файле или в сохранённой истории, остался пароль или ключ; '
             'само значение здесь не показываем.',
        'cost_secrets_zero': 'Паролей и ключей на виду нет.',
        'cost_secrets_ignored': 'Ключи в файлах настроек, которые Git не видит: {n} (обычное '
             'место для личных настроек; опасно, только если файл куда-то отправляли).',
        'plugins_line': 'В установленных плагинах ещё {n} {n_word} (их файлы не ваши, '
             'исправит только обновление плагина): {list}.',
        'foot_quality': 'Почему это важно: в длинном контексте фоновый шум заметно снижает '
             'качество ответов.',
        'foot_tokens': 'Как считаются токены: оценка 4 байта на токен; в зависимости от языка '
             'текста реальное отношение от 3 до 5 байт на токен.',
        'h_wrong': 'Что не так, по-человечески',
        'wrong_none': 'Серьёзного ничего нет: проваленных проверок нет.',
        'plain_secrets': 'В файле лежит пароль/ключ, где его быть не должно',
        'plain_no_prevention': 'Ничто не мешает паролям попасть в сохранённую работу',
        'plain_heavy': 'Папка объёмом {size} без резервной копии и истории изменений',
        'plain_heavy_nosize': 'Большая папка без резервной копии и истории изменений',
        'plain_unowned': 'Некоторые папки вне любых резервных копий: у их содержимого нет '
             'истории',
        'plain_nested': 'Один проект лежит внутри другого проекта, и это путает инструменты '
             'синхронизации и резервного копирования',
        'plain_drift': 'Два файла инструкций противоречат друг другу, агент получает '
             'конфликтные правила',
        'plain_dead': 'Инструкции агента ссылаются на то, чего не существует',
        'plain_boiler': 'Часть инструкций это шаблонный текст, который не даёт агенту полезных '
             'правил',
        'plain_fat': 'Инструкции разрослись, и агент переплачивает за лишнее при каждом '
             'запуске',
        'plain_skills': 'Вспомогательный навык настроен неправильно и никогда не запускается',
        'plain_git': 'Работа ещё не сохранена в историю',
        'plain_config': 'Файл настроек повреждён',
        'plain_noconfig': 'Файлы настроек не нашлись, стоит проверить почему',
        'plain_gov': 'Правила поддерживаются для инструмента, которым давно не пользуются',
        'plain_health': 'В рабочей папке копятся неиспользуемые файлы и старые копии',
        'plain_cq_noise': 'В файле инструкций {file} конкретные правила занимают только {pct}% '
             'строк: остальное агент читает без пользы',
        'cq_short_hint': 'Файл инструкций {file} короткий, правил в нём почти нет. Если это '
             'ссылка на другой файл с правилами, всё в порядке.',
        'h_better': 'Что станет лучше после уборки',
        'better_gates': 'Красных проверок стало {f2} вместо {f1}, жёлтых {w2} вместо {w1}.',
        'better_slim': 'Инструкции агента похудели с {x} до {y}, примерно на {z} токенов '
             'меньше при каждом запуске.',
        'better_tokens': 'Лишних токенов при запуске было около {a}, стало около {b}.',
        'better_junk': 'Мусора было {a}, стало {b}.',
        'better_secrets': 'Паролей на виду было {a}, стало {b}.',
        'better_secrets_zero': 'Паролей на виду было {a}, стало ноль.',
        'still_todo': '**Ещё осталось:**',
        'h_next': 'Что дальше',
        'next_2': 'Потом запустите проверку ещё раз: второй отчёт покажет картину «после» '
             'и то, что изменилось.',
        'next_3': 'Эта проверка ничего не меняла: она только читала файлы и считала.',
        'footer': 'Проверка только читает: ничего не менялось. Отчёт собран {ts}. Числа '
             'это оценки, а не счета: они показывают порядок величины.',
    },
}


# --------------------------------------------------------------------------
# value math
# --------------------------------------------------------------------------

def tokens_from_bytes(b):
    """Mixed English text heuristic: about 4 bytes per token."""
    return b // 4


def token_range(b):
    """(low, mid, high) token estimates for b bytes.

    mid is the working estimate (b // 4); low and high come from the
    5-bytes-per-token and 3-bytes-per-token bounds documented in the
    report footnote.
    """
    return b // 5, b // 4, b // 3


def session_overhead_bytes(rep):
    """Bytes the agent re-reads beyond healthy sizes on every start.

    Two parts, both printed as assumptions in the report:
    - project instructions above the 16 KB benchmark (other roles are
      small by design and cost nothing here);
    - memory-index files over the memory limit; the same path listed in
      both memory_over_limit and memory_over_lines is counted once
      (over-limit bytes approximated as size - 24985).
    """
    ct = rep.get('context_tax') or {}
    bench = ct.get('benchmark_project_bytes', PROJECT_BENCHMARK_DEFAULT)
    total = 0
    sizes = {}
    for f in ct.get('session_files', []):
        sizes[f.get('path')] = f.get('size_bytes', 0)
        if f.get('role') == 'project':
            total += max(0, f.get('size_bytes', 0) - bench)
    over_paths = []
    for key in ('memory_over_limit', 'memory_over_lines'):
        for p in ct.get(key) or []:
            if p not in over_paths:
                over_paths.append(p)
    for p in over_paths:
        total += max(0, sizes.get(p, 0) - MEMORY_LIMIT_BYTES)
    return total


def memory_over_bytes(rep):
    """Bytes of memory-index content above the limit (paths deduped)."""
    ct = rep.get('context_tax') or {}
    sizes = {f.get('path'): f.get('size_bytes', 0)
             for f in ct.get('session_files', [])}
    over_paths = []
    for key in ('memory_over_limit', 'memory_over_lines'):
        for p in ct.get(key) or []:
            if p not in over_paths:
                over_paths.append(p)
    return sum(max(0, sizes.get(p, 0) - MEMORY_LIMIT_BYTES)
               for p in over_paths)


def junk_bytes(rep):
    junk = rep.get('junk') or {}
    files = sum(f.get('size_bytes', 0) for f in junk.get('files') or [])
    dirs = sum(d.get('size_bytes', 0) for d in junk.get('dirs') or [])
    return files + dirs


def duplicates_bytes(rep):
    """Space reclaimable from hash-proven duplicates: every redundant
    copy (all but one per group) is waste."""
    return sum(g.get('size_bytes', 0) * max(0, len(g.get('files') or []) - 1)
               for g in rep.get('duplicates') or [])


def large_files_bytes(rep):
    return sum(f.get('size_bytes', 0) for f in rep.get('large_files') or [])


def project_instruction_bytes(rep):
    ct = rep.get('context_tax') or {}
    total = sum(f.get('size_bytes', 0) for f in ct.get('session_files', [])
                if f.get('role') == 'project')
    return total if total else ct.get('project_total_bytes', 0)


def open_secret_count(rep):
    """Secret findings that need action (a key in a tracked or untracked
    file). Falls back to the raw secrets[] count only for a scan without
    detailed findings: a key in a file that git keeps out is a hint,
    not a key on view (see ignored_secret_count)."""
    findings = rep.get('findings_detailed') or []
    if not findings:
        return len(rep.get('secrets') or [])
    return sum(1 for f in findings
               if f.get('category') == 'secrets' and f.get('status') == 'fail')


def ignored_secret_count(rep):
    """Keys in settings files that .gitignore keeps out of git."""
    return sum(
        1 for f in rep.get('findings_detailed') or []
        if f.get('check_id') == 'SEC_EXPOSED_SECRET'
        and (f.get('evidence') or [{}])[0].get('git') == 'ignored')


def gate_counts(rep):
    fails = sum(1 for g in rep.get('gates') or []
                if g.get('status') == 'fail')
    warns = sum(1 for g in rep.get('gates') or []
                if g.get('status') == 'warn')
    return fails, warns


# --------------------------------------------------------------------------
# number formatting
# --------------------------------------------------------------------------

def fmt_int(n, lang):
    """Grouped integer: EN commas, RU narrow spaces."""
    s = f'{n:,}'
    return s.replace(',', THIN) if lang == 'ru' else s


def _fmt_value(v, lang):
    """One decimal at most; RU uses a comma as the decimal separator."""
    if v >= 100 or abs(v - round(v)) < 0.05:
        s = str(int(round(v)))
    else:
        s = f'{v:.1f}'
    return s.replace('.', ',') if lang == 'ru' else s


def _ru_plural(n, one, few, many):
    n100, n10 = n % 100, n % 10
    if 11 <= n100 <= 14:
        return many
    if n10 == 1:
        return one
    if 2 <= n10 <= 4:
        return few
    return many


def _ru_count_adj(n, one, many):
    """Agreement for a counted adjective used as a substantive
    («1 красная», «2/6 красных»)."""
    return one if n % 10 == 1 and n % 100 != 11 else many


def human_bytes(n, lang):
    """Human-friendly size: KB/MB/GB, rounded, locale-style separators."""
    if lang == 'ru':
        units = {'kb': 'КБ', 'mb': 'МБ', 'gb': 'ГБ'}
    else:
        units = {'kb': 'KB', 'mb': 'MB', 'gb': 'GB'}
    if n >= GB:
        v, key = n / GB, 'gb'
    elif n >= MB:
        v, key = n / MB, 'mb'
    elif n >= KB:
        v, key = n / KB, 'kb'
    else:
        if lang == 'ru':
            word = _ru_plural(n, 'байт', 'байта', 'байт')
            return fmt_int(n, lang) + THIN + word
        return f'{n} byte' if n == 1 else f'{n} bytes'
    sep = THIN if lang == 'ru' else ' '
    return _fmt_value(v, lang) + sep + units[key]


# --------------------------------------------------------------------------
# plain-language sentence mapping
# --------------------------------------------------------------------------

_SIZE_RE = re.compile(r'\s*([\d.]+)\s*(B|KB|MB|GB)?', re.I)
_UNIT_MULT = {'B': 1, 'KB': KB, 'MB': MB, 'GB': GB, None: 1}


def _heavy_size(rep, finding):
    """Best-effort size of a 'heavy directory' finding: first the
    heavy_outside_git list, then the evidence size string."""
    ev = (finding.get('evidence') or [{}])[0]
    path = ev.get('path') or ev.get('location') or ''
    for h in rep.get('heavy_outside_git') or []:
        if h.get('path') == path and h.get('size_bytes'):
            return h['size_bytes']
    m = _SIZE_RE.match(str(ev.get('size') or ''))
    if m and m.group(1):
        try:
            return int(float(m.group(1)) * _UNIT_MULT.get(
                m.group(2).upper() if m.group(2) else None, 1))
        except ValueError:
            return None
    return None


def plain_sentence(rep, finding, lang):
    """One plain sentence for a finding, chosen by category and keywords
    in the title. Falls back to the lowercased title in quotes."""
    s = STRINGS[lang]
    cat = finding.get('category') or ''
    title = finding.get('title') or ''
    t = title.lower()
    if cat == 'secrets':
        if 'no secret' in t or 'prevention' in t:
            return s['plain_no_prevention']
        return s['plain_secrets']
    if cat == 'dirs':
        if 'drifted' in t:
            return s['plain_drift']
        if 'nested' in t:
            return s['plain_nested']
        if ('heavy' in t or 'outside version control' in t
                or 'outside git' in t):
            size = _heavy_size(rep, finding)
            if size:
                return s['plain_heavy'].format(size=human_bytes(size, lang))
            if 'heavy' in t:
                return s['plain_heavy_nosize']
            return s['plain_unowned']
        return _fallback(title, lang)
    if cat == 'rules':
        if 'dead' in t:
            return s['plain_dead']
        if 'drift' in t or 'disagree' in t or 'two rule sources' in t:
            return s['plain_drift']
        if 'chain' in t or 'over 16' in t:
            return s['plain_fat']
        if 'generic' in t or 'boilerplate' in t:
            return s['plain_boiler']
        return _fallback(title, lang)
    if cat == 'skills':
        return s['plain_skills']
    if cat == 'git':
        return s['plain_git']
    if cat == 'config':
        if 'no configuration' in t or 'no settings' in t:
            return s['plain_noconfig']
        return s['plain_config']
    if cat == 'governance':
        return s['plain_gov']
    if cat == 'health':
        return s['plain_health']
    return _fallback(title, lang)


def _fallback(title, lang):
    if lang == 'ru':
        return '«' + title.lower() + '»'
    return '"' + title.lower() + '"'


def _sorted_open_findings(rep):
    """Findings that need a look: most serious first, and inside one
    severity the user's own files before the files of installed
    plugins."""
    open_f = [f for f in rep.get('findings_detailed') or []
              if f.get('status') in OPEN_STATUSES]
    open_f.sort(key=lambda f: (SEVERITY_RANK.get(f.get('severity', 'info'), 9),
                               summary.scope(f, rep)))
    return open_f


def _own_open_findings(rep):
    """The same, without the findings inside installed plugins: their
    files are not the user's, and the report counts them in one line."""
    return [f for f in _sorted_open_findings(rep) if summary.scope(f, rep) != 2]


# --------------------------------------------------------------------------
# sections
# --------------------------------------------------------------------------

def _short_version(rep, lang):
    s = STRINGS[lang]
    fails, warns = gate_counts(rep)
    total = len(rep.get('gates') or [])
    lines = ['## ' + s['h_short'], '']
    open_f = _own_open_findings(rep)
    secret_first = bool(open_f) and _is_secret(open_f[0])
    if fails:
        template = s['state_fail_secret'] if secret_first else s['state_fail']
        if lang == 'ru':
            lines.append(template.format(
                total=total, fail=fails,
                failw=_ru_count_adj(fails, 'красная', 'красных'),
                warn=warns,
                warnw=_ru_count_adj(warns, 'жёлтая', 'жёлтых')))
        else:
            lines.append(template.format(
                total=total, fail=fails, warn=warns))
    elif warns:
        if lang == 'ru':
            lines.append(s['state_warn'].format(
                total=total, warn=warns,
                warnw=_ru_count_adj(warns, 'жёлтая', 'жёлтых')))
        else:
            lines.append(s['state_warn'].format(total=total, warn=warns))
    else:
        lines.append(s['state_ok'].format(total=total))
    open_f = _own_open_findings(rep)
    if open_f:
        first = open_f[0]
        lines.append(s['main_problem'].format(
            sentence=plain_title(rep, first, lang)))
        if _is_secret(first):
            # a key comes before any cleanup advice: say what to do about
            # it (that depends on where its file sits) and say where
            spot = plain_where(rep, first, lang) or s['file_unknown']
            action = plain_action(first, lang)
            if lang == 'ru' and action:
                action = action[0].lower() + action[1:]
            lines.append(s['start_secret'].format(
                action=action or s['start_secret_generic'], where=spot))
        else:
            lines.append(s['promise'])
    unchecked = _unchecked_gates(rep)
    if unchecked:
        # a check that could not run is not a pass: said here, with the
        # reasons in a section of their own
        lines.append(s['not_checked'].format(
            n=len(unchecked),
            list=', '.join(glossary.gate_name(g.get('gid'), lang)
                           for g in unchecked)))
    parts = _unchecked_findings(rep)
    if parts:
        lines.append(s['not_checked_parts'].format(n=len(parts)))
    return lines


def _unchecked_gates(rep):
    """Gates whose check could not run (status unknown), in report order.
    A check that does not apply (not_applicable) is not a gap and stays
    out of the plain report."""
    return [g for g in rep.get('gates') or []
            if isinstance(g, dict) and g.get('status') == 'unknown']


def _unchecked_findings(rep):
    """Findings of checks that could not run (status unknown) inside gates
    that are red or yellow for another reason. An unknown gate is a line
    of its own; these would be the only thing the reader never learns."""
    unknown_gates = {g.get('gid') for g in _unchecked_gates(rep)}
    found = [f for f in rep.get('findings_detailed') or []
             if isinstance(f, dict) and f.get('status') == 'unknown'
             and f.get('gate') not in unknown_gates]
    found.sort(key=lambda f: (SEVERITY_RANK.get(f.get('severity', 'info'), 9),
                              summary.scope(f, rep)))
    return found


def _is_secret(finding):
    """An exposed, tracked or historical secret (not the 'no prevention'
    warning, which is a different piece of advice)."""
    return (finding.get('category') == 'secrets'
            and finding.get('status') == 'fail')


def plain_title(rep, finding, lang):
    """What the finding is, in plain words: the glossary name of its type
    when the scan carries check ids, the category mapping otherwise."""
    title = glossary.title_for(finding, lang)
    if title:
        return title
    return plain_sentence(rep, finding, lang)


def plain_action(finding, lang):
    """One sentence of what the user can do; '' when unknown."""
    action = glossary.action_for(finding, lang)
    if action:
        return action
    if lang == 'en':
        return str(finding.get('recommendation') or '').strip()
    return ''


_FOLDER_CATEGORIES = ('dirs', 'health')


def plain_where(rep, finding, lang):
    """Where a finding sits, in words: the skill, the file and line, the
    folder or repository. Paths are relative to the audited folder (never
    absolute); quoted file content in the evidence is not read."""
    s = STRINGS[lang]
    root, home = rep.get('root'), rep.get('home')
    evidence = [e for e in (finding.get('evidence') or [])
                if isinstance(e, dict)]
    parts = []
    skill = summary.skill_name(finding)
    if skill:
        parts.append(s['skill_at'].format(name=skill))
    folder_like = finding.get('category') in _FOLDER_CATEGORIES
    for e in evidence[:2]:
        file = e.get('file') if isinstance(e.get('file'), str) else None
        if file is None and isinstance(e.get('path'), str):
            file = e['path']
        if file:
            alias = summary.file_alias(file, root, home)
            if alias.startswith('<outside'):
                alias = ''
            if alias:
                line = e.get('line') if isinstance(e.get('line'), int) \
                    else e.get('error_line')
                if folder_like:
                    parts.append(alias)
                elif isinstance(line, int):
                    parts.append(s['file_line_at'].format(file=alias,
                                                          line=line))
                else:
                    parts.append(s['file_at'].format(file=alias))
            if isinstance(e.get('import'), str) and e['import']:
                parts.append(s['import_of'].format(ref=e['import']))
            continue
        # folders named as a list (repositories that were not checked)
        listed = e.get('paths') if isinstance(e.get('paths'), list) else None
        if listed:
            for item in listed[:5]:
                if isinstance(item, str) and item:
                    parts.append(_repo_alias(s, item, root, home))
            total = e.get('repositories')
            if isinstance(total, int) and total > min(len(listed), 5):
                parts.append(s['and_more'].format(
                    n=total - min(len(listed), 5)))
            continue
        for key in ('repo', 'location', 'name', 'tool', 'ref'):
            value = e.get(key)
            if isinstance(value, str) and value and value != skill:
                parts.append(_repo_alias(s, value, root, home)
                             if key == 'repo' else value)
                break
    return ', '.join(dict.fromkeys(p for p in parts if p))


def _repo_alias(s, name, root, home):
    """A repository as a person reads it: the audited folder itself is
    listed under '.' in the scan."""
    if str(name) in ('.', ''):
        return s['audited_folder']
    return summary.file_alias(str(name), root, home)


def _costs_section(rep, lang, sessions_per_day):
    s = STRINGS[lang]
    lines = ['## ' + s['h_costs'], '']
    overhead = session_overhead_bytes(rep)
    if overhead > 0:
        lo, mid, hi = token_range(overhead)
        per_month = DAYS_PER_MONTH * max(0, sessions_per_day)
        mlo, mmid, mhi = lo * per_month, mid * per_month, hi * per_month
        lines.append('- ' + s['cost_tokens'].format(
            lo=fmt_int(lo, lang), hi=fmt_int(hi, lang),
            mid=fmt_int(mid, lang)))
        lines.append('  - ' + s['cost_monthly'].format(
            mlo=fmt_int(mlo, lang), mhi=fmt_int(mhi, lang),
            mmid=fmt_int(mmid, lang)))
        lines.append('  - ' + s['cost_assumption'].format(
            sessions=fmt_int(max(0, sessions_per_day), lang),
            days=DAYS_PER_MONTH))
    else:
        lines.append('- ' + s['cost_tokens_zero'])
    mo = memory_over_bytes(rep)
    if mo > 0:
        lines.append('- ' + s['cost_memory'].format(
            kb=human_bytes(mo, lang)))
    parts = []
    jb = junk_bytes(rep)
    db = duplicates_bytes(rep)
    lb = large_files_bytes(rep)
    if jb:
        parts.append(s['cost_junk'].format(size=human_bytes(jb, lang)))
    if db:
        parts.append(s['cost_dup'].format(size=human_bytes(db, lang)))
    if lb:
        parts.append(s['cost_large'].format(size=human_bytes(lb, lang)))
    if parts:
        lines.append('- ' + ' '.join(parts))
    else:
        lines.append('- ' + s['cost_disk_zero'])
    secrets = open_secret_count(rep)
    if secrets:
        if secrets == 1:
            lines.append('- ' + s['cost_secrets_one'].format(n=secrets))
        else:
            extra = {}
            if lang == 'ru':
                extra = {
                    'parols': _ru_plural(secrets, 'пароль', 'пароля',
                                         'паролей'),
                    'keys': _ru_plural(secrets, 'ключ', 'ключа', 'ключей'),
                }
            lines.append('- ' + s['cost_secrets'].format(n=secrets, **extra))
    else:
        lines.append('- ' + s['cost_secrets_zero'])
    ignored = ignored_secret_count(rep)
    if ignored:
        lines.append('- ' + s['cost_secrets_ignored'].format(n=fmt_int(ignored, lang)))
    lines.append('')
    lines.append('*' + s['foot_quality'] + '*')
    lines.append('*' + s['foot_tokens'] + '*')
    return lines


def _finding_bullet(rep, finding, lang):
    """One finding as a bullet: what it is, where it sits, what to do and
    its id for the explain and fix modes."""
    s = STRINGS[lang]
    line = '- ' + plain_title(rep, finding, lang)
    spot = plain_where(rep, finding, lang)
    if spot:
        line += ': ' + spot if lang == 'ru' else ' (' + spot + ')'
    action = plain_action(finding, lang)
    if action:
        if lang == 'ru':
            action = action[0].lower() + action[1:]
        line += '. %s: %s' % (s['what_to_do'], action)
    fid = str(finding.get('fid', '?'))
    return line + (' ' if line.endswith('.') else '. ') + '(%s)' % fid


def _wrong_section(rep, lang):
    """Every finding that needs a look: what it is, where it sits, what to
    do about it. The most serious come first; a long tail is counted."""
    s = STRINGS[lang]
    lines = ['## ' + s['h_wrong'], '']
    own = _own_open_findings(rep)
    plugins = [f for f in _sorted_open_findings(rep)
               if summary.scope(f, rep) == 2]
    if not own and not plugins:
        lines.append(s['wrong_none'])
        return lines
    # at most three lines of one kind: five equal "dead link in AGENTS.md"
    # lines say less than three and a count
    head, rest, per_kind = [], [], {}
    for f in own:
        kind = f.get('check_id') or f.get('title')
        if len(head) < MAX_WRONG_BULLETS \
                and per_kind.get(kind, 0) < MAX_SAME_KIND:
            per_kind[kind] = per_kind.get(kind, 0) + 1
            head.append(f)
        else:
            rest.append(f)
    for f in head:
        lines.append(_finding_bullet(rep, f, lang))
    if rest:
        counts = {}
        for f in rest:
            name = plain_title(rep, f, lang)
            counts[name] = counts.get(name, 0) + 1
        listing = '; '.join('%s x%d' % (name, n) for name, n in
                            sorted(counts.items(), key=lambda kv: -kv[1]))
        lines.append(s['rest_line'].format(n=len(rest), list=listing))
    if plugins:
        # files of installed plugins: not the user's, one line in all
        counts = {}
        for f in plugins:
            name = plain_title(rep, f, lang)
            counts[name] = counts.get(name, 0) + 1
        listing = '; '.join('%s x%d' % (name, n) for name, n in
                            sorted(counts.items(), key=lambda kv: -kv[1])[:6])
        extra = {'n_word': '%d findings' % len(plugins)}
        if lang == 'ru':
            extra = {'n_word': _ru_plural(len(plugins), 'находка', 'находки',
                                          'находок')}
        lines.append(s['plugins_line'].format(n=len(plugins), list=listing,
                                              **extra))
    return lines


def _not_checked_section(rep, lang):
    """Every check that could not run, each with the reason the scan
    recorded for it. Empty when every check ran."""
    s = STRINGS[lang]
    unchecked = _unchecked_gates(rep)
    parts = _unchecked_findings(rep)
    if not unchecked and not parts:
        return []
    lines = ['## ' + s['h_not_checked'], '']
    for g in unchecked:
        reason = (glossary.reason_text(g.get('status_why'), lang,
                                       g.get('status_count'))
                  or g.get('status_reason') or s['not_checked_no_reason'])
        lines.append('- ' + s['not_checked_item'].format(
            gate=glossary.gate_name(g.get('gid'), lang), reason=reason))
    # checks that could not run inside a red or yellow gate
    for f in parts[:MAX_UNCHECKED_FINDINGS]:
        lines.append(_finding_bullet(rep, f, lang))
    if len(parts) > MAX_UNCHECKED_FINDINGS:
        lines.append(s['not_checked_rest'].format(
            n=len(parts) - MAX_UNCHECKED_FINDINGS))
    return lines


def _improve_section(rep, lang, sessions_per_day):
    """What can be made better even where nothing is broken: extra tokens
    at every start, memory the agent cannot see, junk, duplicates, large
    files without a backup, repeated instruction text. Empty when the
    workspace has nothing of the kind."""
    s = STRINGS[lang]
    tips = []
    overhead = session_overhead_bytes(rep)
    if overhead > 0:
        _lo, mid, _hi = token_range(overhead)
        tips.append(s['improve_tokens'].format(mid=fmt_int(mid, lang)))
    if memory_over_bytes(rep) > 0:
        tips.append(s['improve_memory'])
    if junk_bytes(rep) >= TIP_MIN_BYTES:
        tips.append(s['improve_junk'].format(size=human_bytes(junk_bytes(rep), lang)))
    if duplicates_bytes(rep) >= TIP_MIN_BYTES:
        tips.append(s['improve_dup'].format(size=human_bytes(duplicates_bytes(rep), lang)))
    if large_files_bytes(rep):
        tips.append(s['improve_large'].format(size=human_bytes(large_files_bytes(rep), lang)))
    folder_repo = summary.root_repo(rep)
    if folder_repo is not None \
            and (folder_repo.get('extra') or {}).get('tool_dir_ignored') is False:
        # the reports of this tool hold paths of the machine
        tips.append(s['improve_tool_dir'])
    repeats = sum(1 for f in rep.get('findings_detailed') or []
                  if f.get('check_id') == 'INSTR_DUPLICATION')
    if repeats:
        tips.append(s['improve_repeats'].format(n=repeats))
    cq = rep.get('content_quality') or {}
    if cq:
        # one line per instruction file worth a look: a hint for a
        # pointer-sized file, a note for one between 30% and 50% rules.
        # A file that already has its finding line is not repeated here.
        noise_files = {
            str((f.get('evidence') or [{}])[0].get('file'))
            for f in rep.get('findings_detailed') or []
            if f.get('check_id') == 'RUL_MOSTLY_NOISE'}
        cq_tips = []
        for path, analysis in sorted(cq.items()):
            ratio = analysis.get('signal_ratio', 1.0)
            if ratio >= 0.5:
                continue
            if gates.is_short_instruction(analysis):
                cq_tips.append(s['cq_short_hint'].format(file=path))
            elif str(path) not in noise_files:
                cq_tips.append(s['plain_cq_noise'].format(
                    file=path, pct=int(round(ratio * 100))) + '.')
        tips.extend(cq_tips[:2])
    if not tips:
        return []
    return ['## ' + s['h_improve'], ''] + ['- ' + t for t in tips]


def _has_junk_to_clean(rep):
    return bool(junk_bytes(rep) or duplicates_bytes(rep)
                or rep.get('junk_classified'))


def _next_section(rep, lang):
    """Where to start: the first things to do, taken from the findings
    themselves (most serious first), then the generic follow-ups. The
    cleanup wizard is suggested only when there is junk to clean."""
    s = STRINGS[lang]
    lines = ['## ' + s['h_next'], '']
    # one step per advice, naming every place it applies to
    steps = []
    for f in _own_open_findings(rep):
        if f.get('status') not in OPEN_STATUSES:
            continue
        action = plain_action(f, lang)
        if not action:
            continue
        spot = plain_where(rep, f, lang)
        same = next((x for x in steps if x[0] == action), None)
        if same is not None:
            if spot and spot not in same[1] and len(same[1]) < MAX_TODO + 1:
                same[1].append(spot)
            continue
        if len(steps) >= MAX_TODO:
            break
        steps.append((action, [spot] if spot else []))
    if steps:
        lines.append(s['start_here'])
        for i, (action, spots) in enumerate(steps, 1):
            lines.append('%d. %s%s' % (i, action,
                                       ' (%s)' % '; '.join(spots) if spots else ''))
        lines.append('')
        lines.append(s['then'])
    if _has_junk_to_clean(rep):
        lines.append('- ' + s['clean_only_if'])
    lines.append('- ' + s['next_2'])
    lines.append('- ' + s['next_3'])
    return lines


def _better_section(rep, after, lang):
    s = STRINGS[lang]
    lines = ['## ' + s['h_better'], '']
    f1, w1 = gate_counts(rep)
    f2, w2 = gate_counts(after)
    lines.append('- ' + s['better_gates'].format(
        f1=f1, f2=f2, w1=w1, w2=w2))
    pb = project_instruction_bytes(rep)
    pa = project_instruction_bytes(after)
    if pb != pa:
        saved = max(0, tokens_from_bytes(pb - pa))
        lines.append('- ' + s['better_slim'].format(
            x=human_bytes(pb, lang), y=human_bytes(pa, lang),
            z=fmt_int(saved, lang)))
    tb = tokens_from_bytes(session_overhead_bytes(rep))
    ta = tokens_from_bytes(session_overhead_bytes(after))
    lines.append('- ' + s['better_tokens'].format(
        a=fmt_int(tb, lang), b=fmt_int(ta, lang)))
    jb = junk_bytes(rep)
    ja = junk_bytes(after)
    if jb or ja:
        lines.append('- ' + s['better_junk'].format(
            a=human_bytes(jb, lang), b=human_bytes(ja, lang)))
    sb = open_secret_count(rep)
    sa = open_secret_count(after)
    if sb or sa:
        if sa == 0:
            lines.append('- ' + s['better_secrets_zero'].format(a=sb))
        else:
            lines.append('- ' + s['better_secrets'].format(a=sb, b=sa))
    todo = [GID_PLAIN[g.get('gid')][lang]
            for g in after.get('gates') or []
            if g.get('status') == 'fail' and g.get('gid') in GID_PLAIN]
    if todo:
        lines.append('')
        lines.append(s['still_todo'])
        for item in todo[:MAX_TODO]:
            lines.append('- ' + item)
    return lines


# --------------------------------------------------------------------------
# assembly
# --------------------------------------------------------------------------

def generate_human_markdown(rep, lang='en', sessions_per_day=10, after=None):
    """Render one scan report (dict) as plain-language markdown.

    lang: 'en' or 'ru'. sessions_per_day feeds the monthly estimate and
    is always printed next to it. after: an optional second scan dict
    (made after cleanup) that adds the before/after section.

    Order: the short version (with the most serious problem first), the
    cost, what is wrong (each finding with its place and what to do),
    what could not be checked (only when some check could not run),
    what can be made better, then where to start.
    """
    if lang not in STRINGS:
        raise ValueError(f'unsupported lang: {lang!r}')
    s = STRINGS[lang]
    folder = summary.base_name(rep.get('root') or '.')
    out = ['# ' + s['title'], '',
           s['subtitle'].format(root=folder), '']
    out.extend(_short_version(rep, lang))
    out.append('')
    out.extend(_costs_section(rep, lang, sessions_per_day))
    out.append('')
    out.extend(_wrong_section(rep, lang))
    out.append('')
    not_checked = _not_checked_section(rep, lang)
    if not_checked:
        out.extend(not_checked)
        out.append('')
    improve = _improve_section(rep, lang, sessions_per_day)
    if improve:
        out.extend(improve)
        out.append('')
    if after is not None:
        out.extend(_better_section(rep, after, lang))
        out.append('')
    out.extend(_next_section(rep, lang))
    out.append('')
    out.append('---')
    out.append('')
    out.append(s['footer'].format(ts=rep.get('generated_at', '?')))
    out.append('')
    return '\n'.join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description='render scan.json as a plain-language report (EN/RU)')
    ap.add_argument('scan', help='scan.json produced by audit_scan.py')
    ap.add_argument('--lang', choices=['en', 'ru'], default='en',
                    help='output language (default: en)')
    ap.add_argument('--sessions', type=int,
                    default=DEFAULT_SESSIONS_PER_DAY,
                    help='agent sessions per day for the monthly estimate '
                         f'(default: {DEFAULT_SESSIONS_PER_DAY})')
    ap.add_argument('--after', default=None,
                    help='second scan.json made after cleanup; adds the '
                         'before/after section')
    ap.add_argument('--out', default=None,
                    help='write the markdown here instead of stdout')
    a = ap.parse_args(argv)
    try:
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        rep = json.loads(Path(a.scan).read_text(encoding='utf-8'))
        after = None
        if a.after:
            after = json.loads(Path(a.after).read_text(encoding='utf-8'))
    except (OSError, ValueError) as e:
        sys.exit(f'cannot read report: {e}')
    md = generate_human_markdown(rep, lang=a.lang,
                                 sessions_per_day=a.sessions, after=after)
    if a.out:
        Path(a.out).write_text(md, encoding='utf-8')
        print(f'wrote {a.out}')
    else:
        print(md, end='')
    return 0


if __name__ == '__main__':
    sys.exit(main())
