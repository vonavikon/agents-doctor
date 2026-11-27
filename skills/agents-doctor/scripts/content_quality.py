#!/usr/bin/env python3
"""Content-quality analysis for agent instruction files (AGENTS.md, CLAUDE.md).

The structural scanner (audit_scan.py) checks file health: dead links, twin
drift, size against the 16 KB benchmark, chain budget against 32 KB. It does
not ask whether the words inside are worth the context they cost. This module
covers that half.

The filter behind every metric is the two-question test from Anthropic's
writing about agent instructions:

    1. Could the agent find this information by reading the code?
    2. Would it actually go and look?

If both answers are yes, the line is unnecessary: it restates what the
repository already shows and what the agent would discover anyway, so it only
burns context budget. Lines that fail the test -- narrative, description,
decoration -- are noise. Lines that pass -- imperatives, paths, commands,
constraints the agent could not guess -- are signal.

All metrics are deterministic pattern matching: no LLM, no I/O.
analyze_content() is a pure function over the raw file text, so the scanner
can call it and merge the report into its findings. Staleness (when the file
last matched reality) needs git history and stays a placeholder here; the
caller fills it in when git metadata is available.

Usage:
    from content_quality import analyze_content, quality_summary
    report = analyze_content(text, 'AGENTS.md')
    verdict = quality_summary(report)  # {'overall': ..., 'headline': ..., ...}
"""
import re

__all__ = ['analyze_content', 'quality_summary']

# --- thresholds ----------------------------------------------------------------
REDUNDANT_SIMILARITY = 0.70   # word overlap at which two rules are duplicates
CONTRADICTION_OVERLAP = 0.50  # word overlap at which two directives share a topic
MAX_REDUNDANT_PAIRS = 5       # report cap; redundant_total keeps the real count
OVERLONG_LINE_CHARS = 200     # instruction lines over this are hard to follow

# Words with no discriminating power: dropped before all overlap math.
# Without this, "run the tests before you commit" and "commit directly to main"
# would share "to"/"the" and look related.
STOPWORDS = frozenset('''
a an the to of in on at by for and or with without you your it this that
these those is are be been as from into over under not no
'''.split())

# --- line classification --------------------------------------------------------
_IMPERATIVE_RX = re.compile(
    r"(?i)\b(?:use|don'?t|do not|never|always|must|should|avoid|prefer|"
    r"run|execute|check|verify|ensure)\b")
_CONSTRAINT_RX = re.compile(r'(?i)\b(?:must not|required|forbidden)\b')
_BACKTICK_RX = re.compile(r'`[^`]+`')
_FENCE_RX = re.compile(r'^\s*(?:```|~~~)')
_HEADING_RX = re.compile(r'^\s*#')
_FORMAT_ONLY_RX = re.compile(r'^[|\-:=\s*_#+>]+$')
_LIST_MARKER_RX = re.compile(r'^(?:>\s*)?(?:[-*+]\s+|\d+[.)]\s+)+')

# Generic advice that fits any project: fails both questions of the test above.
_GENERIC_RX = re.compile(
    r"(?i)(write (?:good|clean|quality) code|follow best practices|"
    r"maintain (?:high )?quality|be (?:careful|thorough|consistent)|"
    r"ensure correctness|use proper naming|"
    r"keep (?:it|code) (?:clean|simple|organized)|don'?t reinvent|"
    r"avoid (?:unnecessary )?complexity|"
    r"write (?:clear|concise|readable) (?:code|documentation)|"
    r"test (?:your|all) (?:code|changes)|commit (?:often|regularly)|"
    r"document (?:your|all) (?:code|changes))")

# Directives for contradiction detection: a "do" polarity and a "don't" one.
# Negative matches are masked out of the line before positive matches run, so
# "never use spaces" yields only a negative directive, not a positive "use".
_POSITIVE_RX = re.compile(r"(?i)\b(?:always|use|must|should|prefer)\s+(?!not\b)(.+)")
_NEGATIVE_RX = re.compile(r"(?i)\b(?:must not|never|don'?t|do not|avoid)\s+(.+)")

# Imperative lead for the vague-instruction scan: a directive verb opening
# the sentence (after an optional softener). Broader than _IMPERATIVE_RX on
# purpose: "handle errors properly" or "be careful with security" instruct
# without containing any of the signal verbs, yet they are still orders.
_IMPERATIVE_LEAD_RX = re.compile(
    r"(?i)^(?:please\s+|always\s+|never\s+)?(?:"
    r"don'?t|do not|use|must|should|avoid|prefer|run|execute|check|verify|"
    r"ensure|be|handle|keep|make|write|follow|test|commit|document|review|"
    r"update|add|remove|delete|create|install|configure|set|build|deploy|"
    r"merge|push|pull|fix|refactor|improve|maintain|pay|treat|consider|"
    r"remember|mind|watch)\b")

# Concrete references: paths, commands, URLs, versions, tool names.
_SPECIFIC_RX = re.compile(
    r'(?i)(/|\.py\b|\.js\b|\.md\b|http|\bnpm\b|\bpip\b|\bgit\b|\d+\.\d+)')

_WORD_RX = re.compile(r'\w+', re.UNICODE)


def _normalize(line):
    """Lowercase, strip punctuation, collapse whitespace."""
    return ' '.join(_WORD_RX.findall(line.lower()))


def _content_words(normalized):
    """Word set of a normalized line with stopwords removed."""
    return {w for w in normalized.split() if w not in STOPWORDS}


def _is_signal(core):
    """True if the line carries an actionable instruction.

    Signal: an imperative verb, a path/command in backticks, a hard
    constraint, or a bulleted/numbered instruction (list markers are
    stripped before this check, so the criteria apply to the core text).
    """
    if _BACKTICK_RX.search(core):
        return True
    if _CONSTRAINT_RX.search(core):
        return True
    return bool(_IMPERATIVE_RX.search(core))


def _is_specific(core):
    """True if the line names something concrete the agent can act on."""
    if _BACKTICK_RX.search(core):
        return True
    return bool(_SPECIFIC_RX.search(core))


def _classify(text):
    """Split text into classified lines: blank/fence/code/heading/formatting/
    signal/noise. Pure string work; no I/O."""
    lines = []
    in_fence = False
    for num, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not stripped:
            lines.append({'num': num, 'raw': raw, 'kind': 'blank'})
            continue
        if _FENCE_RX.match(raw):
            in_fence = not in_fence
            lines.append({'num': num, 'raw': raw, 'kind': 'fence'})
            continue
        if in_fence:
            lines.append({'num': num, 'raw': raw, 'kind': 'code'})
            continue
        if _HEADING_RX.match(raw):
            lines.append({'num': num, 'raw': raw, 'kind': 'heading'})
            continue
        if _FORMAT_ONLY_RX.match(stripped):
            lines.append({'num': num, 'raw': raw, 'kind': 'formatting'})
            continue
        core = _LIST_MARKER_RX.sub('', stripped).strip()
        kind = 'signal' if _is_signal(core) else 'noise'
        lines.append({'num': num, 'raw': raw, 'kind': kind})
    return lines


def _generic_scan(lines):
    """Find advice that could sit in any project's instructions unchanged."""
    found = []
    for entry in lines:
        if entry['kind'] in ('blank', 'fence', 'code'):
            continue
        for m in _GENERIC_RX.finditer(entry['raw']):
            found.append({'line': entry['num'], 'phrase': m.group(0),
                          'position': m.start()})
    return found


def _redundancy(signal_lines):
    """Near-duplicate rules. Exact repeats (similarity 1.0) come first, then
    pairs of unique forms with high word overlap. Overlap is the larger of
    Jaccard and |A and B| / min(|A|, |B|): a pair of near-duplicate rules
    can score 0.57 on plain Jaccard but 0.80 on the overlap coefficient,
    so either measure crossing the threshold marks the pair redundant.
    Returns (capped list, total count)."""
    forms = {}
    order = []
    for entry in signal_lines:
        norm = _normalize(entry['raw'])
        if not norm:
            continue
        if norm in forms:
            forms[norm]['count'] += 1
        else:
            forms[norm] = {'text': entry['raw'].strip(), 'count': 1}
            order.append(norm)

    pairs = []
    for norm in order:
        if forms[norm]['count'] > 1:
            pairs.append({'line_1': forms[norm]['text'],
                          'line_2': forms[norm]['text'],
                          'similarity': 1.0})

    items = [(norm, forms[norm]['text']) for norm in order]
    for i in range(len(items)):
        words_a = _content_words(items[i][0])
        if not words_a:
            continue
        for j in range(i + 1, len(items)):
            words_b = _content_words(items[j][0])
            if not words_b:
                continue
            shared = words_a & words_b
            jaccard = len(shared) / len(words_a | words_b)
            overlap = len(shared) / min(len(words_a), len(words_b))
            best = max(jaccard, overlap)
            if best >= REDUNDANT_SIMILARITY:
                pairs.append({'line_1': items[i][1], 'line_2': items[j][1],
                              'similarity': round(best, 3)})

    pairs.sort(key=lambda p: p['similarity'], reverse=True)
    return pairs[:MAX_REDUNDANT_PAIRS], len(pairs)


def _clean_topic(obj):
    """Directive object -> readable topic: no backticks, no trailing dots."""
    topic = ' '.join(obj.replace('`', ' ').split())
    return topic.rstrip('.,;:! ').lower()


def _find_directives(lines):
    """Per line: negative directives first, their spans masked out, then
    positive directives on the rest. Returns (positives, negatives) where each
    item is (line_entry, topic)."""
    positives, negatives = [], []
    for entry in lines:
        if entry['kind'] in ('blank', 'fence', 'code'):
            continue
        raw = entry['raw']
        masked = raw
        spans = []
        for m in _NEGATIVE_RX.finditer(raw):
            negatives.append((entry, _clean_topic(m.group(1))))
            spans.append((m.start(), m.end()))
        for start, end in spans:
            masked = masked[:start] + ' ' * (end - start) + masked[end:]
        for m in _POSITIVE_RX.finditer(masked):
            positives.append((entry, _clean_topic(m.group(1))))
    return positives, negatives


def _contradictions(lines):
    """A 'do' directive and a 'don't' directive about the same object.
    Topic overlap >= CONTRADICTION_OVERLAP on content words (stopwords
    removed, so shared 'the'/'to' never fabricates a conflict)."""
    positives, negatives = _find_directives(lines)
    found = []
    seen = set()
    for pos_entry, pos_topic in positives:
        pos_words = _content_words(_normalize(pos_topic))
        if not pos_words:
            continue
        for neg_entry, neg_topic in negatives:
            if neg_entry['num'] == pos_entry['num']:
                continue
            neg_words = _content_words(_normalize(neg_topic))
            if not neg_words:
                continue
            shared = pos_words & neg_words
            overlap = len(shared) / min(len(pos_words), len(neg_words))
            if overlap < CONTRADICTION_OVERLAP:
                continue
            key = (pos_entry['num'], neg_entry['num'], _normalize(pos_topic))
            if key in seen:
                continue
            seen.add(key)
            found.append({'line_a': pos_entry['raw'].strip(),
                          'line_b': neg_entry['raw'].strip(),
                          'topic': pos_topic})
    return found


def _vague_scan(lines):
    """Directives that order something the agent cannot act on: an
    imperative verb opening the line plus an object with no path, no
    command, no concrete file ("be careful with security", "handle errors
    properly"). The object test is _is_specific on the whole core, so a
    backticked command or a named path keeps the line out of this bucket.
    Headings, code and fences are skipped; list markers are stripped."""
    found = []
    for entry in lines:
        if entry['kind'] in ('blank', 'fence', 'code', 'heading', 'formatting'):
            continue
        core = _LIST_MARKER_RX.sub('', entry['raw'].strip()).strip()
        if not core or not _IMPERATIVE_LEAD_RX.match(core):
            continue
        if _is_specific(core):
            continue
        found.append({'line': entry['num'], 'text': entry['raw'].strip()})
    return found


def _obsolete_scan(lines, dead_refs):
    """Lines referencing files or commands the scanner proved absent from
    the current workspace (dead paths, dead link targets, dead npm/make
    targets). dead_refs comes from the caller's structural scan; each
    (line, ref) pair is reported once, so a markdown link whose text and
    target name the same dead file yields one record."""
    found = []
    for ref in dead_refs or []:
        for entry in lines:
            if entry['kind'] == 'blank':
                continue
            if ref in entry['raw']:
                found.append({'line': entry['num'], 'ref': ref,
                              'text': entry['raw'].strip()})
    return found


def _overlong_scan(lines):
    """Instruction lines over OVERLONG_LINE_CHARS: too long to follow in
    one pass, candidates for splitting. Code inside fences is data, not an
    instruction, and is left alone."""
    found = []
    for entry in lines:
        if entry['kind'] in ('blank', 'code'):
            continue
        if len(entry['raw']) > OVERLONG_LINE_CHARS:
            found.append({'line': entry['num'], 'length': len(entry['raw'])})
    return found


def analyze_content(text, filepath='', dead_refs=None):
    """Pure content-quality analysis of one instruction file's raw text.

    Returns a report dict with one key per dimension:
    signal_ratio, generic_phrases/generic_count, instruction_density,
    redundant_pairs (capped at MAX_REDUNDANT_PAIRS) + redundant_total,
    contradictions, specificity, vague_instructions/vague_count,
    obsolete_hints/obsolete_count, overlong_lines/overlong_count, and a
    staleness_hint placeholder the caller fills from git history.

    dead_refs lists files, link targets and commands the structural scan
    proved absent from the current workspace; lines naming them are
    reported as obsolete hints. None (the default) skips that dimension.
    No I/O, no exceptions on odd input.
    """
    size_bytes = len(text.encode('utf-8'))
    lines = _classify(text)
    signal_lines = [l for l in lines if l['kind'] == 'signal']
    non_blank = [l for l in lines if l['kind'] != 'blank']

    signal_ratio = (len(signal_lines) / len(non_blank)) if non_blank else 0.0

    generic_phrases = _generic_scan(lines)

    unique_rules = len({_normalize(l['raw']) for l in signal_lines} - {''})
    kb = size_bytes / 1024
    instruction_density = round(unique_rules / kb, 3) if kb > 0 else 0.0

    redundant_pairs, redundant_total = _redundancy(signal_lines)
    contradictions = _contradictions(lines)

    specific_count = sum(1 for l in signal_lines if _is_specific(l['raw']))
    specificity = (specific_count / len(signal_lines)) if signal_lines else 0.0

    vague_instructions = _vague_scan(lines)
    obsolete_hints = _obsolete_scan(lines, dead_refs)
    overlong_lines = _overlong_scan(lines)

    return {
        'filepath': filepath,
        'size_bytes': size_bytes,
        'total_lines': len(lines),
        'non_blank_lines': len(non_blank),
        'signal_lines': len(signal_lines),
        'noise_lines': len(non_blank) - len(signal_lines),
        'signal_ratio': round(signal_ratio, 3),
        'generic_phrases': generic_phrases,
        'generic_count': len(generic_phrases),
        'unique_rules': unique_rules,
        'instruction_density': instruction_density,
        'redundant_pairs': redundant_pairs,
        'redundant_total': redundant_total,
        'contradictions': contradictions,
        'specificity': round(specificity, 3),
        'vague_instructions': vague_instructions,
        'vague_count': len(vague_instructions),
        'obsolete_hints': obsolete_hints,
        'obsolete_count': len(obsolete_hints),
        'overlong_lines': overlong_lines,
        'overlong_count': len(overlong_lines),
        'staleness_hint': {'computable': False,
                           'reason': 'requires git history'},
    }


def quality_summary(analysis):
    """Human-readable verdict from an analyze_content() report.

    Verdicts, in threshold order:
    excellent  signal_ratio > 0.7 and generic_count < 3
    good       signal_ratio > 0.5 and generic_count < 8
    noisy      signal_ratio > 0.3
    bloated    instruction_density < 0.3
    mostly-noise  everything else
    """
    ratio = analysis.get('signal_ratio', 0.0)
    generic_count = analysis.get('generic_count', 0)
    density = analysis.get('instruction_density', 0.0)
    unique_rules = analysis.get('unique_rules', 0)
    size_kb = analysis.get('size_bytes', 0) / 1024

    if ratio > 0.7 and generic_count < 3:
        overall = 'excellent'
    elif ratio > 0.5 and generic_count < 8:
        overall = 'good'
    elif ratio > 0.3:
        overall = 'noisy'
    elif density < 0.3:
        overall = 'bloated'
    else:
        overall = 'mostly-noise'

    pct = int(round(ratio * 100))
    if overall == 'excellent':
        headline = ('%d%% of non-blank lines are actionable rules and generic '
                    'advice is absent: the file earns its context budget.' % pct)
    elif overall == 'good':
        headline = ('%d%% of non-blank lines are actionable; %d generic '
                    'phrase(s) and narrative filler dilute the rest.'
                    % (pct, generic_count))
    elif overall == 'noisy':
        headline = ('Only %d%% of non-blank lines are actionable: the file '
                    'is mostly narrative.' % pct)
    elif overall == 'bloated':
        headline = ('%d unique rules in %.1f KB of text: little value per '
                    'byte, cut it down.' % (unique_rules, size_kb))
    else:
        headline = ('Only %d%% of lines are actionable: rewrite the file '
                    'around the rules that survive the two-question test.' % pct)

    def ratio_word(value):
        if value >= 0.7:
            return 'high: most lines are actionable rules'
        if value >= 0.5:
            return 'moderate: about half the lines instruct'
        if value >= 0.3:
            return 'low: mostly narrative'
        return 'very low: nearly all narrative'

    def generic_word(value):
        if value == 0:
            return 'none detected'
        if value < 3:
            return 'a few: trim if trivial'
        if value < 8:
            return 'several: could belong to any project'
        return 'many: boilerplate advice dominates'

    def density_word(value):
        if value >= 5:
            return 'concentrated: many rules per KB'
        if value >= 1:
            return 'moderate: reasonable value per KB'
        return 'sparse: little unique value per KB'

    def specific_word(value):
        if value >= 0.7:
            return 'most rules name concrete files or commands'
        if value >= 0.4:
            return 'mixed: some concrete references'
        return 'rules are mostly generic'

    redundant = len(analysis.get('redundant_pairs', []))
    contradicted = len(analysis.get('contradictions', []))
    vague_count = analysis.get('vague_count', 0)
    obsolete_count = analysis.get('obsolete_count', 0)
    overlong_count = analysis.get('overlong_count', 0)

    def vague_word(value):
        if value == 0:
            return 'none detected'
        if value < 3:
            return 'a few: directives without an actionable object'
        return 'many: orders the agent cannot act on'

    def obsolete_word(value):
        if value == 0:
            return 'none detected'
        return 'references files or commands absent from the workspace'

    def overlong_word(value):
        if value == 0:
            return 'none detected'
        return 'instruction lines over %d chars: split them' % OVERLONG_LINE_CHARS

    details = [
        ('signal_ratio', ratio, ratio_word(ratio)),
        ('generic_phrases', generic_count, generic_word(generic_count)),
        ('instruction_density', density, density_word(density)),
        ('specificity', analysis.get('specificity', 0.0),
         specific_word(analysis.get('specificity', 0.0))),
        ('redundant_pairs', redundant,
         'no near-duplicate rules' if redundant == 0
         else 'near-duplicate rules waste budget'),
        ('contradictions', contradicted,
         'none detected' if contradicted == 0
         else 'conflicting directives detected'),
        ('vague_instructions', vague_count, vague_word(vague_count)),
        ('obsolete_hints', obsolete_count, obsolete_word(obsolete_count)),
        ('overlong_instructions', overlong_count, overlong_word(overlong_count)),
    ]
    return {'overall': overall, 'headline': headline, 'details': details}
