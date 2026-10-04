"""IVA deterministic security gate, Python stdlib port.

Origin: smixs/iva-agent 817bd1e1d02a9774ab7fc335b4202029f87a6570
Copyright (c) 2026 smixs; MIT permission notice in LICENSE.iva-agent.
Tables contain original regex sources and reference Unicode properties/case maps.
No environment, credentials, network or disk writes. See README for mapping.
"""
from __future__ import annotations

import json
import math
import re
from pathlib import Path

_TABLES = json.loads(Path(__file__).with_name('security_gate_tables.json').read_text(encoding='utf-8'))
EXPENSIVE_SCRIPT_MAX_CHARS = 2000
_WS = '\\t\\n\\v\\f\\r \\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff'
_WORD = 'A-Za-z0-9_'


def _char(cp):
    return ('\\u%04x' if cp <= 0xffff else '\\U%08x') % cp


def _ranges_class(ranges):
    return '[' + ''.join(_char(a) + ('-' + _char(b) if a != b else '') for a, b in ranges) + ']'


_LETTER = _ranges_class(_TABLES['L'])
_INVISIBLE = re.compile(_ranges_class(_TABLES['Cf'] + _TABLES['Cc'] + [[0x034f, 0x034f]]))
_EXPENSIVE = re.compile('[\u0f00-\u0fff\ua000-\ua4cf\u2800-\u28ff\U0001d400-\U0001d7ff\U00010000-\U0001034f]')


def _units(text):
    raw = text.encode('utf-16-le', 'surrogatepass')
    return ''.join(chr(raw[i] | raw[i + 1] << 8) for i in range(0, len(raw), 2))


def _points(text):
    return text.encode('utf-16-le', 'surrogatepass').decode('utf-16-le', 'surrogatepass')


def _utf16_slice(text, count):
    return text.encode('utf-16-le', 'surrogatepass')[:count * 2].decode('utf-16-le', 'surrogatepass')


class _JSRegex:
    """Translate only the syntax used by this pinned module, not arbitrary JS regex.

    JS ASCII word/digit classes, whitespace, anchors, dot and case folding are
    explicit. Non-u expressions operate on UTF-16 units. Match offsets map back
    to the original text, so outbound previews/redaction never expose folded text.
    """
    def __init__(self, spec):
        self.unicode = 'u' in spec['flags']
        self.fold = _TABLES['fold_u' if self.unicode else 'fold_legacy'] if 'i' in spec['flags'] else {}
        source = spec['source']
        out = []
        i = 0
        while i < len(source):
            c = source[i]
            if c == '\\':
                if source.startswith(r'\p{L}', i):
                    out.append(_LETTER); i += 5; continue
                e = source[i + 1]; i += 2
                if e in 'sSdDwW':
                    body = {'s': _WS, 'd': '0-9', 'w': _WORD}[e.lower()]
                    out.append('[' + ('^' if e.isupper() else '') + body + ']')
                elif e == 'b':
                    w = '[' + _WORD + ']'
                    out.append('(?:(?<=' + w + ')(?!' + w + ')|(?<!' + w + ')(?=' + w + '))')
                else:
                    out.append('\\' + e if e != '/' else '/')
                continue
            if c == '[':
                end = i + 1
                while end < len(source):
                    if source[end] == '\\': end += 2; continue
                    if source[end] == ']': break
                    end += 1
                body = source[i + 1:end]
                negative = body.startswith('^')
                if negative: body = body[1:]
                # All source classes are BMP; expand their membership once to
                # canonical case representatives, retaining negation afterwards.
                if r'\S' in body:
                    raise ValueError('unsupported source class: \\S')
                body = body.replace(r'\s', _WS)
                body = body.replace(r'\d', '0-9').replace(r'\w', _WORD).replace(r'\/', '/')
                rx = re.compile('[' + body + ']')
                chars = {self.fold.get(chr(cp), chr(cp)) for cp in range(65536) if rx.fullmatch(chr(cp))}
                out.append('[' + ('^' if negative else '') + ''.join(_char(ord(x)) for x in sorted(chars)) + ']')
                i = end + 1; continue
            if c == '.': out.append('[^\\n\\r\\u2028\\u2029]')
            elif c == '^': out.append('(?:\\A|(?<=[\\n\\r\\u2028\\u2029]))' if 'm' in spec['flags'] else '\\A')
            elif c == '$': out.append('(?=\\Z|[\\n\\r\\u2028\\u2029])' if 'm' in spec['flags'] else '\\Z')
            elif c.isalpha(): out.append(re.escape(self.fold.get(c, c)))
            else: out.append(c)
            i += 1
        self.regex = re.compile(''.join(out))

    def matches(self, text):
        original = _points(text) if self.unicode else _units(text)
        probe = ''.join(self.fold.get(c, c) for c in original) if self.fold else original
        for match in self.regex.finditer(probe):
            yield _points(original[match.start():match.end()])

    def test(self, text):
        return next(self.matches(text), None) is not None


_EN_ROLE = _JSRegex(_TABLES['ENGLISH_ROLE_MARKER_RE'])
_WEB_ROLE = _JSRegex(_TABLES['MULTILINGUAL_ROLE_MARKER_RE'])
_EN_OVERRIDE = [_JSRegex(p) for p in _TABLES['ENGLISH_OVERRIDE_PATTERNS']]
_WEB_OVERRIDE = _EN_OVERRIDE + [_JSRegex(p) for name in ('RU_UZ_OVERRIDE_PATTERNS', 'WEB_INTENT_PATTERNS') for p in _TABLES[name]]
_GROUPS = [(kind, [(name, _JSRegex(p)) for name, p in _TABLES[key]]) for kind, key in (
    ('api_key', 'API_KEY_PATTERNS'), ('internal_path', 'INTERNAL_PATH_PATTERNS'),
    ('data_exfil', 'EXFIL_PATTERNS'), ('injection_artifact', 'INJECTION_ARTIFACTS'))]


def has_inbound_attack_signal(result):
    return result['blocked'] or any(flag.split('=', 1)[0] in ('role-markers', 'overrides') for flag in result['flags'])


def _cap(text, max_chars):
    return {'text': text[:max_chars], 'truncatedChars': max(0, len(text) - max_chars)}


def _lookalikes(text):
    return ''.join(_TABLES['LOOKALIKES'].get(c, c) for c in text), sum(c in _TABLES['LOOKALIKES'] for c in text)


def _nfkc(text):
    """Unicode 17 NFKC: reference decomposition/composition and UCD combining class.

    Python's bundled Unicode version may be older. Hangul follows UAX #15's
    algorithm; all other normalization data is pinned beside the regex tables.
    """
    decomposed = []
    for char in text:
        syllable = ord(char) - 0xac00
        if 0 <= syllable < 11172:
            parts = chr(0x1100 + syllable // 588) + chr(0x1161 + (syllable % 588) // 28)
            if syllable % 28:
                parts += chr(0x11a7 + syllable % 28)
        else:
            parts = _TABLES['nfkd'].get(char, char)
        decomposed.extend(parts)
    # Stable canonical ordering within each run of non-starters.
    ordered = []
    run = []
    for char in decomposed:
        if not _TABLES['ccc'].get(char, 0):
            ordered.extend(sorted(run, key=lambda c: _TABLES['ccc'][c]))
            run = []
            ordered.append(char)
        else:
            run.append(char)
    ordered.extend(sorted(run, key=lambda c: _TABLES['ccc'][c]))
    result = []
    starter = None
    last_class = 0
    for char in ordered:
        combining_class = _TABLES['ccc'].get(char, 0)
        composite = None
        if starter is not None:
            base = result[starter]
            l, v = ord(base) - 0x1100, ord(char) - 0x1161
            s, t = ord(base) - 0xac00, ord(char) - 0x11a7
            if 0 <= l < 19 and 0 <= v < 21:
                composite = chr(0xac00 + (l * 21 + v) * 28)
            elif 0 <= s < 11172 and s % 28 == 0 and 0 < t < 28:
                composite = chr(ord(base) + t)
            else:
                composite = _TABLES['compose'].get(base + char)
        if composite is not None and (last_class == 0 or last_class < combining_class):
            result[starter] = composite
        else:
            if combining_class == 0:
                starter = len(result)
            result.append(char)
            last_class = combining_class
    return ''.join(result)


def _judge_inbound(input, max_chars, options):
    if isinstance(max_chars, bool) or not isinstance(max_chars, (int, float)) or not 0 <= max_chars <= 2**53 - 1 or int(max_chars) != max_chars:
        raise ValueError('maxChars must be a non-negative safe integer')
    max_chars = int(max_chars)
    surface = options.get('surface')
    if surface is None:
        surface = 'telegram'
    if surface not in ('telegram', 'web'):
        raise ValueError('unknown inbound surface')
    web = surface == 'web'
    original_len = len(_units(input))
    input = _points(input)
    invisible_removed = 0
    def cleanup(match):
        nonlocal invisible_removed
        if match[0] in '\n\r\t': return match[0]
        invisible_removed += 1
        return ''
    text = _INVISIBLE.sub(cleanup, input)
    expensive_chars = expensive_dropped = 0
    def budget(match):
        nonlocal expensive_chars, expensive_dropped
        expensive_chars += 1
        if not web: return ''
        if expensive_chars <= EXPENSIVE_SCRIPT_MAX_CHARS: return match[0]
        expensive_dropped += 1
        return ''
    text = _EXPENSIVE.sub(budget, text)
    def blocked(reason, flag):
        payload = _cap(text, max_chars) if web else {'text': '', 'truncatedChars': 0}
        return {**payload, 'truncatedChars': payload['truncatedChars'] + expensive_dropped,
                'blocked': True, 'reason': reason, 'flags': [flag]}
    if original_len > 100 and invisible_removed > original_len * 0.05:
        return blocked(f'Excessive invisible characters: {invisible_removed} ({math.floor(invisible_removed * 100 / original_len)}%)', 'invisible-flood')
    flags = [f'invisible={invisible_removed}'] if invisible_removed else []
    if expensive_chars > 50:
        return blocked(f'Wallet drain attempt: {expensive_chars} expensive Unicode chars', 'wallet-drain')
    probe, normalized = _lookalikes(text)
    if normalized: flags.append(f'lookalikes={normalized}')
    views = {text, probe}
    if web:
        folded = _nfkc(text)
        views.update((folded, _lookalikes(folded)[0]))
    role = _WEB_ROLE if web else _EN_ROLE
    patterns = _WEB_OVERRIDE if web else _EN_OVERRIDE
    markers = max(sum(1 for _ in role.matches(view)) for view in views)
    overrides = sum(any(pattern.test(view) for view in views) for pattern in patterns)
    if markers: flags.append(f'role-markers={markers}')
    if overrides: flags.append(f'overrides={overrides}')
    is_blocked = (markers >= 2 and overrides >= 1) or overrides >= 3
    return {**_cap(text, max_chars), 'blocked': is_blocked,
            'reason': f'Prompt injection: {markers} role markers, {overrides} override attempts' if is_blocked else 'clean', 'flags': flags}


def sanitize_inbound(input, max_chars=50000, options=None, *, trace=None):
    """Original sanitizeInbound. Optional callback replaces IVA turn trace context."""
    options = options or {}
    verdict = _judge_inbound(input, max_chars, options)
    if trace is not None:
        trace('telegram' if options.get('surface') is None else options['surface'], verdict, len(_units(input)))
    return verdict


def scan_outbound(input, redact=True):
    """Original scanOutbound; findings inspect input, replacements modify a copy."""
    input = _points(input)
    text = input
    findings = []
    for kind, patterns in _GROUPS:
        for name, pattern in patterns:
            for match in pattern.matches(input):
                artifact = kind == 'injection_artifact'
                findings.append({'type': kind, 'name': name, 'preview': _utf16_slice(match, 20 if artifact else 12) + ('' if artifact else '…')})
                if redact and not artifact:
                    # JS split/join compares UTF-16 units, including lone surrogates.
                    text = _points(_units(text).replace(_units(match), '[REDACTED]'))
    return {'clean': all(f['type'] == 'injection_artifact' for f in findings), 'text': text, 'findings': findings}
