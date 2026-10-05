"""Deterministic security gate and pattern filter for Instinct Mail.

Validates incoming research responses and outgoing messages against prompt
injections, secret leaks, and command execution attempts using standard library.
"""
from __future__ import annotations

import re
import unicodedata

# Maximum length for scanned text before truncation
MAX_SCAN_CHARS = 50000

# Invisible and control characters (excluding standard whitespace \t, \n, \r)
_INVISIBLE_RE = re.compile(
    r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff\u00ad\u034f\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]"
)

# Role markers and system prompt overrides (English & Russian)
_ROLE_MARKERS = [
    re.compile(r"(?i)\b(?:system\s+prompt|developer\s+mode|administrative\s+override|authorized\s+directive|roleplay\s+mode)\b"),
    re.compile(r"(?i)\b(?:системный\s+промпт|режим\s+разработчика|административная\s+директива|команда\s+системы)\b"),
    re.compile(r"(?i)\b(?:you\s+are\s+now|act\s+as\s+(?:an?|the)\b|pretend\s+to\s+be\b)"),
    re.compile(r"(?i)\b(?:теперь\s+ты|действуй\s+как|притворись\b)"),
]

# Override patterns: prompt resets, commands, exfiltration, shell pipes, base64
_OVERRIDE_PATTERNS = [
    re.compile(r"(?i)\b(?:ignore|disregard|forget|bypass)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|prompts|rules|commands|context)\b"),
    re.compile(r"(?i)\b(?:игнорируй|забудь|сбрось|отмени)\s+(?:все\s+)?(?:предыдущие|прошлые|ранние)\s+(?:инструкции|указания|правила|команды|промпты)\b"),
    re.compile(r"(?i)\b(?:execute\s+command|run\s+(?:bash|sh|cmd|powershell)|system\s+call)\b"),
    re.compile(r"(?i)\b(?:выполни\s+команду|запусти\s+(?:bash|терминал|командную\s+строку)|выполни\s+скрипт)\b"),
    re.compile(r"(?i)\b(?:read\s+(?:the\s+)?file|read\s+contents\s+of|cat\s+/)\b"),
    re.compile(r"(?i)\b(?:прочитай\s+файл|выведи\s+(?:содержимое\s+файла|файл)|открой\s+файл)\b"),
    re.compile(r"(?i)\b(?:send|exfiltrate|leak|upload|post)\s+(?:the\s+)?(?:token|api[_-]?key|password|credential|secret|env|environment)\b"),
    re.compile(r"(?i)\b(?:отправь|передай|слей|выгрузи)\s+(?:токен|пароль|секрет|ключ|api[_-]?key|переменные\s+окружения|\.env)\b"),
    re.compile(r"(?i)(?:curl|wget)\s+[^|\n\r]+\|\s*(?:bash|sh|zsh)"),
    re.compile(r"(?i)(?:bash|sh|zsh)\s*<\s*\(\s*(?:curl|wget)"),
    re.compile(r"(?i)\b(?:base64\s+-d|echo\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64)\b"),
]

# Outbound patterns to prevent secret leakage
_OUTBOUND_SECRET_PATTERNS = [
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("google_key", re.compile(r"\bAIza[0-9A-Za-z-_]{35}\b")),
    ("github_pat", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{36,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("generic_secret", re.compile(r"(?i)\b(?:bearer\s+[A-Za-z0-9._~+/-]{20,}|(?:api[_-]?key|secret[_-]?key|app[_-]?password)\s*[:=]\s*['\"]?[A-Za-z0-9_\-.~+/@]{8,}['\"]?)")),
    ("markdown_image_exfil", re.compile(r"!\[.*?\]\(https?://[^\s)]+?[?&](?:token|key|secret|data)=[^\s)]+\)")),
    ("pipe_shell", re.compile(r"(?i)(?:curl|wget)\s+[^|\n]+\|\s*(?:bash|sh)")),
]


def has_inbound_attack_signal(result: dict) -> bool:
    """Return True if the scan verdict contains any inbound attack flags or is blocked."""
    if not isinstance(result, dict):
        return False
    if result.get("blocked", False):
        return True
    return any(flag.split("=", 1)[0] in ("role-markers", "overrides", "invisible-flood") for flag in result.get("flags", []))


def sanitize_inbound(input_text: str, max_chars: int = MAX_SCAN_CHARS, options: dict | None = None, *, trace=None) -> dict:
    """Scan and sanitize incoming message body."""
    raw = input_text or ""
    normalized = unicodedata.normalize("NFKC", raw)

    invisibles_found = len(_INVISIBLE_RE.findall(normalized))
    cleaned = _INVISIBLE_RE.sub("", normalized)

    flags: list[str] = []
    if invisibles_found:
        flags.append(f"invisible={invisibles_found}")

    original_len = len(raw)
    if original_len > 100 and invisibles_found > original_len * 0.05:
        verdict = {
            "text": cleaned[:max_chars],
            "truncatedChars": max(0, len(cleaned) - max_chars),
            "blocked": True,
            "reason": f"Excessive invisible characters: {invisibles_found}",
            "flags": flags + ["invisible-flood"],
        }
        if trace:
            trace("web", verdict, original_len)
        return verdict

    role_matches = sum(1 for pattern in _ROLE_MARKERS if pattern.search(cleaned))
    override_matches = sum(1 for pattern in _OVERRIDE_PATTERNS if pattern.search(cleaned))

    if role_matches:
        flags.append(f"role-markers={role_matches}")
    if override_matches:
        flags.append(f"overrides={override_matches}")

    is_blocked = override_matches >= 1 or role_matches >= 2
    reason = f"Prompt injection: {role_matches} role markers, {override_matches} override attempts" if is_blocked else "clean"

    truncated_chars = max(0, len(cleaned) - max_chars)
    text_capped = cleaned[:max_chars]

    verdict = {
        "text": text_capped,
        "truncatedChars": truncated_chars,
        "blocked": is_blocked,
        "reason": reason,
        "flags": flags,
    }
    if trace:
        trace("web", verdict, original_len)
    return verdict


def scan_outbound(input_text: str, redact: bool = True) -> dict:
    """Scan outgoing text for leaked credentials or injection artifacts."""
    text = input_text or ""
    findings: list[dict] = []

    for name, pattern in _OUTBOUND_SECRET_PATTERNS:
        for match in pattern.finditer(text):
            val = match.group(0)
            kind = "injection_artifact" if name == "pipe_shell" else "api_key"
            preview = val[:12] + "…" if len(val) > 12 else val
            findings.append({"type": kind, "name": name, "preview": preview})
            if redact and kind != "injection_artifact":
                text = text.replace(val, "[REDACTED]")

    is_clean = not any(f["type"] == "api_key" for f in findings)
    return {
        "clean": is_clean,
        "text": text,
        "findings": findings,
    }
