"""Individual guardrail checks.

Every check takes a string and returns a :class:`CheckResult`. Checks are
pure functions over text: no network calls, no model calls, no API keys.
They are deliberately heuristic — they catch the common, cheap-to-detect
failures so that expensive model-based moderation only has to handle the
hard cases. Each result explains *what* matched so a caller can redact,
block, or log with confidence instead of trusting a bare boolean.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class CheckResult:
    """The outcome of one check against one piece of text."""

    passed: bool
    check: str
    message: str = ""
    findings: tuple[str, ...] = ()
    redacted_text: str | None = None

    def __bool__(self) -> bool:
        return self.passed


# ---------------------------------------------------------------------------
# PII: email addresses, phone numbers, and credit-card-shaped numbers.
# ---------------------------------------------------------------------------

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE = re.compile(r"(?<![A-Za-z0-9])(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}(?![A-Za-z0-9])")
_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def _looks_like_card(match: str) -> bool:
    """Luhn check, so ordinary long digit strings are not flagged as cards."""
    digits = re.sub(r"\D", "", match)
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def pii_check(text: str) -> CheckResult:
    """Fail when the text contains email, phone, or card-shaped PII.

    ``redacted_text`` holds the input with each finding replaced by a
    placeholder, so a caller can *redact* instead of blocking outright.
    """
    findings: list[str] = []
    redacted = text
    for label, pattern in (("email", _EMAIL), ("phone", _PHONE)):
        for match in pattern.findall(text):
            findings.append(f"{label}: {match}")
            redacted = redacted.replace(match, f"[REDACTED {label.upper()}]")
    for match in _CARD.findall(text):
        if _looks_like_card(match):
            findings.append(f"credit_card: {match}")
            redacted = redacted.replace(match, "[REDACTED CARD]")
    if findings:
        return CheckResult(
            passed=False,
            check="pii",
            message=f"Found {len(findings)} PII item(s).",
            findings=tuple(findings),
            redacted_text=redacted,
        )
    return CheckResult(passed=True, check="pii", message="No PII detected.")


# ---------------------------------------------------------------------------
# Secrets: API keys and tokens in common formats.
# ---------------------------------------------------------------------------

_SECRET_PATTERNS = (
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("generic_api_key", re.compile(r"(?i)\b(?:api[_-]?key|secret|token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----")),
)


def secret_check(text: str) -> CheckResult:
    """Fail when the text looks like it contains a credential or secret."""
    findings = [
        f"{label}: {match.group(0)[:24]}..."
        for label, pattern in _SECRET_PATTERNS
        for match in pattern.finditer(text)
    ]
    if findings:
        return CheckResult(
            passed=False,
            check="secret",
            message=f"Found {len(findings)} secret-like pattern(s).",
            findings=tuple(findings),
        )
    return CheckResult(passed=True, check="secret", message="No secrets detected.")


# ---------------------------------------------------------------------------
# Prompt injection: instructions smuggled into untrusted input.
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS = (
    re.compile(r"(?i)\bignore (all )?(previous|prior|above) instructions\b"),
    re.compile(r"(?i)\bdisregard (your )?(system prompt|instructions)\b"),
    re.compile(r"(?i)\byou are now (a|an|in) \w+"),
    re.compile(r"(?i)\bnew (system )?instructions?:"),
    re.compile(r"(?i)\bdo not (tell|reveal|mention).*user\b"),
    re.compile(r"(?i)<\s*(system|instruction)\s*>"),
    re.compile(r"(?i)\bact as if you (have no|are not bound by)\b"),
)


def injection_check(text: str) -> CheckResult:
    """Fail when the text contains common prompt-injection phrasings.

    This is a first line of defence, not a guarantee: a determined attacker
    can paraphrase around any keyword list. Treat a failure as "quarantine
    this input for review", not as proof of an attack.
    """
    findings = [
        f"pattern: {pattern.pattern[:60]}"
        for pattern in _INJECTION_PATTERNS
        if pattern.search(text)
    ]
    if findings:
        return CheckResult(
            passed=False,
            check="injection",
            message=f"Matched {len(findings)} injection-like pattern(s).",
            findings=tuple(findings),
        )
    return CheckResult(passed=True, check="injection", message="No injection patterns detected.")


# ---------------------------------------------------------------------------
# Output shape: length bounds and JSON validity.
# ---------------------------------------------------------------------------

def length_check(text: str, *, min_chars: int = 1, max_chars: int = 4000) -> CheckResult:
    """Fail when the text is outside ``[min_chars, max_chars]`` characters."""
    n = len(text)
    if n < min_chars:
        return CheckResult(
            passed=False, check="length",
            message=f"Output too short: {n} chars (minimum {min_chars}).",
        )
    if n > max_chars:
        return CheckResult(
            passed=False, check="length",
            message=f"Output too long: {n} chars (maximum {max_chars}).",
        )
    return CheckResult(passed=True, check="length", message=f"Length OK: {n} chars.")


def json_check(text: str) -> CheckResult:
    """Fail when the text is not parseable JSON; pass its keys on success."""
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        return CheckResult(
            passed=False, check="json", message=f"Invalid JSON: {exc.msg} at line {exc.lineno}.",
        )
    keys = tuple(parsed.keys()) if isinstance(parsed, dict) else ()
    return CheckResult(
        passed=True, check="json",
        message="Valid JSON.", findings=keys,
    )
