"""Compose checks into an input/output guardrail pipeline.

A pipeline runs its checks in order and resolves failures with one policy
per pipeline:

- ``"block"``  — reject the text on the first failing check.
- ``"redact"`` — replace findings with placeholders where the failing
  check supplies ``redacted_text`` (PII), and block on anything that
  cannot be redacted (secrets, injection).
- ``"warn"``   — always pass the text through, but report every failure
  so the caller can log or review it.

Typical wiring for an LLM app: an *input* pipeline (injection + secrets,
policy ``block``) in front of the model, and an *output* pipeline (PII +
length + JSON, policy ``redact``) behind it.

Ordering matters under ``redact``: a redacting check rewrites the text
that later checks see, so put blocking checks (secrets, injection)
before redacting ones — otherwise a redaction could mangle the very
pattern a later check is looking for.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .checks import CheckResult

Check = Callable[[str], CheckResult]


@dataclass
class PipelineResult:
    """The outcome of running a pipeline over one piece of text."""

    allowed: bool
    text: str
    results: list[CheckResult] = field(default_factory=list)
    action: str = "allow"  # "allow" | "block" | "redact"

    @property
    def failures(self) -> list[CheckResult]:
        return [r for r in self.results if not r.passed]

    def summary(self) -> str:
        if self.action == "redact":
            return f"redact: {len(self.failures)} check(s) failed; findings redacted."
        if self.allowed:
            return f"{self.action}: all {len(self.results)} check(s) passed."
        failed = ", ".join(r.check for r in self.failures)
        return f"{self.action}: failed check(s): {failed}."


class GuardrailPipeline:
    """An ordered list of checks plus one failure policy."""

    def __init__(self, checks: list[Check], *, policy: str = "block") -> None:
        if policy not in ("block", "redact", "warn"):
            raise ValueError(f"Unknown policy {policy!r}; use 'block', 'redact', or 'warn'.")
        self.checks = checks
        self.policy = policy

    def run(self, text: str) -> PipelineResult:
        results: list[CheckResult] = []
        current = text
        for check in self.checks:
            result = check(current)
            results.append(result)
            if result.passed:
                continue
            if self.policy == "block":
                return PipelineResult(allowed=False, text=text, results=results, action="block")
            if self.policy == "redact":
                if result.redacted_text is not None:
                    current = result.redacted_text
                    continue
                return PipelineResult(allowed=False, text=text, results=results, action="block")
            # policy == "warn": keep going, report at the end.
        if self.policy == "redact" and current != text:
            return PipelineResult(allowed=True, text=current, results=results, action="redact")
        if any(not r.passed for r in results):
            return PipelineResult(allowed=True, text=text, results=results, action="allow")
        return PipelineResult(allowed=True, text=text, results=results, action="allow")
