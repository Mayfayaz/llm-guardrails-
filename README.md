# llm-guardrails

Lightweight, dependency-free guardrails for LLM applications — in pure
Python stdlib, with no model calls and no API keys.

## Why this matters

Every LLM application faces the same problem: untrusted text goes in,
and untrusted text comes out. Users paste credentials into prompts,
attackers smuggle instructions into pasted content, and models leak PII
or exceed output budgets. Model-based moderation is unnecessary for
cases a pattern check and a length check already catch. This library
provides that first layer: it blocks, redacts, or warns on common
failures so reviewers only handle the hard cases.

## What it checks

| Check | Detects |
|---|---|
| `pii_check` | Email addresses, phone numbers, credit-card-shaped numbers (Luhn-validated, so ordinary digit strings are not flagged) |
| `secret_check` | AWS keys, GitHub tokens, OpenAI keys, `api_key = ...` assignments, private-key blocks |
| `injection_check` | Common prompt-injection phrasings ("ignore all previous instructions", fake system tags, …) |
| `length_check` | Outputs outside a min/max character budget |
| `json_check` | Outputs that are not parseable JSON |

## How to use it

```python
from guardrails import GuardrailPipeline, injection_check, pii_check, secret_check

# Block bad input before it reaches the model.
input_guard = GuardrailPipeline([injection_check, secret_check], policy="block")

# Redact PII from model output instead of dropping the whole reply.
output_guard = GuardrailPipeline([pii_check], policy="redact")

result = input_guard.run(user_message)
if not result.allowed:
    print("Blocked:", result.summary())
else:
    reply = call_model(user_message)  # your model call here
    safe = output_guard.run(reply)
    print(safe.text)
```

### Failure policies

- **`block`** — reject on the first failing check.
- **`redact`** — replace findings with placeholders where possible (PII);
  block anything that cannot be redacted (secrets, injection).
- **`warn`** — always pass the text through, but report every failure for
  logging or review.

### Limitations

The injection check is heuristic keyword/pattern matching, not a
security guarantee — a determined attacker can paraphrase around any
list. Treat a failure as "quarantine this input", not proof of an
attack. For high-stakes moderation, layer a model-based classifier on
top of this one.

## How to run

```bash
python demo.py                      # three worked cases: clean, injection, leaky reply
python -m unittest test_guardrails -v
```

Requires Python 3.10+ and nothing else.

## Layout

```
guardrails/
  __init__.py   public API
  checks.py     the individual checks (pure functions over text)
  pipeline.py   GuardrailPipeline and its block/redact/warn policies
demo.py         worked input/output guard example
test_guardrails.py
```

## License

MIT — see `LICENSE`.
