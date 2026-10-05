---
title: Security gate
status: active
updated: 2026-10-05
tags: [security]
---

# Security gate

`scripts/security_gate.py` is a Python standard-library filter that protects against prompt injections, secret leakage, and destructive commands.

## Inbound responses

`sanitize_inbound` checks the email subject and body before returning them to the agent:
- Normalizes text with `unicodedata.normalize('NFKC')`
- Strips invisible and zero-width characters (e.g. `\u200b`, `\ufeff`, control characters)
- Scans for instruction overrides, role markers, shell command pipes, file access, and credential extraction
- Caps text length and reports `blocked`, `suspicious`, `reason`, `flags`, and `truncatedChars`

The filter does not block anything; it only marks suspicious text (`suspicious: true`, with `blocked` kept for backwards compatibility). Email text is always untrusted.

## Outbound messages

`scan_outbound` checks the subject and plain-text body before SMTP sending:
- Detects API keys (OpenAI, Anthropic, Google, GitHub, Slack, etc.) and bearer tokens
- Redacts recognized credentials with `[REDACTED]` in the transmitted email
- Catches suspicious injection artifacts and shell pipes

## Limits

The gate is a pattern scanner, not a sandbox. Treat all email content as untrusted research data regardless of scanner results.
