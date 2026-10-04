---
title: Security gate port
status: draft
updated: 2026-09-29
tags: [security, provenance]
---

# Security gate port

`scripts/security_gate.py` is a Python standard-library port of IVA Agent's `security-gate.ts`, pinned to commit `817bd1e1d02a9774ab7fc335b4202029f87a6570`. The original MIT notice and upstream location are recorded in `LICENSE.iva-agent/`.

## Inbound responses

`sanitize_inbound` applies the upstream inbound scanner to the full stored body before pagination. The email transport uses the upstream `web` surface. Its returned text is capped at 50,000 Unicode code points; expensive-script checks have a 2,000-character limit. The result reports `blocked`, `reason`, `flags`, and `truncatedChars`. `has_inbound_attack_signal` also reports role-marker and override flags that can matter below the blocking threshold.

The transport marks the body as untrusted and returns scanner metadata with every read. A `blocked` result is a warning signal, not an access-control decision. The saved email and raw MIME are not changed by inbound scanning. Pagination applies to a sanitized copy of the body.

## Outbound messages

`scan_outbound` checks decoded subject and `text/plain` body before SMTP submission. Recognized secret patterns are redacted in the transmitted copy. Stored content, the archived MIME, and its request identity remain unchanged. Injection-like artifacts are findings but do not by themselves block sending. All outgoing messages created by the transport are plain text.

The scanner does not inspect attachments, arbitrary multipart payloads, every encoding, unnamed secrets, or every possible credential format. A clean result does not prove that a message contains no secret.

## Unicode data and compatibility

Static Unicode category, case-mapping, normalization, and lookalike tables are based on Unicode 17.0.0. This avoids depending on the Unicode version bundled with Python. The tables and license notice are in `scripts/security_gate_tables.json` and `THIRD_PARTY_NOTICES`.

The port preserves the upstream result fields and the supported regex/Unicode behaviors described by the source implementation. It is not a claim of exhaustive equivalence for every input string or runtime. Changes to the upstream gate or generated Unicode data require a separate provenance and behavior review.

## Limits

The gate does not authenticate the sender, isolate model execution, inspect attachments, or define BB permissions. Email `From` checks and message-ID correlation are transport filters, not cryptographic authentication. Treat all email content as untrusted regardless of the scanner result. The gate is a pattern scanner, not a sandbox, complete prompt-injection defense, or security certification.

The scanner's original pattern coverage and Unicode behavior are tied to the upstream implementation. This document describes the port's scope, not a claim of complete equivalence for every possible string or a security certification.
