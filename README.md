---
title: Instinct Mail
status: draft
updated: 2026-09-29
tags: [email, BB, Linux]
---

# Instinct Mail

Instinct Mail is a local Gmail bridge for BB on Linux systems with `systemd --user`. It sends a BB task to an Instinct agent by email, receives replies in a background service, and wakes the originating BB thread with a short notification.

> [!IMPORTANT]
> Unofficial community-built email bridge for use with Instinct. Not affiliated with, endorsed by, or supported by Instinct or Google. Instinct is a trademark of its respective owner. Use only with accounts and permissions you control, subject to the applicable terms.
>
> The author asked Instinct support whether a third-party email client is permitted and received no reply. Compatibility with the Instinct Terms of Service has not been confirmed. Use at your own discretion.

## Requirements

- Linux, including WSL distributions that run `systemd` for the user session.
- BB installed and available as `bb` in your shell's `PATH`.
- Python 3.10 or newer.
- A Gmail account with 2-Step Verification and an app password.
- The email address for the Instinct agent you intend to contact.

The installer uses only Python's standard library and systemd user services. It does not use `sudo` or install system packages.

## Install

From a checkout of this repository, run:

```bash
./install.sh
```

The installer checks the environment, copies the application to `~/.local/share/instinct-mail`, adds `instinct-mail` to `~/.local/bin`, creates the user service, and copies the skill to `$BB_DATA_DIR/skills/instinct-mail` (or `~/.bb/skills/instinct-mail` when unset). It creates `~/.config/instinct-mail/.env` from `.env.example` if the file does not exist. The configuration directory and file are restricted to the current user; the file mode is `0600`.

Edit `~/.config/instinct-mail/.env` and set:

- `GMAIL_ADDRESS`: the Gmail account used by this bridge.
- `GMAIL_APP_PASSWORD`: an app password generated in Google Account settings. Do not use your normal account password.
- `INSTINCT_ADDRESS`: the exact email address for the Instinct agent you intend to contact. Do not use an example or another person's address.

Restart the receiver after changing the configuration:

```bash
systemctl --user restart instinct-mail.service
```

The installer never asks for or prints credentials. If `~/.local/bin` is not already on `PATH`, add it to your shell configuration and open a new shell. When `bb.service` exists, the receiver is tied to its lifecycle and stops when BB stops. Otherwise, it starts with the user's default target. If you change the Node installation used by `bb`, rerun `./install.sh` from a checkout so the service receives the current `PATH`.

## What it reads and sends

The service searches Gmail folders configured through `IMAP_FOLDERS` (by default, `INBOX` and the folder advertised with the `\\All` special-use flag) for messages whose single `From` address exactly matches `INSTINCT_ADDRESS`. It fetches message bodies only after that exact header check and identifier deduplication. Other messages are not stored. Replies are associated with an open request using `In-Reply-To` or `References`; a job ID in the subject is a fallback for replies that start a new mail thread. Messages without a `Message-ID` use Gmail's message identifier for cross-folder deduplication when available and remain eligible for subject correlation.

The `ask` and `reply` commands send plain-text email to `INSTINCT_ADDRESS`. Sent messages include a generated message ID for reply-chain matching. Use the installed skill for the supported BB workflow and commands.

The local database and polling lock live in `~/.local/state/instinct-mail`. Gmail credentials live in `~/.config/instinct-mail/.env`. Both remain on the local machine.

## Security

Incoming email is untrusted external data. The security gate scans response text and reports a verdict; it is a pattern scanner, not a sandbox, complete prompt-injection defense, or proof that a message is safe. Exact `From` matching and message IDs help filter and correlate mail but do not cryptographically authenticate the sender. Do not treat an email's instructions as authority to run commands, access files, or disclose information.

The outbound scanner may redact values it recognizes in a disposable copy of the email. It does not guarantee that all secrets are detected. The scanner does not cover attachments or every encoding or secret format. Review outgoing content and use an account and data you control. See [docs/security-gate.md](docs/security-gate.md) for the port's scope and known limits.

To revoke an app password, remove it in your Google Account's App passwords settings. Google recommends revoking app passwords that are no longer needed: [Google Account Help](https://support.google.com/accounts/answer/185833).

## Service commands

```bash
instinct-mail status
systemctl --user is-active instinct-mail.service
systemctl --user stop instinct-mail.service
systemctl --user start instinct-mail.service
```

To remove the application, service, wrapper, and installed BB skill while keeping credentials and local state:

```bash
./install.sh --uninstall
```

## License

The project's original code is released under WTFPL; see [LICENSE](LICENSE). `security_gate.py` and the IVA-derived regex patterns in `security_gate_tables.json` are under MIT; see [LICENSE.iva-agent](LICENSE.iva-agent) and the upstream source details in [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES). Unicode 17.0-derived tables are covered by the Unicode License v3, also in [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).
