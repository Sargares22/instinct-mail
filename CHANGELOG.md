---
title: Changelog
status: draft
updated: 2026-10-06
tags: [release]
---

# Changelog

## Unreleased

### Universal single-file version

- The whole utility is one file, `instinct_mail.py`; the security gate and the skill text are inside it. `install.sh`, `scripts/` and the `instinct-mail` wrapper in `~/.local/bin` are gone. Installation is downloading the file (see README).
- Works with any agent harness and on Windows: portable file locks, UTF-8 output, no POSIX-only permission check on Windows.
- New `wait` command: blocks until a job has an unread reply. A harness that resumes a thread when a background command exits needs no service at all.
- New `sync`, `doctor`, `skill` and `migrate` commands.
- Mailbox polling is shared: one process at a time, at most once per `POLL_SECONDS`, whether it is `serve`, `wait`, `status` or `read`.
- Replies have a read mark (`read_at`), set when the last page of a message is read. `read --job` returns the oldest unread reply. `status` lists unread messages.
- Notifiers replace the hard-coded `bb thread tell`: `NOTIFY_<NAME>` in `.env` is a JSON array of arguments, a question names its notifier with `ask --notify NAME --thread ID`. `--thread` alone no longer triggers a notification, and `bb` is no longer detected automatically.
- The database has a schema version; an older copy of the utility refuses a newer database.
- `.env` and `data/` next to the script are no longer looked up. Only `~/.config/instinct-mail/.env` and `~/.local/state/instinct-mail/` (or `INSTINCT_ENV_FILE`, `INSTINCT_DATA_DIR`).
- systemd and launchd templates moved to `contrib/` as examples.

### Upgrading an installation made with install.sh (BB)

The old code does not check the schema version, so stop it before the new code touches the database.

1. Stop the receiver: `systemctl --user stop instinct-mail.service` (macOS: `launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.instinct-mail.receiver.plist`).
2. Check where the configuration and database are. If they are in `~/.config/instinct-mail` and `~/.local/state/instinct-mail`, nothing to move. If a `.env` or `data/` sits next to the old script, move them there.
3. Copy `~/.local/state/instinct-mail/instinct.sqlite3` somewhere safe.
4. Download the new `instinct_mail.py` to `~/.local/share/instinct-mail/` and regenerate the skill with `skill` (README, steps 1 and 5). Remove the old `scripts/` directory. Remove `~/.local/bin/instinct-mail` too, unless something else calls it (the BB Instinct Inbox plugin does by default); in that case point it at the new file.
5. Add to `~/.config/instinct-mail/.env`: `NOTIFY_BB=["bb", "thread", "tell", "{thread}", "{text}"]`
6. Run `instinct_mail.py migrate --notifier bb`. It upgrades the schema and assigns the `bb` notifier to open jobs that have a thread; without it the receiver will not wake threads for questions asked before the upgrade.
7. Replace the service unit with the example from `contrib/` and start it.
8. Check `doctor`, then confirm on one question that the thread is woken.

### Earlier

- Add native standard-library security gate for prompt injection and secret leak protection.
- Add macOS support via a launchd LaunchAgent in ~/Library/LaunchAgents.
- Make the Instinct agent address a required local setting.
- Add XDG configuration and state paths.
- Fix IMAP selection of Sent folders with spaces in their names.
