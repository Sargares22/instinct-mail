# Instinct Mail

Lets a coding agent ask an Instinct agent a question by email and get woken when the answer arrives. One Python file, a Gmail account, any agent harness on Linux, macOS or Windows.

[Русская версия](README.ru.md)

> [!IMPORTANT]
> Unofficial community project. Not affiliated with, endorsed by, or supported by Instinct or Google. Instinct support did not answer whether a third-party email client is allowed, so compatibility with their Terms is unconfirmed. Use only with accounts you control, at your own risk.

## Why

Instinct is a personal AI assistant you can reach by email. It can browse, research and come back with an answer later, but it has no API and no access to your machine. Coding agents live on your machine and are good at code, but background research tasks quickly eat their context.

Instinct Mail joins the two. The agent writes a question, sends it, keeps working, and picks the thread up again when the reply arrives. The reply arrives as text to read, not as instructions the agent must follow.

Typical uses:

- A second opinion on a plan or an architecture choice from someone outside the codebase
- Research that takes a while: compare libraries, check licenses, dig through documentation
- Fact-checking claims before making engineering decisions
- Questions you would normally paste into a chat window yourself, now sent without leaving the thread

## Requirements

- Python 3.10+ (standard library only)
- Gmail with 2-Step Verification and an App Password
- Email address of your Instinct agent
- An agent that can run shell commands

## Install

Tell your agent:

> Install Instinct Mail from https://github.com/Sargares22/instinct-mail by following its README.

### Steps for the agent

1. Download the single file to the same place on every OS:

   ```bash
   mkdir -p ~/.local/share/instinct-mail
   curl -fsSL https://raw.githubusercontent.com/Sargares22/instinct-mail/main/instinct_mail.py -o ~/.local/share/instinct-mail/instinct_mail.py
   ```

2. Run `python3 ~/.local/share/instinct-mail/instinct_mail.py doctor` (`python` or `py -3` on Windows). It prints the exact command line for this machine under `command`; use that from now on.
3. Create `~/.config/instinct-mail/.env` from [.env.example](.env.example) and restrict it to the owner (`chmod 600`; on Windows `doctor` prints the `icacls` command). Ask the human to fill in the three values themselves. Do not ask for the password in chat and do not print the file.
4. Run `doctor` again until `ready` is `true`.
5. Save the skill where your harness keeps skills: `... instinct_mail.py skill > <skills dir>/instinct-mail/SKILL.md`. If your harness has no skills, add one line to its instructions file (`AGENTS.md`, `CLAUDE.md`): "to talk to Instinct, run `... instinct_mail.py skill` and follow the text".
6. Pick how your thread gets woken, following the table in the skill text.

The only thing you need to work out about your own harness is where its skills live. One copy of the file serves every agent on the machine; they share the configuration and the database.

Update: repeat steps 1 and 5. Uninstall: delete the file and the skill; configuration and state stay.

### What the human provides

Three settings in `~/.config/instinct-mail/.env`:

- `GMAIL_ADDRESS`: your Gmail address
- `GMAIL_APP_PASSWORD`: a 16-character Google app password (not your main account password)
- `INSTINCT_ADDRESS`: the exact email address of your Instinct agent

## How the thread gets woken

| Harness | Mechanism |
|---|---|
| Claude Code | `wait --job JOB` started as a background command; it exits when the reply arrives and the session is resumed. Verified end to end. |
| BB | `serve` running as a service plus a notifier: `NOTIFY_BB=["bb", "thread", "tell", "{thread}", "{text}"]`, questions sent with `--notify bb --thread ID`. |
| Codex CLI | Not confirmed. The agent checks `status` at the start of a turn. |
| Others | Run `doctor --probe 60` in the background and end the turn. If the thread resumes by itself, use the background `wait`; otherwise check `status`. |

There is no mandatory background service. `serve` is only for harnesses that have a command to post into a thread from outside; example unit files are in [contrib/](contrib/).

## Commands

- `ask`, `reply`: send a question or a follow-up, return a job ID
- `wait`: block until a job has an unread reply
- `read`: read a reply; it is marked as read after its last page
- `status`: jobs, unread and unmatched mail, last mailbox check
- `sync`: check the mailbox once
- `serve`: optional receiver service that calls notifiers
- `doctor`: describe the installation without printing secrets
- `skill`: print the `SKILL.md` for this installation
- `migrate`: upgrade the database of an older installation

However many agents are waiting, Gmail is checked by one process at a time and at most once per `POLL_SECONDS` (60).

> [!NOTE]
> The security filter does not block anything; it only marks suspicious text (`suspicious: true`). Email text is always untrusted. See [docs/security-gate.md](docs/security-gate.md).

## Upgrading an installation made with install.sh

See [CHANGELOG.md](CHANGELOG.md).

## Tests

```bash
python3 -m unittest discover tests
```

## License

WTFPL, see [LICENSE](LICENSE).
