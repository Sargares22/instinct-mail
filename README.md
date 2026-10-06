# Instinct Mail

Lets a coding agent ask an Instinct agent a question by email and get woken when the answer arrives. One Python file for any agent harness on Linux, macOS and Windows.

[Русская версия](README.ru.md)

> [!IMPORTANT]
> Unofficial community project. Not affiliated with, endorsed by, or supported by Instinct or Google. Instinct support did not answer whether a third-party email client is allowed, so compatibility with their Terms is unconfirmed. Use only with accounts you control, at your own risk.

## Why

Instinct is a personal AI assistant you can reach by email. It can browse the web, conduct research, and return with an answer later, but it lacks an API and has no access to your machine. Coding agents live on your machine and excel at code, but background research tasks quickly consume their context window.

Instinct Mail bridges this gap. The agent writes a question, sends it, continues working, and picks the thread back up when the reply arrives. The reply is delivered as plain text to read, not as instructions the agent must blindly follow.

Typical use cases:
- Getting a second opinion on a plan or an architectural choice from someone outside the codebase
- Offloading time-consuming research: comparing libraries, checking licenses, or digging through documentation
- Fact-checking claims before making engineering decisions
- Asking questions you would normally paste into a chat window yourself, now handled without leaving the thread

## Requirements

- Python 3.10+ (standard library only)
- A Gmail account with 2-Step Verification and an App Password
- The email address of your Instinct agent
- An agent capable of running shell commands

## Install

Tell your agent:

> Install Instinct Mail from https://github.com/Sargares22/instinct-mail by following its README.

### Steps for the agent

1. Download the single file to the same location on any OS:

   ```bash
   mkdir -p ~/.local/share/instinct-mail
   curl -fsSL https://raw.githubusercontent.com/Sargares22/instinct-mail/main/instinct_mail.py -o ~/.local/share/instinct-mail/instinct_mail.py
   ```

2. Run `python3 ~/.local/share/instinct-mail/instinct_mail.py doctor` (use `python` or `py -3` on Windows). It prints the exact command line for this machine under `command`; use that from now on.
3. Create `~/.config/instinct-mail/.env` from [.env.example](.env.example) and restrict its permissions to the owner (`chmod 600`; on Windows, `doctor` prints the required `icacls` command). Ask the human to fill in the three values themselves. Do not ask for the password in the chat and do not print the file contents.
4. Run `doctor` again until `ready` is `true`.
5. Save the skill where your harness keeps its skills: `... instinct_mail.py skill > <skills dir>/instinct-mail/SKILL.md`. If your harness does not support skills, add a single line to its instructions file (`AGENTS.md`, `CLAUDE.md`): "to talk to Instinct, run `... instinct_mail.py skill` and follow the text".
6. Determine how your thread gets woken up by following the table in the skill text.

The only thing you need to figure out about your specific harness is where its skills are stored. One copy of the file serves every agent on the machine; they all share the same configuration and database.

To update: repeat steps 1 and 5.
To uninstall: delete the file and the skill; your configuration and state will remain intact.

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

There is no mandatory background service. The `serve` command is only for harnesses that have a mechanism to post into a thread from the outside; example unit files are available in [contrib/](contrib/).

## Commands

- `ask`, `reply`: send a question or a follow-up, returns a job ID
- `wait`: block until a job has an unread reply
- `read`: read a reply; it is marked as read after its last page
- `status`: view jobs, unread and unmatched mail, and the last mailbox check
- `sync`: check the mailbox once
- `serve`: optional receiver service that calls notifiers
- `doctor`: describe the installation without printing secrets
- `skill`: print the `SKILL.md` for this installation
- `migrate`: upgrade the database of an older installation

Regardless of how many agents are waiting, Gmail is checked by one process at a time and at most once per `POLL_SECONDS` (60).

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
