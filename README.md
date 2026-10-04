# Instinct Mail

Lets a BB agent ask an Instinct agent a question by email and get the answer back into its thread. A small Gmail bridge for Linux with `systemd --user`.

[Русская версия](README.ru.md)

> [!IMPORTANT]
> Unofficial community project. Not affiliated with, endorsed by, or supported by Instinct or Google. Instinct support did not answer whether a third-party email client is allowed, so compatibility with their Terms is unconfirmed. Use only with accounts you control, at your own risk.

## Why

Instinct is a personal AI assistant you can reach by email. It can browse, research and come back with an answer later, but it has no API and no access to your machine. BB agents live on your machine and are good at code, but every extra research task eats their context.

Instinct Mail joins the two. A BB agent writes a question, sends it, keeps working, and gets woken up when the answer lands. The reply arrives as text the agent can read, not as instructions it must follow.

Typical uses:

- A second opinion on a plan or an architecture choice from someone outside the codebase
- Research that takes a while: compare libraries, check licenses, dig through documentation
- Fact-checking claims an agent is about to rely on
- Questions you would normally paste into a chat window yourself, now sent without leaving the thread

## How it works

The `ask` command sends a plain-text email from your Gmail to the Instinct address. A background service polls Gmail over IMAP, takes only messages whose sender exactly matches that address, links each reply to the request by mail headers, and wakes the BB thread that asked. The agent then reads the reply with `read`. Replies are untrusted text: a pattern scanner flags suspicious content, but it is not a sandbox and does not make a message safe.

## Requirements

- Linux or WSL with `systemd` for the user session
- BB on `PATH`
- Python 3.10+
- Gmail with 2-Step Verification and an app password
- The email address of your Instinct agent

No `sudo`, no system packages, no Python dependencies.

## Install

```bash
./install.sh
```

Then edit `~/.config/instinct-mail/.env`:

- `GMAIL_ADDRESS`: your Gmail account
- `GMAIL_APP_PASSWORD`: an app password, not your account password
- `INSTINCT_ADDRESS`: the exact address of your Instinct agent

Restart the service after editing:

```bash
systemctl --user restart instinct-mail.service
```

The installer puts the code in `~/.local/share/instinct-mail`, the `instinct-mail` command in `~/.local/bin`, the BB skill in `~/.bb/skills/instinct-mail`, and state in `~/.local/state/instinct-mail`. Credentials stay on your machine. If you change the Node installation used by `bb`, run `./install.sh` again.

## Daily use

```bash
instinct-mail status
systemctl --user restart instinct-mail.service
./install.sh --uninstall   # keeps credentials and state
```

The installed skill explains the `ask`, `reply` and `read` commands for the agent.

## License

Original code: WTFPL, see [LICENSE](LICENSE). The security gate is a port from IVA Agent under MIT, and the Unicode tables are under the Unicode License v3. Details in [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES) and [docs/security-gate.md](docs/security-gate.md).
