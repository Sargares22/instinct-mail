# Instinct Mail

Lets a BB agent ask an Instinct agent a question by email and receive the answer directly in its thread. A Gmail bridge for Linux (`systemd --user`) and macOS (`launchd`).

[Русская версия](README.ru.md)

> [!IMPORTANT]
> Unofficial community project. Not affiliated with, endorsed by, or supported by Instinct or Google. Instinct support did not answer whether a third-party email client is allowed, so compatibility with their Terms is unconfirmed. Use only with accounts you control, at your own risk.

## Why

Instinct is a personal AI assistant you can reach by email. It can browse, research and come back with an answer later, but it has no API and no access to your machine. BB agents live on your machine and are good at code, but background research tasks quickly eat their context.

Instinct Mail joins the two. A BB agent writes a question, sends it, keeps working, and wakes up when the reply arrives. The reply arrives as text to read, not as instructions the agent must follow.

Typical uses:

- A second opinion on a plan or an architecture choice from someone outside the codebase
- Research that takes a while: compare libraries, check licenses, dig through documentation
- Fact-checking claims before making engineering decisions
- Questions you would normally paste into a chat window yourself, now sent without leaving the thread

## Install via your agent

Tell your agent:
> Install Instinct Mail from https://github.com/Sargares22/instinct-mail and set up Gmail.

One-line installation command:

```bash
curl -fsSL https://raw.githubusercontent.com/Sargares22/instinct-mail/main/install.sh | bash
```

### What your agent does automatically

- Downloads the repository, puts files in `~/.local/share/instinct-mail`, and adds `instinct-mail` to `~/.local/bin`
- Registers the `instinct-mail` BB skill
- Configures and starts the background service (`systemd --user` on Linux, LaunchAgent on macOS)
- Verifies service status with `instinct-mail status`

### What your agent will ask you

The bridge requires three settings in `~/.config/instinct-mail/.env`:
- `GMAIL_ADDRESS`: your Gmail address
- `GMAIL_APP_PASSWORD`: a 16-character Google app password (not your main account password)
- `INSTINCT_ADDRESS`: the exact email address of your Instinct agent

### How to use it

Once configured, the agent uses the installed skill:
- `instinct-mail ask`: sends a question to Instinct and returns a job ID
- `instinct-mail read`: reads the received answer (scanned by a built-in injection filter)
- `instinct-mail status`: checks background receiver status and unmatched incoming mail

Uninstall anytime with `./install.sh --uninstall` (credentials and state are preserved).

## License

WTFPL, see [LICENSE](LICENSE).
