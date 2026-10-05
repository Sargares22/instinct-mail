#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=""
if [[ -n "${BASH_SOURCE[0]:-}" && "${BASH_SOURCE[0]}" != "-" && "${BASH_SOURCE[0]}" != "/dev/stdin" ]]; then
    SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd -P || true)
fi

if [[ -z "$SCRIPT_DIR" || ! -f "$SCRIPT_DIR/scripts/instinct_mail.py" ]]; then
    DEFAULT_ARCHIVE="https://github.com/Sargares22/instinct-mail/archive/refs/heads/main.tar.gz"
    ARCHIVE_URL="${INSTINCT_MAIL_ARCHIVE_URL:-$DEFAULT_ARCHIVE}"
    TMP_DL=$(mktemp -d "${TMPDIR:-/tmp}/instinct-mail-dl.XXXXXX")
    trap 'rm -rf -- "$TMP_DL"' EXIT

    ARCHIVE_FILE="$TMP_DL/archive.tar.gz"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$ARCHIVE_URL" -o "$ARCHIVE_FILE"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$ARCHIVE_FILE" "$ARCHIVE_URL"
    else
        printf 'Error: curl or wget is required to download Instinct Mail.\n' >&2
        exit 1
    fi

    mkdir -p -- "$TMP_DL/src"
    tar -xzf "$ARCHIVE_FILE" -C "$TMP_DL/src" --strip-components=1
    bash "$TMP_DL/src/install.sh" "$@"
    exit $?
fi

SOURCE_DIR="$SCRIPT_DIR"
SKIP_SYSTEMD=0
UNINSTALL=0

usage() {
    printf 'Usage: %s [--skip-systemd] [--uninstall]\n' "${0##*/}"
}

for arg in "$@"; do
    case "$arg" in
        --skip-systemd|--skip-launchd) SKIP_SYSTEMD=1 ;;
        --uninstall) UNINSTALL=1 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done

OS=$(uname -s)
case "$OS" in
    Linux|Darwin) ;;
    *) printf 'Error: Linux or macOS (Darwin) is required.\n' >&2; exit 1 ;;
esac

PYTHON=$(command -v python3 || true)
BB=$(command -v bb || true)
SYSTEMCTL=$(command -v systemctl || true)
LAUNCHCTL=$(command -v launchctl || true)

SHARE="$HOME/.local/share/instinct-mail"
BIN_DIR="$HOME/.local/bin"
WRAPPER="$BIN_DIR/instinct-mail"
CONFIG_DIR="$HOME/.config/instinct-mail"
ENV_FILE="$CONFIG_DIR/.env"
STATE_DIR="$HOME/.local/state/instinct-mail"
SKILL_DIR="${BB_DATA_DIR:-$HOME/.bb}/skills/instinct-mail"
UNIT_DIR="$HOME/.config/systemd/user"
UNIT_FILE="$UNIT_DIR/instinct-mail.service"
LAUNCH_AGENTS_DIR="$HOME/Library/LaunchAgents"
PLIST_FILE="$LAUNCH_AGENTS_DIR/com.instinct-mail.receiver.plist"

is_file_locked() {
    local lock_file="$1"
    if [[ ! -e "$lock_file" ]]; then
        return 1
    fi
    if command -v flock >/dev/null 2>&1; then
        ! flock -n "$lock_file" true
    elif [[ -n "$PYTHON" ]]; then
        ! "$PYTHON" -c '
import fcntl, sys
try:
    fd = open(sys.argv[1], "a")
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    sys.exit(0)
except (BlockingIOError, IOError):
    sys.exit(1)
' "$lock_file" 2>/dev/null
    else
        return 1
    fi
}

remove_common_files() {
    rm -rf -- "$SHARE" "$SKILL_DIR"
    rm -f -- "$WRAPPER"
}

uninstall_linux() {
    if [[ -n "$SYSTEMCTL" ]] && systemctl --user is-active --quiet instinct-mail.service; then
        local active_exec
        active_exec=$(systemctl --user show instinct-mail.service -p ExecStart --value 2>/dev/null || true)
        if [[ "$active_exec" == *"$SHARE/scripts/instinct_mail.py"* ]]; then
            if (( SKIP_SYSTEMD )); then
                printf 'Error: cannot uninstall with --skip-systemd while the service is active.\n' >&2
                exit 1
            fi
            systemctl --user stop instinct-mail.service
        fi
    fi
    if is_file_locked "$STATE_DIR/serve.lock"; then
        printf 'Error: cannot uninstall with --skip-systemd while the service is active.\n' >&2
        exit 1
    fi
    if (( ! SKIP_SYSTEMD )); then
        if [[ -n "$SYSTEMCTL" ]] && systemctl --user show-environment >/dev/null 2>&1 && systemctl --user is-enabled --quiet instinct-mail.service; then
            systemctl --user disable instinct-mail.service >/dev/null
        fi
    fi
    remove_common_files
    rm -f -- "$UNIT_FILE"
    if (( ! SKIP_SYSTEMD )) && [[ -n "$SYSTEMCTL" ]] && systemctl --user show-environment >/dev/null 2>&1; then
        systemctl --user daemon-reload
    fi
    printf 'Removed Instinct Mail code, command, unit, and BB skill.\n'
    printf 'Kept configuration: %s\n' "$ENV_FILE"
    printf 'Kept state: %s\n' "$STATE_DIR"
    exit 0
}

uninstall_darwin() {
    if (( ! SKIP_SYSTEMD )); then
        if [[ -f "$PLIST_FILE" ]]; then
            if ! launchctl bootout "gui/$(id -u)" "$PLIST_FILE" 2>/dev/null; then
                launchctl unload "$PLIST_FILE" 2>/dev/null || true
            fi
        fi
    fi
    if is_file_locked "$STATE_DIR/serve.lock"; then
        printf 'Error: cannot uninstall with --skip-systemd while the service is active.\n' >&2
        exit 1
    fi
    remove_common_files
    rm -f -- "$PLIST_FILE"
    printf 'Removed Instinct Mail code, command, LaunchAgent, and BB skill.\n'
    printf 'Kept configuration: %s\n' "$ENV_FILE"
    printf 'Kept state: %s\n' "$STATE_DIR"
    exit 0
}

if (( UNINSTALL )); then
    if [[ "$OS" == "Linux" ]]; then
        uninstall_linux
    else
        uninstall_darwin
    fi
fi

validate_requirements() {
    if [[ -z "$PYTHON" ]]; then
        printf 'Error: python3 3.10 or newer is required.\n' >&2
        exit 1
    fi
    "$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' || {
        printf 'Error: python3 3.10 or newer is required.\n' >&2
        exit 1
    }
    if [[ -z "$BB" ]]; then
        printf 'Error: the bb command must be available in PATH.\n' >&2
        exit 1
    fi

    for path in "$SHARE" "$CONFIG_DIR" "$STATE_DIR"; do
        if [[ -L "$path" ]]; then
            printf 'Error: refusing to use a symbolic-link directory: %s\n' "$path" >&2
            exit 1
        fi
    done
    if [[ -L "$ENV_FILE" ]]; then
        printf 'Error: refusing to replace a symbolic-link configuration file.\n' >&2
        exit 1
    fi
    if [[ -L "$WRAPPER" ]]; then
        printf 'Error: refusing to replace a symbolic-link command.\n' >&2
        exit 1
    fi

    if [[ "$OS" == "Linux" ]]; then
        if (( ! SKIP_SYSTEMD )); then
            if [[ -z "$SYSTEMCTL" ]] || ! systemctl --user show-environment >/dev/null 2>&1; then
                printf 'Error: a working systemd --user session is required.\n' >&2
                exit 1
            fi
        fi
    elif [[ "$OS" == "Darwin" ]]; then
        if (( ! SKIP_SYSTEMD )); then
            if [[ -z "$LAUNCHCTL" ]]; then
                printf 'Error: the launchctl command is required on macOS.\n' >&2
                exit 1
            fi
        fi
    fi

    if [[ -d "$SHARE" && "$SOURCE_DIR" -ef "$SHARE" ]]; then
        printf 'Error: run install.sh from a checkout, not from its installed copy.\n' >&2
        exit 1
    fi
}

stop_active_receiver() {
    if [[ "$OS" == "Linux" ]]; then
        if (( ! SKIP_SYSTEMD )) && systemctl --user is-active --quiet instinct-mail.service; then
            systemctl --user stop instinct-mail.service
        fi
    elif [[ "$OS" == "Darwin" ]]; then
        if (( ! SKIP_SYSTEMD )) && [[ -f "$PLIST_FILE" ]]; then
            if ! launchctl bootout "gui/$(id -u)" "$PLIST_FILE" 2>/dev/null; then
                launchctl unload "$PLIST_FILE" 2>/dev/null || true
            fi
        fi
    fi
    if is_file_locked "$STATE_DIR/serve.lock"; then
        printf 'Error: the receiver is active; stop it before replacing installed files.\n' >&2
        exit 1
    fi
}

STAGE_DIR=
OLD_SHARE=
cleanup_install() {
    local status=$?
    trap - EXIT
    if (( status == 0 )); then
        [[ -n "$OLD_SHARE" && -d "$OLD_SHARE" ]] && rm -rf -- "$OLD_SHARE"
    elif [[ -n "$OLD_SHARE" && -d "$OLD_SHARE" ]]; then
        rm -rf -- "$SHARE"
        mv -- "$OLD_SHARE" "$SHARE" || printf 'Error: previous installation is at %s\n' "$OLD_SHARE" >&2
    fi
    [[ -n "$STAGE_DIR" && -d "$STAGE_DIR" ]] && rm -rf -- "$STAGE_DIR"
    exit "$status"
}
trap cleanup_install EXIT

install_common_files() {
    mkdir -p -- "$(dirname -- "$SHARE")"
    STAGE_DIR=$(mktemp -d "${SHARE}.new.XXXXXX")
    OLD_SHARE=

    mkdir -p -- "$STAGE_DIR/scripts" "$STAGE_DIR/systemd" "$STAGE_DIR/launchd" "$STAGE_DIR/docs" "$BIN_DIR" \
        "$CONFIG_DIR" "$STATE_DIR" "$SKILL_DIR"
    chmod 700 "$CONFIG_DIR" "$STATE_DIR"
    install -m 644 "$SOURCE_DIR/scripts/instinct_mail.py" "$STAGE_DIR/scripts/instinct_mail.py"
    install -m 644 "$SOURCE_DIR/scripts/security_gate.py" "$STAGE_DIR/scripts/security_gate.py"
    install -m 644 "$SOURCE_DIR/SKILL.md" "$STAGE_DIR/SKILL.md"
    install -m 644 "$SOURCE_DIR/docs/security-gate.md" "$STAGE_DIR/docs/security-gate.md"
    install -m 644 "$SOURCE_DIR/systemd/instinct-mail.service.in" "$STAGE_DIR/systemd/instinct-mail.service.in"
    install -m 644 "$SOURCE_DIR/launchd/com.instinct-mail.receiver.plist.in" "$STAGE_DIR/launchd/com.instinct-mail.receiver.plist.in"
    install -m 644 "$SOURCE_DIR/LICENSE" "$STAGE_DIR/LICENSE"
    install -m 644 "$SOURCE_DIR/.env.example" "$STAGE_DIR/.env.example"
    install -m 644 "$SOURCE_DIR/README.md" "$STAGE_DIR/README.md"
    if [[ -f "$SOURCE_DIR/README.ru.md" ]]; then
        install -m 644 "$SOURCE_DIR/README.ru.md" "$STAGE_DIR/README.ru.md"
    fi
    install -m 644 "$SOURCE_DIR/CHANGELOG.md" "$STAGE_DIR/CHANGELOG.md"

    if [[ ! -e "$ENV_FILE" ]]; then
        install -m 600 "$SOURCE_DIR/.env.example" "$ENV_FILE"
    else
        if [[ ! -f "$ENV_FILE" ]]; then
            printf 'Error: configuration path is not a regular file.\n' >&2
            exit 1
        fi
        chmod 600 "$ENV_FILE"
    fi
    install -m 755 "$SOURCE_DIR/install.sh" "$STAGE_DIR/install.sh"
    printf '#!/usr/bin/env bash\nexec %q %q "$@"\n' "$PYTHON" "$SHARE/scripts/instinct_mail.py" > "$WRAPPER"
    chmod 755 "$WRAPPER"
    install -m 644 "$SOURCE_DIR/SKILL.md" "$SKILL_DIR/SKILL.md"

    if [[ -e "$SHARE" ]]; then
        local previous_share
        previous_share=$(mktemp -d "${SHARE}.old.XXXXXX")
        rmdir -- "$previous_share"
        if mv -- "$SHARE" "$previous_share"; then
            OLD_SHARE=$previous_share
        else
            rmdir -- "$previous_share"
            exit 1
        fi
    fi
    if ! mv -- "$STAGE_DIR" "$SHARE"; then
        if [[ -n "$OLD_SHARE" ]]; then
            mv -- "$OLD_SHARE" "$SHARE"
            OLD_SHARE=
        fi
        exit 1
    fi
    STAGE_DIR=
}

setup_linux_service() {
    local bb_dir service_path dependencies wanted_by
    bb_dir=$(dirname -- "$BB")
    service_path="$BIN_DIR:$bb_dir:$PATH"
    if systemctl --user cat bb.service >/dev/null 2>&1; then
        dependencies=$'BindsTo=bb.service\nAfter=bb.service'
        wanted_by=bb.service
    else
        dependencies=
        wanted_by=default.target
    fi
    mkdir -p -- "$UNIT_DIR"
    "$PYTHON" - "$SHARE/systemd/instinct-mail.service.in" "$UNIT_FILE" \
        "$PYTHON" "$SHARE" "$service_path" "$dependencies" "$wanted_by" <<'PY'
from pathlib import Path
import os
import sys
import tempfile

template, target, python, share, path, dependencies, wanted_by = sys.argv[1:]

def quote(value):
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%') + '"'

def path_value(value):
    return value.replace('\\', '\\\\').replace(' ', '\\x20').replace('%', '%%')

text = Path(template).read_text(encoding='utf-8')
values = {
    '@PYTHON@': quote(python),
    '@WORKDIR@': path_value(share),
    '@PROGRAM@': quote(f'{share}/scripts/instinct_mail.py'),
    '@PATH@': path.replace('"', '\\"').replace('%', '%%'),
    '@DEPENDENCIES@': dependencies,
    '@WANTED_BY@': wanted_by,
}
for marker, value in values.items():
    text = text.replace(marker, value)
target_path = Path(target)
fd, temporary = tempfile.mkstemp(dir=target_path.parent, prefix='.instinct-mail.')
with os.fdopen(fd, 'w', encoding='utf-8') as stream:
    stream.write(text)
os.chmod(temporary, 0o644)
os.replace(temporary, target_path)
PY
    systemctl --user daemon-reload
    systemctl --user enable instinct-mail.service >/dev/null
    if ! systemctl --user restart instinct-mail.service; then
        systemctl --user start instinct-mail.service
    fi
}

setup_darwin_service() {
    local bb_dir service_path
    bb_dir=$(dirname -- "$BB")
    service_path="$BIN_DIR:$bb_dir:$PATH"
    mkdir -p -- "$LAUNCH_AGENTS_DIR"
    "$PYTHON" - "$SHARE/launchd/com.instinct-mail.receiver.plist.in" "$PLIST_FILE" \
        "$PYTHON" "$SHARE" "$service_path" "$STATE_DIR" <<'PY'
from pathlib import Path
import os
import sys
import tempfile

template, target, python, share, path, state_dir = sys.argv[1:]

def xml_escape(value):
    return (
        value.replace('&', '&amp;')
        .replace('<', '&lt;')
        .replace('>', '&gt;')
        .replace('"', '&quot;')
        .replace("'", '&apos;')
    )

text = Path(template).read_text(encoding='utf-8')
values = {
    '@PYTHON@': xml_escape(python),
    '@PROGRAM@': xml_escape(f'{share}/scripts/instinct_mail.py'),
    '@WORKDIR@': xml_escape(share),
    '@PATH@': xml_escape(path),
    '@STATE_DIR@': xml_escape(state_dir),
    '@STATEDIR@': xml_escape(state_dir),
}
for marker, value in values.items():
    text = text.replace(marker, value)
target_path = Path(target)
fd, temporary = tempfile.mkstemp(dir=target_path.parent, prefix='.instinct-mail.')
with os.fdopen(fd, 'w', encoding='utf-8') as stream:
    stream.write(text)
os.chmod(temporary, 0o644)
os.replace(temporary, target_path)
PY
    if ! launchctl bootstrap "gui/$(id -u)" "$PLIST_FILE" 2>/dev/null; then
        launchctl load "$PLIST_FILE"
    fi
}

validate_requirements
stop_active_receiver
install_common_files

if (( ! SKIP_SYSTEMD )); then
    if [[ "$OS" == "Linux" ]]; then
        setup_linux_service
    elif [[ "$OS" == "Darwin" ]]; then
        setup_darwin_service
    fi
fi

printf 'Installed Instinct Mail command: %s\n' "$WRAPPER"
printf 'Configuration: %s (mode 600)\n' "$ENV_FILE"
printf 'State: %s\n' "$STATE_DIR"
if [[ "$OS" == "Linux" ]]; then
    if (( SKIP_SYSTEMD )); then
        printf 'Systemd service setup skipped.\n'
    else
        printf 'Service: %s\n' "$(systemctl --user is-active instinct-mail.service)"
    fi
else
    if (( SKIP_SYSTEMD )); then
        printf 'Launchd service setup skipped.\n'
    else
        printf 'Service: active (launchd)\n'
    fi
fi

if [[ -f "$ENV_FILE" ]]; then
    missing=()
    for var in GMAIL_ADDRESS GMAIL_APP_PASSWORD INSTINCT_ADDRESS; do
        val=$(grep -E "^${var}=" "$ENV_FILE" 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d "'\"[:space:]")
        if [[ -z "$val" ]]; then
            missing+=("$var")
        fi
    done
    if (( ${#missing[@]} > 0 )); then
        printf '\nRemaining configuration in %s to fill:\n' "$ENV_FILE"
        for item in "${missing[@]}"; do
            printf '  - %s\n' "$item"
        done
        printf 'After filling .env, verify with: instinct-mail status\n'
    fi
fi
