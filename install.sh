#!/usr/bin/env bash
set -euo pipefail

SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
SKIP_SYSTEMD=0
UNINSTALL=0

usage() {
    printf 'Usage: %s [--skip-systemd] [--uninstall]\n' "${0##*/}"
}

for arg in "$@"; do
    case "$arg" in
        --skip-systemd) SKIP_SYSTEMD=1 ;;
        --uninstall) UNINSTALL=1 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done

case "$(uname -s)" in
    Linux) ;;
    *) printf 'Error: Linux is required.\n' >&2; exit 1 ;;
esac

PYTHON=$(command -v python3 || true)
BB=$(command -v bb || true)
SYSTEMCTL=$(command -v systemctl || true)

SHARE="$HOME/.local/share/instinct-mail"
BIN_DIR="$HOME/.local/bin"
WRAPPER="$BIN_DIR/instinct-mail"
CONFIG_DIR="$HOME/.config/instinct-mail"
ENV_FILE="$CONFIG_DIR/.env"
STATE_DIR="$HOME/.local/state/instinct-mail"
SKILL_DIR="${BB_DATA_DIR:-$HOME/.bb}/skills/instinct-mail"
UNIT_DIR="$HOME/.config/systemd/user"
UNIT_FILE="$UNIT_DIR/instinct-mail.service"

if (( UNINSTALL )); then
    if [[ -n "$SYSTEMCTL" ]] && systemctl --user is-active --quiet instinct-mail.service; then
        ACTIVE_EXEC=$(systemctl --user show instinct-mail.service -p ExecStart --value 2>/dev/null || true)
        if [[ "$ACTIVE_EXEC" == *"$SHARE/scripts/instinct_mail.py"* ]]; then
            if (( SKIP_SYSTEMD )); then
                printf 'Error: cannot uninstall with --skip-systemd while the service is active.\n' >&2
                exit 1
            fi
            systemctl --user stop instinct-mail.service
        fi
    fi
    if [[ -e "$STATE_DIR/serve.lock" ]] && ! flock -n "$STATE_DIR/serve.lock" true; then
        printf 'Error: cannot uninstall with --skip-systemd while the service is active.\n' >&2
        exit 1
    fi
    if (( ! SKIP_SYSTEMD )); then
        if [[ -n "$SYSTEMCTL" ]] && systemctl --user show-environment >/dev/null 2>&1 && systemctl --user is-enabled --quiet instinct-mail.service; then
            systemctl --user disable instinct-mail.service >/dev/null
        fi
    fi
    rm -rf -- "$SHARE" "$SKILL_DIR"
    rm -f -- "$WRAPPER" "$UNIT_FILE"
    if (( ! SKIP_SYSTEMD )) && [[ -n "$SYSTEMCTL" ]] && systemctl --user show-environment >/dev/null 2>&1; then
        systemctl --user daemon-reload
    fi
    printf 'Removed Instinct Mail code, command, unit, and BB skill.\n'
    printf 'Kept configuration: %s\n' "$ENV_FILE"
    printf 'Kept state: %s\n' "$STATE_DIR"
    exit 0
fi

if [[ -z "$PYTHON" ]]; then
    printf 'Error: python3 3.10 or newer is required.\n' >&2; exit 1
fi
"$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' || {
    printf 'Error: python3 3.10 or newer is required.\n' >&2; exit 1;
}
if [[ -z "$BB" ]]; then
    printf 'Error: the bb command must be available in PATH.\n' >&2; exit 1
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

if (( ! SKIP_SYSTEMD )); then
    if [[ -z "$SYSTEMCTL" ]] || ! systemctl --user show-environment >/dev/null 2>&1; then
        printf 'Error: a working systemd --user session is required.\n' >&2; exit 1
    fi
fi

if [[ -d "$SHARE" && "$SOURCE_DIR" -ef "$SHARE" ]]; then
    printf 'Error: run install.sh from a checkout, not from its installed copy.\n' >&2
    exit 1
fi

if (( ! SKIP_SYSTEMD )) && systemctl --user is-active --quiet instinct-mail.service; then
    systemctl --user stop instinct-mail.service
fi
if [[ -e "$STATE_DIR/serve.lock" ]] && ! flock -n "$STATE_DIR/serve.lock" true; then
    printf 'Error: the receiver is active; stop it before replacing installed files.\n' >&2
    exit 1
fi

mkdir -p -- "$(dirname -- "$SHARE")"
STAGE_DIR=$(mktemp -d "${SHARE}.new.XXXXXX")
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

mkdir -p -- "$STAGE_DIR/scripts" "$STAGE_DIR/systemd" "$STAGE_DIR/docs" "$BIN_DIR" \
    "$CONFIG_DIR" "$STATE_DIR" "$SKILL_DIR"
chmod 700 "$CONFIG_DIR" "$STATE_DIR"
install -m 644 "$SOURCE_DIR/scripts/instinct_mail.py" "$STAGE_DIR/scripts/instinct_mail.py"
install -m 644 "$SOURCE_DIR/scripts/security_gate.py" "$STAGE_DIR/scripts/security_gate.py"
install -m 644 "$SOURCE_DIR/scripts/security_gate_tables.json" "$STAGE_DIR/scripts/security_gate_tables.json"
install -m 644 "$SOURCE_DIR/SKILL.md" "$STAGE_DIR/SKILL.md"
install -m 644 "$SOURCE_DIR/docs/security-gate.md" "$STAGE_DIR/docs/security-gate.md"
install -m 644 "$SOURCE_DIR/systemd/instinct-mail.service.in" "$STAGE_DIR/systemd/instinct-mail.service.in"
install -m 644 "$SOURCE_DIR/LICENSE" "$STAGE_DIR/LICENSE"
install -m 644 "$SOURCE_DIR/LICENSE.iva-agent" "$STAGE_DIR/LICENSE.iva-agent"
install -m 644 "$SOURCE_DIR/THIRD_PARTY_NOTICES" "$STAGE_DIR/THIRD_PARTY_NOTICES"
install -m 644 "$SOURCE_DIR/.env.example" "$STAGE_DIR/.env.example"
install -m 644 "$SOURCE_DIR/README.md" "$STAGE_DIR/README.md"
install -m 644 "$SOURCE_DIR/CHANGELOG.md" "$STAGE_DIR/CHANGELOG.md"
if [[ ! -e "$ENV_FILE" ]]; then
    install -m 600 "$SOURCE_DIR/.env.example" "$ENV_FILE"
else
    if [[ ! -f "$ENV_FILE" ]]; then
        printf 'Error: configuration path is not a regular file.\n' >&2; exit 1
    fi
    chmod 600 "$ENV_FILE"
fi
install -m 755 "$SOURCE_DIR/install.sh" "$STAGE_DIR/install.sh"
printf '#!/usr/bin/env bash\nexec %q %q "$@"\n' "$PYTHON" "$SHARE/scripts/instinct_mail.py" > "$WRAPPER"
chmod 755 "$WRAPPER"
install -m 644 "$SOURCE_DIR/SKILL.md" "$SKILL_DIR/SKILL.md"

if [[ -e "$SHARE" ]]; then
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

if (( ! SKIP_SYSTEMD )); then
    BB_DIR=$(dirname -- "$BB")
    SERVICE_PATH="$BIN_DIR:$BB_DIR:$PATH"
    if systemctl --user cat bb.service >/dev/null 2>&1; then
        DEPENDENCIES=$'BindsTo=bb.service\nAfter=bb.service'
        WANTED_BY=bb.service
    else
        DEPENDENCIES=
        WANTED_BY=default.target
    fi
    mkdir -p -- "$UNIT_DIR"
    "$PYTHON" - "$SHARE/systemd/instinct-mail.service.in" "$UNIT_FILE" \
        "$PYTHON" "$SHARE" "$SERVICE_PATH" "$DEPENDENCIES" "$WANTED_BY" <<'PY'
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
fi

printf 'Installed Instinct Mail command: %s\n' "$WRAPPER"
printf 'Configuration: %s (mode 600)\n' "$ENV_FILE"
printf 'State: %s\n' "$STATE_DIR"
if (( SKIP_SYSTEMD )); then
    printf 'Systemd service setup skipped.\n'
else
    printf 'Service: %s\n' "$(systemctl --user is-active instinct-mail.service)"
fi
