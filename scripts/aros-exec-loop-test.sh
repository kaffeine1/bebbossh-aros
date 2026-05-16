#!/usr/bin/env sh
set -eu

host=${BEBBOSSH_AROS_HOST:-127.0.0.1}
port=${BEBBOSSH_AROS_PORT:-10022}
user=${BEBBOSSH_AROS_USER:-test}
pass=${BEBBOSSH_AROS_PASS:-test}
known_hosts=${BEBBOSSH_AROS_KNOWN_HOSTS:-${TMPDIR:-/tmp}/bebbossh_aros_exec_known_hosts_${port}}
iterations=${BEBBOSSH_AROS_EXEC_ITERATIONS:-200}
command=${BEBBOSSH_AROS_EXEC_COMMAND:-C:Version}
auth_helper=${BEBBOSSH_AROS_AUTH_HELPER:-askpass}
extra_opts=${BEBBOSSH_AROS_SSH_OPTS:-}
askpass_file=
askpass_script=

ssh_base_opts="-o StrictHostKeyChecking=no -o UserKnownHostsFile=$known_hosts -o ConnectTimeout=8 -o PreferredAuthentications=password -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1"
if [ -n "$extra_opts" ]; then
    ssh_base_opts="$ssh_base_opts $extra_opts"
fi

need() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required command: $1" >&2
        exit 1
    fi
}

run_auth() {
    if [ "$auth_helper" = "askpass" ]; then
        DISPLAY=${DISPLAY:-none} \
        SSH_ASKPASS="$askpass_script" \
        SSH_ASKPASS_REQUIRE=force \
        BEBBOSSH_AROS_ASKPASS_FILE="$askpass_file" \
            "$@" </dev/null
    else
        sshpass -p "$pass" "$@"
    fi
}

setup_auth() {
    case "$auth_helper" in
        askpass)
            askpass_file=$(mktemp "${TMPDIR:-/tmp}/bebbossh-askpass-secret.XXXXXX")
            askpass_script=$(mktemp "${TMPDIR:-/tmp}/bebbossh-askpass.XXXXXX")
            printf '%s\n' "$pass" > "$askpass_file"
            cat > "$askpass_script" <<'EOF'
#!/bin/sh
cat "$BEBBOSSH_AROS_ASKPASS_FILE"
EOF
            chmod 600 "$askpass_file"
            chmod 700 "$askpass_script"
            ;;
        sshpass)
            need sshpass
            ;;
        *)
            echo "unsupported BEBBOSSH_AROS_AUTH_HELPER: $auth_helper" >&2
            exit 1
            ;;
    esac
}

cleanup() {
    rm -f "$askpass_file" "$askpass_script"
}
trap cleanup EXIT HUP INT TERM

need ssh
setup_auth
rm -f "$known_hosts"

i=1
while [ "$i" -le "$iterations" ]; do
    out=$(run_auth ssh $ssh_base_opts -p "$port" "$user@$host" "$command" 2>&1) || {
        printf 'fail: iteration %s/%s\n%s\n' "$i" "$iterations" "$out" >&2
        exit 1
    }
    case "$out" in
        *Kickstart*|*"SSH key saved"*|*"written"*)
            ;;
        *)
            printf 'fail: unexpected output at iteration %s/%s\n%s\n' "$i" "$iterations" "$out" >&2
            exit 1
            ;;
    esac
    if [ $((i % 100)) -eq 0 ]; then
        printf 'exec loop %s/%s\n' "$i" "$iterations"
    fi
    i=$((i + 1))
done

echo "ok"
