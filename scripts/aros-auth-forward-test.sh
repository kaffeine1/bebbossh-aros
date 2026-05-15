#!/usr/bin/env sh
set -eu

host=${BEBBOSSH_AROS_HOST:-127.0.0.1}
port=${BEBBOSSH_AROS_PORT:-10022}
user=${BEBBOSSH_AROS_USER:-test}
pass=${BEBBOSSH_AROS_PASS:-test}
known_hosts=${BEBBOSSH_AROS_KNOWN_HOSTS:-/tmp/bebbossh_aros_auth_forward_known_hosts}
identity_file=${BEBBOSSH_AROS_IDENTITY_FILE:-}
public_key_file=${BEBBOSSH_AROS_PUBLIC_KEY_FILE:-}
install_authorized_keys=${BEBBOSSH_AROS_INSTALL_AUTHORIZED_KEYS:-0}
authorized_keys=${BEBBOSSH_AROS_AUTHORIZED_KEYS:-ENVARC:.ssh/authorized_keys}
authorized_keys_dir=${BEBBOSSH_AROS_AUTHORIZED_KEYS_DIR:-ENVARC:.ssh}
pubkey_command=${BEBBOSSH_AROS_PUBKEY_COMMAND:-version}
forward_target_host=${BEBBOSSH_AROS_FORWARD_TARGET_HOST:-}
forward_target_port=${BEBBOSSH_AROS_FORWARD_TARGET_PORT:-}
forward_local_host=${BEBBOSSH_AROS_FORWARD_LOCAL_HOST:-127.0.0.1}
forward_local_port=${BEBBOSSH_AROS_FORWARD_LOCAL_PORT:-23922}
forward_payload=${BEBBOSSH_AROS_FORWARD_PAYLOAD:-}

password_opts="-o StrictHostKeyChecking=no -o UserKnownHostsFile=$known_hosts -o ConnectTimeout=8 -o ExitOnForwardFailure=yes -o PreferredAuthentications=password -o PubkeyAuthentication=no"
pubkey_opts="-o StrictHostKeyChecking=no -o UserKnownHostsFile=$known_hosts -o ConnectTimeout=8 -o ExitOnForwardFailure=yes -o PreferredAuthentications=publickey -o PasswordAuthentication=no -o IdentitiesOnly=yes"

tmpdir=
ssh_pid=

need() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required command: $1" >&2
        exit 1
    fi
}

cleanup() {
    if [ -n "$ssh_pid" ]; then
        kill "$ssh_pid" >/dev/null 2>&1 || true
        wait "$ssh_pid" >/dev/null 2>&1 || true
    fi
    if [ -n "$tmpdir" ]; then
        rm -rf "$tmpdir"
    fi
}

password_ssh() {
    sshpass -p "$pass" ssh $password_opts -p "$port" "$user@$host" "$@"
}

password_scp() {
    sshpass -p "$pass" scp $password_opts -P "$port" "$@"
}

pubkey_ssh() {
    ssh -i "$identity_file" $pubkey_opts -p "$port" "$user@$host" "$@"
}

generate_identity() {
    tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/bebbossh-aros-auth.XXXXXX")
    identity_file="$tmpdir/id_ed25519"
    public_key_file="$identity_file.pub"
    ssh-keygen -q -t ed25519 -N '' -f "$identity_file"
}

resolve_public_key_file() {
    if [ -n "$public_key_file" ]; then
        return
    fi
    if [ -f "$identity_file.pub" ]; then
        public_key_file="$identity_file.pub"
        return
    fi
    echo "set BEBBOSSH_AROS_PUBLIC_KEY_FILE for identity without .pub companion" >&2
    exit 1
}

install_key() {
    need sshpass
    need scp
    if [ -z "$identity_file" ]; then
        need ssh-keygen
        generate_identity
    fi
    resolve_public_key_file
    password_ssh "makedir $authorized_keys_dir" >/dev/null 2>&1 || true
    password_scp "$public_key_file" "$user@$host:$authorized_keys"
}

test_public_key() {
    if [ -z "$identity_file" ]; then
        echo "skip: public-key auth, set BEBBOSSH_AROS_IDENTITY_FILE or BEBBOSSH_AROS_INSTALL_AUTHORIZED_KEYS=1"
        return 0
    fi
    echo "public-key auth"
    pubkey_ssh "$pubkey_command" >/dev/null
}

test_forward() {
    if [ -z "$forward_target_host" ] || [ -z "$forward_target_port" ]; then
        echo "skip: direct-tcpip forwarding, set BEBBOSSH_AROS_FORWARD_TARGET_HOST and BEBBOSSH_AROS_FORWARD_TARGET_PORT"
        return 0
    fi
    need nc
    echo "direct-tcpip forwarding to $forward_target_host:$forward_target_port"

    if [ -n "$identity_file" ]; then
        ssh -i "$identity_file" -N $pubkey_opts \
            -L "$forward_local_host:$forward_local_port:$forward_target_host:$forward_target_port" \
            -p "$port" "$user@$host" &
    else
        need sshpass
        sshpass -p "$pass" ssh -N $password_opts \
            -L "$forward_local_host:$forward_local_port:$forward_target_host:$forward_target_port" \
            -p "$port" "$user@$host" &
    fi
    ssh_pid=$!

    sleep "${BEBBOSSH_AROS_FORWARD_START_DELAY:-1}"
    if ! kill -0 "$ssh_pid" >/dev/null 2>&1; then
        wait "$ssh_pid" >/dev/null 2>&1 || true
        ssh_pid=
        echo "forward ssh process exited before test traffic" >&2
        return 1
    fi

    if [ -n "$forward_payload" ]; then
        printf '%s\n' "$forward_payload" | nc -w 2 "$forward_local_host" "$forward_local_port"
    else
        nc -z "$forward_local_host" "$forward_local_port"
    fi
}

need ssh
rm -f "$known_hosts"
trap cleanup EXIT HUP INT TERM

if [ "$install_authorized_keys" = "1" ]; then
    install_key
fi

test_public_key
test_forward
echo "ok"
