#!/usr/bin/env sh
set -eu

host=${BEBBOSSH_AROS_HOST:-127.0.0.1}
port=${BEBBOSSH_AROS_PORT:-10022}
user=${BEBBOSSH_AROS_USER:-test}
pass=${BEBBOSSH_AROS_PASS:-test}
known_hosts=${BEBBOSSH_AROS_KNOWN_HOSTS:-/tmp/bebbossh_aros_known_hosts}
telegram_test=${BEBBOSSH_AROS_TELEGRAM_TEST:-DH0:TGTEST/telegram-test}
workdir=${BEBBOSSH_AROS_WORKDIR:-DH0:TGTEST}

ssh_base_opts="-o StrictHostKeyChecking=no -o UserKnownHostsFile=$known_hosts -o ConnectTimeout=8 -o PreferredAuthentications=password -o PubkeyAuthentication=no"

need() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required command: $1" >&2
        exit 1
    fi
}

run_ssh() {
    sshpass -p "$pass" ssh $ssh_base_opts -p "$port" "$user@$host" "$@"
}

expect_rc() {
    expected=$1
    shift
    set +e
    "$@"
    rc=$?
    set -e
    if [ "$rc" -ne "$expected" ]; then
        echo "expected rc $expected, got $rc: $*" >&2
        exit 1
    fi
}

need ssh
need scp
need sshpass

rm -f "$known_hosts"

echo "1/6 ssh version"
expect_rc 0 run_ssh version

echo "2/6 rejected redirection"
expect_rc 2 run_ssh "version >/NIL:"

echo "3/6 daemon still healthy after redirection rejection"
expect_rc 0 run_ssh version

echo "4/6 telegram-amiga help command"
expect_rc 0 run_ssh "$telegram_test --help"

echo "5/6 telegram-amiga nonzero exit propagation"
expect_rc 1 run_ssh "$telegram_test --definitely-invalid-option"

echo "6/6 scp round trip on $workdir"
local_file=$(mktemp "${TMPDIR:-/tmp}/bebbossh-aros-scp.XXXXXX")
back_file=$(mktemp "${TMPDIR:-/tmp}/bebbossh-aros-scp-back.XXXXXX")
remote_file="$workdir/bebbossh-aros-smoke-test.txt"
trap 'rm -f "$local_file" "$back_file"' EXIT HUP INT TERM

printf 'bebbossh-aros smoke test\nhost=%s\nport=%s\n' "$host" "$port" > "$local_file"
sshpass -p "$pass" scp $ssh_base_opts -P "$port" "$local_file" "$user@$host:$remote_file"
sshpass -p "$pass" scp $ssh_base_opts -P "$port" "$user@$host:$remote_file" "$back_file"
cmp "$local_file" "$back_file"
expect_rc 0 run_ssh "delete $remote_file"

echo "ok"
