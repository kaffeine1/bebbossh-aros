#!/usr/bin/env sh
set -eu

host=${BEBBOSSH_AROS_HOST:-127.0.0.1}
port=${BEBBOSSH_AROS_PORT:-10022}
user=${BEBBOSSH_AROS_USER:-test}
pass=${BEBBOSSH_AROS_PASS:-test}
known_hosts=${BEBBOSSH_AROS_KNOWN_HOSTS:-/tmp/bebbossh_aros_known_hosts}
telegram_test=${BEBBOSSH_AROS_TELEGRAM_TEST:-DH0:TGTEST/telegram-test}
workdir=${BEBBOSSH_AROS_WORKDIR:-DH0:TGTEST}
transfer_sizes=${BEBBOSSH_AROS_TRANSFER_SIZES:-"1048576 5242880"}

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
need sftp
need sshpass

rm -f "$known_hosts"

echo "1/10 ssh version"
expect_rc 0 run_ssh version

echo "2/10 rejected redirection"
expect_rc 2 run_ssh "version >/NIL:"

echo "3/10 daemon still healthy after redirection rejection"
expect_rc 0 run_ssh version

echo "4/10 non-PTY interactive command guard"
expect_rc 2 run_ssh "more ?"

echo "5/10 daemon still healthy after non-PTY guard"
expect_rc 0 run_ssh version

echo "6/10 telegram-amiga help command"
expect_rc 0 run_ssh "$telegram_test --help"

echo "7/10 telegram-amiga nonzero exit propagation"
expect_rc 1 run_ssh "$telegram_test --definitely-invalid-option"

echo "8/10 PTY exec command"
pty_out=$(mktemp "${TMPDIR:-/tmp}/bebbossh-aros-pty.XXXXXX")
(sleep 1; :) | sshpass -p "$pass" ssh -tt $ssh_base_opts -p "$port" "$user@$host" version > "$pty_out" 2>&1
grep "Kickstart" "$pty_out" >/dev/null

echo "9/10 interactive shell sequence"
shell_out=$(mktemp "${TMPDIR:-/tmp}/bebbossh-aros-shell.XXXXXX")
(sleep 1; printf 'dir\ncd %s\nversion\ncd DH0:\nexit\n' "$workdir") | \
  sshpass -p "$pass" ssh -tt $ssh_base_opts -p "$port" "$user@$host" > "$shell_out" 2>&1
grep "Kickstart" "$shell_out" >/dev/null

echo "10/10 scp and sftp round trips on $workdir"
local_file=$(mktemp "${TMPDIR:-/tmp}/bebbossh-aros-scp.XXXXXX")
back_file=$(mktemp "${TMPDIR:-/tmp}/bebbossh-aros-scp-back.XXXXXX")
remote_file="$workdir/bebbossh-aros-smoke-test.txt"
sftp_back_file=$(mktemp "${TMPDIR:-/tmp}/bebbossh-aros-sftp-back.XXXXXX")
sftp_batch=$(mktemp "${TMPDIR:-/tmp}/bebbossh-aros-sftp-batch.XXXXXX")
sftp_dir="$workdir/bebbossh-aros-sftp-test"
sftp_remote_file="$sftp_dir/payload.txt"
trap 'rm -f "$local_file" "$back_file" "$sftp_back_file" "$sftp_batch" "$pty_out" "$shell_out"' EXIT HUP INT TERM

printf 'bebbossh-aros smoke test\nhost=%s\nport=%s\n' "$host" "$port" > "$local_file"
sshpass -p "$pass" scp $ssh_base_opts -P "$port" "$local_file" "$user@$host:$remote_file"
sshpass -p "$pass" scp $ssh_base_opts -P "$port" "$user@$host:$remote_file" "$back_file"
cmp "$local_file" "$back_file"
expect_rc 0 run_ssh "delete $remote_file"

cat > "$sftp_batch" <<EOF
-rm $sftp_remote_file
-rmdir $sftp_dir
mkdir $sftp_dir
put $local_file $sftp_remote_file
get $sftp_remote_file $sftp_back_file
rm $sftp_remote_file
rmdir $sftp_dir
EOF

sshpass -p "$pass" sftp -oBatchMode=no $ssh_base_opts -P "$port" -b "$sftp_batch" "$user@$host"
cmp "$local_file" "$sftp_back_file"

for size in $transfer_sizes; do
    echo "transfer stress ${size} bytes on $workdir"
    stress_local=$(mktemp "${TMPDIR:-/tmp}/bebbossh-aros-stress.XXXXXX")
    stress_back=$(mktemp "${TMPDIR:-/tmp}/bebbossh-aros-stress-back.XXXXXX")
    stress_batch=$(mktemp "${TMPDIR:-/tmp}/bebbossh-aros-stress-batch.XXXXXX")
    stress_remote="$workdir/bebbossh-aros-stress-${size}.bin"
    dd if=/dev/urandom of="$stress_local" bs="$size" count=1 >/dev/null 2>&1
    sshpass -p "$pass" scp $ssh_base_opts -P "$port" "$stress_local" "$user@$host:$stress_remote"
    sshpass -p "$pass" scp $ssh_base_opts -P "$port" "$user@$host:$stress_remote" "$stress_back"
    cmp "$stress_local" "$stress_back"
    rm -f "$stress_back"
    cat > "$stress_batch" <<EOF
put $stress_local $stress_remote
get $stress_remote $stress_back
rm $stress_remote
EOF
    sshpass -p "$pass" sftp -oBatchMode=no $ssh_base_opts -P "$port" -b "$stress_batch" "$user@$host"
    cmp "$stress_local" "$stress_back"
    rm -f "$stress_local" "$stress_back" "$stress_batch"
done

echo "ok"
