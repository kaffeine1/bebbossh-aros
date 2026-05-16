#!/usr/bin/env sh
set -eu

host=${BEBBOSSH_AROS_HOST:-127.0.0.1}
port=${BEBBOSSH_AROS_PORT:-10022}
user=${BEBBOSSH_AROS_USER:-test}
pass=${BEBBOSSH_AROS_PASS:-test}
known_hosts=${BEBBOSSH_AROS_KNOWN_HOSTS:-${TMPDIR:-/tmp}/bebbossh_aros_stress_known_hosts_${port}}
workdir=${BEBBOSSH_AROS_WORKDIR:-DH0:TGTEST}
iterations=${BEBBOSSH_AROS_STRESS_ITERATIONS:-20}
sizes=${BEBBOSSH_AROS_STRESS_SIZES:-"257 4096 65536 1048576"}
delay=${BEBBOSSH_AROS_STRESS_DELAY:-1}
extra_opts=${BEBBOSSH_AROS_SSH_OPTS:-}
auth_helper=${BEBBOSSH_AROS_AUTH_HELPER:-sshpass}
askpass_file=
askpass_script=

ssh_base_opts="-o StrictHostKeyChecking=no -o UserKnownHostsFile=$known_hosts -o ConnectTimeout=8 -o PreferredAuthentications=password -o PubkeyAuthentication=no"
if [ -n "$extra_opts" ]; then
    ssh_base_opts="$ssh_base_opts $extra_opts"
fi

need() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required command: $1" >&2
        exit 1
    fi
}

run_ssh() {
    run_auth ssh $ssh_base_opts -p "$port" "$user@$host" "$@"
}

remote_delete() {
    run_ssh "delete $1" >/dev/null 2>&1 || true
}

run_auth() {
    if [ "$auth_helper" = "askpass" ]; then
        DISPLAY=${DISPLAY:-none} \
        SSH_ASKPASS="$askpass_script" \
        SSH_ASKPASS_REQUIRE=force \
        BEBBOSSH_AROS_ASKPASS_FILE="$askpass_file" \
            "$@"
    else
        sshpass -p "$pass" "$@"
    fi
}

setup_auth() {
    case "$auth_helper" in
        sshpass)
            need sshpass
            ;;
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
        *)
            echo "unsupported BEBBOSSH_AROS_AUTH_HELPER: $auth_helper" >&2
            exit 1
            ;;
    esac
}

need cmp
need dd
need scp
need sftp
need ssh
setup_auth

rm -f "$known_hosts"

tmp_files=""
cleanup() {
    for f in $tmp_files; do
        rm -f "$f"
    done
    rm -f "$askpass_file" "$askpass_script"
}
trap cleanup EXIT HUP INT TERM

echo "transfer stress target: $host:$port $workdir"
run_ssh version >/dev/null

i=1
while [ "$i" -le "$iterations" ]; do
    for size in $sizes; do
        tag="bebbossh-stress-${i}-${size}-$$"
        local_file=$(mktemp "${TMPDIR:-/tmp}/bebbossh-stress-local.XXXXXX")
        scp_back=$(mktemp "${TMPDIR:-/tmp}/bebbossh-stress-scp-back.XXXXXX")
        sftp_back=$(mktemp "${TMPDIR:-/tmp}/bebbossh-stress-sftp-back.XXXXXX")
        sftp_batch=$(mktemp "${TMPDIR:-/tmp}/bebbossh-stress-batch.XXXXXX")
        tmp_files="$tmp_files $local_file $scp_back $sftp_back $sftp_batch"

        remote_file="$workdir/$tag.bin"

        echo "iteration $i/$iterations size $size"
        dd if=/dev/urandom of="$local_file" bs="$size" count=1 >/dev/null 2>&1

        run_auth scp $ssh_base_opts -P "$port" "$local_file" "$user@$host:$remote_file"
        run_auth scp $ssh_base_opts -P "$port" "$user@$host:$remote_file" "$scp_back"
        cmp "$local_file" "$scp_back"

        cat > "$sftp_batch" <<EOF
put $local_file $remote_file
get $remote_file $sftp_back
rm $remote_file
EOF
        run_auth sftp -oBatchMode=no $ssh_base_opts -P "$port" -b "$sftp_batch" "$user@$host"
        cmp "$local_file" "$sftp_back"

        remote_delete "$remote_file"
        run_ssh version >/dev/null

        rm -f "$local_file" "$scp_back" "$sftp_back" "$sftp_batch"
        tmp_files=""

        if [ "$delay" != "0" ]; then
            sleep "$delay"
        fi
    done
    i=$((i + 1))
done

echo "ok"
