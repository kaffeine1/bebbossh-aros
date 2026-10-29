#!/usr/bin/env sh
# AROS x86_64 public-release smoke. Mirrors the i386 release smoke but targets
# the bebbossh-aros-x86_64-* runtime kit. Copyright (C) 2026 Michele Dipace
# <michele.dipace@kaffeine.net>
set -eu

repo=${BEBBOSSH_RELEASE_REPO:-kaffeine1/bebbossh-aros}
tag=${BEBBOSSH_RELEASE_TAG:-v1.0.8-aros-x86_64}
version=${BEBBOSSH_RELEASE_VERSION:-v1.0.8}
base="bebbossh-aros-x86_64-$version"
# Defaults match the v1.0.8 release archives. Override at release time.
expected_zip=${BEBBOSSH_RELEASE_ZIP_SHA256:-e772117194bac7d44205b922ca4fc4c204a0a6ddd9b884d9e64b464343ebfbc7}
expected_tgz=${BEBBOSSH_RELEASE_TGZ_SHA256:-cf22d2c02f21d4c51b6ded5a8d584efc812f5806f56e1c416702e38b40e571f0}

host=${BEBBOSSH_AROS_HOST:-127.0.0.1}
port=${BEBBOSSH_AROS_PORT:-}
user=${BEBBOSSH_AROS_USER:-test}
pass=${BEBBOSSH_AROS_PASS:-test}
workdir=${BEBBOSSH_AROS_WORKDIR:-T:}
known_hosts=${BEBBOSSH_AROS_KNOWN_HOSTS:-${TMPDIR:-/tmp}/bebbossh_release_x86_64_known_hosts_${port:-none}}
auth_helper=${BEBBOSSH_AROS_AUTH_HELPER:-sshpass}
askpass_file=
askpass_script=

tmpdir=

need() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required command: $1" >&2
        exit 1
    fi
}

cleanup() {
    if [ -n "$tmpdir" ]; then
        rm -rf "$tmpdir"
    fi
    rm -f "$askpass_file" "$askpass_script"
}
trap cleanup EXIT HUP INT TERM

sha256_of() {
    shasum -a 256 "$1" | awk '{print $1}'
}

check_hash() {
    file=$1
    expected=$2
    if [ -z "$expected" ]; then
        echo "skip: sha256 $(basename "$file") (no expected value set)"
        return
    fi
    actual=$(sha256_of "$file")
    if [ "$actual" != "$expected" ]; then
        echo "sha256 mismatch for $file" >&2
        echo "expected: $expected" >&2
        echo "actual:   $actual" >&2
        exit 1
    fi
    echo "ok: sha256 $(basename "$file")"
}

check_tar_member() {
    archive=$1
    member=$2
    if ! tar -tzf "$archive" "$member" >/dev/null 2>&1; then
        echo "missing tar member: $member" >&2
        exit 1
    fi
}

check_package_contents() {
    archive=$1
    root=$2

    check_tar_member "$archive" "$root/bebbossh"
    check_tar_member "$archive" "$root/bebboscp"
    check_tar_member "$archive" "$root/bebbosshd"
    check_tar_member "$archive" "$root/bebbosshkeygen"
    check_tar_member "$archive" "$root/README.AROS.txt"
    check_tar_member "$archive" "$root/README.md"
    check_tar_member "$archive" "$root/AROS_PORTING.md"
    check_tar_member "$archive" "$root/COPYING"
    check_tar_member "$archive" "$root/LICENSE"
    check_tar_member "$archive" "$root/SHA256SUMS"
    check_tar_member "$archive" "$root/sshd_config.example"
    check_tar_member "$archive" "$root/passwd.example"

    if tar -tzf "$archive" | grep -i 'hosted' >/dev/null 2>&1; then
        echo "unexpected hosted artifact in public x86_64 kit" >&2
        exit 1
    fi

    echo "ok: package content"
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

run_ssh() {
    run_auth ssh \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile="$known_hosts" \
        -o ConnectTimeout=8 \
        -o PreferredAuthentications=password \
        -o PubkeyAuthentication=no \
        -p "$port" "$user@$host" "$@"
}

run_scp() {
    run_auth scp \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile="$known_hosts" \
        -o ConnectTimeout=8 \
        -o PreferredAuthentications=password \
        -o PubkeyAuthentication=no \
        -P "$port" "$@"
}

run_sftp() {
    run_auth sftp \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile="$known_hosts" \
        -o ConnectTimeout=8 \
        -o PreferredAuthentications=password \
        -o PubkeyAuthentication=no \
        -oBatchMode=no \
        -P "$port" "$@"
}

remote_join() {
    dir=$1
    name=$2
    case "$dir" in
        *:) printf '%s%s\n' "$dir" "$name" ;;
        */) printf '%s%s\n' "$dir" "$name" ;;
        *) printf '%s/%s\n' "$dir" "$name" ;;
    esac
}

runtime_smoke() {
    need ssh
    need scp
    need sftp
    setup_auth

    rm -f "$known_hosts"
    echo "runtime smoke: $host:$port workdir=$workdir"

    run_ssh version | grep "Kickstart" >/dev/null

    local_file=$(mktemp "${TMPDIR:-/tmp}/bebbossh-release-scp.XXXXXX")
    scp_back=$(mktemp "${TMPDIR:-/tmp}/bebbossh-release-scp-back.XXXXXX")
    sftp_back=$(mktemp "${TMPDIR:-/tmp}/bebbossh-release-sftp-back.XXXXXX")
    sftp_batch=$(mktemp "${TMPDIR:-/tmp}/bebbossh-release-sftp.XXXXXX")
    remote_file=$(remote_join "$workdir" "bebbossh-release-smoke.txt")
    sftp_file=$(remote_join "$workdir" "bebbossh-release-sftp.txt")

    printf 'bebbossh x86_64 public release smoke\n' > "$local_file"
    run_scp "$local_file" "$user@$host:$remote_file"
    run_scp "$user@$host:$remote_file" "$scp_back"
    cmp "$local_file" "$scp_back"
    run_ssh "delete $remote_file"

    cat > "$sftp_batch" <<EOF
put $local_file $sftp_file
get $sftp_file $sftp_back
rm $sftp_file
EOF
    run_sftp -b "$sftp_batch" "$user@$host"
    cmp "$local_file" "$sftp_back"

    rm -f "$local_file" "$scp_back" "$sftp_back" "$sftp_batch"
    echo "ok: runtime smoke"
}

need gh
need shasum
need tar

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/bebbossh-release-x86_64.XXXXXX")
echo "download: $repo $tag"
gh release download "$tag" --repo "$repo" --dir "$tmpdir" --pattern "$base.*"

zip_file="$tmpdir/$base.zip"
tgz_file="$tmpdir/$base.tar.gz"
test -f "$zip_file"
test -f "$tgz_file"

check_hash "$zip_file" "$expected_zip"
check_hash "$tgz_file" "$expected_tgz"
check_package_contents "$tgz_file" "$base"

if [ -n "$port" ]; then
    runtime_smoke
else
    echo "skip: runtime smoke; set BEBBOSSH_AROS_PORT for a clean x86_64 VM"
fi

echo "ok"
