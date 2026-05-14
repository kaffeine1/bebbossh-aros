#!/usr/bin/env sh
set -eu

status=0
step_skipped=0

ok() {
    printf 'ok: %s\n' "$*"
}

skip() {
    printf 'skip: %s\n' "$*"
    step_skipped=1
}

fail() {
    printf 'fail: %s\n' "$*" >&2
    status=1
}

need() {
    command -v "$1" >/dev/null 2>&1
}

run_step() {
    name=$1
    shift
    step_skipped=0
    printf '== %s ==\n' "$name"
    if "$@"; then
        if [ "$step_skipped" -eq 0 ]; then
            ok "$name"
        fi
    else
        fail "$name"
    fi
}

run_cmd() {
    "$@"
}

build_x86_64() {
    toolchain=${BEBBOSSH_AROS_X86_64_TOOLCHAIN:-}
    sdk=${BEBBOSSH_AROS_X86_64_SDK:-}
    outdir=${BEBBOSSH_AROS_X86_64_OUTDIR:-aros-x86_64-gate}

    if [ -z "$toolchain" ] || [ -z "$sdk" ]; then
        skip "x86_64 build: set BEBBOSSH_AROS_X86_64_TOOLCHAIN and BEBBOSSH_AROS_X86_64_SDK"
        return 0
    fi

    run_cmd make -f Makefile.aros-x86_64 bebbosshd bebbosshkeygen probes \
        OUTDIR="$outdir" \
        CC="$toolchain/x86_64-aros-gcc" \
        CXX="$toolchain/x86_64-aros-g++" \
        AR="$toolchain/x86_64-aros-ar" \
        STRIP="$toolchain/x86_64-aros-strip" \
        OBJCOPY="$toolchain/x86_64-aros-objcopy" \
        AROS_SDK_ROOT="$sdk"
}

smoke_target() {
    label=$1
    port=$2
    workdir=$3
    shell_home=$4
    telegram_test=$5
    sizes=$6

    if [ -z "$port" ]; then
        skip "$label smoke: no port configured"
        return 0
    fi

    BEBBOSSH_AROS_PORT="$port" \
    BEBBOSSH_AROS_WORKDIR="$workdir" \
    BEBBOSSH_AROS_SHELL_HOME="$shell_home" \
    BEBBOSSH_AROS_TELEGRAM_TEST="$telegram_test" \
    BEBBOSSH_AROS_TRANSFER_SIZES="$sizes" \
        ./scripts/aros-ssh-smoke-test.sh
}

stress_target() {
    label=$1
    port=$2
    workdir=$3
    iterations=$4
    sizes=$5
    delay=$6

    if [ -z "$port" ]; then
        skip "$label stress: no port configured"
        return 0
    fi

    BEBBOSSH_AROS_PORT="$port" \
    BEBBOSSH_AROS_WORKDIR="$workdir" \
    BEBBOSSH_AROS_STRESS_ITERATIONS="$iterations" \
    BEBBOSSH_AROS_STRESS_SIZES="$sizes" \
    BEBBOSSH_AROS_STRESS_DELAY="$delay" \
        ./scripts/aros-transfer-stress-test.sh
}

printf 'BebboSSH AROS release gate\n'

need ssh || fail "missing ssh"
need scp || fail "missing scp"
need sftp || fail "missing sftp"
need sshpass || skip "sshpass missing: runtime SSH tests will be skipped unless installed"

run_step "shell syntax: smoke script" run_cmd sh -n scripts/aros-ssh-smoke-test.sh
run_step "shell syntax: transfer stress script" run_cmd sh -n scripts/aros-transfer-stress-test.sh
run_step "shell syntax: release gate script" run_cmd sh -n scripts/aros-release-gate.sh
run_step "x86_64 build plus probes" build_x86_64

if need sshpass; then
    hosted_sizes=${BEBBOSSH_GATE_TRANSFER_SIZES:-"1048576 5242880 10485760 26214400"}
    hosted_stress_sizes=${BEBBOSSH_GATE_STRESS_SIZES:-"257 4096 65536 1048576"}
    x64_port=${BEBBOSSH_GATE_X64_PORT:-}
    i386_port=${BEBBOSSH_GATE_I386_PORT:-}
    x64_workdir=${BEBBOSSH_GATE_X64_WORKDIR:-SYS:TGTEST}
    i386_workdir=${BEBBOSSH_GATE_I386_WORKDIR:-SYS:TGTEST}
    x64_shell_home=${BEBBOSSH_GATE_X64_SHELL_HOME:-SYS:}
    i386_shell_home=${BEBBOSSH_GATE_I386_SHELL_HOME:-SYS:}
    x64_telegram=${BEBBOSSH_GATE_X64_TELEGRAM_TEST:-SYS:TGTEST/telegram-test}
    i386_telegram=${BEBBOSSH_GATE_I386_TELEGRAM_TEST:-SYS:TGTEST/telegram-test}

    run_step "hosted x86_64 smoke" smoke_target x86_64 "$x64_port" "$x64_workdir" "$x64_shell_home" "$x64_telegram" "$hosted_sizes"
    run_step "hosted i386 smoke" smoke_target i386 "$i386_port" "$i386_workdir" "$i386_shell_home" "$i386_telegram" "$hosted_sizes"
    run_step "hosted x86_64 zero-delay stress" stress_target x86_64 "$x64_port" "$x64_workdir" "${BEBBOSSH_GATE_X64_STRESS_ITERATIONS:-5}" "$hosted_stress_sizes" 0
    run_step "hosted i386 zero-delay stress" stress_target i386 "$i386_port" "$i386_workdir" "${BEBBOSSH_GATE_I386_STRESS_ITERATIONS:-3}" "$hosted_stress_sizes" 0
else
    skip "runtime SSH tests"
fi

if [ -z "${BEBBOSSH_GATE_AROS_ONE_X64_PORT:-}" ]; then
    skip "AROS One x86_64 daemon validation: set BEBBOSSH_GATE_AROS_ONE_X64_PORT when the VM is reachable"
else
    run_step "AROS One x86_64 smoke" smoke_target aros-one-x86_64 \
        "$BEBBOSSH_GATE_AROS_ONE_X64_PORT" \
        "${BEBBOSSH_GATE_AROS_ONE_X64_WORKDIR:-AROS:BSSHOK}" \
        "${BEBBOSSH_GATE_AROS_ONE_X64_SHELL_HOME:-AROS:}" \
        "${BEBBOSSH_GATE_AROS_ONE_X64_TELEGRAM_TEST:-AROS:TGTEST/telegram-test}" \
        "${BEBBOSSH_GATE_AROS_ONE_X64_TRANSFER_SIZES:-1048576}"
fi

exit "$status"
