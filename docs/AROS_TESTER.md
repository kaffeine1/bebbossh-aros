# AROS Test Scripts

The scripts in `scripts/` drive a running `bebbosshd` from the host with
OpenSSH. They do not start VMs: boot the guest, start the daemon, forward its
port, then pass the port.

## Where to test

- Hosted AROS i386 and x86_64: the fast development loop (smoke, SCP/SFTP,
  stress). It does not replace a release test.
- QEMU AROS One i386 and x86_64: required before every i386 and x86_64 kit
  (clean install, startup, package layout). Use an rtl8139 or pcnet card on
  x86_64 (see `docs/AROS_X86_64_RELEASE.md`).
- Raspberry Pi: required before every aarch64 kit. QEMU `raspi3b` is fine for
  functional checks, too slow for transfers.

The release checklists are `docs/AROS_I386_RELEASE.md`,
`docs/AROS_X86_64_RELEASE.md` and `docs/AROS_AARCH64_RELEASE.md`.

## Common variables

```text
BEBBOSSH_AROS_HOST         default 127.0.0.1
BEBBOSSH_AROS_PORT         forwarded SSH port (lab convention: 10022 i386, 20022 x86_64)
BEBBOSSH_AROS_USER/PASS    default test/test
BEBBOSSH_AROS_WORKDIR      AROS directory for transfers, for example T: or SYS:TGTEST
BEBBOSSH_AROS_AUTH_HELPER  sshpass (default) or askpass
```

`askpass` passes the password through `SSH_ASKPASS`. Prefer it for long runs:
`sshpass` can miss the password prompt when connections follow each other
without delay. With `sshpass`, `sftp -b` needs `-oBatchMode=no`.

## Smoke test

```sh
BEBBOSSH_AROS_PORT=20022 \
BEBBOSSH_AROS_WORKDIR=SYS:TGTEST \
BEBBOSSH_AROS_SHELL_HOME=SYS: \
BEBBOSSH_AROS_TELEGRAM_TEST=SYS:TGTEST/telegram-test \
./scripts/aros-ssh-smoke-test.sh
```

Expected daemon behavior:

- Commands return their whole output and exit status.
- SFTP and OpenSSH `scp` work in the work directory.
- `ssh -tt ... version` works for short commands; the interactive shell runs
  `dir`, `cd`, `version` and `exit`.
- Redirection, pipes and programs that read their input are rejected with
  exit status 2; an unknown command gives 127.

## Transfer stress

```sh
BEBBOSSH_AROS_PORT=10022 \
BEBBOSSH_AROS_WORKDIR=SYS:TGTEST \
./scripts/aros-transfer-stress-test.sh
```

Defaults:

```text
BEBBOSSH_AROS_STRESS_ITERATIONS=20
BEBBOSSH_AROS_STRESS_SIZES="257 4096 65536 1048576"
BEBBOSSH_AROS_STRESS_DELAY=1
```

`BEBBOSSH_AROS_STRESS_DELAY=0` is the zero-delay regression test of the
release checklists; keep the default delay for routine automation.

## Public-key login and forwarding

```sh
BEBBOSSH_AROS_PORT=10022 \
BEBBOSSH_AROS_IDENTITY_FILE=/path/to/id_ed25519 \
BEBBOSSH_AROS_FORWARD_TARGET_HOST=10.255.223.1 \
BEBBOSSH_AROS_FORWARD_TARGET_PORT=39123 \
BEBBOSSH_AROS_FORWARD_LOCAL_PORT=23923 \
BEBBOSSH_AROS_FORWARD_PAYLOAD=bebbossh-forward-i386 \
./scripts/aros-auth-forward-test.sh
```

The forward target must already listen where the guest can reach it, for
example a host `nc -l` on the gateway address. With
`BEBBOSSH_AROS_INSTALL_AUTHORIZED_KEYS=1` the script creates a temporary
Ed25519 key and installs it in `ENVARC:.ssh/authorized_keys`.

## Release gate

`scripts/aros-release-gate.sh` runs the scripts above against several
daemons:

```sh
BEBBOSSH_GATE_QEMU_I386_PORT=10022 \
BEBBOSSH_GATE_QEMU_X64_PORT=20022 \
./scripts/aros-release-gate.sh
```

Paths in the VMs:

```text
BEBBOSSH_GATE_QEMU_I386_WORKDIR=DH0:TGTEST
BEBBOSSH_GATE_QEMU_I386_SHELL_HOME=DH0:
BEBBOSSH_GATE_QEMU_I386_TELEGRAM_TEST=DH0:TGTEST/telegram-test
BEBBOSSH_GATE_QEMU_X64_WORKDIR=AROS:TGTEST
BEBBOSSH_GATE_QEMU_X64_SHELL_HOME=AROS:
BEBBOSSH_GATE_QEMU_X64_TELEGRAM_TEST=AROS:TGTEST/telegram-test
```

`BEBBOSSH_GATE_QEMU_STRESS=1` adds the slower paced stress on the VMs.
Public-key and forwarding checks run when `BEBBOSSH_GATE_IDENTITY_FILE` and
the `BEBBOSSH_GATE_I386_FORWARD_TARGET_*` variables are set.

The public release smoke scripts (`scripts/aros-*-public-release-smoke.sh`)
are described in the release checklists.
