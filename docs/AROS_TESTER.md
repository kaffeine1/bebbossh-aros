# AROS Hosted Tester Notes

These notes describe the hosted AROS SSH test setup used by downstream
automation such as telegram-amiga.

## Runtime Targets

Use OpenSSH with password authentication and an isolated known-hosts file.

```sh
sshpass -p test ssh \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/tmp/bebbossh_aros_known_hosts \
  -o PreferredAuthentications=password \
  -o PubkeyAuthentication=no \
  -p 20022 test@127.0.0.1 \
  'SYS:TGTEST/telegram-test --help'
```

Current hosted target ports:

- x86_64 hosted AROS: local tunnel port `20022`.
- i386 hosted AROS: local tunnel port `10022`.

The hosted test work directory is `SYS:TGTEST`. Do not assume `DH0:` exists in
hosted runs. Avoid `RAM:` for automated transfer tests.

## Test Tiers

Use hosted AROS for the fast development loop and QEMU AROS One VMs for release
validation.

- Hosted i386/x86_64: required for routine smoke, SCP/SFTP, and zero-delay
  connection-churn regression tests.
- QEMU AROS One i386: required before publishing an i386 runtime kit, because
  it validates the release-style filesystem, startup path, and package layout.
- QEMU AROS One x86_64: required before promoting x86_64 beyond experimental,
  because hosted x86_64 does not prove the non-hosted AROS One daemon path.

The release gate does not start QEMU VMs. Boot the VM, start or autostart
`bebbosshd`, expose its guest SSH port through QEMU forwarding, then pass the
forwarded port to `scripts/aros-release-gate.sh`.

```sh
BEBBOSSH_GATE_QEMU_I386_PORT=10022 \
BEBBOSSH_GATE_QEMU_X64_PORT=20022 \
./scripts/aros-release-gate.sh
```

If the QEMU VM uses different paths, override them explicitly:

```sh
BEBBOSSH_GATE_QEMU_I386_WORKDIR=DH0:TGTEST
BEBBOSSH_GATE_QEMU_I386_SHELL_HOME=DH0:
BEBBOSSH_GATE_QEMU_I386_TELEGRAM_TEST=DH0:TGTEST/telegram-test
BEBBOSSH_GATE_QEMU_X64_WORKDIR=AROS:TGTEST
BEBBOSSH_GATE_QEMU_X64_SHELL_HOME=AROS:
BEBBOSSH_GATE_QEMU_X64_TELEGRAM_TEST=AROS:TGTEST/telegram-test
```

QEMU paced transfer stress is optional and disabled by default because it is
slower than hosted stress:

```sh
BEBBOSSH_GATE_QEMU_STRESS=1 ./scripts/aros-release-gate.sh
```

## Expected BebboSSHd Behavior

- Non-interactive commands return complete output and preserve exit status.
- SFTP and OpenSSH scp work on `SYS:TGTEST`.
- `ssh -tt ... version` works for simple bounded commands.
- The minimal interactive shell can run `dir`, `cd`, `version`, and `exit`.
- Shell redirection and pipes are rejected with exit status `2`.
- Stdin-driven interactive programs are rejected with exit status `2` until a
  stable AROS console/file-handle backend exists.

## Smoke Test

From this repository:

```sh
BEBBOSSH_AROS_PORT=20022 \
BEBBOSSH_AROS_WORKDIR=SYS:TGTEST \
BEBBOSSH_AROS_SHELL_HOME=SYS: \
BEBBOSSH_AROS_TELEGRAM_TEST=SYS:TGTEST/telegram-test \
./scripts/aros-ssh-smoke-test.sh
```

Use `BEBBOSSH_AROS_PORT=10022` for hosted i386.

## Transfer Stress

For repeated SCP/SFTP validation:

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

Keep the default delay for downstream automation. Zero-delay mode is available
as an explicit regression stress test:

```sh
BEBBOSSH_AROS_STRESS_DELAY=0 ./scripts/aros-transfer-stress-test.sh
```

## Public-Key Auth And Forwarding

`scripts/aros-auth-forward-test.sh` validates OpenSSH public-key login and,
when a reachable target is supplied, `direct-tcpip` forwarding.

```sh
BEBBOSSH_AROS_PORT=10022 \
BEBBOSSH_AROS_IDENTITY_FILE=/path/to/id_ed25519 \
BEBBOSSH_AROS_FORWARD_TARGET_HOST=10.255.223.1 \
BEBBOSSH_AROS_FORWARD_TARGET_PORT=39123 \
BEBBOSSH_AROS_FORWARD_LOCAL_PORT=23923 \
BEBBOSSH_AROS_FORWARD_PAYLOAD=bebbossh-forward-i386 \
./scripts/aros-auth-forward-test.sh
```

The target service must already be listening from the guest's network view. In
the hosted lab this is normally a host-side `nc -l` bound to the TAP gateway
address. For disposable runtimes, the script can generate a temporary Ed25519
key and install the public key to `ENVARC:.ssh/authorized_keys` when
`BEBBOSSH_AROS_INSTALL_AUTHORIZED_KEYS=1` is set.

The release gate can run the same checks when the identity and target are
provided:

```sh
BEBBOSSH_GATE_IDENTITY_FILE=/path/to/id_ed25519 \
BEBBOSSH_GATE_I386_FORWARD_TARGET_HOST=10.255.223.1 \
BEBBOSSH_GATE_I386_FORWARD_TARGET_PORT=39123 \
BEBBOSSH_GATE_I386_FORWARD_PAYLOAD=bebbossh-forward-i386 \
./scripts/aros-release-gate.sh
```

## Current Validation

The hosted x86_64 and i386 runtimes have passed this smoke test with
`BEBBOSSH_AROS_WORKDIR=SYS:TGTEST`, including SCP/SFTP round-trips and 1 MiB
plus 5 MiB transfer stress. Both runtimes also passed the telegram-amiga
offline checks for JSON, getUpdates, inbox, sendMessage, client-state, and
TLS-status. Both hosted runtimes also passed public-key authentication and
`direct-tcpip` forwarding to a host-side TCP listener through their TAP
gateway addresses.

After accept-loop hardening, hosted i386 passed 3 zero-delay transfer stress
iterations with sizes `257 4096 65536 1048576` on `SYS:TGTEST`. Hosted x86_64
now passes the focused 5-iteration zero-delay transfer stress target with the
same sizes after the server loop was changed to service accepted sockets and
already-ready client sockets in the same iteration. The aggregate hosted gate
still has an intermittent x86_64 password-auth failure during zero-delay churn
after the smoke phase. Keep paced stress enabled for routine automation, and
run zero-delay stress as an explicit short-session robustness regression.
