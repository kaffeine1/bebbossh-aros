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

## Current Validation

The hosted x86_64 and i386 runtimes have passed this smoke test with
`BEBBOSSH_AROS_WORKDIR=SYS:TGTEST`, including SCP/SFTP round-trips and 1 MiB
plus 5 MiB transfer stress. Both runtimes also passed the telegram-amiga
offline checks for JSON, getUpdates, inbox, sendMessage, client-state, and
TLS-status.

After backlog/accept-loop hardening, hosted x86_64 passed 5 zero-delay transfer
stress iterations and hosted i386 passed 3 zero-delay transfer stress iterations
with sizes `257 4096 65536 1048576` on `SYS:TGTEST`. Hosted runtime logs showed
no trap after these runs. Keep paced stress enabled for routine validation, and
run zero-delay stress only when specifically checking short-session robustness.
