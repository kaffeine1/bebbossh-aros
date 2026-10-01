# AROS x86_64 Release Checklist

This checklist is for AROS One / VMware 64-bit `x86_64` runtime kits. It mirrors
`docs/AROS_I386_RELEASE.md`. As of v1.0.0 the `mincrt` x86_64 build is **stable**
(closure gates at the end of this document all passed); use this checklist
for every subsequent release.

## Scope

The x86_64 runtime kit is the AROS One / VMware 64-bit package. It contains:

- `bebbossh`
- `bebboscp`
- `bebbosshd`
- `bebbosshkeygen`
- AROS README and example configuration files
- GPL and upstream license files

AROS i386 `alt-abiv0` is a separate, stable target with its own gate
(`docs/AROS_I386_RELEASE.md`). The two kits are not interchangeable.

Release naming (see `AROS_PORTING.md`):

```text
v1.0.3-aros-x86_64
bebbossh-aros-x86_64-<version>.zip
bebbossh-aros-x86_64-<version>.tar.gz
```

## ELF ABI note (load-bearing)

AROS One x86_64 ships ELF64 commands with `EI_ABIVERSION = 11`. The build wrapper
patches the ELF header after link/strip (`Makefile.aros-x86_64`, the `POST_LINK`
step writes `0x0B` at byte offset 8). ABI version 1 binaries are rejected by the
AROS Shell. If a freshly built `bebbosshd`/`bebbossh` is rejected at launch,
confirm the ABI byte before suspecting the binary is otherwise invalid.

When replacing a binary over SCP/SFTP, delete the existing file first, then
upload and download it back for a byte compare, to avoid stale trailing bytes
from an in-place overwrite without truncation.

## Public Asset Gate

After publishing a release, verify the assets from GitHub rather than the local
`dist/` directory:

```sh
BEBBOSSH_RELEASE_ZIP_SHA256=<sha256> \
BEBBOSSH_RELEASE_TGZ_SHA256=<sha256> \
./scripts/aros-x86_64-public-release-smoke.sh
```

The script downloads the release archive, verifies the expected SHA256 values
(skipped if unset), checks the runtime kit contains the required
binaries/docs/licenses, and rejects any public package that contains `hosted`
artifacts.

For a future version, override the defaults:

```sh
BEBBOSSH_RELEASE_TAG=v1.0.4-aros-x86_64 \
BEBBOSSH_RELEASE_VERSION=v1.0.4 \
./scripts/aros-x86_64-public-release-smoke.sh
```

## Clean VM Install Gate

Use a fresh or explicitly reset AROS One x86_64 VM. Do not use a long-lived lab
VM as the only release proof. The x86_64 system volume is typically `AROS:`
(the i386 kit uses `DH0:`).

1. Download the public release archive.
2. Copy the unpacked directory to `AROS:BSSHPKG`.
3. In an AROS shell:

   ```text
   cd AROS:BSSHPKG
   copy sshd_config.example sshd_config
   copy passwd.example passwd
   bebbosshkeygen -f ssh_host_ed25519_key
   stack 262144
   bebbosshd
   ```

4. From the host, run the runtime smoke against the forwarded SSH port (the
   x86_64 hosted/QEMU port convention is `20022`):

   ```sh
   BEBBOSSH_AROS_PORT=20022 \
   BEBBOSSH_AROS_WORKDIR=T: \
   ./scripts/aros-x86_64-public-release-smoke.sh
   ```

5. If the VM uses another forwarded port or credentials, override:

   ```sh
   BEBBOSSH_AROS_PORT=21022 \
   BEBBOSSH_AROS_USER=test \
   BEBBOSSH_AROS_PASS=test \
   BEBBOSSH_AROS_WORKDIR=T: \
   ./scripts/aros-x86_64-public-release-smoke.sh
   ```

## Optional C: Command Install

The client-side tools can be copied to `C:` and called without a full path:

```text
copy AROS:BSSHPKG/bebbossh C:
copy AROS:BSSHPKG/bebboscp C:
copy AROS:BSSHPKG/bebbosshkeygen C:
protect C:bebbossh +e
protect C:bebboscp +e
protect C:bebbosshkeygen +e
```

For `bebbosshd`, keep the daemon and its config together in `AROS:BSSHPKG`
(package defaults use `PROGDIR:` paths; when run from `C:`, `PROGDIR:` becomes
`C:`). If the daemon is installed in `C:`, pass explicit config paths:

```text
bebbosshd -A AROS:BSSHPKG/passwd -K AROS:BSSHPKG/ssh_host_ed25519_key -H AROS:
```

## AROS Native Client Gate

The host-side smoke proves the daemon, OpenSSH SCP, and OpenSSH SFTP. The
AROS-native client tools also need one real AROS shell validation (via VNC or a
real console) before a release is considered complete, the same as the i386
gate. Keep this gate manual until there is a robust way to inject AROS shell
commands without focus races.

## Autostart Gate

For integration images, add this block to `S:User-Startup`:

```text
;BEGIN BebboSSHd AROS
Stack 262144
If EXISTS AROS:BSSHPKG/bebbosshd
    Run AROS:BSSHPKG/bebbosshd
EndIf
;END BebboSSHd AROS
```

After reboot, the host-side runtime smoke should pass without opening VNC:

```sh
BEBBOSSH_AROS_PORT=20022 ./scripts/aros-x86_64-public-release-smoke.sh
```

## Closure gates — CLOSED at v1.0.0

All three documented gates closed for v1.0.0; re-run them for every release.

1. **Entropy review (CLOSED).** The previous x86_64/mincrt `randfill()` had
   `aros_rdtsc()` stubbed to `0` and `DateStamp` gated out, so per-call entropy
   was only addresses + a counter — not cryptographically random. `src/rand.c`
   now enables inline-asm `rdtsc` (safe under `-nostdlib`: pure CPU instruction)
   and routes `DateStamp` through the mincrt-safe `bebbossh_aros_datestamp`
   wrapper so each call mixes ns-class CPU time + 20 ms-class system tick.
   Residual: still a best-effort PRNG mixer, not a true CSPRNG; replace with
   an AROS CSPRNG if one becomes available. Re-validation per release:
   `make -f Makefile.aros-x86_64 run-tests` (testEd25519, testChacha20) +
   confirm `bebbosshkeygen` outputs differ across runs.
2. **Zero-delay password-auth churn (CLOSED).** Per-login passwd-cache reset
   in `SshSession::login` was the failure; removed so the cache loads once per
   daemon lifetime (same as i386). Adding/removing a user requires a daemon
   restart on both architectures. Re-validation per release:
   `BEBBOSSH_AROS_STRESS_DELAY=0 scripts/aros-transfer-stress-test.sh` against
   the QEMU x86_64 VM — expect 0 password-auth failures.
3. **QEMU AROS One x86_64 daemon gate (CLOSED).** Validated on AROS One x86_64
   QEMU e1000 (host port 20222 → guest 2222): SSH smoke, P4 publickey, password
   churn 100/100, SFTP `ls/put/get/rm`, reduced transfer stress, full transfer
   stress including 1 MiB at `BEBBOSSH_AROS_STRESS_DELAY=0` 20/20, immediate
   post-stress banner. Re-validation per release:
   `BEBBOSSH_GATE_QEMU_X64_PORT=20222 scripts/aros-release-gate.sh`.

After re-validation: refresh `scripts/aros-x86_64-public-release-smoke.sh` with
the release's tag/version/SHA256 and cut the next `v1.0.x-aros-x86_64` tag.

### Network card for the stress gates

The AROS `e1000.device` allocates and frees a buffer per transmitted packet in
interrupt context, while the exec memory functions are protected by
`Forbid()` only. Under heavy load the guest can halt, reboot by itself, or
send a corrupted packet. This is an AROS driver problem, not a BebboSSH one:
with four daemons and the zero-delay stress, e1000 failed in 3 of 12 fresh
boots, rtl8139 in 0 of 24 and pcnet in 0 of 6.

Run the stress and multi-daemon gates with `-device rtl8139` or
`-device pcnet`, and set the matching driver in
`ENVARC:AROSTCP/db/interfaces`:

```text
net0 DEV=DEVS:networks/rtl8139.device UNIT=0  IP=DHCP NETMASK=255.255.255.0 UP
```

A halt or reboot in an e1000 run is not by itself a BebboSSH regression;
repeat the run with another card before investigating the daemon.

## Optional functional-parity flags (experimental)

The x86_64/`mincrt` build keeps several i386 behaviors behind opt-in runtime
flags so they can be A/B tested on the VM without rebuilding. All default OFF;
set them before launching the daemon, globally with `setenv NAME 1` or as a
local variable of the starting shell with `set NAME 1`:

- `BEBBOSSH_AROS_X64_SFTP_MTIME=1`: preserve SFTP modification times via
  `SetFileDate`.
- `BEBBOSSH_AROS_X64_CD=1`: enable the interactive-shell `cd` / `pwd` / dynamic
  prompt path. The shell acquires a real current-directory Lock through the
  mincrt-safe DOS wrappers; raw `CurrentDir` could previously block the daemon,
  so validate under `dir`/`cd` churn before relying on it.
- `BEBBOSSH_AROS_X64_SFTP_LINKS=1`: SFTP `READLINK` / `SYMLINK` via the
  `ReadLink` / `MakeLink` wrappers.

When a flag is unset, the current safe default behavior is unchanged.

## Parity changes to validate before the next tag

These are on by default since the mincrt parity work and have only been
compile- and link-checked against the AROS SDK, so the next release needs one
VM pass over them:

1. SFTP overwrite: upload a large file, then a smaller one to the same name,
   and byte-compare the download (the target is deleted before re-creation).
   The "delete the old file first" advice above is no longer needed once this
   passes.
2. `bebbosshd -v5` prints log lines on x86_64 (it was silent before).
3. Daemon teardown: when the daemon exits after a client has connected, the
   `-v5` log shows the timer request, message ports and `bsdsocket.library`
   being released and the process ends without a guru. Check both exits: a
   fatal path such as a duplicate channel id, and `Break <process>` (Ctrl-C)
   with and without a connected client; restart the daemon right away and
   connect again.
4. Malformed channel requests (a second `shell` on the same channel, a
   `subsystem` request with an unknown or short name) are answered with
   CHANNEL_FAILURE and the daemon keeps serving.
5. AROS-native client (`bebbossh`): after exit the shell console is back in
   cooked mode; Ctrl-C at the password prompt quits; Shift+cursor keys reach
   the remote side as modified cursor keys; `setenv USER name` is used as the
   default login name.
6. Interactive shell: `C:Li<TAB>` completes to `C:List`.
7. Crypto: one SCP transfer with each cipher (`-c aes128-gcm@openssh.com`,
   `-c chacha20-poly1305@openssh.com`), on a VM CPU model that exposes
   AES-NI/PCLMULQDQ (QEMU `-cpu qemu64,+aes,+pclmulqdq,+ssse3` or `-cpu host`)
   and on one that does not (QEMU `qemu64`) to cover both GCM paths.
   `make -f Makefile.aros-x86_64 run-tests` builds the self-tests, but on AROS
   One they crash before `main` (also on master): the prebuilt `libautoinit.a`
   calls `OpenLibrary` without SysBase in `r12`, and the test link pulls
   posixc/stdc stubs that AROS One does not ship.
8. `sshd_config`: the x86_64 daemon now reads it (releases up to v1.0.2
   ignored it). In the Clean VM Install Gate layout, change `Port 22` to
   `Port 2222` in `AROS:BSSHPKG/sshd_config` (QEMU forwards host port 20222
   to guest port 2222). `ENVARC:ssh/sshd_config`, if present, is read instead,
   so remove it first. Stop the daemon with `Break <process>` and start it
   again, then check from the host:

   ```sh
   sshpass -p test ssh -o StrictHostKeyChecking=no \
     -o UserKnownHostsFile=/tmp/bebbossh_known_hosts \
     -o PreferredAuthentications=password -o PubkeyAuthentication=no \
     -p 20222 test@127.0.0.1 version
   ```

   It must print the AROS version, and the same command with `-p 20022` must
   fail. Then rename `sshd_config` to `sshd_config.off`, restart the daemon,
   and check that `-p 20022` answers again with the `test` login from
   `PROGDIR:passwd`. The example file sets `Stack 262144`, which x86_64 now
   applies instead of its 1 MiB default, so run the runtime smoke with the
   example file in place.

Status at v1.0.1 (AROS One x86_64, QEMU `qemu64` and
`qemu64,+aes,+pclmulqdq,+ssse3`): items 1 to 4 and 7 pass. For item 7 the
self-tests were linked with a replacement autoinit loop that loads `r12`
(see the note above). Items 5 and 6 need an AROS console and are still open.
The AROS-native clients were also exercised over loopback with public-key
login: `bebboscp` upload and download (byte-identical), `bebbossh` command
execution and `-L` forwarding.

Not covered by this list: DOS requester suppression is i386-only for now (see
`AROS_PORTING.md`), so on x86_64 an SFTP path on an unmounted volume still
opens the "insert volume" requester and blocks the daemon until it is closed.

### Known divergence kept on purpose: synchronous exec

x86_64/`mincrt` runs SSH commands through a synchronous `SystemTagList` backend
that captures output to a temporary file and streams it back, blocking the
daemon main loop while a command runs. The non-blocking child-task backend
(`CreateNewProcTagList`) used by i386 previously hit a crash class on the minimal
x86_64 runtime, so it is intentionally not compiled for x86_64. Treat the
synchronous backend as the intended x86_64 behavior for short, bounded commands;
porting the async backend to mincrt is future work that requires VM validation,
not a runtime flag.
