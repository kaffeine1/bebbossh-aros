# BebboSSH AROS Porting Notes

This is a multi-target AROS porting tree. The same source is used for i386 and
x86_64, while makefiles, package names, release tags, and validation status are
kept target-specific.

| Target | Status | Build entry point | Notes |
| --- | --- | --- | --- |
| AROS i386 `alt-abiv0` | stable / validated | `Makefile.aros` | current published runtime kits |
| AROS i386 hosted | automation validated | `Makefile.aros` | hosted AROS i386 passed the telegram-amiga offline suite |
| AROS x86_64 hosted | offline automation validated | `Makefile.aros-x86_64` | hosted AROS x64 passed the telegram-amiga offline suite |

This port is maintained as a derivative of Stefan "Bebbo" Franke's original
BebboSSH source tree:

```text
https://franke.ms/git/bebbo/bebbossh
```

AROS porting changes are by Michele Dipace
<michele.dipace@kaffeine.net> and are licensed under GPLv3 or later,
consistent with the upstream project.

## What changed

- Added `include/platform.h` to separate Amiga API usage from Linux/POSIX-only
  server paths.
- Added `include/compat_endian.h` for hosts without Linux `<endian.h>`.
- Added `Makefile.aros` for shared AROS builds of `bebbosshd`,
  `bebbosshkeygen`, and the crypto self-tests, with target triplet overrides.
- Added `Makefile.aros-x86_64` as an experimental AROS x86_64 build wrapper.
- Added an AROS x86_64 minimal startup/runtime path for `bebbosshkeygen` and
  `bebbosshd`, avoiding standard runtime paths that were unstable on the test
  VM.
- Kept m68k assembly out of the AROS build.
- Kept the interactive AmigaDOS shell path enabled for AROS, while leaving the
  Linux PTY/PAM path Linux-only.
- Added AROS-specific fallback random filling in `src/rand.c`.
- Added AROS startup probes for isolating ABI/startup failures.
- Added `PROGDIR:` fallbacks for ISO-based AROS One testing.
- Added read-only password-file support so test ISOs can authenticate without
  writing back hashed passwords.
- Hardened the AROS `randfill()` fallback by mixing wall-clock time,
  microseconds, DOS ticks, current task address, heap state, stack address, and
  x86 CPU cycle counter data where available into an internal 64-bit mixer
  instead of seeding `rand()` from `time(0)`.
- Added a minimal AROS remote `exec` backend using `SystemTags()` for
  non-interactive commands.
- Adjusted SFTP path validation on AROS to use `GetDeviceProc()`, so assigns
  such as `T:` and `DH0:` resolve correctly.
- Adjusted SFTP reads to honor explicit client offsets and fail partial writes
  instead of silently acknowledging short writes.
- Raised the default AROS command stack to 1 MiB for all AROS daemon builds.
  This is required for larger automation commands such as telegram-amiga inbox
  and client self-tests on hosted i386.
- Tightened daemon/session cleanup so remaining sessions, listeners, and open
  channel objects are released on shutdown or abnormal disconnect.

## Stable AROS i386 build

The current AROS One VM freezes during basic `RAM:` operations such as
`makedir` and source copies, so the reliable path for now is host-side
cross-compilation. In-guest builds should be retried only after the VM storage
problem is isolated.

From the source directory:

```sh
make -f Makefile.aros all
make -f Makefile.aros run-tests
```

The expected default build products are:

- `aros-i386/bebbosshd`
- `aros-i386/bebbosshkeygen`
- `aros-i386/testAES`
- `aros-i386/testChacha20`
- `aros-i386/testEd25519`
- `aros-i386/testGCM`
- `aros-i386/testSHA512`

## Experimental AROS x86_64 build

The x86_64 wrapper can be used either inside an AROS x86_64 development
environment or from host-side `x86_64-aros` crosstools whose GCC was configured
with an AROS sysroot:

```sh
make -f Makefile.aros-x86_64 bebbosshkeygen bebbosshd
```

The currently validated x86_64 build products are:

```text
aros-x86_64/bebbosshkeygen
aros-x86_64/bebbosshd
```

For host-side crosstools, set `AROS_SDK_ROOT` to an AROS x86_64 SDK that
provides `startup.o` and the static AROS libraries, and override the tool
commands as needed:

```sh
make -f Makefile.aros-x86_64 bebbosshkeygen bebbosshd \
  CC=<toolchain>/x86_64-aros-gcc \
  CXX=<toolchain>/x86_64-aros-g++ \
  AR=<toolchain>/x86_64-aros-ar \
  STRIP=<toolchain>/x86_64-aros-strip \
  OBJCOPY=<toolchain>/x86_64-aros-objcopy \
  AROS_SDK_ROOT=<path-to-aros-x86_64-sdk>
```

AROS One x86_64 currently ships ELF64 AROS commands with ELF ABI version 11.
The x86_64 wrapper therefore patches `EI_ABIVERSION` to 11 after linking and
stripping. Binaries left at ABI version 1 are rejected by the AROS One x86_64
Shell as not executable before their startup code runs.

The wrapper also uses an x86_64-safe code model and disables unwind-table and
hot/cold partition output that introduced unsupported relocation records in
early builds. The intended final relocation shape is only `R_X86_64_64`;
`R_X86_64_32`, `R_X86_64_PC32`, and `R_X86_64_PLT32` should not appear in the
linked AROS ELF64 executables.

`bebbosshkeygen` x86_64 currently uses a minimal AROS runtime source
(`src/aros_mincrt.c`) and disables standard AROS init/exit symbol sets. The
standard startup path reached `main()` in early tests, but crashed during
startup cleanup or runtime library calls on return. The keygen path has been
validated from an ISO transfer on AROS One x86_64 by copying to a persistent
`AROS:` directory, applying `Protect <file> RWED`, generating an Ed25519 key,
and verifying that both the private key and `.pub` file are written.

The x86_64 random fallback is intentionally still marked experimental. The
minimal-runtime path avoids the OS entropy calls that crashed on the test VM and
mixes stack/address jitter, an internal counter, and the x86 CPU cycle counter.
Do not publish a stable x86_64 security release until this path is validated on
the target VM and replaced or supplemented if an AROS CSPRNG becomes available.

The first runtime validation goal for x86_64 is deliberately small:

- `bebbosshkeygen` starts and creates an Ed25519 host key. Done on AROS One
  x86_64 via ISO transfer.
- `bebbosshd` starts, binds, and authenticates from a modern OpenSSH client.
  Done in hosted AROS x86_64 with TAP networking.
- Non-PTY exec returns complete output and exit status for simple commands
  such as `C:Version` and `C:Echo OK`. Done in hosted AROS x86_64.
- Explicit missing commands return SSH exit status 127 and leave the daemon
  usable. Done in hosted AROS x86_64.
- The telegram-amiga offline automation suite passes on hosted AROS x86_64:
  `--help`, JSON, getUpdates, inbox, sendMessage, client-state, and TLS-status
  checks all returned exit status 0.
- SFTP/SCP upload and download work on a persistent volume. Done in hosted AROS
  x86_64 on `SYS:TGTEST`, including 1 MiB and 5 MiB transfer round-trips.
- PTY exec for simple commands and the minimal interactive shell pass the
  hosted smoke test. The shell sequence covers `dir`, `cd`, `version`, and
  `exit`.

The AROS-specific task launch code now uses real `struct TagItem` arrays with
`IPTR` payloads, and synthetic DOS file handles store channel pointers through
`SIPTR` fields. This avoids the known pointer truncation risks from the i386
implementation when compiling for x86_64.

## Release naming

Use architecture-specific release tags and assets so users can identify the
correct kit without reading the build log:

```text
v0.2.1-aros-i386
bebbossh-aros-i386-<version>.zip
bebbossh-aros-i386-<version>.tar.gz

v0.3.0-aros-x86_64
bebbossh-aros-x86_64-<version>.zip
bebbossh-aros-x86_64-<version>.tar.gz
```

Only mark x86_64 releases stable after the same smoke-test class used for i386
passes on an AROS x86_64 system and the remaining entropy/security-release
questions are closed.

## QEMU environment

The local AROS One i386 VM used for validation was configured with a VNC
display and a writable QEMU FAT shared disk. The host path is installation
specific; in the AROS desktop this is visible as `Qemu Vfat`.

```text
<VM_SHARED_DIR>
```

Do not run `make` directly inside `Qemu Vfat:`. The AROS toolchain can read
makefiles from the QEMU FAT handler as if they contained NUL bytes. The VM has
also frozen during copies and `makedir` on `RAM:`, so avoid large file
operations in the guest until that is fixed.

For x86_64 runtime validation, do not treat `Qemu Vfat` as a reliable executable
transfer path. In the current AROS One x86_64 VM, a native AROS command copied
through the QEMU FAT shared disk and then protected `RWED` on `DH0:` was still
rejected by the Shell as not executable. Prefer an ISO image, a native AROS
volume, or another byte-preserving transfer path before concluding that a
generated x86_64 binary is invalid.

Current x86_64 runtime status: ISO transfer to `CD0:` has been validated with
native AROS commands and generated `bebbosshkeygen` binaries copied to an
`AROS:` directory and executed successfully. `bebbosshkeygen` can generate
Ed25519 private/public key files on AROS One x86_64. In hosted AROS x86_64,
`bebbosshd` starts with AROSTCP/TAP networking, authenticates OpenSSH password
clients, returns complete output and exit status 0 for `C:Version` and
`C:Echo OK`, returns exit status 127 for an explicit missing command, and stays
usable after that failure. It also passes the telegram-amiga offline automation
suite used for JSON, getUpdates, inbox, sendMessage, client-state, and
TLS-status checks. Hosted x86_64 now also passes SFTP/SCP upload/download,
PTY exec, the minimal interactive shell sequence, 1 MiB plus 5 MiB transfer
stress, and a bounded zero-delay SCP/SFTP stress run on `SYS:TGTEST`. Keep
x86_64 marked experimental until the entropy path and non-hosted AROS One
daemon validation are closed.

Current hosted i386 runtime status: hosted AROS i386 starts with AROSTCP/TAP
networking and authenticates OpenSSH password clients. After the default AROS
command stack was raised to 1 MiB, it passes the telegram-amiga offline
automation suite used for `--help`, JSON, getUpdates, inbox, sendMessage,
client-state, and TLS-status checks. It also passes the hosted smoke test for
redirection rejection, interactive-command rejection, PTY exec, minimal shell,
SCP/SFTP, 1 MiB plus 5 MiB transfer stress, and a bounded zero-delay SCP/SFTP
stress run on `SYS:TGTEST`. Keep SFTP/SCP stress in the regression suite. This
hosted validation does not replace the separate AROS One `alt-abiv0` release
validation path.

## Host cross-build for AROS One i386

AROS One i386 uses the `alt-abiv0` ABI. Set these variables for your local
toolchain and SDK paths:

```sh
export AROS_ABIV0_TOOLCHAIN=<path-to-aros-i386-alt-abiv0-toolchain>
export AROS_SDK_ROOT=<path-to-aros-one-development-sdk>
```

From the source directory:

```sh
make -f Makefile.aros bebbosshd bebbosshkeygen probes \
  OUTDIR=aros-i386-abiv0-arosone \
  CC="$AROS_ABIV0_TOOLCHAIN/i386-aros-gcc" \
  CXX="$AROS_ABIV0_TOOLCHAIN/i386-aros-g++" \
  AR="$AROS_ABIV0_TOOLCHAIN/i386-aros-ar" \
  STRIP="$AROS_ABIV0_TOOLCHAIN/i386-aros-strip" \
  AROS_SDK_ROOT="$AROS_SDK_ROOT"
```

The current cross-build product is:

```text
aros-i386-abiv0-arosone/bebbosshd
aros-i386-abiv0-arosone/bebbosshkeygen
```

The local i386 `alt-abiv0` build requires a complete AROS One SDK/sysroot, not
only headers and GCC runtime files. If linking fails with missing startup or
static AROS libraries such as `startup.o`, `libamiga.a`, `libaros.a`, or
`libdos.a`, the sysroot is incomplete and the result must not be published as a
fresh AROS One i386 kit. Hosted-tested i386 binaries are tracked separately
from AROS One `alt-abiv0` release validation.

The VM CD image with only the current binary and crypto tests is generated or
stored outside the repository. Use an installation-specific path:

```text
<TEST_ISO_PATH>
```

## Runtime package

After building `bebbosshd` and `bebbosshkeygen`, generate the distributable
runtime kit with:

```sh
make -f Makefile.aros package-aros-runtime \
  OUTDIR=aros-i386-abiv0-arosone \
  PACKAGE_DIR=dist/bebbossh-aros-i386-abiv0 \
  CC="$AROS_ABIV0_TOOLCHAIN/i386-aros-gcc" \
  CXX="$AROS_ABIV0_TOOLCHAIN/i386-aros-g++" \
  AR="$AROS_ABIV0_TOOLCHAIN/i386-aros-ar" \
  STRIP="$AROS_ABIV0_TOOLCHAIN/i386-aros-strip" \
  AROS_SDK_ROOT="$AROS_SDK_ROOT"
```

The package target creates:

```text
dist/bebbossh-aros-i386-abiv0/
dist/bebbossh-aros-i386-abiv0.tar.gz
dist/bebbossh-aros-i386-abiv0.zip
```

The directory contains the static AROS binaries for the selected target,
example config files, runtime README, upstream license files, porting notes,
and `SHA256SUMS`.
It intentionally does not include private host keys or real passwords.

Package validation on AROS One i386:

- The generated package directory was copied to `DH0:BSSHPKG` with `scp -r`.
- `sshd_config.example` and `passwd.example` were copied to runtime names.
- `DH0:BSSHPKG/bebbosshkeygen -f DH0:BSSHPKG/ssh_host_ed25519_key` generated
  a fresh host key inside AROS.
- `DH0:BSSHPKG/bebbosshd -p 2222` started from the packaged directory.
- Through QEMU forwarding at `127.0.0.1:12222`, OpenSSH completed auth and
  `version` returned `Kickstart 51.51, Workbench 40.0`.
- SFTP against the packaged daemon listed the package directory successfully.

To start `bebbosshd` automatically after AROS boot, install the package in a
persistent directory such as `DH0:BSSHPKG` and add this stanza to
`S:User-Startup`:

```text
;BEGIN BebboSSHd AROS
Stack 262144
If EXISTS DH0:BSSHPKG/bebbosshd
    Run DH0:BSSHPKG/bebbosshd
EndIf
;END BebboSSHd AROS
```

The current autostart recommendation intentionally avoids `Run >NIL:` while
the AROS redirection path is being hardened. Startup status messages are logged
at debug level, so the normal `DebugLevel 1` package configuration should not
leave a daemon output window at boot. For diagnostics, temporarily use
`DebugLevel debug` or launch `bebbosshd` with `-v5`.

When replacing `DH0:BSSHPKG/bebbosshd` through SCP/SFTP, delete the existing
file first, then upload the new binary and download it back for a byte compare.
This avoids stale trailing bytes if an existing executable is overwritten
without truncation.

If launching from an AROS Shell, use a larger stack while testing:

```text
stack 262144
bebbosshd -v5
```

AROS runtime notes:

- The classic Amiga `grabFx()` file-handle hack is disabled on AROS because it
  reads private memory before `BADDR(Input())` and can fault on the validated
  AROS i386 runtime.
- AROS logging does not read the m68k custom chip at `0xdff000`.
- If `ENVARC:ssh/sshd_config` is missing, AROS builds fall back to
  `PROGDIR:sshd_config`.
- If `ENVARC:ssh/ssh_host_ed25519_key` is missing, AROS builds fall back to
  `PROGDIR:ssh_host_ed25519_key`. The VM test ISO includes a development key
  for this purpose only.
- If the password file can only be opened read-only, plaintext test passwords
  are accepted without rewriting the file to `{ssha256}` format. This is useful
  for ISO-based tests.
- AROS does not provide a known system CSPRNG in this porting environment. The
  current `randfill()` path is a best-effort fallback that mixes several local
  runtime sources and is materially stronger than the original `time(0)` seed,
  but it should be replaced if a real AROS CSPRNG or entropy device becomes
  available.
- AROS minimal-runtime builds avoid AROS OS entropy calls that have proven
  fragile in the x86_64 validation VM. That path mixes CPU cycle counter jitter,
  stack/data/function addresses, output buffer identity, length, and an internal
  counter through a SplitMix64-style diffuser. Non-minimal AROS builds use the
  richer AROS source mix where the C runtime and OS calls are available.
- `bebbosshkeygen` is built as a static AROS executable. The i386 build has
  been launched successfully on AROS One i386 far enough to generate ED25519
  randomart.
- Remote `exec` is implemented for simple non-interactive commands on AROS.
  The backend runs `SystemTags()` inside a child task, redirects command output
  to a temporary `T:` file, and sends it back over SSH after the command exits.
  The command return code is sent as the SSH `exit-status`.
- Non-PTY exec has a soft 30-second timeout. The daemon remains responsive
  while the child task runs; on timeout it writes a warning and sends a break to
  the command task.
- AROS remote exec rejects shell redirection and pipes (`>`, `<`, `|`) before
  calling `SystemTags()`. A remote `>/NIL:` test degraded the daemon, so these
  constructs are intentionally unsupported until a safer execution backend is
  implemented.
- Known interactive commands are rejected in non-PTY exec mode with exit status
  2 and a message asking the caller to use `ssh -tt`. This prevents commands
  such as `more ?` from blocking the daemon's synchronous non-PTY exec path.
- Interactive SSH sessions use the same backend for simple commands and return
  to the prompt after each command.
- Interactive shell stdin now drains command lines already received in the same
  SSH packet after an AROS command completes, which keeps piped sequences such
  as `dir`, `version`, `exit` moving through the minimal shell backend.
- Interactive `dir` in the SSH shell is translated to `list ... lformat %N`
  so directory listings are readable one entry per line. Non-interactive
  `ssh ... dir` keeps the native AROS `dir` output.
- AROS PTY exec for simple commands is routed through the same output-file
  command backend used by non-PTY exec. The earlier synthetic DOS file-handle
  backend caused hosted AROS traps on `version`/`list` and is no longer used for
  the minimal automation path.
- Full PTY-style interactive program support is still incomplete on AROS.
  Stdin-driven console programs should remain guarded until a stable file-handle
  or console-device backend is implemented.
- Known stdin-driven programs are rejected with exit status 2 even when the
  client requested a PTY, so automation fails fast instead of hanging on a fake
  interactive stdin path.

Forwarded host ports:

- VNC: `127.0.0.1:5901`
- guest SSH: `127.0.0.1:10022`
- guest telnet: `127.0.0.1:10023`

At the time of these notes, `bebbosshd` starts from the AROS One test ISO,
loads the host key, binds port 22, and listens. OpenSSH from macOS reaches the
server through QEMU forwarding at `127.0.0.1:10022`, completes SSH protocol
identification, key exchange, and password authentication.

Remote command execution now works for simple non-interactive commands:

```sh
sshpass -p test ssh \
  -o ConnectTimeout=5 \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/tmp/bebbossh_known_hosts \
  -o PreferredAuthentications=password \
  -o PubkeyAuthentication=no \
  -p 10022 test@127.0.0.1 version
```

This has returned:

```text
Kickstart 51.51, Workbench 40.0
```

`dir` has also been tested successfully. A `telegram-amiga` invalid-option test
returned SSH exit status 1. Remote redirection such as `>/NIL:` is blocked with
exit status 2. Non-PTY exec is intended for short automation commands and now
runs outside the daemon's main loop. Interactive programs should be launched
with `ssh -tt`.

The repeatable host-side smoke test for the current AROS automation workflow is:

```sh
scripts/aros-ssh-smoke-test.sh
```

Defaults:

```text
BEBBOSSH_AROS_HOST=127.0.0.1
BEBBOSSH_AROS_PORT=10022
BEBBOSSH_AROS_USER=test
BEBBOSSH_AROS_PASS=test
BEBBOSSH_AROS_TELEGRAM_TEST=DH0:TGTEST/telegram-test
BEBBOSSH_AROS_WORKDIR=DH0:TGTEST
BEBBOSSH_AROS_SHELL_HOME=DH0:
BEBBOSSH_AROS_TRANSFER_SIZES="1048576 5242880"
```

It validates:

- `version` over non-interactive SSH.
- rejection of `version >/NIL:` with exit status 2.
- daemon health after the rejected redirection.
- rejection of known interactive commands in non-PTY exec mode.
- daemon health after the non-PTY interactive-command guard.
- `telegram-test --help` exit status 0.
- `telegram-test --definitely-invalid-option` exit status 1.
- `version` through PTY exec.
- a piped interactive shell sequence using `dir`, `cd`, `version`, and `exit`.
- SCP upload/download byte comparison on `DH0:TGTEST`.
- SFTP `mkdir`, upload, download, compare, remove, and `rmdir` on `DH0:TGTEST`.
- SCP and SFTP transfer stress round-trips for the configured byte sizes.

For repeated SCP/SFTP stress beyond the smoke test:

```sh
scripts/aros-transfer-stress-test.sh
```

Additional defaults:

```text
BEBBOSSH_AROS_STRESS_ITERATIONS=20
BEBBOSSH_AROS_STRESS_SIZES="257 4096 65536 1048576"
BEBBOSSH_AROS_STRESS_DELAY=1
```

Earlier hosted validation found that `BEBBOSSH_AROS_STRESS_DELAY=0` could
reproduce intermittent OpenSSH password/authentication failures during rapid
SCP/SFTP connection storms. After increasing the AROS listen backlog and
accepting several pending sockets per event-loop pass, hosted x86_64 passed
5 zero-delay stress iterations and hosted i386 passed 3 zero-delay stress
iterations with sizes `257 4096 65536 1048576` on `SYS:TGTEST`. Keep the
default one-second pacing for downstream automation, and use zero-delay mode as
an explicit regression stress test.

SFTP/SCP status:

- `sftp` `ls T:` works.
- `sftp` upload, download, compare, and remove have been tested on `T:`.
- `sftp` upload, download, compare, and remove have been tested on `DH0:`.
- `sftp` 1 MiB and 5 MiB upload/download round-trips on `DH0:` matched by
  SHA-256 and byte compare.
- SFTP reads honor the offset requested by the client, which is required for
  non-sequential OpenSSH read patterns.
- `sftp` `mkdir`, upload inside the directory, `rm`, and `rmdir` have been
  tested on `DH0:`.
- OpenSSH `scp` default mode, which uses SFTP, has been tested for upload and
  download on `T:` and for a 5 MiB round-trip on `DH0:`.
- OpenSSH `scp -r` has been tested with a temporary 336 KiB
  `telegram-amiga`-style source tree copied to `DH0:`, copied back, and
  verified with `diff -qr`.
- OpenSSH `scp` overwrite of a smaller file over a larger file has been tested
  on `DH0:` and verified by byte compare.
- AROS SFTP upload permission mapping keeps AmigaDOS execute protection
  allowed. This avoids byte-correct uploaded binaries failing at boot with
  `File non eseguibile` after OpenSSH sends Unix-style `0644` permissions.

Clean install status:

- The generated runtime kit was copied to a fresh `DH0:` directory.
- `sshd_config.example` and `passwd.example` were copied to runtime names.
- `bebbosshkeygen -f <install-dir>/ssh_host_ed25519_key` generated a fresh host
  key on AROS One i386.
- `bebbosshd -p 2222` launched from that directory and answered `version`
  through the QEMU host forward at `127.0.0.1:12222`.

When using `sshpass` with `sftp -b`, pass `-oBatchMode=no`; OpenSSH otherwise
forces batch mode authentication and will not send the password:

```sh
sshpass -p test sftp \
  -oBatchMode=no \
  -o ConnectTimeout=5 \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/tmp/bebbossh_known_hosts \
  -o PreferredAuthentications=password \
  -o PubkeyAuthentication=no \
  -P 10022 \
  test@127.0.0.1
```

## Host-side verification

The crypto tests compile and pass on macOS with the Linux-flavoured make path:

```sh
make linux=1 LIBS_D= linux/testAES linux/testChacha20 linux/testEd25519 linux/testGCM linux/testSHA512
```
