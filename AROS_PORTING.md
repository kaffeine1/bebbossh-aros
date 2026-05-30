# BebboSSH AROS Porting Notes

This is a multi-target AROS porting tree. The same source is used for i386 and
x86_64, while makefiles, package names, release tags, and validation status are
kept target-specific.

| Target | Status | Build entry point | Notes |
| --- | --- | --- | --- |
| AROS i386 `alt-abiv0` for AROS One / VMware 32 bit | stable / validated | `Makefile.aros` | public runtime kit: `bebbossh-aros-i386-abiv0-*` |
| AROS x86_64 for AROS One / VMware 64 bit | hosted validated, external VMware feedback OK | `Makefile.aros-x86_64` | public runtime kit: `bebbossh-aros-x86_64-*` |
| Hosted AROS i386/x86_64 | automation and transfer stress validated | target-specific makefile | internal validation only; do not publish as `hosted` runtime kits |

This port is maintained as a derivative of Stefan "Bebbo" Franke's original
BebboSSH source tree:

```text
https://franke.ms/git/bebbo/bebbossh
```

The current AROS tree has been checked against BebboSSH upstream source version
1.45. The canonical upstream commit from a fresh upstream clone is:

```text
5d68dd169cfbb701c5fe8debda8df0a8d896320e
```

That upstream snapshot includes the 1.45 `bebbosshkeygen` OpenSSH key-format
fixes and the constant-upper-bound KEX reply timing envelope. Both are present
in this AROS tree, with AROS-specific compatibility changes layered on top.

AROS porting changes are by Michele Dipace
<michele.dipace@kaffeine.net> and are licensed under GPLv3 or later,
consistent with the upstream project.

## What changed

- Added a platform/endian compatibility layer to separate Amiga API usage from
  Linux/POSIX-only server paths.
- Added `Makefile.aros` (shared i386/x86_64 source build) and
  `Makefile.aros-x86_64` (x86_64 wrapper), with target triplet overrides.
- Added an AROS x86_64 minimal startup/runtime path for `bebbosshkeygen` and
  `bebbosshd`, avoiding standard runtime paths that were unstable on the VM.
- Kept m68k assembly out of the AROS build, kept the interactive AmigaDOS shell
  path enabled, and left the Linux PTY/PAM path Linux-only.
- Hardened the AROS `randfill()` fallback to mix several local runtime entropy
  sources instead of seeding `rand()` from `time(0)`.
- Added startup/entropy probes for isolating ABI/startup failures.
- Added `PROGDIR:` config/host-key fallbacks and read-only password-file
  support for ISO-based AROS One testing.
- Added an AROS remote `exec` backend for simple non-interactive commands.
- Added configurable accept-loop burst handling (`ListenAcceptBurst`, `-B`).
- Adjusted SFTP path validation to resolve assigns, honor explicit client read
  offsets, and fail (not silently ack) short writes.
- Raised the default AROS command stack to 1 MiB for all AROS daemon builds.
- Tightened daemon/session cleanup on shutdown and abnormal disconnect.
- Hardened SSH banner and KEX name-list parsing against binary KEX data
  arriving with the client banner.

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

Packager notes for the x86_64 wrapper:

- AROS One x86_64 ships ELF64 commands with ELF ABI version 11, so the wrapper
  patches `EI_ABIVERSION` to 11 after link/strip; ABI version 1 binaries are
  rejected by the Shell.
- The wrapper uses an x86_64-safe code model and disables unwind-table and
  hot/cold partition output; the only expected relocation is `R_X86_64_64`.
- The x86_64 binaries use the minimal AROS runtime with standard init/exit
  symbol sets disabled, and the random fallback is still experimental (see
  Known limits). Do not publish a stable x86_64 security release until it is
  validated on the target VM.

x86_64 is hosted-validated and the mincrt keygen path is also validated on
AROS One x86_64 via ISO transfer. Detailed test status lives in
`docs/AROS_TESTER.md`.

## Release naming

Use architecture/ABI-specific release tags and assets so users can identify the
correct kit without reading the build log. Do not publish public release assets
with `hosted` in the name; hosted describes a validation environment, not a
runtime target.

```text
v0.2.1-aros-i386-abiv0
bebbossh-aros-i386-abiv0-<version>.zip
bebbossh-aros-i386-abiv0-<version>.tar.gz

v0.3.0-aros-x86_64
bebbossh-aros-x86_64-<version>.zip
bebbossh-aros-x86_64-<version>.tar.gz
```

Use the i386 `abiv0` archive for 32-bit AROS One/VMware systems. Use the
`x86_64` archive for 64-bit AROS systems. Keep any hosted-only binaries and
packages as ignored local lab artifacts, especially for i386 where the hosted
binary is not interchangeable with the AROS One/VMware `alt-abiv0` build.

Only mark x86_64 releases stable after the same smoke-test class used for i386
passes on an AROS x86_64 system and the remaining entropy/security-release
questions are closed.

## QEMU environment

Do not run `make` directly inside `Qemu Vfat:`: the AROS toolchain can read
makefiles from the QEMU FAT handler as if they contained NUL bytes. Likewise,
do not treat `Qemu Vfat` as a reliable executable transfer path. A native AROS
command copied through the QEMU FAT shared disk and protected `RWED` on `DH0:`
was still rejected by the Shell. Prefer an ISO image, a native AROS volume, or
another byte-preserving transfer path before concluding that a generated binary
is invalid.

## Runtime validation summary

x86_64 (mincrt) is hosted-validated for keygen, daemon bind/auth, non-PTY and
PTY exec with real output and exit status, the minimal interactive shell,
missing-command exit 127, telegram-amiga automation, and SFTP/SCP. The keygen
path is additionally validated on AROS One x86_64 via ISO transfer. Keep x86_64
marked experimental until the entropy path is reviewed and non-hosted AROS One
daemon validation is closed. For SFTP/SCP, the validated operations are `ls`,
`get`, `put`, `rm`, `rename` (including overwrite), `mkdir`, `rmdir`, and
`chmod`. `READLINK`/`SYMLINK` remain unsupported and x86_64/mincrt does not
preserve SFTP mtime.

Hosted AROS i386 is validated for daemon bind/auth, the telegram-amiga
automation suite, redirection and interactive-command rejection, PTY exec,
minimal shell, and SFTP/SCP for the same operation set. This hosted validation
does not replace the separate AROS One `alt-abiv0` release validation path. For
detailed test status and counts, see `docs/AROS_TESTER.md`.

AROS x86_64/mincrt SSH exec uses a synchronous DOS `SystemTagList` backend that
redirects command stdout/stderr to a temporary `T:` file, reads it back over
SSH, and deletes it. This avoids the earlier `CreateNewProcTagList`/mincrt crash
class, but is deliberately blocking: while a command runs, the daemon main loop
does not service other clients. Treat it as a short-command automation path; run
long commands from the AROS console/VNC or on the i386 daemon.

The x86_64/mincrt interactive shell deliberately rejects `cd`, because changing
current directory through the raw `CurrentDir()` path can block the daemon. Use
explicit paths such as `dir C:` on x86_64/mincrt; i386 retains working `cd`
support.

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

The generated package has been validated on AROS One i386 end-to-end: copied to
`DH0:BSSHPKG` with `scp -r`, host key generated in-guest with `bebbosshkeygen`,
loopback SSH exec and SCP copy completed from a real AROS shell with
byte-identical files, and the packaged `bebbosshd -p 2222` answered OpenSSH auth
and SFTP through QEMU forwarding.

Autostart: see `packaging/aros/README.AROS.txt`.

When replacing `DH0:BSSHPKG/bebbosshd` through SCP/SFTP, delete the existing
file first, then upload the new binary and download it back for a byte compare.
This avoids stale trailing bytes if an existing executable is overwritten
without truncation.

If launching from an AROS Shell, use a larger stack while testing:

```text
stack 262144
bebbosshd -v5
```

Known limits:

- Config/host-key fallbacks: if `ENVARC:ssh/sshd_config` or
  `ENVARC:ssh/ssh_host_ed25519_key` is missing, AROS builds fall back to the
  matching `PROGDIR:` file. A read-only password file accepts plaintext test
  passwords without rewriting to `{ssha256}`, which is useful for ISO tests.
- No known AROS system CSPRNG in this environment. `randfill()` is a best-effort
  fallback that mixes local runtime entropy sources; it is stronger than the
  original `time(0)` seed but should be replaced if an AROS CSPRNG becomes
  available. Minimal-runtime builds avoid the fragile AROS OS entropy calls and
  use a self-contained mixer instead.
- Remote `exec` covers simple non-interactive commands only. The child-task
  backend has a soft 30-second timeout and keeps the daemon responsive; the
  x86_64/mincrt synchronous backend blocks the daemon and is for bounded
  commands only.
- Shell redirection and pipes (`>`, `<`, `|`) are rejected before execution; a
  remote `>/NIL:` test degraded the daemon.
- Known interactive/stdin-driven commands are rejected with exit status 2 (even
  with a PTY requested), asking the caller to use `ssh -tt`, so automation fails
  fast instead of hanging the synchronous exec path.
- Interactive `dir` in the SSH shell is translated to `list ... lformat %N` for
  one-entry-per-line output; non-interactive `ssh ... dir` keeps native output.
- Full PTY-style interactive program support is still incomplete on AROS.
- The classic Amiga `grabFx()` file-handle hack is disabled (it can fault on the
  AROS i386 runtime), and AROS logging does not read the m68k custom chip.

Remote command execution works for simple non-interactive commands. OpenSSH
from the host reaches the daemon through QEMU port forwarding, completes auth,
and runs the command:

```sh
sshpass -p test ssh \
  -o ConnectTimeout=5 \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/tmp/bebbossh_known_hosts \
  -o PreferredAuthentications=password \
  -o PubkeyAuthentication=no \
  -p 10022 test@127.0.0.1 version
```

Script di test e variabili: vedi `docs/AROS_TESTER.md`. For rapid SCP/SFTP
connection churn, `BEBBOSSH_AROS_STRESS_DELAY=0` is a useful regression gate and
`BEBBOSSH_AROS_AUTH_HELPER=askpass` is preferred for long password-auth churn,
since `sshpass` can intermittently fail to provide a pseudo-terminal prompt at
zero delay. Keep the default one-second pacing for downstream automation, and
use `ListenAcceptBurst` or `bebbosshd -B` for targeted accept-loop experiments
rather than changing the default package behavior.

Public-key and forwarding: `ENVARC:.ssh/authorized_keys` works for OpenSSH
Ed25519 public-key login on hosted i386 and x86_64, and `direct-tcpip` local
forwarding is validated through both hosted runtimes.
`scripts/aros-auth-forward-test.sh` covers both (forwarding needs a caller-
provided target listener).

SFTP/SCP are validated for `ls`, `get`, `put`, `rm`, `rename`, `mkdir`,
`rmdir`, and `chmod` on `T:` and `DH0:` (including multi-MiB round-trips matched
by SHA-256, `scp -r` trees, and overwrite). SFTP reads honor the client-
requested offset. AROS SFTP upload permission mapping keeps AmigaDOS execute
protection allowed, so byte-correct uploaded binaries do not fail at boot after
OpenSSH sends Unix-style `0644` permissions.

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
