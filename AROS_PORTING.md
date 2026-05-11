# BebboSSH AROS/i386 Porting Notes

Current target: AROS i386 first. x86_64 is intentionally deferred until the
i386 port builds and runs cleanly.

This port is maintained as a derivative of Stefan "Bebbo" Franke's original
BebboSSH source tree:

```text
https://franke.ms/git/bebbo/bebbossh
```

AROS/i386 porting changes are by Michele Dipace
<michele.dipace@kaffeine.net> and are licensed under GPLv3 or later,
consistent with the upstream project.

## What changed

- Added `include/platform.h` to separate Amiga API usage from Linux/POSIX-only
  server paths.
- Added `include/compat_endian.h` for hosts without Linux `<endian.h>`.
- Added `Makefile.aros` for AROS/i386 builds of `bebbosshd`,
  `bebbosshkeygen`, and the crypto self-tests.
- Kept m68k assembly out of the AROS build.
- Kept the interactive AmigaDOS shell path enabled for AROS, while leaving the
  Linux PTY/PAM path Linux-only.
- Added AROS-specific fallback random filling in `src/rand.c`.
- Added AROS startup probes for isolating ABI/startup failures.
- Added `PROGDIR:` fallbacks for ISO-based AROS One testing.
- Added read-only password-file support so test ISOs can authenticate without
  writing back hashed passwords.
- Added a minimal AROS remote `exec` backend using `SystemTags()` for
  non-interactive commands.
- Adjusted SFTP path validation on AROS to use `GetDeviceProc()`, so assigns
  such as `T:` and `DH0:` resolve correctly.

## Build inside AROS/i386

The current AROS One VM freezes during basic `RAM:` operations such as
`makedir` and source copies, so the reliable path for now is host-side
cross-compilation. In-guest builds should be retried only after the VM storage
problem is isolated.

From the source directory:

```sh
make -f Makefile.aros all
make -f Makefile.aros run-tests
```

The expected first build products are:

- `aros-i386/bebbosshd`
- `aros-i386/bebbosshkeygen`
- `aros-i386/testAES`
- `aros-i386/testChacha20`
- `aros-i386/testEd25519`
- `aros-i386/testGCM`
- `aros-i386/testSHA512`

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

The directory contains the static AROS/i386 binaries, example config files,
runtime README, upstream license files, porting notes, and `SHA256SUMS`.
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

If launching from an AROS Shell, use a larger stack while testing:

```text
stack 262144
bebbosshd -v5
```

AROS runtime notes:

- The classic Amiga `grabFx()` file-handle hack is disabled on AROS because it
  reads private memory before `BADDR(Input())` and can fault on AROS/i386.
- AROS logging does not read the m68k custom chip at `0xdff000`.
- If `ENVARC:ssh/sshd_config` is missing, AROS builds fall back to
  `PROGDIR:sshd_config`.
- If `ENVARC:ssh/ssh_host_ed25519_key` is missing, AROS builds fall back to
  `PROGDIR:ssh_host_ed25519_key`. The VM test ISO includes a development key
  for this purpose only.
- If the password file can only be opened read-only, plaintext test passwords
  are accepted without rewriting the file to `{ssha256}` format. This is useful
  for ISO-based tests.
- `bebbosshkeygen` is built as a static AROS/i386 executable and has been
  launched successfully on AROS One i386 far enough to generate ED25519
  randomart.
- Remote `exec` is implemented for simple non-interactive commands on AROS.
  The current backend redirects command output to a temporary `T:` file and
  sends it back over SSH after the command exits. The command return code is
  sent as the SSH `exit-status`.
- Interactive SSH sessions use the same backend for simple commands and return
  to the prompt after each command.
- Full PTY-style interactive program support is still incomplete on AROS.

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
returned SSH exit status 1. The backend is intentionally minimal: it is
synchronous and should be used first for short development commands while
SFTP/SCP and a fuller PTY path are stabilized.

SFTP/SCP status:

- `sftp` `ls T:` works.
- `sftp` upload, download, compare, and remove have been tested on `T:`.
- `sftp` upload, download, compare, and remove have been tested on `DH0:`.
- `sftp` 1 MiB and 5 MiB upload/download round-trips on `DH0:` matched by
  SHA-256 and byte compare.
- `sftp` `mkdir`, upload inside the directory, `rm`, and `rmdir` have been
  tested on `DH0:`.
- OpenSSH `scp` default mode, which uses SFTP, has been tested for upload and
  download on `T:` and for a 5 MiB round-trip on `DH0:`.
- OpenSSH `scp -r` has been tested with a temporary 336 KiB
  `telegram-amiga`-style source tree copied to `DH0:`, copied back, and
  verified with `diff -qr`.

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
