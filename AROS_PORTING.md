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

The local AROS One i386 VM is configured with a VNC display and a writable
QEMU FAT shared disk. The shared host path is:

```text
/Volumes/EXT/Macchine Virtuali/AROSOne_x86/shared/bebbossh-aros
```

In the AROS desktop this is visible as `Qemu Vfat`.

Do not run `make` directly inside `Qemu Vfat:`. The AROS toolchain can read
makefiles from the QEMU FAT handler as if they contained NUL bytes. The VM has
also frozen during copies and `makedir` on `RAM:`, so avoid large file
operations in the guest until that is fixed.

## Host cross-build for AROS One i386

AROS One i386 uses the `alt-abiv0` ABI. The current working cross-toolchain is:

```text
/Users/kaffeine/amiga-dev/toolchains/aros-i386-abiv0
```

From the source directory:

```sh
make -f Makefile.aros bebbosshd bebbosshkeygen probes \
  OUTDIR=aros-i386-abiv0-arosone \
  CC=/Users/kaffeine/amiga-dev/toolchains/aros-i386-abiv0/i386-aros-gcc \
  CXX=/Users/kaffeine/amiga-dev/toolchains/aros-i386-abiv0/i386-aros-g++ \
  AR=/Users/kaffeine/amiga-dev/toolchains/aros-i386-abiv0/i386-aros-ar \
  STRIP=/Users/kaffeine/amiga-dev/toolchains/aros-i386-abiv0/i386-aros-strip \
  AROS_SDK_ROOT="/Volumes/AROS One DVD/Development"
```

The current cross-build product is:

```text
aros-i386-abiv0-arosone/bebbosshd
aros-i386-abiv0-arosone/bebbosshkeygen
```

The VM CD image with only the current binary and crypto tests is:

```text
/Volumes/EXT/Macchine Virtuali/AROSOne_x86/bebbossh-aros-i386-bin.iso
```

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
- The interactive shell backend is temporarily disabled on AROS until it is
  reworked around AROS file handles. SFTP/server startup remains the first
  runtime target.

Forwarded host ports:

- VNC: `127.0.0.1:5901`
- guest SSH: `127.0.0.1:10022`
- guest telnet: `127.0.0.1:10023`

At the time of these notes, `bebbosshd` starts from the AROS One test ISO,
loads the host key, binds port 22, and listens. OpenSSH from macOS reaches the
server through QEMU forwarding at `127.0.0.1:10022`, completes SSH protocol
identification, key exchange, and password authentication.

Remote command execution is not complete yet. The AROS shell backend currently
reports:

```text
AROS shell backend not available yet
```

Native in-guest compilation therefore still needs either an enabled shell
service or manual/VNC launch of an AROS shell.

## Host-side verification

The crypto tests compile and pass on macOS with the Linux-flavoured make path:

```sh
make linux=1 LIBS_D= linux/testAES linux/testChacha20 linux/testEd25519 linux/testGCM linux/testSHA512
```
