# BebboSSH AROS Porting Notes

One source tree builds three AROS targets. Makefiles, package names, release
tags and validation are kept per target.

| Target | Build entry point | Runtime kit | Validated on |
| --- | --- | --- | --- |
| i386 `alt-abiv0` (AROS One 32-bit) | `Makefile.aros` | `bebbossh-aros-i386-abiv0-*` | AROS One i386 under QEMU |
| x86_64 `mincrt` (AROS One 64-bit) | `Makefile.aros-x86_64` | `bebbossh-aros-x86_64-*` | AROS One x86_64 under QEMU |
| aarch64 (`raspi-aarch64`) | `Makefile.aros-aarch64` | `bebbossh-aros-aarch64-*` | Raspberry Pi 400, QEMU `raspi3b` |

Hosted AROS builds are used only for development tests; never publish them as
runtime kits.

## Upstream and license

The port is a derivative of Stefan "Bebbo" Franke's BebboSSH
(https://franke.ms/git/bebbo/bebbossh), based on upstream 1.45, commit
`5d68dd169cfbb701c5fe8debda8df0a8d896320e` of a fresh clone. That snapshot
includes the 1.45 `bebbosshkeygen` key-format fixes and the constant upper
bound for the key exchange reply time.

The AROS changes are by Michele Dipace <michele.dipace@kaffeine.net>, GNU GPL
v3 or later like the upstream code.

## What the port changes

- A platform and endian layer separates the Amiga API from the Linux/POSIX
  server paths. No m68k assembly in the AROS build; the Linux PTY/PAM path
  stays Linux-only.
- `bebbosshd`: `PROGDIR:` fallbacks for `sshd_config` and the host key, a
  read-only password file for ISO tests, remote commands through AmigaDOS
  (`exec`), accept-loop burst control (`ListenAcceptBurst`, `-B`), a 1 MiB
  default command stack, cleanup on shutdown and on dropped connections.
- SFTP: assigns resolved in paths, client read offsets honored, short writes
  reported as errors, uploads keep the AmigaDOS execute bit.
- Banner and key exchange name lists parsed safely when binary data arrives
  with the client banner.
- The security fixes of bebbossh 1.46.1 by Matthias Münch (patches 0005 and
  0010 to 0016): packet parsing bounded to the received packet in daemon and
  client, authentication required before the connection protocol, no login
  from a public-key query alone, SFTP attribute and write bounds,
  `AllowTcpForwarding`, buffer fixes in `barrett_reduce()` and
  `bebbosshkeygen`, canonical Ed25519 signatures only, constant-time tag
  checks, an all-zero X25519 secret refused, key material wiped on exit, and
  client host key checks that refuse a changed key and ask only at a console.
- `randfill()` is a SHA-512 entropy pool with the seed file
  `ENVARC:.ssh/random_seed` (`src/aros_randpool.cpp`, from patch 0008 of
  1.46.1). The older mixer in `src/rand.c` is built only with
  `BEBBOSSH_RANDPOOL=0`. `bebbosshkeygen` checks its writes, deletes a partial
  key and wipes the secrets.

## Crypto is linked statically

The 68k BebboSSH ships its crypto as `libcryptossh.library`. On AROS the same
source is linked statically (`libcryptossh.a`) into each of the four tools;
`src/libcryptossh.def` is kept but not used. A real AROS library needs
`genmodule` and an ABI-specific jump table on the two ABIs that were hardest to
stabilize (`alt-abiv0` and `mincrt`), and static binaries cannot mismatch their
library. Each binary carries about 150 KB of crypto.

## i386 build

Cross-compile on the host with an AROS One `alt-abiv0` toolchain and a
complete AROS One SDK (with `startup.o` and the static libraries):

```sh
make -f Makefile.aros all \
  CC=<toolchain>/i386-aros-gcc CXX=<toolchain>/i386-aros-g++ \
  AR=<toolchain>/i386-aros-ar STRIP=<toolchain>/i386-aros-strip \
  OBJCOPY=<toolchain>/i386-aros-objcopy \
  AROS_SDK_ROOT=<aros-one-sdk>/Development
```

`all` builds the four tools and the self-tests (`testAES`, `testChacha20`,
`testEd25519`, `testGCM`, `testSHA512`, `testRandpool`) in `aros-i386/`, or in
`OUTDIR`. A build that fails for missing `startup.o`, `libamiga.a` or similar
has an incomplete SDK and must not be published.

## x86_64 build

```sh
make -f Makefile.aros-x86_64 all \
  CC=<toolchain>/x86_64-aros-gcc CXX=<toolchain>/x86_64-aros-g++ \
  AR=<toolchain>/x86_64-aros-ar STRIP=<toolchain>/x86_64-aros-strip \
  OBJCOPY=<toolchain>/x86_64-aros-objcopy
```

Use crosstools whose GCC already has an AROS sysroot, and leave
`AROS_SDK_ROOT` unset unless that SDK has the startup and crt libraries
`Makefile.aros` expects. The products land in `aros-x86_64/`. What is special
about this target:

- AROS One x86_64 accepts only ELF ABI version 11. The wrapper writes `0x0B`
  at byte 8 of each binary after link and strip; the Shell rejects version 1.
- x86_64-safe code model, no unwind tables, no hot/cold partitions; the only
  expected relocation is `R_X86_64_64`.
- The binaries use a minimal runtime (`mincrt`, `src/aros_mincrt.c`) without
  the standard init and exit symbol sets.
- The crosstools headers do not match AROS One in two ways. They are SMP
  headers, so structures that embed a `struct MsgPort`, such as
  `struct Process`, have wrong field offsets (`struct Library`,
  `struct IntuitionBase` and `struct Window` are fine). And their inline
  library calls pass the library base as a C argument, while AROS One reads it
  from `r12`. Every system call therefore goes through a wrapper in
  `src/aros_mincrt.c` that loads `r12` and calls the jump table. Do not add a
  direct `proto/` call to x86_64 code.
- `Delay()` does nothing on `mincrt`.
- A command without a terminal runs synchronously (`SystemTagList`, output
  through a `T:` file): the daemon serves no other client while it runs. The
  child-task backend of i386 is not compiled: its entry reads
  `pr_ExitData`, which the crosstools headers place 240 bytes away from
  where AROS One keeps it.
- A console mode command (see below) runs in its own process all the same:
  its entry, `ShellChannel::arosConsoleProcX64()`, calls only wrappers, reads
  no field of `struct Process`, and gets its channel through `NP_UserData`
  (`tc_UserData` of `struct Task`, which has the same layout on both sides).
- The daemon does not set `pr_WindowPtr` (see the SMP note), so an SFTP path
  on a missing volume opens a DOS requester.
- `HomeDir` is used only with `BEBBOSSH_AROS_X64_CD` (the daemon does not
  change its own directory).
- Opt-in flags, off by default, read by `bebbossh_aros_x64_flag()`: on when
  the variable exists globally (`setenv NAME 1`) or in the starting shell
  (`set NAME 1`).
  - `BEBBOSSH_AROS_X64_SFTP_MTIME`: keep upload times (`SetFileDate`).
  - `BEBBOSSH_AROS_X64_CD`: `cd`, `pwd` and a dynamic prompt in the
    interactive shell.
  - `BEBBOSSH_AROS_X64_SFTP_LINKS`: SFTP `READLINK` and `SYMLINK`.
- The self-tests build (`run-tests`) but do not start on AROS One: the
  prebuilt `libautoinit.a` calls `OpenLibrary` without SysBase in `r12`.

Crypto fast paths, used only on x86_64:

- AES-GCM with AES-NI and PCLMULQDQ, chosen at run time through `CPUID` (the
  VM must expose the flags, for example QEMU `-cpu host`); otherwise the
  portable table code runs. Only legacy SSE encodings, no AVX.
- ChaCha20 with SSE2, four blocks at a time; Poly1305 with 64-bit limbs.
- Output matches the portable code (differential tests, RFC 8439 vector,
  AES-GCM checked against PyCryptodome).

## aarch64 build

`Makefile.aros-aarch64` wraps `Makefile.aros` for the `aarch64-aros`
crosstools (GCC 6.5.0), with the `Developer` directory of an AROS
`raspi-aarch64` build as sysroot. `AROS_SDK_ROOT` stays unset:

```sh
make -f Makefile.aros-aarch64 all \
  AROS_TOOLCHAIN=<toolchain dir> \
  SYSROOT=<AROS build>/bin/raspi-aarch64/AROS/Developer
```

The products land in `aros-aarch64/`, stripped (the strip keeps the AROS
OS/ABI tag). Extra compiler flags:

- `-ffixed-x18`: the register is reserved on AROS aarch64.
- `-fno-common`: the AROS loader rejects COMMON symbols.
- `-fsigned-char`: the code expects a signed `char`.
- `-noposixc`: the programs open stdc.library and stdcio.library only. A
  program that opens AROS posixc.library loses about 160 KB when it ends
  (the library opens stdc.library and stdcio.library for itself and does not
  close them). The option also removes the posixc headers:
  `include/aros_noposixc` has the ones the sources ask for, and
  `src/aros_noposixc.c` has `gettimeofday()`, `gmtime_r()` and `mkdir()`.

aarch64 uses the i386 code paths (full SDK, remote commands in child tasks),
with three differences:

- The entropy pool reads the generic timer `cntvct_el0` (54 MHz on the Pi
  400, 62.5 MHz in QEMU) instead of `rdtsc`.
- The SDK declares `CreateExtIO()` and `CreatePort()` in
  `clib/alib_protos.h`, which bind to the `amiga.lib` versions while the frees
  went elsewhere, and every daemon exit crashed. On aarch64 the timer request
  in `bebbosshd.cpp` and the keyboard.device port and request in
  `keyboard.cpp` use `CreateMsgPort()`/`CreateIORequest()` and their
  `Delete` pairs.
- AES-GCM is portable C (no AES or PMULL instructions), so the daemon also
  offers chacha20-poly1305 without a `Ciphers` line, and `bebbossh`/`bebboscp`
  try it first (`DEFAULT_ENC_ORDER` in `include/client.h`).

## Console mode (InteractiveShell)

BebboSSH on AmigaOS gives a command the SSH channel as console: the daemon
answers the DOS packets of three file handles (`handleMsg()` in
`src/bebbosshd.cpp`). The AROS port first ran commands with `NIL:` as input
and a file in `T:` as output. With `InteractiveShell yes` (the default) a
command of the interactive shell, or of an exec request with a terminal, uses
the packet console again:

- The command runs through `System()` in a child process; its handles come
  from `AllocDosObject()` and are closed with `Close()`.
- The daemon keeps a cooked mode (echo, backspace, complete lines, Ctrl-D as
  end of file) and switches to raw mode on `ACTION_SCREEN_MODE`.
- Ctrl-C goes to the process that `ACTION_CHANGE_SIGNAL` named; AROS passes
  either its message port or the process itself there.
- `ACTION_WAIT_CHAR` and `ACTION_SCREEN_MODE` carry no file handle: the
  channel is found by the sender's port, or it is the only one in console
  mode.
- An exec request without a terminal keeps the file mode.
- x86_64: the daemon loop also waits for the packet port, the replies go
  through the `ReplyPkt` wrapper, the process port named by
  `ACTION_CHANGE_SIGNAL` follows `struct Task` (as on AROS One), and
  `SetProgramDir(BNULL)` around `System()` keeps the program directory
  unlocked, also for commands without a terminal.

## Runtime kit

```sh
./scripts/package-aros-runtime.sh <build output dir> dist/bebbossh-aros-<target>-<version>
```

The target comes from the kit directory name (`x86_64`, `aarch64`, otherwise
i386). The script writes the kit directory with its `.zip` and `.tar.gz`: the
four tools, the example `sshd_config` and `passwd`, `README.AROS.txt`, the
test scripts and release checklist of the target, `AROS_TESTER.md`,
`README.md`, this file, the license files and `SHA256SUMS`. It never adds host
keys or real passwords.

Release tags and asset names:

```text
v1.0.9-aros-i386-abiv0
bebbossh-aros-i386-abiv0-<version>.zip
bebbossh-aros-i386-abiv0-<version>.tar.gz

v1.0.9-aros-x86_64
bebbossh-aros-x86_64-<version>.zip
bebbossh-aros-x86_64-<version>.tar.gz

v1.0.9-aros-aarch64
bebbossh-aros-aarch64-<version>.zip
bebbossh-aros-aarch64-<version>.tar.gz
```

The three kits are not interchangeable, and a hosted i386 binary does not run
on AROS One. Asset names never contain `hosted`; the release smoke scripts
reject such packages.

## Notes for test VMs

- Do not build inside the QEMU `Qemu Vfat:` share, and do not move binaries
  through it: the FAT handler can corrupt makefiles and executables. Use an
  ISO image or a native AROS volume.
- When replacing a binary over SCP or SFTP on an older daemon, delete the old
  file first and compare a download afterwards.
- AROS One x86_64 with an Intel e1000 card can halt under heavy network load
  (AROS driver, fixed upstream in deadwood2/AROS#274). Use rtl8139 or pcnet
  for stress tests.
- With `sshpass`, `sftp -b` needs `-oBatchMode=no`. For long password churn
  prefer `BEBBOSSH_AROS_AUTH_HELPER=askpass`; `sshpass` can miss the prompt
  at zero delay.

The limits users see are listed in `packaging/aros/README.AROS.txt`; the test
scripts and their variables are in `docs/AROS_TESTER.md`.

## Host-side check

The crypto tests also build and pass on macOS through the Linux make path:

```sh
make linux=1 LIBS_D= linux/testAES linux/testChacha20 linux/testEd25519 linux/testGCM linux/testSHA512
```
