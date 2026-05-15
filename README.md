# BebboSSH

**Short:** BebboSSH - SSH2 suite (client/server, sftp) with modern ciphers
**Author:** s.franke@bebbosoft.de
**Uploader:** s.franke@bebbosoft.de
**Upstream architecture:** m68k-amigaos
**AROS fork targets:** i386 `alt-abiv0` stable, x86_64 experimental
**Type:** comm/net
**Version:** 1.44
**Required:** bsdsocket.library (e.g. AmiTCP)
**Replaces:** amigassh

---

## AROS fork status

This repository is a derivative work / fork of the original BebboSSH project by
Stefan "Bebbo" Franke.

- Original upstream source: https://franke.ms/git/bebbo/bebbossh
- AROS porting changes: Copyright (C) 2026 Michele Dipace
  <michele.dipace@kaffeine.net>
- License of the AROS modifications: GNU GPL v3 or later, consistent with
  the upstream project license.

This is a multi-target AROS porting repository. The same source tree is used
for all AROS architectures, with separate makefile entry points and release
assets per target.

| Target | Status | Build entry point | Release assets |
| --- | --- | --- | --- |
| AROS i386 `alt-abiv0` | stable / validated | `Makefile.aros` | `bebbossh-aros-i386-*` |
| AROS i386 hosted | automation validated, transfer stress validated | `Makefile.aros` | hosted test kits only |
| AROS x86_64 hosted | paced automation validated, zero-delay release gate blocked | `Makefile.aros-x86_64` | experimental `bebbossh-aros-x86_64-*` |
| AROS x86_64 AROS One | keygen validated, daemon validation pending | `Makefile.aros-x86_64` | pre-release kits only |

The AROS port currently includes:

- a shared AROS build makefile (`Makefile.aros`) with target triplet overrides;
- static AROS builds of `bebbosshd` and `bebbosshkeygen`;
- compatibility headers for AROS builds;
- startup/runtime fixes for AROS One `alt-abiv0`;
- fallback loading of `PROGDIR:sshd_config` and
  `PROGDIR:ssh_host_ed25519_key` for ISO-based testing;
- read-only password-file support for test media;
- a minimal AROS remote `exec` backend for non-interactive commands;
- SFTP/SCP path validation for AROS assigns such as `T:` and `DH0:`;
- reproducible AROS runtime package targets;
- an experimental AROS x86_64 daemon/keygen path using minimal startup/runtime
  code;
- QEMU/AROS One test notes in `AROS_PORTING.md`.

Runtime status on AROS One i386:

- `bebbosshd` starts, loads an Ed25519 host key, binds port 22, and listens.
- `bebbosshkeygen` starts on AROS One i386 and reaches ED25519 key generation.
- OpenSSH from the host completes protocol identification, key exchange, and
  password authentication through QEMU port forwarding.
- Remote `exec` works for simple non-interactive commands through an AROS task
  wrapper around `SystemTags()`. `version` and `dir` have been tested, command
  output is returned after completion, and the command exit status is
  propagated to the SSH client.
- Long non-interactive commands no longer block the daemon's main loop. A soft
  timeout sends a break after 30 seconds.
- AROS remote exec intentionally rejects shell redirection and pipes (`>`, `<`,
  `|`) until they are stable. A rejected redirection returns SSH exit status 2
  and leaves the daemon usable.
- Interactive SSH sessions can run simple AROS commands and return to the
  prompt. Simple piped multi-command input such as `dir`, `cd`, `version`,
  and `exit` has been tested. Interactive `dir`, including `dir <path>`, is
  normalized to one name per line for readability.
- PTY exec for simple commands is routed through the same stable AROS command
  backend as non-PTY exec. Full stdin-driven PTY programs remain incomplete.
- Known interactive commands are rejected in non-PTY exec mode with exit status
  2 and a message asking the caller to use `ssh -tt`, so they do not block the
  daemon's main loop.
- SFTP and OpenSSH `scp` transfers work on `T:` and `DH0:`; 1 MiB and 5 MiB
  file round-trips and a small `telegram-amiga`-style directory tree have been
  tested. The SFTP server now honors explicit client read offsets instead of
  relying on sequential file position. Overwriting a larger file with a smaller
  file on `DH0:` has been verified to truncate correctly. AROS SFTP uploads
  also keep the AmigaDOS execute protection allowed, so uploaded binaries can
  be started without a manual `protect +e` step.
- The AROS daemon uses a larger listen backlog, and its per-loop accept burst
  can be configured with `ListenAcceptBurst` or the AROS `-B` option. The
  hosted default stays conservative while short-session churn remains under
  investigation.
- SFTP `mkdir`/`rmdir` has been tested on `DH0:`.
- A clean package install was tested by copying the runtime kit to a fresh
  `DH0:` directory, generating a host key with `bebbosshkeygen`, and starting a
  separate daemon from that directory.
- Full PTY-style interactive program support is still incomplete; use the
  minimal shell for short commands and non-PTY exec for automation.

Hosted AROS i386 automation status:

- The hosted i386 daemon uses a 1 MiB default command stack on all AROS builds.
  This avoids command-task crashes seen with larger `telegram-amiga` offline
  self-tests.
- The hosted i386 runtime has passed `telegram-test --help`,
  `--telegram-json-self-test`, `--telegram-get-updates-self-test`,
  `--telegram-inbox-self-test`, `--telegram-send-message-self-test`,
  `--telegram-client-self-test`, `--telegram-tls-status`, and a follow-up
  `C:Version` health check over OpenSSH.

The stable AROS i386 runtime kit can be generated with:

```sh
make -f Makefile.aros package-aros-runtime OUTDIR=aros-i386-abiv0-arosone
```

Published builds are attached to GitHub Releases as `.zip` and `.tar.gz`
runtime kits.

The experimental AROS x86_64 build wrapper builds the validated keygen and the
daemon used for hosted AROS smoke tests:

```sh
make -f Makefile.aros-x86_64 bebbosshkeygen bebbosshd
```

For host-side x86_64 crosstools, point `AROS_SDK_ROOT` at the matching AROS
x86_64 SDK and override the tool commands:

```sh
make -f Makefile.aros-x86_64 bebbosshkeygen bebbosshd \
  CC=<toolchain>/x86_64-aros-gcc \
  CXX=<toolchain>/x86_64-aros-g++ \
  AR=<toolchain>/x86_64-aros-ar \
  STRIP=<toolchain>/x86_64-aros-strip \
  OBJCOPY=<toolchain>/x86_64-aros-objcopy \
  AROS_SDK_ROOT=<path-to-aros-x86_64-sdk>
```

`Makefile.aros-x86_64` marks generated ELF files with AROS ABI version 11,
matching the current AROS One x86_64 runtime. Without this marker AROS One
x86_64 rejects otherwise valid ELF64 AROS binaries as not executable.
The wrapper also builds with x86_64-safe code model and unwind-table settings
so the final AROS ELF64 binaries keep relocation records to `R_X86_64_64`.
When using host-side crosstools, pass the matching `OBJCOPY` if it is not named
`objcopy`.

Do not use `Qemu Vfat` as proof that an x86_64 executable is valid. On the
current AROS One x86_64 VM, even a native AROS command copied through the QEMU
FAT shared disk can be rejected as not executable after copying to `DH0:`.
Use a byte-preserving transfer path, such as an ISO image or a native AROS
volume, before judging runtime validity.

Current x86_64 status: `bebbosshkeygen` has been validated on AROS One x86_64
from ISO transfer after copying to a persistent `AROS:` directory and applying
`Protect <file> RWED`; it generates both private and public Ed25519 key files.
`bebbosshd` x86_64 has been validated in hosted AROS x86_64 for short
non-interactive OpenSSH commands: `C:Version` and `C:Echo OK` return complete
output and exit status 0, an explicit missing command returns exit status 127,
and the daemon remains usable afterwards. With the current hosted test
environment, x86_64 also passes the `telegram-amiga` offline automation suite
used for `--help`, JSON, getUpdates, inbox, sendMessage, client-state, and
TLS-status checks. SFTP/SCP, PTY exec for simple commands, and the minimal
interactive shell pass the hosted smoke test on both x86_64 and i386, including
1 MiB and 5 MiB transfer round-trips on `SYS:TGTEST` in hosted runs. The x86_64
entropy path and non-hosted AROS One daemon validation remain experimental, so
x86_64 builds are published as experimental/pre-release kits.

### AROS automation workflow

For current AROS One i386 automation, prefer non-interactive SSH commands and
SFTP/SCP transfers on persistent volumes such as `DH0:`:

```sh
sshpass -p test ssh \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/tmp/bebbossh_aros_known_hosts \
  -p 10022 test@127.0.0.1 \
  'DH0:TGTEST/telegram-test --help'
```

Avoid `RAM:` in the current VM setup and do not use remote shell redirection or
pipes (`>`, `<`, `|`) yet.

The host-side smoke test used for the AROS automation workflow is:

```sh
scripts/aros-ssh-smoke-test.sh
```

It validates `version`, redirection rejection, non-PTY interactive-command
rejection, daemon health after both guards, `telegram-amiga` command exit
status propagation, PTY exec, an interactive shell sequence, and SCP/SFTP round
trips on `DH0:TGTEST`. By default it also performs 1 MiB and 5 MiB transfer
stress round-trips; override this with `BEBBOSSH_AROS_TRANSFER_SIZES`. Hosted
AROS tests can set `BEBBOSSH_AROS_WORKDIR=SYS:TGTEST` and
`BEBBOSSH_AROS_SHELL_HOME=SYS:`.

For repeated transfer stress, use:

```sh
BEBBOSSH_AROS_PORT=10022 \
BEBBOSSH_AROS_WORKDIR=SYS:TGTEST \
./scripts/aros-transfer-stress-test.sh
```

The transfer stress script defaults to a one-second delay between cycles for
downstream automation. Hosted AROS i386 passes the zero-delay stress gate with
sizes `257 4096 65536 1048576` on `SYS:TGTEST`; hosted AROS x86_64 previously
showed an intermittent longer zero-delay churn failure where OpenSSH could
report `incorrect signature` during handshake, but that failure was not
reproduced in the latest 10-iteration zero-delay run. Keep the paced default
for routine CI-style automation; use `BEBBOSSH_AROS_STRESS_DELAY=0` only as an
explicit regression stress test.

### AROS autostart

After copying the runtime kit to a persistent directory such as
`DH0:BSSHPKG`, add this to `S:User-Startup`:

```text
;BEGIN BebboSSHd AROS
Stack 262144
If EXISTS DH0:BSSHPKG/bebbosshd
    Run DH0:BSSHPKG/bebbosshd
EndIf
;END BebboSSHd AROS
```

This intentionally avoids `>NIL:` while the AROS redirection path is being
hardened. The default build keeps startup status messages at debug level, so a
normal autostart should not leave a daemon output window. For diagnostics, use
`DebugLevel debug` or launch with `-v5`.

When replacing an existing `bebbosshd` on AROS over SCP/SFTP, delete the old
file first and then upload the new one. This avoids stale trailing bytes on
filesystems or transfer paths that do not truncate an overwritten executable
reliably. Current AROS SFTP uploads set AmigaDOS file protection so uploaded
executables remain runnable.

## Overview

**BebboSSH** is an SSH2 implementation for
- Amiga systems (68000+).
- Linux systems (all cpu should do).

**Original Source Code:** https://franke.ms/git/bebbo/bebbossh

It requires a server that supports the included cryptographic algorithms.
The supported cryptographic methods are
- curve25519-sha256
- curve25519-sha256@libssh.org
- ssh-ed25519
- aes128-gcm@openssh.com
- chacha20-poly1305@openssh.com
- hmac-sha2-256
- sha512
So it needs a server that supports that. E.g. bebbosshd :-)

It provides the following tools and libraries:

- `bebbosshd` - SSH2 server daemon
- `bebbossh` - SSH2 client
- `bebboscp` - SCP file transfer utility
- `bebbosshkeygen` - Key generation tool (Ed25519)
- `libcryptossh.library`    (Amiga only)
- `libcryptossh.library020` (Amiga only, rename and use on 68020-68040 or 68080 CPUs)
- `libcryptossh.library060` (Amiga only, rename and use on 68060 CPUs)

Also check out **bebboget** for fast HTTPS downloads!

---

## Performance

It will work on an unaccelerated Amiga but establishing the connection takes
about one minute.

Example timings on an Amiga 3000:
- X25519 key pair creation: ~0.9s
- Signature verification: ~1.2s
Use `-v5` for DEBUG logs with timing info

Expected SCP transfer speeds (kB/s):
```
| Cipher       | UAE-A500/68000 | UAE-1200/68020 | A3000/68030 | V4SA/68080 |
|--------------|----------------|----------------|-------------|------------|
| AES-GCM      | 6.6            | 35.6           | -           | 317        |
| ChaChaPoly   | 5.8            | 32.2           | -           | 351        |

020 library version:

| Cipher       | UAE-A500/68000 | UAE-1200/68020 | A3000/68030 | V4SA/68080 |
|--------------|----------------|----------------|-------------|------------|
| AES-GCM      | -              | 44.6           | -           | 353        |
| ChaChaPoly   | -              | 60.1           | -           | 396        |
```

---

## Programs

### `bebbossh`
SSH2 client for interactive shells or remote command execution.
Supports config files, key authentication, port forwarding, verbosity levels, and cipher selection.

### `bebbosshd`
SSH2 server daemon.
Provides terminal emulation and SFTP file transfers.
Requires configuration in `ENVARC:ssh` (config, keys, passwd).

### `bebbosshkeygen`
Generates Ed25519 key files.

### `bebboscp`
SCP utility for copying files between local and remote systems.
Supports wildcards, config files, key authentication, verbosity, and cipher selection.

---

## Testing

Special thanks to testers:
- Patrik Axelsson
- Javier de las Rivas
- AiO (Joakim Ekblad)

---

## License

Most of BebboSSH is licensed under **GPLv3+**.
This includes:
- Core tools (`bebbossh`, `bebbosshd`, `bebboscp`, `bebbosshkeygen`)
- Cryptographic implementations (AES, ChaCha20, DES, 3DES, RC4, GCM, MD5, Poly1305, SHA-256/384/512)
- STL/ministl infrastructure and wrappers
- Java-like classes

Some components are derived from **SUPERCOP** (Bernstein, Lange, Schwabe, et al.) and are released into the **Public Domain**:
- Ed25519 internal math routines
- X25519 scalar multiplication
- Field arithmetic helpers

Combined use: The project as a whole is GPLv3+, but PD-marked files remain PD.

The AROS porting changes in this repository are licensed under GPLv3 or later.
Existing upstream copyright notices, license files, and public-domain notices
must be preserved when redistributing this fork or binaries built from it.

---

## Disclaimer of Warranty

Software is provided **"AS IS"** without warranty of any kind.
Use at your own risk.

---

## Limitation of Liability

The author shall not be liable for any damages (direct, indirect, incidental, or consequential) arising from use or distribution of this software.

---

## History

see bebbossh.readme

---

## RANDOM HINTS

- the know hosts are stored in `ENVARC:.ssh/known-hosts`

- the random generator is not the best...
  It's rand() pimped with time and vpos. Then SHA256 is applied. Good enough?
  But who would talk about security on an unprotected system like the Amiga?

- preset your username with
    set USER=<yourname>
  you can do this in `s:shell-startup`

- you can start it from the workbench!
  Use the icon tooltypes to set
    COMMAND a remote command to execute instead of a shell
    CONSOLE an Amiga console string (defaults to CON://///AUTO/CLOSE/WAIT)
    HOST    the host name
    PORT    the port (defaults to 22)
    TERM    the terminal emulation (defaults to xterm-amiga)
    USER    the user name

- no console graphics?
  install the `xterm-amiga` terminfo!

- no console colors?
  install the `xterm-amiga` terminfo!

- no mouse in mc or other applications?
  install the `xterm-amiga` terminfo!

- keys not working properly?
  install the `xterm-amiga` terminfo!

- can't install xterm-amiga and have to build it for my system?
  use tic and add the switch -s:
    tic -s xterm-amiga.src

- some key does still not work
  try pimping the xterm-amiga terminfo.
  use `tic -xsv9 -o. xterm-amiga.src`

- console displays trash? text look blank? lines are bogus?
  unset the variable `LANG`

- scp to bebbosshd: closed remote port
  ensure you are using the sftp subsystem, on some systems it's the `-s` flag
  `scp -s ...`

- your remote Amiga is blocking coz you accessed a volume that doesn't exist?
  e.g.: list foobar:
  Get https://aminet.net/util/boot/Requester.lha
  and run "Cancel 5" from your startup-sequence!
  Or try https://aminet.net/util/cdity/OkayDokey14.lha.

- public key authentication does not work!?
  Check the file ENVARC:.ssh/authorized_keys if your
  public key is listed there.

- can't scp to a server named 'ram', e.g. amigascp c:s* ram:folder
  add your user name to avoid detection as a local assign/drive:
    myname@ram:folder

- the program aborts with a message like "can't resolve _Z9splitLineRPc"?
  - ensure that you are using the recent libcryptossh.library
  - if you just updated bebbossh, close all running bebbossh programs and run
    "avail flush"

- ENTER does not work with multiple SSH hops? Try CTRL+J

---

## Summary

BebboSSH brings **modern SSH2, SCP, and SFTP functionality** to classic Amiga systems, with optimized cryptographic routines and support for both 68000 and 68020+ CPUs.
