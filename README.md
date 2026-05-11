# BebboSSH

**Short:** BebboSSH - SSH2 suite (client/server, sftp) with modern ciphers
**Author:** s.franke@bebbosoft.de
**Uploader:** s.franke@bebbosoft.de
**Architecture:** m68k-amigaos
**Type:** comm/net
**Version:** 1.44
**Required:** bsdsocket.library (e.g. AmiTCP)
**Replaces:** amigassh

---

## AROS/i386 fork status

This repository is a derivative work / fork of the original BebboSSH project by
Stefan "Bebbo" Franke.

- Original upstream source: https://franke.ms/git/bebbo/bebbossh
- AROS/i386 porting changes: Copyright (C) 2026 Michele Dipace
  <michele.dipace@kaffeine.net>
- License of the AROS/i386 modifications: GNU GPL v3 or later, consistent with
  the upstream project license.

The current porting target is AROS i386. x86_64 support is intentionally
deferred until the i386 build and runtime behaviour are stable.

The AROS/i386 work currently includes:

- an AROS-specific cross-build makefile (`Makefile.aros`);
- static AROS/i386 builds of `bebbosshd` and `bebbosshkeygen`;
- compatibility headers for AROS/i386 builds;
- startup/runtime fixes for AROS One `alt-abiv0`;
- fallback loading of `PROGDIR:sshd_config` and
  `PROGDIR:ssh_host_ed25519_key` for ISO-based testing;
- read-only password-file support for test media;
- a minimal AROS remote `exec` backend for non-interactive commands;
- SFTP/SCP path validation for AROS assigns such as `T:` and `DH0:`;
- a reproducible AROS/i386 runtime package target;
- QEMU/AROS One test notes in `AROS_PORTING.md`.

Runtime status on AROS One i386:

- `bebbosshd` starts, loads an Ed25519 host key, binds port 22, and listens.
- `bebbosshkeygen` starts on AROS One i386 and reaches ED25519 key generation.
- OpenSSH from the host completes protocol identification, key exchange, and
  password authentication through QEMU port forwarding.
- Remote `exec` works for simple non-interactive commands through the current
  AROS `SystemTags()` backend. `version` and `dir` have been tested.
- Interactive SSH sessions can run simple AROS commands and return to the
  prompt using the same `SystemTags()` backend.
- SFTP and OpenSSH `scp` transfers work on `T:` and `DH0:`; 1 MiB and 5 MiB
  file round-trips and a small `telegram-amiga`-style directory tree have been
  tested.
- SFTP `mkdir`/`rmdir` has been tested on `DH0:`.
- Full PTY-style interactive program support is still incomplete.

The AROS/i386 runtime kit can be generated with:

```sh
make -f Makefile.aros package-aros-runtime OUTDIR=aros-i386-abiv0-arosone
```

Published builds are attached to GitHub Releases as `.zip` and `.tar.gz`
runtime kits.

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

The AROS/i386 porting changes in this repository are licensed under GPLv3 or
later. Existing upstream copyright notices, license files, and public-domain
notices must be preserved when redistributing this fork or binaries built from
it.

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
