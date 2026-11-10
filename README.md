# BebboSSH

**Short:** BebboSSH - SSH2 suite (client/server, sftp) with modern ciphers
**Author:** s.franke@bebbosoft.de
**Uploader:** s.franke@bebbosoft.de
**Upstream architecture:** m68k-amigaos
**AROS fork targets:** i386 `alt-abiv0`, x86_64 (mincrt), aarch64 (Raspberry Pi)
**Type:** comm/net
**Version:** 1.45
**Required:** bsdsocket.library (e.g. AmiTCP)
**Replaces:** amigassh

---

<!-- patreon-support:start -->
## Support development

You can support my work on the AROS port on [Patreon](https://www.patreon.com/c/kaffeine1), or with a one-time contribution on [Ko-fi](https://ko-fi.com/kaffeine1). Contributions are voluntary; no subscription is required to use the software. BebboSSH is by Stefan "Bebbo" Franke; his authorship and the upstream license are unchanged.
<!-- patreon-support:end -->

## AROS port

This repository is a fork of BebboSSH by Stefan "Bebbo" Franke, based on
upstream 1.45 (commit `5d68dd169cfbb701c5fe8debda8df0a8d896320e`) with the
security fixes of bebbossh 1.46.1 by Matthias Münch. The AROS changes are
Copyright (C) 2026 Michele Dipace <michele.dipace@kaffeine.net>, GNU GPL v3
or later like the upstream code.

One source tree builds three AROS targets:

| Target | Makefile | Latest release |
| --- | --- | --- |
| i386 `alt-abiv0` (AROS One 32-bit) | `Makefile.aros` | [v1.0.9](https://github.com/kaffeine1/bebbossh-aros/releases/tag/v1.0.9-aros-i386-abiv0) |
| x86_64 `mincrt` (AROS One 64-bit) | `Makefile.aros-x86_64` | [v1.0.9](https://github.com/kaffeine1/bebbossh-aros/releases/tag/v1.0.9-aros-x86_64) |
| aarch64 (AROS on the Raspberry Pi) | `Makefile.aros-aarch64` | [v1.0.9](https://github.com/kaffeine1/bebbossh-aros/releases/tag/v1.0.9-aros-aarch64) |

The kits are also on Aminet (`comm/net/bebbossh.*-aros.lha`) and on the AROS
Archives (`network/misc`).

What works: the server (`bebbosshd`) with password and Ed25519 public-key
login, remote commands, SFTP, OpenSSH `scp` and `direct-tcpip` forwarding; the
client (`bebbossh`), `bebboscp` and `bebbosshkeygen`. A minimal interactive
shell runs simple commands.

On aarch64 a command of the interactive shell, or of `ssh -t host command`,
has the SSH session as its console: it can read input, its output arrives at
once and Ctrl-C stops it (`InteractiveShell` in `sshd_config`).

Not supported on i386 and x86_64: interactive programs that read their
input, and redirection or pipes (`>`, `<`, `|`) in remote commands.

Open work:

- i386: test `InteractiveShell` (off by default there). Without it a command
  typed in the interactive shell runs inside the daemon, so other connections
  wait until it ends and Ctrl-C does not stop it. x86_64 always works this way.
- i386 and aarch64: a remote command still running after 30 seconds gets a
  timeout notice and exit status 124, but it is not stopped.
- x86_64: remote commands run synchronously, and an SFTP path on a missing
  volume opens a DOS requester.
- SFTP: apply the times from `FSETSTAT` after `CLOSE` (OpenSSH `put -p`).

Documentation:

- Install and use: `packaging/aros/README.AROS.txt` (`README.AROS.txt` in
  the kits).
- Build and port notes: `AROS_PORTING.md`.
- Release checklists: `docs/AROS_I386_RELEASE.md`,
  `docs/AROS_X86_64_RELEASE.md`, `docs/AROS_AARCH64_RELEASE.md`.
- Test scripts: `docs/AROS_TESTER.md`.

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
