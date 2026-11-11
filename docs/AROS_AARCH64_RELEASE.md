# AROS aarch64 Release Checklist

For the runtime kit of the Raspberry Pi port of AROS (`raspi-aarch64`). The
i386 and x86_64 kits have their own checklists (`docs/AROS_I386_RELEASE.md`,
`docs/AROS_X86_64_RELEASE.md`); the kits are not interchangeable.

The kit contains `bebbossh`, `bebboscp`, `bebbosshd`, `bebbosshkeygen`, the
AROS README, example configuration, test scripts and the license files. The
binaries use the i386 code paths (full AROS SDK, remote commands in child
tasks), not the x86_64 `mincrt` runtime.

Release naming (see `AROS_PORTING.md`):

```text
v1.0.10-aros-aarch64
bebbossh-aros-aarch64-<version>.zip
bebbossh-aros-aarch64-<version>.tar.gz
```

## Build

```sh
make -f Makefile.aros-aarch64 all \
  AROS_TOOLCHAIN=<toolchain dir> \
  SYSROOT=<AROS build>/bin/raspi-aarch64/AROS/Developer
./scripts/package-aros-runtime.sh aros-aarch64 dist/bebbossh-aros-aarch64-<version>
```

The compiler flags are explained in `Makefile.aros-aarch64` and
`AROS_PORTING.md`.

## Public asset gate

After publishing, check the assets from GitHub, not from `dist/`, and run the
SSH/SCP/SFTP smoke against a Pi on the local network:

```sh
BEBBOSSH_RELEASE_TAG=v1.0.11-aros-aarch64 \
BEBBOSSH_RELEASE_VERSION=v1.0.11 \
BEBBOSSH_RELEASE_ZIP_SHA256=<sha256> \
BEBBOSSH_RELEASE_TGZ_SHA256=<sha256> \
BEBBOSSH_AROS_HOST=<pi address> \
BEBBOSSH_AROS_PORT=22 \
BEBBOSSH_AROS_WORKDIR=RAM: \
./scripts/aros-aarch64-public-release-smoke.sh
```

Without `BEBBOSSH_AROS_PORT` only the archives are checked.
`BEBBOSSH_AROS_AUTH_HELPER=askpass` passes the password through `SSH_ASKPASS`
instead of `sshpass`.

## Install on the Raspberry Pi

1. Copy the unpacked kit to the system volume, for example `SYS:BebboSSH`.
2. In an AROS shell:

   ```text
   cd SYS:BebboSSH
   copy sshd_config.example sshd_config
   copy passwd.example passwd
   bebbosshkeygen -f T:seed_key
   delete T:seed_key T:seed_key.pub
   bebbosshkeygen -f ssh_host_ed25519_key
   stack 262144
   bebbosshd
   ```

3. Replace the test login in `passwd` before the Pi is reachable from other
   machines.

`SYS:` is a FAT volume: `protect` reports an error there, which can be
ignored.

## Autostart

AROSTCP starts at boot when `ENVARC:AROSTCP/AutoRun` contains `True`.
`S:User-Startup` then starts the daemon a few seconds later in its own console
window:

```text
; S:User-Startup
Execute SYS:BebboSSH/StartBSSH
```

```text
; SYS:BebboSSH/StartBSSH
FailAt 21
CD SYS:BebboSSH
If NOT EXISTS SYS:BebboSSH/ssh_host_ed25519_key
  Delete >NIL: T:seed_key T:seed_key.pub
  SYS:BebboSSH/bebbosshkeygen -f T:seed_key
  Delete >NIL: T:seed_key T:seed_key.pub
  SYS:BebboSSH/bebbosshkeygen -f SYS:BebboSSH/ssh_host_ed25519_key
EndIf
Run >NIL: NewShell CON:0/30/1000/620/BebboSSH FROM SYS:BebboSSH/RunDaemon
```

```text
; SYS:BebboSSH/RunDaemon
Stack 262144
Wait 5 SECS
SYS:BebboSSH/bebbosshd -p 22 -A SYS:BebboSSH/passwd -K SYS:BebboSSH/ssh_host_ed25519_key -H SYS:
```

Keep the default log level (see Known limits).

## Checks for every release

On a Raspberry Pi 400 with Ethernet and DHCP, the daemon at the default log
level:

1. The five crypto self-tests and `testRandpool`.
2. OpenSSH login and commands; 100 sequential logins.
3. SFTP uploads up to 16 MiB, OpenSSH `scp` of 4 MiB both ways with each
   cipher, `bebboscp` over loopback with each cipher, byte-identical. SFTP
   overwrite with a shorter file, also on the FAT system volume; a READ above
   the limit returns the capped size.
4. Zero-delay transfer stress (`BEBBOSSH_AROS_STRESS_DELAY=0`), 80 transfers.
5. Two daemons, a command on one while the other runs `Wait 12`, a reconnect
   during a dropped command, no leftover `T:bebbosshd-*` files.
6. Refused commands answer with exit status 2 (redirection, stdin-driven
   command) and 127 (unknown command); a second shell request and unknown
   subsystem names are rejected; a channel close sent first by the client is
   answered.
7. `direct-tcpip` forwarding with a session channel open, and a 4 MiB upload
   through it.
8. Native clients over loopback with public-key login; on the Pi console the
   host key question waits for the answer, and history, cursor keys,
   Shift+cursor and Ctrl+cursor work in the daemon's shell.
9. An SFTP path or a command on a missing volume fails at once, with no
   requester.
10. A client that stops reading during a long command output: a new login
    works after the 30-second bound, and Ctrl-C during the stall stops the
    daemon within 2 seconds.
11. `Break` (Ctrl-C): an idle daemon exits at once; with a running command or
    a parked session it exits when the command ends; each time it restarts
    right away.

## QEMU

QEMU `raspi3b` with `usb-net` runs the kit, but the guest receives about 340
bytes per second, and one large upload failed with a packet signature
mismatch that the Pi does not show. Use it for functional checks (login,
commands, channel handling, daemon exit without a kernel trap), not for
transfer tests.

## Ciphers

AES-GCM is plain C on aarch64, without AES instructions. Without a `Ciphers`
line the daemon offers `chacha20-poly1305@openssh.com` and
`aes128-gcm@openssh.com`, and `bebbossh`/`bebboscp` try ChaCha20-Poly1305
first; `--ciphers` and `ssh_config` still set the order. On the Pi 400 both
ciphers take the same time: 4 MiB with `scp` in about 0.5 s up and 2 s down,
with `bebboscp` 0.7 s each way.

## Known limits

- Raspberry Pi 400: a daemon logging at debug level (`-v5`) into a console
  window during the transfer stress froze the system twice. The same stress
  passes at the default level, so keep `DebugLevel 1` and use `-v5` only for
  short diagnostics.
- The limits of the i386 daemon apply too (see `README.AROS.txt`).
