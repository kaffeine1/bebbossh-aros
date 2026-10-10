# AROS aarch64 Release Checklist

This checklist is for the AROS aarch64 runtime kit, built for the Raspberry Pi
port of AROS (`raspi-aarch64`). It mirrors `docs/AROS_I386_RELEASE.md` and
`docs/AROS_X86_64_RELEASE.md`.

## Scope

The aarch64 runtime kit contains:

- `bebbossh`
- `bebboscp`
- `bebbosshd`
- `bebbosshkeygen`
- AROS README and example configuration files
- GPL and upstream license files

The aarch64 binaries use the same code paths as i386 (full AROS SDK, remote
commands in child tasks), not the x86_64 `mincrt` runtime. The kits of the
three targets are not interchangeable.

Release naming (see `AROS_PORTING.md`):

```text
v1.0.5-aros-aarch64
bebbossh-aros-aarch64-<version>.zip
bebbossh-aros-aarch64-<version>.tar.gz
```

## Build

The build uses the `aarch64-aros` crosstools (GCC 6.5.0) with the `Developer`
directory of an AROS `raspi-aarch64` build as sysroot:

```sh
make -f Makefile.aros-aarch64 all \
  AROS_TOOLCHAIN=<toolchain dir> \
  SYSROOT=<AROS build>/bin/raspi-aarch64/AROS/Developer
./scripts/package-aros-runtime.sh aros-aarch64 dist/bebbossh-aros-aarch64-<version>
```

The compiler flags and the reasons for them are in `Makefile.aros-aarch64`.
The binaries are stripped; the strip keeps the AROS OS/ABI tag in the ELF
header.

## Public Asset Gate

After publishing a release, verify the assets from GitHub rather than the local
`dist/` directory:

```sh
BEBBOSSH_RELEASE_ZIP_SHA256=<sha256> \
BEBBOSSH_RELEASE_TGZ_SHA256=<sha256> \
./scripts/aros-aarch64-public-release-smoke.sh
```

The script downloads the release archive, verifies the expected SHA256 values
(skipped if unset), checks that the kit contains the required
binaries/docs/licenses, and rejects any package that contains `hosted`
artifacts. To also run the SSH/SCP/SFTP smoke against a Raspberry Pi on the
local network, set its address and port:

```sh
BEBBOSSH_AROS_HOST=<pi address> \
BEBBOSSH_AROS_PORT=22 \
BEBBOSSH_AROS_WORKDIR=RAM: \
./scripts/aros-aarch64-public-release-smoke.sh
```

## Install on the Raspberry Pi

1. Copy the unpacked directory to the AROS system volume, for example
   `SYS:BebboSSH`.
2. In an AROS shell:

   ```text
   cd SYS:BebboSSH
   copy sshd_config.example sshd_config
   copy passwd.example passwd
   bebbosshkeygen -f ssh_host_ed25519_key
   stack 262144
   bebbosshd
   ```

3. Replace the test credentials in `passwd` before the Pi is reachable from
   other machines.

`SYS:` on the Raspberry Pi image is a FAT volume. `protect` reports an error
there; the files still run, so the error can be ignored.

## Autostart

Validated on the Raspberry Pi 400: AROSTCP starts at boot when
`ENVARC:AROSTCP/AutoRun` contains `True`, and `S:User-Startup` starts the
daemon a few seconds later in its own console window:

```text
; S:User-Startup
Execute SYS:BebboSSH/StartBSSH
```

```text
; SYS:BebboSSH/StartBSSH
FailAt 21
CD SYS:BebboSSH
If NOT EXISTS SYS:BebboSSH/ssh_host_ed25519_key
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

Keep the default log level here (see Known limits).

## Validation status

First aarch64 release, on a Raspberry Pi 400 (AROS `raspi-aarch64` of
2026-09-12, `bcmgenet.device` Ethernet, DHCP), with the daemon at the default
log level unless noted:

1. The five crypto self-tests (`testAES`, `testGCM`, `testChacha20`,
   `testSHA512`, `testEd25519`) pass.
2. OpenSSH login and command execution; 100 sequential logins.
3. SFTP upload and download of 200 KB and 1 MiB, and OpenSSH `scp` of 1 MiB
   both ways with `aes128-gcm@openssh.com`, byte-identical. SFTP overwrite
   with a shorter file, also on the FAT system volume. An SFTP READ above the
   limit returns the capped size.
4. Zero-delay transfer stress (`BEBBOSSH_AROS_STRESS_DELAY=0`), 20 iterations,
   80 transfers up to 1 MiB.
5. Two daemons at once, a command on one while the other runs `Wait 12`,
   reconnect during a dropped command, no leftover `T:bebbosshd-*` files.
6. Refused commands answer with exit status 2 (redirection, stdin-driven
   command) and 127 (unknown command); a second shell request and unknown
   subsystem names are rejected.
7. `direct-tcpip` forwarding with a session channel open, 4 of 4.
8. Native clients over loopback with public-key login: `bebboscp` upload and
   download (byte-identical) and a `bebbossh` remote command.
9. Native client on the Pi 400 console (`bebbossh` in an AROS shell, password
   login): the host key question waits for the answer and saves the key, so
   the next connection does not ask again; in the daemon's shell the history,
   the cursor keys, Shift+cursor and Ctrl+cursor (word jump) work; `exit`
   returns to the local shell.
10. Interactive shell: `C:Vers<TAB>` completes to `C:Version` and `C:Li<TAB>`
    lists the matches; a cursor sequence and the next character sent in one
    packet are both applied.
11. An SFTP path or a command on a missing volume (`FOO:`, `DF0:`) fails at
    once; no requester blocks the daemon.
12. `Break` (Ctrl-C) on the daemon: an idle daemon exits at once; with a
    running command or a parked session it exits when the command ends; each
    time it restarts right away.
13. Entropy: `src/rand.c` reads the generic timer count `cntvct_el0`, which
    AROS tasks can read (54 MHz on the Pi 400).

In QEMU (`raspi3b`, AROS nightly of 2026-10-05) the daemon also exits without
a kernel trap after a duplicate channel id and after `Break`, and the battery
of items 2 and 5 to 8 passes.

## Known limits

- Raspberry Pi 400: a daemon logging at debug level (`-v5`) into a console
  window during the transfer stress froze the system twice (first the
  display, then the network). The same stress passes at the default log
  level, so keep `DebugLevel 1` and use `-v5` only for short diagnostics.
- QEMU `raspi3b` with `usb-net`: the guest receives about 340 bytes per
  second and one large upload failed with a packet signature mismatch, while
  the same uploads pass on the Pi 400. Use real hardware for transfer tests.
- The limits of the i386 daemon apply too (see
  `packaging/aros/README.AROS.txt`): commands typed in the interactive shell
  run inside the daemon, and a remote command still running after 30 seconds
  gets a timeout notice but is not stopped.
