# AROS x86_64 Release Checklist

For the AROS One x86_64 (`mincrt`) runtime kit. The i386 and aarch64 kits have
their own checklists (`docs/AROS_I386_RELEASE.md`,
`docs/AROS_AARCH64_RELEASE.md`); the kits are not interchangeable.

The kit contains `bebbossh`, `bebboscp`, `bebbosshd`, `bebbosshkeygen`, the
AROS README, example configuration, test scripts and the license files.

Release naming (see `AROS_PORTING.md`):

```text
v1.0.10-aros-x86_64
bebbossh-aros-x86_64-<version>.zip
bebbossh-aros-x86_64-<version>.tar.gz
```

## ELF ABI version

AROS One x86_64 runs only ELF commands with `EI_ABIVERSION = 11`; the build
writes `0x0B` at byte 8 after link and strip. If the Shell rejects a fresh
binary, check that byte first.

## Network card

The AROS `e1000.device` can halt or reboot the guest under heavy load, or
send a corrupted packet (fixed upstream in deadwood2/AROS#274). With four
daemons and the zero-delay stress, e1000 failed in 3 of 12 fresh boots,
rtl8139 in 0 of 24 and pcnet in 0 of 6. Run the gates with
`-device rtl8139` or `-device pcnet` and the matching driver in
`ENVARC:AROSTCP/db/interfaces`:

```text
net0 DEV=DEVS:networks/rtl8139.device UNIT=0  IP=DHCP NETMASK=255.255.255.0 UP
```

A halt in an e1000 run is not by itself a BebboSSH regression.

## Public asset gate

After publishing, check the assets from GitHub, not from `dist/`:

```sh
BEBBOSSH_RELEASE_TAG=v1.0.11-aros-x86_64 \
BEBBOSSH_RELEASE_VERSION=v1.0.11 \
BEBBOSSH_RELEASE_ZIP_SHA256=<sha256> \
BEBBOSSH_RELEASE_TGZ_SHA256=<sha256> \
./scripts/aros-x86_64-public-release-smoke.sh
```

The script downloads the archives, checks the SHA256 values (skipped if
unset) and the kit content, and rejects packages with `hosted` artifacts. With
`BEBBOSSH_AROS_PORT` set it also runs the SSH/SCP/SFTP smoke against that
port. `BEBBOSSH_AROS_AUTH_HELPER=askpass` passes the password through
`SSH_ASKPASS` instead of `sshpass`.

## Clean VM install

Use a fresh or reset AROS One x86_64 VM, not a long-lived lab VM. The system
volume is `AROS:`.

1. Copy the unpacked kit to `AROS:BSSHPKG`.
2. In an AROS shell:

   ```text
   cd AROS:BSSHPKG
   copy sshd_config.example sshd_config
   copy passwd.example passwd
   bebbosshkeygen -f T:seed_key
   delete T:seed_key T:seed_key.pub
   bebbosshkeygen -f ssh_host_ed25519_key
   stack 262144
   bebbosshd
   ```

3. From the host, against the forwarded port (`20022` by convention):

   ```sh
   BEBBOSSH_AROS_PORT=20022 \
   BEBBOSSH_AROS_WORKDIR=T: \
   ./scripts/aros-x86_64-public-release-smoke.sh
   ```

   `BEBBOSSH_AROS_USER` and `BEBBOSSH_AROS_PASS` override the `test` login.

For autostart, add to `S:User-Startup` and check that the smoke passes after a
reboot:

```text
;BEGIN BebboSSHd AROS
Stack 262144
If EXISTS AROS:BSSHPKG/bebbosshd
    Run AROS:BSSHPKG/bebbosshd
EndIf
;END BebboSSHd AROS
```

## Checks for every release

Run on QEMU `qemu64` (portable AES-GCM) and on
`qemu64,+aes,+pclmulqdq,+ssse3` or `-cpu host` (AES-NI path), with an
rtl8139 card:

1. One SCP transfer with each cipher (`-c aes128-gcm@openssh.com`,
   `-c chacha20-poly1305@openssh.com`), byte-identical.
2. Password churn: 100 sequential logins, and
   `BEBBOSSH_AROS_STRESS_DELAY=0 scripts/aros-transfer-stress-test.sh` with no
   authentication failure.
3. SFTP: uploads up to 16 MiB; overwrite with a shorter file leaves no
   trailing bytes; a READ above the limit returns the capped size.
4. `bebbosshd -v5` logs. When the daemon exits after a duplicate channel id,
   and on `Break` (Ctrl-C) idle, with an idle client and during a command, it
   releases its resources without a guru and starts again at once.
5. Malformed channel requests (a second `shell`, an unknown or short
   `subsystem` name) get CHANNEL_FAILURE and the daemon keeps serving.
6. A channel close sent first by the client is answered, at once when idle
   and for SFTP and `direct-tcpip`, at the end of a running command.
7. A client that stops reading during a long command output: a new login
   works after the 30-second bound. With `SendNoop many`, keep-alives go to
   channel 1 after the daemon closed channel 0.
8. `sshd_config` is read: with `Port 2222` the daemon answers on 2222 and not
   on 22; without the file it answers on 22 with `PROGDIR:passwd`.
9. Native clients on the AROS console: the host key question waits for the
   answer and saves the key, a changed key is refused; after exit the console
   is back in cooked mode; Ctrl-C at the password prompt quits;
   Shift+cursor keys reach the remote side. In QEMU, start the client in its
   own window through the daemon (`NewShell CON:0/20/800/500/CLIENT FROM
   <script>`) and type with the monitor's `sendkey`.
10. Native clients over loopback with public-key login: `bebboscp` upload and
    download, `bebbossh` remote command.
11. Interactive shell: `C:Vers<TAB>` completes to `C:Version`, `C:Li<TAB>`
    lists the matches.
12. Console mode (`InteractiveShell`, on by default): a question with a
    typed answer, output while a script runs, Ctrl-C, redirection, the
    console opened as a file, a nested `bebbossh` session, a second session
    during a long command, `ssh -t host command` with the exit status, a
    dropped connection and a daemon stop during a question; with
    `InteractiveShell no` the shell refuses programs that read their input.
13. Entropy: `bebbosshkeygen` and the daemon create and replace
    `ENVARC:.ssh/random_seed`, and keys differ across identical snapshot
    boots.

The self-tests do not start on AROS One (see `AROS_PORTING.md`); run them on
i386 or on the host.

After the release: point `scripts/aros-x86_64-public-release-smoke.sh` at the
new tag, version and SHA256 values.

## Known differences from i386

Commands without a terminal run synchronously, `HomeDir` needs
`BEBBOSSH_AROS_X64_CD`, an SFTP path on a missing volume opens a DOS
requester, and some features are opt-in flags. Details in `AROS_PORTING.md`.
