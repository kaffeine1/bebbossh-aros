# AROS i386 Release Checklist

For the AROS One i386 `alt-abiv0` runtime kit. The x86_64 and aarch64 kits
have their own checklists (`docs/AROS_X86_64_RELEASE.md`,
`docs/AROS_AARCH64_RELEASE.md`); the kits are not interchangeable.

The kit contains `bebbossh`, `bebboscp`, `bebbosshd`, `bebbosshkeygen`, the
AROS README, example configuration, test scripts and the license files.

Release naming (see `AROS_PORTING.md`):

```text
v1.0.9-aros-i386-abiv0
bebbossh-aros-i386-abiv0-<version>.zip
bebbossh-aros-i386-abiv0-<version>.tar.gz
```

Latest release:
https://github.com/kaffeine1/bebbossh-aros/releases/tag/v1.0.9-aros-i386-abiv0

## Public asset gate

After publishing, check the assets from GitHub, not from `dist/`:

```sh
BEBBOSSH_RELEASE_TAG=v1.0.10-aros-i386-abiv0 \
BEBBOSSH_RELEASE_VERSION=v1.0.10 \
BEBBOSSH_RELEASE_ZIP_SHA256=<sha256> \
BEBBOSSH_RELEASE_TGZ_SHA256=<sha256> \
./scripts/aros-i386-public-release-smoke.sh
```

The script downloads the archives, checks the SHA256 values and the kit
content, and rejects packages with `hosted` artifacts. With
`BEBBOSSH_AROS_PORT` set it also runs the SSH/SCP/SFTP smoke against that
port. `BEBBOSSH_AROS_AUTH_HELPER=askpass` passes the password through
`SSH_ASKPASS` instead of `sshpass`.

## Clean VM install

Use a fresh or reset AROS One i386 VM, not a long-lived lab VM.

1. Copy the unpacked kit to `DH0:BSSHPKG`.
2. In an AROS shell:

   ```text
   cd DH0:BSSHPKG
   copy sshd_config.example sshd_config
   copy passwd.example passwd
   bebbosshkeygen -f T:seed_key
   delete T:seed_key T:seed_key.pub
   bebbosshkeygen -f ssh_host_ed25519_key
   stack 262144
   bebbosshd
   ```

3. From the host, against the forwarded port:

   ```sh
   BEBBOSSH_AROS_PORT=10022 \
   BEBBOSSH_AROS_WORKDIR=T: \
   ./scripts/aros-i386-public-release-smoke.sh
   ```

   `BEBBOSSH_AROS_USER` and `BEBBOSSH_AROS_PASS` override the `test` login.

For autostart, add to `S:User-Startup` and check that the smoke passes after a
reboot. If it fails, make sure the VM runs the release binary and not an older
one left in `DH0:BSSHPKG`.

```text
;BEGIN BebboSSHd AROS
Stack 262144
If EXISTS DH0:BSSHPKG/bebbosshd
    Run DH0:BSSHPKG/bebbosshd
EndIf
;END BebboSSHd AROS
```

## Native clients

The host-side smoke covers the daemon with OpenSSH. The AROS clients need a
console:

```text
cd DH0:BSSHPKG
makedir ENV:.ssh
makedir ENVARC:.ssh
; the first connection asks to trust the host key: answer yes
bebbossh -c client-loop-config loop echo vncok to BSSHPKG/client-vnc-touch
type BSSHPKG/client-vnc-touch
echo scpok to BSSHPKG/scp-src
bebboscp -c client-loop-config BSSHPKG/scp-src loop:BSSHPKG/scp-dst
type BSSHPKG/scp-dst
```

Check also that a second connection does not ask again and that a changed
host key is refused. In QEMU, start the client in its own window through the
daemon (`NewShell CON:0/20/800/500/CLIENT FROM <script>`) and type with the
monitor's `sendkey`.

## Checks for every release

1. 100 sequential logins and the zero-delay transfer stress
   (`BEBBOSSH_AROS_STRESS_DELAY=0 scripts/aros-transfer-stress-test.sh`).
2. SFTP uploads up to 16 MiB, OpenSSH `scp` both ways, SFTP times and
   overwrite with a shorter file, a READ above the limit, a missing volume
   (an error, no requester).
3. Two daemons at once, a reconnect during a dropped command, no leftover
   `T:bebbosshd-*` files.
4. Malformed channel requests get CHANNEL_FAILURE and the daemon keeps
   serving; a channel close sent first by the client is answered.
5. A client that stops reading during a long command output: a new login
   works after the 30-second bound, and Ctrl-C during the stall stops the
   daemon within 2 seconds. With `SendNoop many`, keep-alives go to channel 1
   after the daemon closed channel 0.
6. Public-key login, `AllowTcpForwarding off`, `direct-tcpip` forwarding.
7. The six self-tests of the same build, run in the VM (`testAES`,
   `testChacha20`, `testEd25519`, `testGCM`, `testSHA512`, `testRandpool`).
8. Daemon stop: start `bebbosshd -v5` and send `Break` (Ctrl-C):
   - idle, and with an idle client: it exits within a second or two and
     starts again at once;
   - during `ssh ... Wait 20`: the command runs to its end (Break cannot reach
     a command whose output goes to a file), the log shows "waiting for N busy
     sessions to end their commands", then "exiting main loop", no guru;
   - the same with the connection dropped during `Wait 20` and a new
     connection on the same socket: the daemon also waits for the parked
     command.

After the release: point `scripts/aros-i386-public-release-smoke.sh` at the
new tag, version and SHA256 values.
