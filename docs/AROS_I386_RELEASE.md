# AROS i386 Release Checklist

This checklist is for public AROS One i386 `alt-abiv0` runtime kits. It keeps
release validation separate from local development VMs, which may contain
experimental binaries or stale startup scripts.

## Scope

The i386 runtime kit is the stable AROS One / VMware 32-bit package. It
contains:

- `bebbossh`
- `bebboscp`
- `bebbosshd`
- `bebbosshkeygen`
- AROS README and example configuration files
- GPL and upstream license files

AROS x86_64 is a separate experimental target and is not part of the i386
release gate.

The latest complete public i386 runtime release is published on GitHub
Releases, next to the repository tag list:

```text
https://github.com/kaffeine1/bebbossh-aros/releases/tag/v0.2.5-aros-i386-abiv0
```

## Public Asset Gate

After publishing a release, verify the assets from GitHub rather than the local
`dist/` directory:

```sh
./scripts/aros-i386-public-release-smoke.sh
```

The script downloads the release archive, verifies the expected SHA256 values,
checks that the runtime kit contains the required binaries/docs/licenses, and
rejects any public package that contains `hosted` artifacts.

For a future version, override the defaults:

```sh
BEBBOSSH_RELEASE_TAG=v0.2.6-aros-i386-abiv0 \
BEBBOSSH_RELEASE_VERSION=v0.2.6 \
BEBBOSSH_RELEASE_ZIP_SHA256=<sha256> \
BEBBOSSH_RELEASE_TGZ_SHA256=<sha256> \
./scripts/aros-i386-public-release-smoke.sh
```

## Clean VM Install Gate

Use a fresh or explicitly reset AROS One i386 VM. Do not use a long-lived lab
VM as the only release proof.

1. Download the public release archive.
2. Copy the unpacked directory to `DH0:BSSHPKG`.
3. In an AROS shell:

   ```text
   cd DH0:BSSHPKG
   copy sshd_config.example sshd_config
   copy passwd.example passwd
   bebbosshkeygen -f ssh_host_ed25519_key
   stack 262144
   bebbosshd
   ```

4. From the host, run the runtime smoke against the forwarded SSH port:

   ```sh
   BEBBOSSH_AROS_PORT=10022 \
   BEBBOSSH_AROS_WORKDIR=T: \
   ./scripts/aros-i386-public-release-smoke.sh
   ```

5. If the VM uses another forwarded port or credentials, override:

   ```sh
   BEBBOSSH_AROS_PORT=11022 \
   BEBBOSSH_AROS_USER=test \
   BEBBOSSH_AROS_PASS=test \
   BEBBOSSH_AROS_WORKDIR=T: \
   ./scripts/aros-i386-public-release-smoke.sh
   ```

## Optional C: Command Install

AROS normally searches `C:` for shell commands. The client-side tools can be
copied there and then called without a full path:

```text
copy DH0:BSSHPKG/bebbossh C:
copy DH0:BSSHPKG/bebboscp C:
copy DH0:BSSHPKG/bebbosshkeygen C:
protect C:bebbossh +e
protect C:bebboscp +e
protect C:bebbosshkeygen +e
```

Then these work from any AROS Shell:

```text
bebbossh user@host
bebboscp localfile user@host:remotefile
bebbosshkeygen -f DH0:BSSHPKG/ssh_host_ed25519_key
```

For `bebbosshd`, prefer keeping the daemon and its config together in
`DH0:BSSHPKG`. The package defaults use `PROGDIR:` paths, and when a program is
run from `C:`, `PROGDIR:` becomes `C:`. If the daemon is installed in `C:`, pass
explicit config paths:

```text
bebbosshd -A DH0:BSSHPKG/passwd -K DH0:BSSHPKG/ssh_host_ed25519_key -H DH0:
```

## AROS Native Client Gate

The public host-side smoke proves the daemon, OpenSSH SCP, and OpenSSH SFTP.
The AROS-native client tools also need one real AROS shell validation before a
release is considered complete:

```text
cd DH0:BSSHPKG
makedir ENV:.ssh
makedir ENVARC:.ssh
; Install a valid known_hosts entry for loopback first.

bebbossh -c client-loop-config loop echo vncok to BSSHPKG/client-vnc-touch
type BSSHPKG/client-vnc-touch
```

For `bebboscp`, copy a small file over loopback and compare the source and
destination:

```text
echo scpok to BSSHPKG/scp-src
bebboscp -c client-loop-config BSSHPKG/scp-src loop:BSSHPKG/scp-dst
type BSSHPKG/scp-src
type BSSHPKG/scp-dst
```

This gate requires VNC or another real AROS console today. Keep it manual until
there is a robust way to inject AROS shell commands without focus races.

## Autostart Gate

For integration images, add this block to `S:User-Startup`:

```text
;BEGIN BebboSSHd AROS
Stack 262144
If EXISTS DH0:BSSHPKG/bebbosshd
    Run DH0:BSSHPKG/bebbosshd
EndIf
;END BebboSSHd AROS
```

After reboot, the host-side runtime smoke should pass without opening VNC:

```sh
BEBBOSSH_AROS_PORT=10022 ./scripts/aros-i386-public-release-smoke.sh
```

If it fails, first confirm that the VM is actually running the public release
binary and not an older lab `bebbosshd` left in `DH0:BSSHPKG`.
