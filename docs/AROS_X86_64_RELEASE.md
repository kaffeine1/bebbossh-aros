# AROS x86_64 Release Checklist

This checklist is for AROS One / VMware 64-bit `x86_64` runtime kits. It mirrors
`docs/AROS_I386_RELEASE.md` but targets the `mincrt` x86_64 build, which is still
**experimental**: do not publish a kit as stable until the closure gates at the
end of this document pass.

## Scope

The x86_64 runtime kit is the AROS One / VMware 64-bit package. It contains:

- `bebbossh`
- `bebboscp`
- `bebbosshd`
- `bebbosshkeygen`
- AROS README and example configuration files
- GPL and upstream license files

AROS i386 `alt-abiv0` is a separate, stable target with its own gate
(`docs/AROS_I386_RELEASE.md`). The two kits are not interchangeable.

Release naming (see `AROS_PORTING.md`):

```text
v0.3.0-aros-x86_64
bebbossh-aros-x86_64-<version>.zip
bebbossh-aros-x86_64-<version>.tar.gz
```

## ELF ABI note (load-bearing)

AROS One x86_64 ships ELF64 commands with `EI_ABIVERSION = 11`. The build wrapper
patches the ELF header after link/strip (`Makefile.aros-x86_64`, the `POST_LINK`
step writes `0x0B` at byte offset 8). ABI version 1 binaries are rejected by the
AROS Shell. If a freshly built `bebbosshd`/`bebbossh` is rejected at launch,
confirm the ABI byte before suspecting the binary is otherwise invalid.

When replacing a binary over SCP/SFTP, delete the existing file first, then
upload and download it back for a byte compare, to avoid stale trailing bytes
from an in-place overwrite without truncation.

## Public Asset Gate

After publishing a release, verify the assets from GitHub rather than the local
`dist/` directory:

```sh
BEBBOSSH_RELEASE_ZIP_SHA256=<sha256> \
BEBBOSSH_RELEASE_TGZ_SHA256=<sha256> \
./scripts/aros-x86_64-public-release-smoke.sh
```

The script downloads the release archive, verifies the expected SHA256 values
(skipped if unset), checks the runtime kit contains the required
binaries/docs/licenses, and rejects any public package that contains `hosted`
artifacts.

For a future version, override the defaults:

```sh
BEBBOSSH_RELEASE_TAG=v0.3.1-aros-x86_64 \
BEBBOSSH_RELEASE_VERSION=v0.3.1 \
./scripts/aros-x86_64-public-release-smoke.sh
```

## Clean VM Install Gate

Use a fresh or explicitly reset AROS One x86_64 VM. Do not use a long-lived lab
VM as the only release proof. The x86_64 system volume is typically `AROS:`
(the i386 kit uses `DH0:`).

1. Download the public release archive.
2. Copy the unpacked directory to `AROS:BSSHPKG`.
3. In an AROS shell:

   ```text
   cd AROS:BSSHPKG
   copy sshd_config.example sshd_config
   copy passwd.example passwd
   bebbosshkeygen -f ssh_host_ed25519_key
   stack 262144
   bebbosshd
   ```

4. From the host, run the runtime smoke against the forwarded SSH port (the
   x86_64 hosted/QEMU port convention is `20022`):

   ```sh
   BEBBOSSH_AROS_PORT=20022 \
   BEBBOSSH_AROS_WORKDIR=T: \
   ./scripts/aros-x86_64-public-release-smoke.sh
   ```

5. If the VM uses another forwarded port or credentials, override:

   ```sh
   BEBBOSSH_AROS_PORT=21022 \
   BEBBOSSH_AROS_USER=test \
   BEBBOSSH_AROS_PASS=test \
   BEBBOSSH_AROS_WORKDIR=T: \
   ./scripts/aros-x86_64-public-release-smoke.sh
   ```

## Optional C: Command Install

The client-side tools can be copied to `C:` and called without a full path:

```text
copy AROS:BSSHPKG/bebbossh C:
copy AROS:BSSHPKG/bebboscp C:
copy AROS:BSSHPKG/bebbosshkeygen C:
protect C:bebbossh +e
protect C:bebboscp +e
protect C:bebbosshkeygen +e
```

For `bebbosshd`, keep the daemon and its config together in `AROS:BSSHPKG`
(package defaults use `PROGDIR:` paths; when run from `C:`, `PROGDIR:` becomes
`C:`). If the daemon is installed in `C:`, pass explicit config paths:

```text
bebbosshd -A AROS:BSSHPKG/passwd -K AROS:BSSHPKG/ssh_host_ed25519_key -H AROS:
```

## AROS Native Client Gate

The host-side smoke proves the daemon, OpenSSH SCP, and OpenSSH SFTP. The
AROS-native client tools also need one real AROS shell validation (via VNC or a
real console) before a release is considered complete, the same as the i386
gate. Keep this gate manual until there is a robust way to inject AROS shell
commands without focus races.

## Autostart Gate

For integration images, add this block to `S:User-Startup`:

```text
;BEGIN BebboSSHd AROS
Stack 262144
If EXISTS AROS:BSSHPKG/bebbosshd
    Run AROS:BSSHPKG/bebbosshd
EndIf
;END BebboSSHd AROS
```

After reboot, the host-side runtime smoke should pass without opening VNC:

```sh
BEBBOSSH_AROS_PORT=20022 ./scripts/aros-x86_64-public-release-smoke.sh
```

## Experimental → Stable closure gates

x86_64 stays experimental until ALL of these pass (see `AROS_PORTING.md` and
`docs/AROS_TESTER.md`):

1. **Entropy review.** The `mincrt` `randfill()` fallback (`src/rand.c`) is a
   best-effort self-contained mixer. Review it against the security-release
   threat model before promoting; replace with an AROS CSPRNG if one becomes
   available.
2. **Zero-delay password-auth churn.** x86_64 has a known intermittent
   password-auth failure under zero-delay connection churn
   (`BEBBOSSH_AROS_STRESS_DELAY=0`). Reproduce, fix, and gate via
   `scripts/aros-transfer-stress-test.sh`.
3. **QEMU AROS One x86_64 daemon gate.** Hosted validation does not prove the
   non-hosted AROS One daemon path. Run `scripts/aros-release-gate.sh` with
   `BEBBOSSH_GATE_QEMU_X64_PORT` set against a real AROS One x86_64 VM.

Only after these pass: flip the status tables in `README.md` / `AROS_PORTING.md`
to stable, cut the `v0.3.x-aros-x86_64` tag, and fill the real SHA256 values
into `scripts/aros-x86_64-public-release-smoke.sh`.

## Optional functional-parity flags (experimental)

The x86_64/`mincrt` build keeps several i386 behaviors behind opt-in runtime
flags so they can be A/B tested on the VM without rebuilding. All default OFF;
enable them in the daemon's environment before launch:

- `BEBBOSSH_AROS_X64_SFTP_MTIME=1` — preserve SFTP modification times via
  `SetFileDate`.
- `BEBBOSSH_AROS_X64_CD=1` — enable the interactive-shell `cd` / `pwd` / dynamic
  prompt path. The shell acquires a real current-directory Lock through the
  mincrt-safe DOS wrappers; raw `CurrentDir` could previously block the daemon,
  so validate under `dir`/`cd` churn before relying on it.

When a flag is unset, the current safe default behavior is unchanged.

### Known divergence kept on purpose: synchronous exec

x86_64/`mincrt` runs SSH commands through a synchronous `SystemTagList` backend
that captures output to a temporary file and streams it back, blocking the
daemon main loop while a command runs. The non-blocking child-task backend
(`CreateNewProcTagList`) used by i386 previously hit a crash class on the minimal
x86_64 runtime, so it is intentionally not compiled for x86_64. Treat the
synchronous backend as the intended x86_64 behavior for short, bounded commands;
porting the async backend to mincrt is future work that requires VM validation,
not a runtime flag.
