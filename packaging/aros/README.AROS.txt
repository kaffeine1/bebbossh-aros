BebboSSH AROS/i386 Runtime Kit
==============================

This kit contains the AROS/i386 alt-abiv0 port of BebboSSH server tools:

- bebbosshd
- bebbosshkeygen
- sshd_config.example
- passwd.example
- README.AROS.txt
- COPYING, LICENSE, README.md, AROS_PORTING.md

Legal and Attribution
---------------------

This is a derivative of Stefan "Bebbo" Franke's BebboSSH project:

  https://franke.ms/git/bebbo/bebbossh

AROS/i386 porting changes are by Michele Dipace
<michele.dipace@kaffeine.net> and are licensed under GPLv3 or later,
consistent with the upstream project. Keep COPYING, LICENSE, and upstream
notices with redistributions.

Corresponding source code for this binary release is available from the
matching Git tag in the public repository:

  https://github.com/kaffeine1/bebbossh-aros/releases

For example, release v0.1.3-aros-i386 corresponds to:

  https://github.com/kaffeine1/bebbossh-aros/tree/v0.1.3-aros-i386

The binaries in this kit are statically linked with libcryptossh.a. There is
no separate libcryptossh.library requirement for the current AROS/i386 port.

Install
-------

1. Copy this directory to an AROS volume, for example:

     DH0:BebboSSH/

2. Rename the example config files:

     copy sshd_config.example sshd_config
     copy passwd.example passwd

3. Edit passwd and replace the example credentials.

4. Generate a host key in the same directory:

     bebbosshkeygen -f ssh_host_ed25519_key

5. Start the server from an AROS Shell:

     stack 262144
     bebbosshd

The example configuration uses PROGDIR: paths, so the server can find
sshd_config, passwd, and ssh_host_ed25519_key when launched from its own
directory.

Autostart
---------

To start the server automatically after boot, install the kit in a persistent
directory such as DH0:BSSHPKG and add this to S:User-Startup:

  ;BEGIN BebboSSHd AROS
  Stack 262144
  If EXISTS DH0:BSSHPKG/bebbosshd
      Run DH0:BSSHPKG/bebbosshd
  EndIf
  ;END BebboSSHd AROS

This deliberately avoids >NIL: redirection while the AROS redirection path is
being hardened. Startup status messages are logged at debug level, so the
normal DebugLevel 1 package configuration should not leave a daemon output
window during boot. For diagnostics, temporarily use DebugLevel debug or launch
bebbosshd with -v5.

When replacing an existing bebbosshd over SCP/SFTP, delete the old file first
and then upload the new binary. Download it back and byte-compare it if this is
a release or test VM update.

Current Runtime Status
----------------------

Verified on AROS One i386 alt-abiv0:

- SSH protocol identification, KEX, and password authentication.
- Remote exec for simple non-interactive commands such as version and dir.
- SFTP and OpenSSH scp transfers on T: and DH0:.
- SFTP mkdir/rmdir on DH0:.
- 1 MiB and 5 MiB file round-trips.
- A small telegram-amiga style directory tree round-trip with scp -r.

Known Limits
------------

- Interactive SSH sessions can run simple commands and return to the prompt.
- Simple piped stdin for multi-command interactive sessions has been tested
  with dir, version, and exit. Non-interactive SSH exec remains the recommended
  automation path.
- Full PTY-style interactive program support is not complete on AROS yet.
- Remote exec is synchronous and intended for short commands at this stage.
  Command exit status is propagated to the SSH client.
- Shell redirection and pipes (`>`, `<`, `|`) are rejected on AROS until they
  are stable. Rejected redirection returns SSH exit status 2.
- The test password in passwd.example is not safe. Change it before use.
- Do not distribute private host keys generated for local testing.

Host Test Examples
------------------

From the host side, through QEMU forwarding:

  ssh -p 10022 test@127.0.0.1 version

For the current telegram-amiga style automation workflow:

  sshpass -p test ssh -p 10022 test@127.0.0.1 \
    'DH0:TGTEST/telegram-test --help'

Use DH0: or another persistent volume for uploads. Avoid RAM: in VM setups
where RAM: file operations have shown freezes. Avoid remote redirection and
pipes until they are explicitly supported.

For batch SFTP with sshpass, force password authentication in batch mode:

  sshpass -p test sftp -oBatchMode=no -P 10022 test@127.0.0.1
