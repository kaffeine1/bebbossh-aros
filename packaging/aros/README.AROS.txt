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

For example, release v0.1.1-aros-i386 corresponds to:

  https://github.com/kaffeine1/bebbossh-aros/tree/v0.1.1-aros-i386

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
- Full PTY-style interactive program support is not complete on AROS yet.
- Remote exec is synchronous and intended for short commands at this stage.
- The test password in passwd.example is not safe. Change it before use.
- Do not distribute private host keys generated for local testing.

Host Test Examples
------------------

From the host side, through QEMU forwarding:

  ssh -p 10022 test@127.0.0.1 version

For batch SFTP with sshpass, force password authentication in batch mode:

  sshpass -p test sftp -oBatchMode=no -P 10022 test@127.0.0.1
