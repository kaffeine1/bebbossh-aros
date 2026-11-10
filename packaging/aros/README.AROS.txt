BebboSSH for AROS
=================

SSH2 server and client suite with SFTP:

- bebbosshd       SSH2 server (remote commands, SFTP, scp, forwarding)
- bebbossh        SSH2 client
- bebboscp        scp client
- bebbosshkeygen  Ed25519 key generator

Also in the kit: sshd_config.example, passwd.example, test scripts, the
release checklist of the target (docs/), README.md, AROS_PORTING.md, COPYING
and LICENSE.

Pick the kit for your system; the binaries are not interchangeable:

- bebbossh-aros-i386-abiv0-*  AROS One i386 (alt-abiv0)
- bebbossh-aros-x86_64-*      AROS One x86_64 (ABIv11)
- bebbossh-aros-aarch64-*     AROS on the Raspberry Pi (aarch64)

The crypto is linked into each program; no libcryptossh.library is needed.

License and source
------------------

BebboSSH is by Stefan "Bebbo" Franke: https://franke.ms/git/bebbo/bebbossh
The AROS port is by Michele Dipace <michele.dipace@kaffeine.net>. Both are
GNU GPL v3 or later; keep COPYING, LICENSE and the upstream notices when you
redistribute.

The source of each release is the matching tag, for example:

  https://github.com/kaffeine1/bebbossh-aros/tree/v1.0.9-aros-i386-abiv0

Install
-------

1. Copy this directory to a persistent volume, for example DH0:BebboSSH
   (AROS: on AROS One x86_64, SYS: on the Raspberry Pi).

2. Create the configuration and change the password:

     copy sshd_config.example sshd_config
     copy passwd.example passwd
     ed passwd

3. Create the random seed with a throwaway key (see Random numbers), then
   the host key:

     bebbosshkeygen -f T:seed_key
     delete T:seed_key T:seed_key.pub
     bebbosshkeygen -f ssh_host_ed25519_key

4. Start the server from that directory:

     stack 262144
     bebbosshd

sshd_config uses PROGDIR: paths, so the server finds its files when it runs
from its own directory. If ENVARC:ssh/sshd_config exists, it is read first.

On the Raspberry Pi, SYS: is a FAT volume: protect reports an error there,
which can be ignored.

Commands in C:
--------------

To call the clients without a path, copy them to C::

  copy bebbossh bebboscp bebbosshkeygen C:
  protect C:bebbossh +e
  protect C:bebboscp +e
  protect C:bebbosshkeygen +e

Keep bebbosshd next to its configuration. Run from C:, PROGDIR: is C:, so
pass the paths:

  bebbosshd -A DH0:BebboSSH/passwd -K DH0:BebboSSH/ssh_host_ed25519_key -H DH0:

passwd
------

One user per line, user name and password:

  miki mySecretPassword

The test/test entry of passwd.example is for a first test only. Change it
before the machine is on a real network, and never publish a real passwd.

Public-key login reads ENVARC:.ssh/authorized_keys (OpenSSH Ed25519 keys).

Host key
--------

bebbosshkeygen -f ssh_host_ed25519_key creates the key that identifies the
server; -C "comment" adds a comment. The private key stays on that machine:
do not copy it to other machines or into archives.

sshd_config
-----------

  Port 22
      TCP port of the server.

  ListenAddress 0.0.0.0
      Listen on all interfaces.

  HostKey PROGDIR:ssh_host_ed25519_key
      Private host key.

  Passwords PROGDIR:passwd
      Password file.

  HomeDir DH0:
      Start directory of remote commands and SFTP. Use a writable volume.
      On x86_64 it is used only with BEBBOSSH_AROS_X64_CD (see Known limits).

  Stack 262144
      Stack of command and shell tasks. Without a Stack line: 1 MiB.

  DebugLevel 1
      Log level: a name or the number used by -v: 0 none, 1 fatal, 2 error,
      3 warn, 4 info, 5 debug, 6 fine, 7 trace, 8 ultra.

  SendNoop some
      Keep-alive messages on idle connections (off without this line).

  Ciphers aes128-gcm@openssh.com,chacha20-poly1305@openssh.com
      Ciphers the server offers. Without this line the i386 server offers
      only aes128-gcm, and a client that insists on chacha20-poly1305 is
      disconnected; x86_64 and aarch64 offer both.

  AllowTcpForwarding yes
      direct-tcpip forwarding (ssh -L), allowed by default. no refuses it.
      There is no remote forwarding.

  InteractiveShell yes
      A command typed in the interactive shell, or started with a terminal
      (ssh -t host command), runs in its own task with the SSH session as
      console: it can ask questions, its output arrives at once and Ctrl-C
      stops it. On by default on aarch64. Off by default on i386, where it
      is not tested yet. Not available on x86_64.

Command-line options override the file, for example:

  bebbosshd -p 10022 -A PROGDIR:passwd -K PROGDIR:ssh_host_ed25519_key -H DH0:

Autostart
---------

Add to S:User-Startup:

  ;BEGIN BebboSSHd AROS
  Stack 262144
  If EXISTS DH0:BebboSSH/bebbosshd
      Run DH0:BebboSSH/bebbosshd
  EndIf
  ;END BebboSSHd AROS

With DebugLevel 1 the server opens no output window at boot.

On the Raspberry Pi, AROSTCP must start at boot (ENVARC:AROSTCP/AutoRun
containing True) and the server a few seconds later; the scripts are in
docs/AROS_AARCH64_RELEASE.md.

Client host keys
----------------

bebbossh and bebboscp keep server keys in ENVARC:.ssh/known_hosts. The first
connection asks whether to trust the key, but only in a console window.
Without a console, for example in a remote command, an unknown server is
refused: connect once from a Shell first. A changed key is refused with a
warning; if the change is expected, remove the server's line from
known_hosts.

Random numbers
--------------

Keys, session secrets and packet padding come from a SHA-512 pool, filled at
start from CPU timer jitter, timer.device wake-ups, system counters and the
seed file ENVARC:.ssh/random_seed, which each program replaces at once.

- Every machine needs its own seed. Delete ENVARC:.ssh/random_seed before you
  copy a disk or SD card image, and never put it into a package.
- On read-only media the seed cannot be replaced, and each run relies on its
  own timer jitter.
- bebbosshkeygen collects more samples before it creates a key, and warns
  when the CPU timer shows little jitter (a CPU emulated by QEMU without
  hardware virtualisation). Create long-term keys after a seed exists.
- On i386 and aarch64, bebbosshkeygen without -f asks for the file name. In
  scripts pass -f, or redirect the input from NIL: to take the defaults.

Known limits
------------

- With InteractiveShell (aarch64): every line of the interactive shell runs
  in a shell of its own, so local variables and aliases do not carry over
  to the next line. A command without a terminal ("ssh host command") gets
  no input, and no redirection or pipes (>, <, |).
- Without InteractiveShell (i386, x86_64): no programs that read their
  input (rejected with exit status 2), no redirection or pipes, and a
  command typed in the interactive shell runs inside the server: other
  connections wait until it ends, and Ctrl-C does not stop it.
- i386 and aarch64: run long commands as "ssh host command", which runs them
  in a separate task. A command still running after 30 seconds gets a
  timeout notice and exit status 124, but it runs until it ends; a server
  stopped with Ctrl-C waits for it.
- x86_64: every remote command blocks the server until it returns: keep
  commands short.
- x86_64: an SFTP path on a missing volume opens an "insert volume"
  requester and blocks the server until it is closed.
- x86_64: some features are off unless set before starting bebbosshd
  (setenv NAME 1): BEBBOSSH_AROS_X64_CD (cd and pwd in the interactive shell,
  HomeDir), BEBBOSSH_AROS_X64_SFTP_MTIME (keep upload times),
  BEBBOSSH_AROS_X64_SFTP_LINKS (SFTP readlink and symlink).
- AROS One x86_64 with an Intel e1000 card can halt or reboot under heavy
  network load. The cause is the AROS e1000 driver, fixed upstream
  (deadwood2/AROS issue 274); until AROS One ships it, use an rtl8139 or
  pcnet card (DEVS:networks/rtl8139.device or pcnet32.device).
- Raspberry Pi 400: a server logging at debug level (-v5) into a console
  window during heavy transfers froze the system. Keep DebugLevel 1 there.
- OpenSSH "put -p" sets the file time before it closes the file, and AROS
  updates the date on close, so that time is not kept.

Test from another machine
-------------------------

  ssh -p 10022 test@127.0.0.1 version
  sftp -P 10022 test@127.0.0.1

(the port forwarded by QEMU or VMware, or 22 on a real network). With
sshpass, sftp -b needs -oBatchMode=no.
