/* bebbossh - interactive SSH client core
 * Copyright (C) 2024-2025  Stefan Franke <stefan@franke.ms>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version (GPLv3+).
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * ----------------------------------------------------------------------
 * Project: bebbossh - SSH2 client for Amiga
 * Purpose: Establish secure connections, negotiate KEX, and manage channels
 *
 * Features:
 *  - Hostname resolution, TCP connect, and packet framing
 *  - KEXINIT, ECDH, NEWKEYS, and authenticated encryption (AES-GCM / ChaCha20-Poly1305)
 *  - PTY and console integration, window/mouse handling
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing.
 *  - Designed for AmigaOS with bsdsocket.library; uses explicit buffer sizing.
 *
 * Author's intent:
 *  Deliver a secure, maintainable SSH client foundation for classic Amiga systems.
 * ----------------------------------------------------------------------
 */
#include <inttypes.h>
#include <fnmatch.h>

#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <netinet/in.h>

#ifdef __AMIGA__
#include <amistdio.h>

#include <proto/dos.h>
#include <proto/exec.h>
#include <proto/intuition.h>
#include <proto/socket.h>

#else
#include <stdio.h>
#include "amiemul.h"
#endif

#include <log.h>
#include <ssh.h>

#include <test.h>
#include <rand.h>
#include <sha256.h>
#include <aes.h>
#include <gcm.h>
#include <chacha20poly1305.h>
#include <mime.h>
#include <ed25519.h>


#include "client.h"
#include "clientchannel.h"
#include "revision.h"

// #define DUMP_PACKETS 1

#if defined(DUMP_HASH)
static uint8_t * hsd;
static uint8_t * hsdp;
#define HSU(a,b,c) \
	memcpy(hsdp, a+b, c); \
	hsdp += c
#else
#define HSU(a,b,c)
#endif

err error = NO_ERROR;

static char const * ERR_MSG[] = {
		"not enough memory",
		"can't open bsdsocket.library version >=4",
		"can't create a socket",
		"can't resolve the host name",
		"can't connect to given host",
		"tcp write failed",
		"tcp read failed",
		"received a wrong packet/can't handle it",
		"received an invalid packet",
		"packet signature did not match",
		"invalid host public key",
		"failed to verify the host",
		"no SSH2 auth service available",
		"password login not supported",
		"login failed",
		"can't bind the socket to a port",
		"no host name given",
		"no user name given",
		"no cipher"
};

struct Library *SocketBase = 0;

static uint8_t server_version[24] = "SSH-2.0-" _VNAME "\r\n";

extern char const * sshDir;
extern char const * sshDotDir;
char const * configFile;
char const * knownHosts;

int port = 22;
char const * hostname;
char const * username;
short stopped;

uint32_t maxBuffer;

// the client's channels
Stack<ClientChannel> clientChannels(33);
Stack<Acceptor> initacceptors(16);
Stack<Acceptor> acceptors(16);
Stack<Listener> listeners(16);

enum ptype {
	TEXT_CRLF,
	UNENCRYPTED,
	ENCRYPTED
};

// network
static int sockfd;
static struct sockaddr_in sinLocal;
static struct sockaddr_in sinRemote;
static fd_set readfds;
static int packetSize;

// the buffer and it's size
uint8_t *buffer;
unsigned buffersize = 35000;

// set if console was grabbed
extern BPTR stdinBptr;
extern BPTR stdoutBptr;

short escape;
// the window...
struct Window * theWindow;
static char const * orgWindowTitle;
extern struct IntuitionBase * IntuitionBase;
// the key material,
static KeyMaterial keyMat;

static BlockCipher *readBc;
static AeadBlockCipher *readAead;
static BlockCipher *writeBc;
static AeadBlockCipher *writeAead;
static ChaCha20 *readCounterBc;
static ChaCha20 * writeCounterBc;

char hostnameSet, portSet, usernameSet, consoleSet, termSet, keyfileSet, loglevelSet;

// 1 = aes128-gcm@openssh.com, 2 = chacha20poly1305@openssh.com
char const * encOrder = "12";
char const * userOrder = 0;
char const * const AES128 = "aes128-gcm@openssh.com";
char const * const CHACHA20 = "chacha20-poly1305@openssh.com";

static uint8_t KEX_INIT[272];

static uint8_t KEX_ECDH_INIT[10] = { 0, 0, 0, 44, // length 1 + pad + 1 + 32
		6, // pad
		SSH_MSG_KEX_ECDH_INIT, // SSH_MSG_KEX_ECDH_INIT
		0, 0, 0, 32, // length of the key
		};

static uint8_t NEWKEYS[16] = { 0, 0, 0, 12, 10,
SSH_MSG_NEWKEYS, 1, 2, 3, 4, 5, 6, 7, 8, 9, 'A' };

static uint8_t SERVICEREQUEST[17] = {
SSH_MSG_SERVICE_REQUEST, 0, 0, 0, 12, 's', 's', 'h', '-', 'u', 's', 'e', 'r', 'a', 'u', 't', 'h', };


// server secret key
static uint8_t csk[32];
static uint8_t cpk[32];

static uint8_t hostPK[32];
static uint8_t userPK[32];
static uint8_t userSK[64];

// the shared secret
static struct SharedSecret sharedSecret;

// the hash and sessionId - no re-keying supported yet
static uint8_t hash[32];

/**
 * send encrypted data.
 * Return true on success.
 */
bool mysend(int fd, void const *data, int len) {
	if (isLogLevel(L_ULTRA))
		_dump("sending", data, len);
	for (uint8_t * p = (uint8_t *)data;;) {
		int sent = send(fd, p, len, 0);
		if (sent < 0) {
			int lerrno = Errno();
			if (lerrno == EAGAIN) {
				logme(L_DEBUG, "failed to send %ld bytes on socket %ld: sent %ld, errno=%ld, retrying", len, fd, sent, lerrno);
				Delay(100);
				continue;
			}
			logme(L_ERROR, "failed to send %ld bytes on socket %ld: sent %ld, errno=%ld", len, fd, sent, lerrno);
			return false;
		}
		len -= sent;
		if (!len)
			break;

		logme(L_DEBUG, "fixup send remaining %ld bytes on socket %ld", len, fd);
		p += sent;
	}

	return true;
}

/**
 * For the initial messages: find the \r and terminate there with 0.
 * Return the strlen.
 */
static int termzero(uint8_t *q) {
	uint8_t *p = q;
	while (*p != '\r')
		++p;
	*p = 0;
	return p - q;
}

static bool ensureBufferSize(unsigned nsize) {
	if (buffersize < nsize) {
		uint8_t *nb = (uint8_t*) malloc(nsize + 512);
		if (nb == 0)
			return false;
		nb[0] = buffer[0];
		nb[1] = buffer[1];
		nb[2] = buffer[2];
		nb[3] = buffer[3];
		free(buffer);
		buffer = nb;
		buffersize = nsize;
	}
	return true;
}

static void increment(uint8_t iv[12]) {
	for (int i = 11; i >= 0; --i) {
		if (++iv[i])
			break;
	}
}

/**
 * send encrypted.
 * Return true on success.
 */
bool sendEncrypted(uint8_t const *data, int len) {
	int outlen = len + 16 + 4 + 1; // hash size + length bytes  + pad uint8_t

	if (!ensureBufferSize(outlen)) // plus room for padding data
		return false;

	// copy if not in place
	if (data != buffer + 5)
		memmove(buffer + 5, data, len);

	randfill(buffer, 1);
	unsigned padSize = 16 + (buffer[0] & 0x70);
	unsigned padLen = padSize + 3 - ((len + 4) & (padSize - 1)); // 4..padSize+3 bytes

	len += 1 + padLen;
	buffer[4] = padLen;
	outlen += padLen;
	putInt32Aligned(buffer, len);

	randfill(buffer + outlen - 16 - padLen, padLen);
#ifdef DUMP_PACKETS
	_dump("writeIV", keyMat.encIvWrite, 12);
	_dump("clearText", buffer, outlen);
#endif
	if (writeCounterBc) {
		writeCounterBc->setNonce(keyMat.encIvWrite, 12);
		writeCounterBc->zeroCounter();
		writeCounterBc->chacha(buffer, buffer, 4);
		writeAead->init(keyMat.encIvWrite, 12);
		writeAead->encrypt(buffer + 4, buffer + 4, len);
		writeAead->updateHash(buffer, 4 + len);
	} else {
		writeAead->init(keyMat.encIvWrite, 12);
		writeAead->updateHash(buffer, 4);
		writeAead->encrypt(buffer + 4, buffer + 4, len);
	}
	writeAead->calcHash(buffer + 4 + len);
	increment(keyMat.encIvWrite);
#ifdef DUMP_PACKETS
	_dump("cipherText", buffer, outlen);
#endif
	logme(L_FINE, "sending encrypted packet of length %ld to socket %ld", outlen, sockfd);

	if (!mysend(sockfd, buffer, outlen)) {
		logme(L_ERROR, "failed to send %ld bytes", outlen);
		error = ERROR_WRITE;
		return false;
	}
	return true;
}

static unsigned waitFor(unsigned usecs) {
    struct timeval tv;
    tv.tv_sec  = 0;
    tv.tv_usec = usecs;
    struct timeval *ptv = usecs ? &tv : 0;

    FD_ZERO(&readfds);
    FD_SET(sockfd, &readfds);

#ifdef __AMIGA__
    ULONG signals = 0;
    WaitSelect(sockfd + 1, &readfds, NULL, NULL, ptv, &signals);
    return signals;

#elif defined(__linux__) || defined(__unix__)
    int r = select(sockfd + 1, &readfds, NULL, NULL, ptv);
    if (r > 0 && FD_ISSET(sockfd, &readfds))
        return 1;   // data ready
    return 0;

#elif defined(_WIN32)
    int r = select(0, &readfds, NULL, NULL, ptv);
    if (r > 0 && FD_ISSET(sockfd, &readfds))
        return 1;
    return 0;

#else
    return 0;
#endif
}


/**
 * Receive wrapper.
 * if isPacket == false: read until \n
 * else read packet size and full packet.
 */
int receivePacket(ptype packetType) {
	waitFor(0);

	if (!FD_ISSET(sockfd, &readfds))
		return 0;

	// just read what's available
	if (packetType == TEXT_CRLF) {
		// read bytes until \n occurs.
		int pos = 0;
		for (;; ++pos) {
			if (1 != recv(sockfd, buffer + pos, 1, 0))
				return 0;
			if (buffer[pos] == '\n')
				break;
		}
		return pos;
	}

	// read the packet length
	int n4 = recv(sockfd, buffer, 4, 0);
	if (n4 != 4) {
		if (n4)
			logme(L_ERROR, "can't read 4 byte header, got %ld", n4);
		error = ERROR_READ;
		return 0;
	}
	// get the size
	if (packetType == ENCRYPTED && readCounterBc) {
		readCounterBc->setNonce(keyMat.encIvRead, 12);
		readCounterBc->zeroCounter();
		readCounterBc->chacha(&packetSize, buffer, 4);
		packetSize = htonl(packetSize);
	} else {
		packetSize = getInt32Aligned(buffer);
	}
//	printf("%08lx\n", packetSize);
	int nsize = packetSize + 4;

	// resize buffer if needed
	if (!ensureBufferSize(nsize))
		return 0;

	uint8_t *p = buffer + 4;
	if (packetType == ENCRYPTED)
		packetSize += 16; // also read signature
	for (int pos = 0; pos < packetSize;) {
		int toread = packetSize - pos;
		int n = recv(sockfd, p, toread, 0);
		if (n <= 0) {
			logme(L_ERROR, "can't read %ld bytes, got %ld", toread, n);
			error = ERROR_READ;
			return 0;
		}
		p += n;
		pos += n;
	}
	if (isLogLevel(L_ULTRA))
		_dump("receive", buffer, packetSize + 4);

#ifdef DEBUG
	printf("recv: packet of size %ld\n", packetSize);
	dump("packet", buffer, packetSize + 4);
#endif

	if (packetType == ENCRYPTED)
		packetSize -= 16; // also read signature
	return packetSize;
}

int receiveEncryptedPacket() {
	unsigned len = receivePacket(ENCRYPTED);
	if (len == 0)
		return 0;

#ifdef DUMP_PACKETS
	_dump("readIV", keyMat.encIvRead, 12);
	_dump("cipherText", buffer, 4 + len);
#endif
	readAead->init(keyMat.encIvRead, 12);
	if (readCounterBc) {
		readAead->updateHash(buffer, 4 + len);
	} else {
		readAead->updateHash(buffer, 4);
	}
	uint8_t * p = buffer + 4;
	readAead->decrypt(p, p, len);
#ifdef DUMP_PACKETS
	_dump("clearText", p, len);
#endif

	unsigned pad1 = *p + 1;
	if (pad1 >= len) {
		error = ERROR_INVALID_PACKET;
		return 0;
	}

	uint8_t check[16];
	readAead->calcHash(check);
	if (0 != memcmp(check, p + len, 16)) {
		error = ERROR_SIGNATURE_MISMATCH;
		return 0;
	}

	increment(keyMat.encIvRead);

	len -= pad1;
	if (isLogLevel(L_TRACE))
		_dump("packet content", p + 1, len > 256 ? 256 : len);
	logme(L_FINE, "got packet type %ld, len=%ld", buffer[5], len);
	return len;
}

/**
 *  create the KEX_ECDH_INIT message
 */
static void makeKexEcdhInit() {
	memcpy(buffer, KEX_ECDH_INIT, sizeof(KEX_ECDH_INIT));
	memcpy(buffer + sizeof(KEX_ECDH_INIT), cpk, 32);
	memset(buffer + sizeof(KEX_ECDH_INIT) + 32, 0, 6); // clear padding data
}

// helper to skip whitespace
static inline char *skip_ws(char *p) {
    while (*p && *p <= 32) ++p;
    return p;
}

// helper to extract next token
static inline char *next_token(char **pp) {
    char *p = skip_ws(*pp);
    char *tok = p;
    while (*p && *p > 32) ++p;
    if (*p) *p++ = 0;
    *pp = p;
    return tok;
}

// helper function to parse n, c, k
static void parse_line(char *line, char **n, char **c, char **k) {
    char *p = line;
    *n = next_token(&p);
    *c = next_token(&p);
    *k = next_token(&p);
}

// helper: write one line into a memory buffer
static char *append_line(char *out, const char *n, const char *c, const char *k) {
    out = stpcpy(out, n);
    *out++ = ' ';
    out = stpcpy(out, c);
    *out++ = ' ';
    out = stpcpy(out, k);
    *out++ = '\n';
    *out = '\0';
    return out;
}

static bool verifyHost(uint8_t const * hostBase64) {
	if (!sshDotDir) sshDotDir = concat(sshDir, ".ssh", NULL);
	if (!knownHosts) knownHosts = concat(sshDotDir, "/known_hosts", NULL);

	BPTR f = Open(knownHosts, MODE_READWRITE);
	if (!f) {
		mkdir(sshDotDir, 0755);
		f = Open(knownHosts, MODE_NEWFILE);
		if (!f)
			return false;
	}

	if (port != 22) {
		char buf[12];
		utoa(port, buf, 10);
		hostname = concat(hostname, ":", buf, NULL);
 	}

	char * buf = (char *)buffer;
	bool replace = false;
	bool r = false;
	Seek(f, OFFSET_BEGINNING, 0);
	while(!r) {
		char * p = buf + 1000;
		if (!fgets(p, buffersize - 1000, f))
			break;

	    char *n, *c, *k;
	    parse_line(p, &n, &c, &k);

		if (0 == strcmp(n, hostname) && 0 == strcmp(c, "ssh-ed25519")) {
			r = 0 == strcmp(k, (char *)hostBase64);
			if (!r) {
				printf("host key %s differs from stored host key %s for host %s\n", hostBase64, k, hostname);
				replace = true;
			}
			break;
		}
	}
	if (!r) {
		printf("do you trust host %s with ssh-ed25519 key %s? Then enter: yes\n", hostname, hostBase64);
		fflush(stdout);
		*buf = 0;
		fgets(buf, 5, stdin);
		if (0 == strncmp("yes", (char *)buffer, 3)) {
			r = true;
			if (replace) {
				// Get file size
				Seek(f, 0, OFFSET_END);
				long size = Seek(f, 0, OFFSET_CURRENT);

				Close(f);
				f = Open(knownHosts, MODE_OLDFILE);

				size += 1024;// extra room
				char *mem = (char *)malloc(size);
				if (!mem) {
					logme(L_ERROR, "out of memory for %ld bytes", size);
					exit(10);
				}

				char *out = mem;
				char * p = buf + 1000;
				while (fgets(p, buffersize - 1000, f)) {
					char *n, *c, *k;
					parse_line(p, &n, &c, &k);

					// skip lines without 3 values
					if (!*n || !*c || !*k)
						continue;

					if (strcmp(n, hostname) == 0 && strcmp(c, "ssh-ed25519") == 0) {
						// skip old entry
						continue;
					}
					out = append_line(out, n, c, k);
				}

				// append new entry
				out = append_line(out, hostname, "ssh-ed25519", (char *)hostBase64);

				// rewind and truncate
				Close(f);
				f = Open(knownHosts, MODE_NEWFILE);
				Write(f, mem, out - mem);

				free(mem);
			} else {
				// just append
				Seek(f, OFFSET_END, 0);
				fprintf(f, "%s ssh-ed25519 %s\n", hostname, hostBase64);
			}
		}
	}

	Close(f);
	return r;
}

/**
 * Handle the KexEcdhReply packet.
 * Returns true if the host was successfully verified.
 */
static bool handleKexEcdhReply(SHA256 &handshakeMD, unsigned long packetSize) {
	// packet data starts at buffer + 5;
	uint8_t *p = buffer + 5;

	if (*p++ != SSH_MSG_KEX_ECDH_REPLY) {
		error = ERROR_WRONG_PACKET;
		return false;
	}

	// get host digest
	unsigned long length = getInt32(p);
	if (length + (p - buffer) > packetSize) {
		error = ERROR_INVALID_PACKET;
		return false;
	}

	uint32_t len_be = htonl(length);
	handshakeMD.update(&len_be, 4);
	HSU(&len_be, 0, 4);
	p += 4;
	handshakeMD.update(p, length);
	HSU(p, 0, length);

	if (length + (p - buffer) > packetSize) {
		error = ERROR_INVALID_PACKET;
		return false;
	}

	uint8_t hostBase64[64];
	{
		uint8_t hostDigest[32];
		{
			SHA256 sha256;
			sha256.update(p, length);
			sha256.digest(hostDigest);
		}
		mimeEncode(hostBase64, hostDigest, 32);
	}

	length = getInt32(p);
	p += 4;
	if (length + (p - buffer) > packetSize) {
		error = ERROR_INVALID_PACKET;
		return false;
	}
	p += length; // check the name? no, check will fail else.

	// host public key
	length = getInt32(p);
	p += 4;
	if (length + (p - buffer) > packetSize) {
		error = ERROR_INVALID_PACKET;
		return false;
	}
	// host public key.
	uint8_t *hpk = p;
	memcpy(hostPK, hpk, 32);
	p += length;
	if (!verifyHost(hostBase64)) {
		error = ERROR_HOST_VERIFY;
		return false;
	}
	// get server public key
	length = getInt32(p);
	if (length != 32) {
		error = ERROR_SERVER_PUBKEY;
		return false;
	}
	p += 4;

	// add server public key to hash
	len_be = htonl(length);
	handshakeMD.update(&len_be, 4);
	HSU(&len_be, 0, 4);
	handshakeMD.update(cpk, 32);
	HSU(cpk, 0, 32);

	// add server public key to hash
	handshakeMD.update(&len_be, 4);
	HSU(&len_be, 0, 4);
	handshakeMD.update(p, 32);
	HSU(p, 0, 32);

	logme(L_DEBUG, "calculating shared secret using X25519 START");
	fe_scalarmult_x25519(sharedSecret.data, csk, p);
	logme(L_DEBUG, "calculating shared secret using X25519 STOP");
	p += length;
	if ((int8_t)sharedSecret.data[0] < 0) {
		sharedSecret.size = 33;
		memmove(&sharedSecret.data[1], &sharedSecret.data[0], 32);
		sharedSecret.data[0] = 0;
	} else {
		sharedSecret.size = 32;
	}

#if (BYTE_ORDER == BIG_ENDIAN)
	handshakeMD.update(&sharedSecret, sharedSecret.size + 4);
	HSU(&sharedSecret, 0, sharedSecret.size + 4);
#else
	len_be = htonl(sharedSecret.size);
	handshakeMD.update(&len_be, 4);
	handshakeMD.update(&sharedSecret.data, sharedSecret.size);
	HSU(&len_be, 0, 4);
	HSU(&sharedSecret.data, 0, sharedSecret.size);
#endif

	handshakeMD.digest(hash);
#if defined(DUMP_HASH)
	_dump("shared secret", &sharedSecret, sharedSecret.size + 4);
	_dump("hashdata", hsd, hsdp - hsd);
	_dump("hash", hash, 32);
#endif

	unsigned long sigBlobLength = getInt32(p);
	if (sigBlobLength + (p - buffer) - 1 > packetSize) {
		printf("%ld > %ld\n", sigBlobLength + (p - buffer), packetSize);
		error = ERROR_INVALID_PACKET;
		return false;
	}
	p += 4;

	length = getInt32(p);
	if (length + (p - buffer) - 1 > packetSize) {
		error = ERROR_INVALID_PACKET;
		return false;
	}
	p += 4;
	p += length; // check the name? no, check will fail else.
	length = getInt32(p);
	if (length != 64 || length + (p - buffer) - 1 > packetSize) {
		error = ERROR_INVALID_PACKET;
		return false;
	}
	p += 4;

	logme(L_DEBUG, "verifying server signature ed25519 START");
	int r = ge_verify_ed25519(hash, 32, p, hpk);
	logme(L_DEBUG, "verifying server signature ed25519 STOP");
	if (!r) {
//_dump("hash", hash, 32);
//_dump("p   ", p, 64);
//_dump("hpk ", hpk, 32);
		logme(L_ERROR, "failed to verify the host");
		error = ERROR_HOST_VERIFY;
	}
	return r;
}

static unsigned makeAuth(char const *auth) {
	uint8_t *p = buffer + 5;
	*p++ = SSH_MSG_USERAUTH_REQUEST;

	putString(p, username);
	putString(p, "ssh-connection");

	putString(p, auth);
	return p - buffer - 5;
}

static bool waitForService() {
	sendEncrypted(SERVICEREQUEST, sizeof(SERVICEREQUEST));

	for (;;) {
		if (receiveEncryptedPacket() == 0)
			return false;
		if (buffer[5] == SSH_MSG_SERVICE_ACCEPT) {
			if (0 == memcmp(&buffer[6], &SERVICEREQUEST[1], sizeof(SERVICEREQUEST) - 1))
				break;;
			error = ERROR_NO_AUTH_SERVICE;
			return false;
		}
	}
	return true;
}

// keep originals around
#if defined(__linux__) || defined(__unix__)
static struct termios origTermios;
#elif defined(_WIN32)
static DWORD origMode;
#endif

static void freeConsole(void) {
#ifdef __AMIGA__
    if (stdinBptr) {
        struct FileHandle * fh = (struct FileHandle *)BADDR(stdinBptr);
        if (IsInteractive(stdinBptr) == DOSTRUE) {
            Write(stdinBptr, "\x1b[2;11;12}", 10);
            SetMode(stdinBptr, 0);
        }
        stdinBptr = 0;
    }

    if (theWindow && orgWindowTitle) {
        SetWindowTitles(theWindow, orgWindowTitle, 0);
        theWindow = 0;
    }

#elif defined(__linux__) || defined(__unix__)
    if (stdinBptr) {
        tcsetattr(fileno(stdinBptr), TCSANOW, &origTermios);
        stdinBptr = NULL;
    }

#elif defined(_WIN32)
    if (stdinBptr) {
        HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
        SetConsoleMode(hIn, origMode);
        stdinBptr = NULL;
    }
#endif
}

static bool grabConsole(void) {
#ifdef __AMIGA__
    stdinBptr = Input();
    if (IsInteractive(stdinBptr) != DOSTRUE)
        return false;

    SetMode(stdinBptr, 1);   // raw console mode
    stdoutBptr = Output();
    return true;

#elif defined(__linux__) || defined(__unix__)
    if (isatty(fileno(stdout))) {
        // disable buffering if stdout is a terminal
        setvbuf(stdout, NULL, _IONBF, 0);
    }

    stdinBptr = stdin;
    if (!isatty(fileno(stdinBptr)))
        return false;

    if (tcgetattr(fileno(stdinBptr), &origTermios) == -1)
        return false;
    struct termios t = origTermios;
    cfmakeraw(&t);
    if (tcsetattr(fileno(stdinBptr), TCSANOW, &t) == -1)
        return false;

    stdoutBptr = stdout;
    return true;

#elif defined(_WIN32)
    if (isatty(fileno(stdout))) {
        // disable buffering if stdout is a terminal
        setvbuf(stdout, NULL, _IONBF, 0);
    }

    stdinBptr = stdin;
    if (!_isatty(_fileno(stdinBptr)))
        return false;

    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    if (!GetConsoleMode(hIn, &origMode))
        return false;
    DWORD mode = origMode;
    mode &= ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT);
    mode |= ENABLE_PROCESSED_INPUT;
    if (!SetConsoleMode(hIn, mode))
        return false;

    stdoutBptr = stdout;
    return true;

#else
    return false;
#endif
}

static bool loginPK() {

	if (!loadEd25519Key(userPK, userSK, keyFile))
		return false;

	uint8_t * p5 = buffer + 5;
	uint8_t * p = p5;
	*p++ = SSH_MSG_USERAUTH_REQUEST;

	putString(p, username);
	putString(p, "ssh-connection");
	putString(p, "publickey");
	*p++ = 0;
	putString(p, "ssh-ed25519");

	// server pk blob
	putInt32AndInc(p, 0x33);
	putString(p, "ssh-ed25519");
	putAny(p, userPK, 0x20);

	if (!sendEncrypted(p5, p - p5))
		return false;

	if (receiveEncryptedPacket() == 0)
		return false;

	if (*p5 != SSH_MSG_USERAUTH_PK_OK) {
		logme(L_INFO, "server declined our key");
		return false;
	}

	p = p5;
	*p++ = SSH_MSG_USERAUTH_REQUEST;

	putString(p, username);
	putString(p, "ssh-connection");

//	putString(p, "publickey-hostbound-v00@openssh.com");
	putString(p, "publickey");
	*p++ = 1;
	putString(p, "ssh-ed25519");

	// server pk blob
	putInt32AndInc(p, 0x33);
	putString(p, "ssh-ed25519");
	putAny(p, userPK, 0x20);

// server pk blob - only if publickey-hostbound-v00@openssh.com is used
//	putInt32AndInc(p, 0x33);
//	putString(p, "ssh-ed25519");
//	putAny(p, hostPK, 0x20);

	int msgLen = p - p5;
	uint8_t * msg = buffer + 2000;
	uint8_t * t = msg;
	putAny(t, hash, 0x20);
	memcpy(t, p5, msgLen);
	msgLen += 36;
//	_dump("hash", msg, msgLen);

	// add signature
	putInt32AndInc(p, 0x53);
	putString(p, "ssh-ed25519");
	putInt32AndInc(p, 0x40);

	logme(L_DEBUG, "signing auth message START");
	ge_sign_ed25519(p, msg, msgLen, userSK);
	logme(L_DEBUG, "signing auth message STOP");
	int plen = p - p5 + 0x40;

//	_dump("auth", buffer, plen + 5);

	if (!sendEncrypted(p5, plen))
		return false;

	if (receiveEncryptedPacket() == 0)
		return false;

	if (buffer[5] != SSH_MSG_USERAUTH_SUCCESS) {
		logme(L_INFO, "server declined our signature");
		return false;
	}

	return true;
}

static bool loginPass() {
	uint8_t * p = buffer + 5;
	*p++ = SSH_MSG_USERAUTH_REQUEST;

	putString(p, username);
	putString(p, "ssh-connection");
	putString(p, "password");

	printf("%s@%s's password: ", username, hostname);
	fflush(stdout);

	*p++ = 0;
	uint8_t * q = p;
	p += 4;
	if (stdoutBptr) {
		uint8_t * start = p;
		for(;;) {
#ifdef __AMIGA__
			signed l = Read(stdinBptr, p, 100);
			if(SetSignal(0L,SIGBREAKF_CTRL_C) & SIGBREAKF_CTRL_C)
				exit(0);
#else
			signed l = Read(stdinBptr, p, 1);
			if (l <= 0)
				continue;
#endif
			if (l > 1 && *p == '\x1b')
				continue;
			for (int i = 0; i < l; ++i) {
				if (*p == '\r' || *p == '\n')
					goto Outer;
				if (*p <= 4)
					exit(0);
				if (*p == '\b') {
					if (p > start) {
						--p;
					}
					continue;
				}
				++p;
			}
		}
		Outer:;
	} else {
		*p = 0;
		fgets((char *)p, buffersize - 1000, stdin);
		p += strlen((char *)p);
		while (p > q + 5 && p[-1] < 32)
			--p;
	}

	unsigned plen = p - q - 4;
	putInt32AndInc(q, plen);

	printf("\r\n");

	if (!sendEncrypted(buffer + 5, p - buffer - 5))
		return false;

	if (receiveEncryptedPacket() == 0)
		return false;

	return buffer[5] == SSH_MSG_USERAUTH_SUCCESS;
}


static bool authenticate() {
	unsigned len = makeAuth("none");
	if (!sendEncrypted(buffer + 5, len))
		return false;

	for(;;) {
		if (receiveEncryptedPacket() == 0)
			return false;
		if (buffer[5] != SSH_MSG_USERAUTH_BANNER)
			break;

		len = getInt32Aligned(buffer + 6); // even
		buffer[10 + len] = 0;
		puts((char *)buffer + 10);
	}

	// try loginPass with public key
	if (strstr((char *)buffer + 10, "publickey")) {
		if (loginPK())
			return true;
	}


	if (!strstr((char *)buffer + 10, "password")) {
		error = ERROR_NO_PASSWORD_METHOD;
		return false;
	}

	for (int i = 0;; ++i) {
		if (loginPass())
			break;

		if (error != NO_ERROR)
			return false;

		if (i == 2) {
			error = ERROR_NO_LOGIN;
			return false;
		}
		puts("Permission denied, please try again.");
	}

	return true;
}

void cleanup() {
	// close all remaining
	for (int i = 0; i < listeners.getMax(); ++i) {
		auto l = listeners[i];
		if (l) {
			logme(L_DEBUG, "closing listener for socket %ld", l->getSockFd());
			l->__close();
		}
	}
	// close all remaining
	for (int i = 0; i < acceptors.getMax(); ++i) {
		auto a = acceptors[i];
		if (a) {
			logme(L_DEBUG, "closing acceptor for socket %ld", a->getSockFd());
			delete a;
		}
	}
	if (readAead) delete readAead;
	if (writeAead) delete writeAead;
	if (readBc) delete readBc;
	if (writeBc) delete writeBc;
	if (readCounterBc) delete readCounterBc;
	if (writeCounterBc) delete writeCounterBc;

	if (sockfd != 0)
		CloseSocket(sockfd);

#ifdef __AMIGA__
    if (SocketBase != 0)
        CloseLibrary(SocketBase);
#elif defined(_WIN32)
    WSACleanup();   // after successful WSAStartup()
#else
    // Linux/Unix: nothing to do, sockets are always available
#endif

}


int setupEncryption() {
	uint8_t * p = buffer + 22; // start of encoding
	uint8_t * sig = sshString(p);
	uint8_t * kex = sshString(p);
	uint8_t * read = sshString(p);
	uint8_t * write = sshString(p);

//	puts((char*)read);
//	puts((char*)write);

	char selected = 0;
	for (char const * c = encOrder; *c; ++c) {
		char const * t = 0;
		if (*c == '1')
			t = AES128;
		if (*c == '2')
			t = CHACHA20;

		if (strstr((char *)read, t)) {
			selected = *c;
			break;
		}
	}

	switch (selected) {
	case '1':
		readBc = new AES();
		if (readBc) {
			readAead = new GCM(readBc);
			if (readAead) {
				readBc = NULL;
				writeBc = new AES();
				if (writeBc) {
					writeAead = new GCM(writeBc);
					writeBc = NULL;
				}
			}
		}
		keyMat.ivLen = 12;
		keyMat.keyLen = 16;
		break;
	case '2':
		readAead = new ChaCha20Poly1305_SSH2();
		writeAead = new ChaCha20Poly1305_SSH2();
		readCounterBc = new ChaCha20();
		writeCounterBc = new ChaCha20();
		keyMat.ivLen = 0; // we start with zeroes
		keyMat.keyLen = 64;
		break;
	}

	return writeAead != 0;
}

bool connectClient() {
	static char buf[256];

	atexit(cleanup);

#ifdef __AMIGA__
	// see DOS RKRM: converted to a buffered stream before flushing!
	FGetC(stdin);
	fflush(stdin);

	if (escape && !theWindow) {
		theWindow = IntuitionBase->ActiveWindow;
		orgWindowTitle = theWindow->Title;
	}
#endif

	do { // while (0);
		buffer = (uint8_t*) malloc(buffersize + 512);
		if (buffer == 0) {
			error = ERROR_NOMEM;
			break;
		}

		if (!hostname) {
			error = ERROR_NO_HOST;
			break;
		}

		if (!username) {
			error = ERROR_NO_USER;
			break;
		}

		if (error)
			break;

		int kexLen = fillKexInit(KEX_INIT, encOrder);
		if (!kexLen)
			break;


		// create the secret/public key pair
		logme(L_DEBUG, "creating new X25519 key pair");
		fe_new_key_pair(cpk, csk);
		logme(L_DEBUG, "created new X25519 key pair");

#ifdef __AMIGA__
		SocketBase = OpenLibrary("bsdsocket.library", 4);
		logme(L_FINE, "opened bsdsocket.library %08lx", SocketBase);
		if (SocketBase == 0) {
			error = ERROR_BSDSOCKET;
			break;
		}

		SocketBaseTags(SBTM_SETVAL(SBTC_BREAKMASK), 0, TAG_DONE);

#elif defined(__linux__) || defined(__unix__)
		// No library to open: sockets are part of libc/kernel
		logme(L_FINE, "using BSD sockets via libc");
		// nothing to configure; just ensure you can call socket(), bind(), etc.

#elif defined(_WIN32)
		WSADATA wsa;
		int rc = WSAStartup(MAKEWORD(2,2), &wsa);
		if (rc != 0) {
			error = ERROR_BSDSOCKET;
			break;
		}
		logme(L_FINE, "initialized Winsock version %d.%d", LOBYTE(wsa.wVersion), HIBYTE(wsa.wVersion));
		// no breakmask equivalent; Winsock handles signals internally

#else
		error = ERROR_BSDSOCKET;
		break;
#endif

		sockfd = socket(AF_INET, SOCK_STREAM, 0);

		logme(L_FINE, "opened socket %ld", sockfd);
		if (sockfd < 0) {
			error = ERROR_SOCKET;
			break;
		}

		struct hostent *host = gethostbyname((STRPTR)hostname);
		logme(L_FINE, "resolved hostname %s -> %08lx", hostname, host);
		if (host == 0) {
			error = ERROR_RESOLVE;
			break;
		}

		// bind to a local port before connecting
		sinLocal.sin_family = AF_INET;
		sinLocal.sin_addr.s_addr = INADDR_ANY;
		if (bind(sockfd, (struct sockaddr *)&sinLocal, sizeof(sinLocal))) {
			error = ERROR_BIND;
			break;
		}
		logme(L_FINE, "bound socket");

		sinRemote.sin_family = host->h_addrtype;
		sinRemote.sin_port = htons(port);
		sinRemote.sin_addr.s_addr = getInt32(host->h_addr);

		if (0 != connect(sockfd, (struct sockaddr* )&sinRemote, sizeof(sinRemote))) {
			error = ERROR_CONNECT;
			break;
		}
		logme(L_FINE,  "connected to %ld.%ld.%ld.%ld:%ld",
			(0xff & (sinRemote.sin_addr.s_addr >> 24)),
			(0xff & (sinRemote.sin_addr.s_addr >> 16)),
			(0xff & (sinRemote.sin_addr.s_addr >> 8)),
			(0xff & sinRemote.sin_addr.s_addr), port);

		// send server version without terminating zero
		if (!mysend(sockfd, server_version, sizeof(server_version) - 1)) {
			error = ERROR_WRITE;
			break;
		}

		unsigned len = termzero(server_version);
		logme(L_FINE, "sent server version %s", server_version);

#ifdef DEBUG
		printf("sent: %s\n", server_version);
#endif

#if defined(DUMP_HASH)
		hsd = (uint8_t *)malloc(0x2000);
		hsdp = hsd;
#endif
		SHA256 handshakeMD;
		uint32_t len_be = htonl(len);
		handshakeMD.update(&len_be, 4);
		HSU(&len_be, 0, 4);
		handshakeMD.update(server_version, len);
		HSU(server_version, 0, len);

		// receive hostname version
		if (receivePacket(TEXT_CRLF) == 0) {
			logme(L_ERROR, "can't read SSH2 hello");
			error = ERROR_READ;
			break;
		}

		len = termzero(buffer);
		logme(L_FINE, "received server version %s", buffer);

#ifdef DEBUG
		printf("recv: %s\n", buffer);
#endif

		len_be = htonl(len);
		handshakeMD.update(&len_be, 4);
		HSU(&len_be, 0, 4);
		handshakeMD.update(buffer, len);
		HSU(buffer, 0, len);

		if (!mysend(sockfd, KEX_INIT, kexLen)) {
			error = ERROR_WRITE;
			break;
		}

		len = kexLen - 5 - KEX_INIT[4]; // minus header, padding
		len_be = htonl(len);
		handshakeMD.update(&len_be, 4);
		HSU(&len_be, 0, 4);
		handshakeMD.update(&KEX_INIT[0] + 5, len);
		HSU(&KEX_INIT[0], 5, len);
		logme(L_FINE, "sent server SSH_MSG_KEX_INIT");

		if (receivePacket(UNENCRYPTED) == 0) {
			logme(L_ERROR, "can't read SSH_MSG_KEX_INIT");
			error = ERROR_READ;
			break;
		}

		if (!setupEncryption()) {
			error = ERROR_NOCIPHERS;
			break;
		}

		len = packetSize - 1 - buffer[4];
		len_be = htonl(len);
		handshakeMD.update(&len_be, 4);
		HSU(&len_be, 0, 4);
		handshakeMD.update(buffer + 5, len);
		HSU(buffer, 5, len);
		logme(L_FINE, "got server SSH_MSG_KEX_ECDH_INIT");

		makeKexEcdhInit();
		len =  getInt32Aligned(buffer) + 4;
		if (!mysend(sockfd, buffer, len)) {
			error = ERROR_WRITE;
			break;
		}
		logme(L_FINE, "sent server SSH_MSG_KEX_ECDH_INIT");

		if (receivePacket(UNENCRYPTED) == 0) {
			logme(L_ERROR, "can't read SSH_MSG_KEX_ECDH_REPLY");
			error = ERROR_READ;
			break;
		}

		logme(L_FINE, "got server SSH_MSG_KEX_ECDH_REPLY");

		if (!handleKexEcdhReply(handshakeMD, packetSize - 1 - buffer[4]))
			break; // error set inside function
		logme(L_FINE, "processed server SSH_MSG_KEX_ECDH_REPLY");

		deriveKeys(&keyMat, &sharedSecret, hash, true);
		logme(L_FINE, "created key material");

		if (!mysend(sockfd, NEWKEYS, sizeof(NEWKEYS))) {
			error = ERROR_WRITE;
			break;
		}
		logme(L_FINE, "sent server SSH_MSG_NEWKEYS");

		if (receivePacket(UNENCRYPTED) == 0) {
			logme(L_ERROR, "can't read SSH_MSG_NEWKEYS");
			error = ERROR_READ;
			break;
		}

		len = packetSize - 1 - buffer[4];
		if (len != 1 || buffer[5] != SSH_MSG_NEWKEYS) {
			error = ERROR_WRONG_PACKET;
			break;
		}
		logme(L_FINE, "got server SSH_MSG_NEWKEYS");
		if (readCounterBc) {
			keyMat.encIvRead[11] = 3;
			keyMat.encIvWrite[11] = 3;
			int half = keyMat.keyLen >> 1;
			if (!writeAead->setKey(keyMat.encKeyWrite, half) ||
					!readAead->setKey(keyMat.encKeyRead, half) ||
					!writeCounterBc->setKey(&keyMat.encKeyWrite[half], half) ||
					!readCounterBc->setKey(&keyMat.encKeyRead[half], half)
							) {
				error = ERROR_NOMEM;
				break;
			}
		} else
		if ((!writeAead->setKey(keyMat.encKeyWrite, keyMat.keyLen) ||
			 !readAead->setKey(keyMat.encKeyRead, keyMat.keyLen))) {
			error = ERROR_NOMEM;
			break;
		}

		if (!waitForService())
			break;
		logme(L_FINE, "establishing service");

		if (grabConsole())
			atexit(freeConsole);

		if (!authenticate())
			break;
		logme(L_FINE, "authenticated");
	} while (0);
	return error == NO_ERROR;
}


void printError() {
	printf("ERROR: %ld - %s\n", error, (error >= 10 && error < ERROR_LAST) ? ERR_MSG[error - 10] : "unknown error");
	fflush(stdout);
}

static uint8_t OPEN_SESSION[24] = {
		SSH_MSG_CHANNEL_OPEN,
		0x00, 0x00, 0x00, 0x07, 's', 'e', 's', 's', 'i', 'o', 'n',
		0x00, 0x00, 0x00, 0x00, // channel 0
		0x80, 0x00, 0x00, 0x00, // initial window size 2GiB
		0x00, 0x01, 0x00, 0x00  // max packet size 32k
};

bool openChannels() {
	if (!sendEncrypted(OPEN_SESSION, sizeof(OPEN_SESSION)))
		return false;

	do {
		if (!receiveEncryptedPacket()) {
			return false;
		}
	} while (buffer[5] == SSH_MSG_GLOBAL_REQUEST || buffer[5] == SSH_MSG_DEBUG);


	if (buffer[5] != SSH_MSG_CHANNEL_OPEN_CONFIRMATION)
		return false;

	uint8_t * pp = buffer + 18;
	maxBuffer = getInt32(pp);
	if (maxBuffer > 32768)
		maxBuffer = 32768;
	maxBuffer -= 512;

	uint32_t sz = clientChannels.getMax();
	for (int i = 0; i < sz; ++i) {
		auto c = clientChannels[i];
		if (!c)
			continue;
		if (!c->start())
			return false;
	}

	return true;
}

void checkChannelFinished(ClientChannel * cc) {
	// do nothing if CONFIRMED but no finished.
	if (!cc->canBeRemoved()) {
		logme(L_FINE, "can't close now channel %ld/%ld, state=%ld", cc->getChannelNo(), cc->getRemoteChannelNo(), cc->getState());
		return;
	}

	Listener * l = cc->getListener();
	if (l) {
		l->close();
		listeners.remove(l->getSockFd());
	}

	clientChannels.remove(cc->getChannelNo());
	delete cc;

	stopped |= !clientChannels.getCount();
	logme(L_DEBUG, "closed channel %ld/%ld, ccsize=%ld", cc->getChannelNo(), cc->getRemoteChannelNo(), clientChannels.getCount());
}

void eventLoop() {
	ULONG signales = 0;
	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 100 * 1000; // 100ms

	int noop = 0;

	while (!stopped) {
		static fd_set readfds;

		if (++noop == 600) {
			logme(L_FINE, "@%ld sending noop", sockfd);
			buffer[5] = SSH_MSG_CHANNEL_DATA;
			*(uint32_t*) &buffer[6] = 0;
			*(uint32_t*) &buffer[10] = 0;
			sendEncrypted(buffer + 5, 9);
			noop = 0;
		}

		// wait 1ms for data
		handleKeyboard();

		FD_ZERO(&readfds);
		FD_SET(sockfd, &readfds);

		for (int i = 0; i < acceptors.getMax(); ++i) {
			Acceptor * a = acceptors[i];
			if (a && a->isOpen())
				FD_SET(a->getSockFd(), &readfds);
		}
		for (int i = 0; i < listeners.getMax(); ++i) {
			Listener * l = listeners[i];
			if (l && l->isOpen())
				FD_SET(l->getSockFd(), &readfds);
		}

		int maxFd = acceptors.getMax();
		if (listeners.getMax() > maxFd)
			maxFd = listeners.getMax();

//		logme(L_DEBUG, "waitselect max=%ld listeners=%ld acceptors=%ld", maxFd, listeners.getCount(), acceptors.getCount());

#ifdef __AMIGA__
		if (0 == WaitSelect(maxFd + 1, &readfds, NULL, NULL, &tv, &signales))
			continue;

#elif defined(__linux__) || defined(__unix__)
		int r = select(maxFd + 1, &readfds, NULL, NULL, &tv);
		if (r == 0)   // timeout, no descriptors ready
			continue;
		if (r < 0) {
			perror("select");
			break;
		}

#elif defined(_WIN32)
		int r = select(0, &readfds, NULL, NULL, &tv);
		if (r == 0)   // timeout
			continue;
		if (r == SOCKET_ERROR) {
			fprintf(stderr, "select() failed: %d\n", WSAGetLastError());
			break;
		}

#endif

		for (int i = 0; i < acceptors.getMax(); ++i) {
			Acceptor * a = acceptors[i];
			if (a && a->isOpen() && FD_ISSET(a->getSockFd(), &readfds))
			{
				struct sockaddr_in server;
				int c = sizeof(server);
				for(;;) {
					int clientFds = accept(a->getSockFd(), (struct sockaddr* )&server, (socklen_t* )&c);
					if (clientFds < 0)
						break;
					logme(L_DEBUG, "connect on %ld new socket %ld", a->getSockFd(), clientFds);
					if (clientFds > 0) {
						a->handleAccept(clientFds);
					}
				}
			}
		}

		for (int i = 0; i < listeners.getMax(); ++i) {
			Listener * l = listeners[i];
			if (!l)
				continue;

			ClientChannel * c = l->getChannel();
			int sfd = l->getSockFd();
			if (sfd > 0 && FD_ISSET(sfd, &readfds) && c->canRead()) {
				// offset 14 to avoid copying data as channel data
				char * p = 14 + (char *)buffer;
				int read = recv(l->getSockFd(), p, buffersize - 14, 0);
				if (read > 0) {
					logme(L_DEBUG, "read on socket %ld len=%ld ", l->getSockFd(), read);
					read = l->processSocketData(p, read);
				}
				if (read <= 0) {
					logme(L_DEBUG, "read on socket %ld returned %ld ", l->getSockFd(), read);

					if (c && !(c->getState() & ClientChannel::CLIENT_CLOSE)) {
						uint8_t * p;
						c->closeChannel(ClientChannel::CLIENT_CLOSE | ClientChannel::CLIENT_EOF);
					}
					break;
				}
			}
		}

		if (FD_ISSET(sockfd, &readfds)) {
			int len = receiveEncryptedPacket();
			if (!len)
				break;

			// inside loop, since buffer may change!
			uint8_t * p = buffer + 5;
			uint8_t k = *p++;

			if (k >= SSH_MSG_CHANNEL_OPEN && *p <= SSH_MSG_CHANNEL_FAILURE) {
				uint32_t channelNo = getInt32(p);
				p += 4;
				ClientChannel * cc = clientChannels[channelNo];
				if (!cc) {
					logme(L_ERROR, "got packet for invalid channel %ld", channelNo);
				} else {
					bool r = cc->handleMessage(k, p, len - 9); // 9 = PACKETLEN + MSG + CHANNELNO = 4 + 1 + 4
					if (!r)
						stopped = 1;
				}
			} else
			if (k == SSH_MSG_DISCONNECT) {
				uint32_t err = getInt32(p);
				p += 4;
				uint8_t * msg = sshString(p);
				logme(err ? L_ERROR : L_DEBUG, "disconnect %08lx : %s", err, msg);
				stopped = 1;
			}

			// TODO: handle other messages...
		}
	}
}

bool startAcceptors() {
	for (int i = 0; i < initacceptors.getMax(); ++i) {
		Acceptor * a = initacceptors[i];
		if (!a)
			continue;

		if (!a->init()) {
			logme(L_ERROR, "failed to start a listener");
			return false;
		}
		acceptors.add(a->getSockFd(), a);
	}
	return true;
}

extern bool addForwardAcceptor(char const *s);

void parseConfigFile(int ssh) {
	if (!configFile) configFile = concat(sshDir, ".ssh/ssh_config", NULL);
	BPTR ini = Open(configFile, MODE_OLDFILE);
	if (!ini) {
		logme(L_DEBUG, "can't open `%s`", configFile);
		return;
	}

	char const * hn = hostname;
	bool match = false;
	for(;;) {
		char buf[256];
		char * s = FGets(ini, buf, 256);
		if (!s)
			break;

		char * p = (char *)splitLine(s);
		if (!p)
			continue;

		// s = keyword, p = parameter

		logme(L_DEBUG, "ssh_config: %s %s", s, p);
		if (0 == stricmp("Host", s)) {
			match = !fnmatch(p, hn, 0);
			continue;
		}
		if (!match)
			continue;

		if (0 == stricmp("Ciphers", s)) {
			if (userOrder) {
				logme(L_INFO, "Ciphers already set");
			} else {
				char const * aes = strstr(p, AES128);
				char const * chacha = strstr(p, CHACHA20);
				if (aes && chacha) {
					if (aes < chacha)
						userOrder = "12";
					else
						userOrder = "21";
				} else if (aes) {
					userOrder = "1";
				} else if (chacha) {
					userOrder = "2";
				}
				if (userOrder) {
					encOrder = userOrder;
				} else {
					logme(L_WARN, "no valid ciphers given in %s: %s", configFile, p);
				}
			}
		} else
		if (0 == stricmp("LogLevel", s)) {
			if (!loglevelSet)
				parseLogLevel(p);
			else
				logme(L_INFO, "LogLevel already set");
		} else
		if (0 == stricmp("HostName", s)) {
			hostname = strdup(p);
		} else
		if (0 == stricmp("User", s)) {
			if (!usernameSet)
				username = strdup(p);
			else
				logme(L_INFO, "User already set");
		} else
		if (0 == stricmp("Port", s)) {
			if (!portSet)
				port = strtoul(p, 0, 10);
			else
				logme(L_INFO, "Port already set");
		} else
		if (0 == stricmp("IdentityFile", s)) {
			if (!keyfileSet)
				keyFile = strdup(p);
			else
				logme(L_INFO, "IdentityFile already set");
		} else
		if (0 == stricmp("LocalForward", s)) {
			if (ssh) addForwardAcceptor(p);
		} else {
			logme(L_WARN, "ssh_config: unknown directive: %s %s", s, p);
		}
	}

	Close(ini);
	return;
}

void runClient() {
#ifdef __AMIGA__
#else
#endif
	if (connectClient()) {
		if (openChannels()) {
			logme(L_FINE, "opened ssh channels");
			if (startAcceptors()) {
				eventLoop();
			}
		}
	}
	logme(L_FINE, "bye bye");

	if (error) {
		printError();
	}
}
