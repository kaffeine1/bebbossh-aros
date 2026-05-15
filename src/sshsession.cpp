/* bebbossh - SSH session handler
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
 * Project: bebbossh - SSH2 client/server suite for Amiga
 * Purpose: Manage per-connection state, encryption, and channel lifecycle
 *
 * Features:
 *  - HELLO/KEXINIT negotiation and cipher selection (AES-GCM / ChaCha20-Poly1305)
 *  - Encrypted packet framing, IV increment, and AEAD authentication
 *  - Channel I/O, EOF/CLOSE sequencing, and break signaling
 *  - Buffered socket processing with partial-consume handling
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing.
 *  - Integrates with bsdsocket.library, AmigaDOS messaging, and timer.device.
 *
 * Author's intent:
 *  Provide a robust, maintainable session core with explicit resource
 *  management and predictable behavior on classic Amiga systems.
 * ----------------------------------------------------------------------
 */
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/errno.h>
#include "platform.h"

#if BEBBOSSH_AMIGA_API
#include <amistdio.h>

#include <proto/dos.h>
#include <proto/exec.h>
#include <proto/socket.h>

#define DPTR BPTR
extern struct SignalSemaphore theLock;


#else
#include "amiemul.h"

extern pthread_mutex_t  theLock;

#if BEBBOSSH_PAM_AUTH
// --- PAM authentication ---
#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include <security/pam_appl.h>
#include <stdlib.h>
#include <string.h>

static int conv_func(int num_msg,
                     const struct pam_message **msg,
                     struct pam_response **resp,
                     void *appdata_ptr)
{
    if (num_msg <= 0) return PAM_CONV_ERR;

    *resp = (struct pam_response*)calloc(num_msg, sizeof(struct pam_response));
    if (!*resp) return PAM_CONV_ERR;

    const char *password = (const char*)appdata_ptr;

    for (int i = 0; i < num_msg; ++i) {
        if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF) {
            // supply password
            (*resp)[i].resp = strdup(password);
        } else {
            // ignore other prompts
            (*resp)[i].resp = strdup("");
        }
    }
    return PAM_SUCCESS;
}
#endif

#endif

#include <ed25519.h>
#include <forwardchannel.h>
#include <log.h>
#include <mime.h>
#include <rand.h>
#include <sshsession.h>
#include <test.h>

#include "channel.h"
#include "shellchannel.h"
#include "sftpchannel.h"

#include "revision.h"

char const * AES128 = "aes128-gcm@openssh.com";
char const * CHACHA20 = "chacha20-poly1305@openssh.com";

extern Stack<Listener> *listenersPtr;
#define listeners (*listenersPtr)
extern char* splitLine(char *&s);

extern uint8_t hostPK[32];
extern uint8_t hostSK[64];

extern char const *passwords;

static unsigned SSHNO;
static char const *hello = "SSH-2.0-" _VNAME "\r\n";

extern bool hasAes;
extern bool hasChacha;

/*
 * Timing-normalization envelope for the KEX reply.
 *
 * The Amiga's scalar-mult and signature routines are not constant-time,
 * so we enforce a constant-upper-bound execution time across the entire
 * KEX reply. We track the last N durations, pad shorter runs to the
 * rolling maximum, and update the max conservatively. This reduces
 * observable timing variance and mitigates timing side-channel leakage.
 */
void timing_protection(struct timeval *start) {
#define N 16   /* number of samples to track */

static uint32_t durations[N] = {0};
static int idx = 0;
static uint32_t max_duration = 0;

	struct timeval  end;
    gettimeofday(&end, nullptr);

    struct timeval diff;
    timersub(&end, start, &diff);
    uint32_t dt = diff.tv_sec * 20 + diff.tv_usec / 50000;

    /* Pad if shorter than max */
    if (dt < max_duration) {
        uint32_t pad = max_duration - dt;
        Delay(pad);
        dt = max_duration; /* normalized */
    }

    /* Store duration in ring buffer */
    durations[idx] = dt;
    idx = (idx + 1) % N;

    /* Recompute max conservatively */
    uint32_t new_max = 0;
    for (int i = 0; i < N; i++) {
        if (durations[i] > new_max)
            new_max = durations[i];
    }

	max_duration = new_max;
}


static uint8_t kex_reply[24] = {
SSH_MSG_KEX_ECDH_REPLY, 0, 0, 0, 0x33, 0, 0, 0, 0x0b, 's', 's', 'h', '-', 'e', 'd', '2', '5', '5', '1', '9', 0, 0, 0, 0x20 };

static uint8_t kex_reply2[23] = { 0, 0, 0, 0x53, 0, 0, 0, 0x0b, 's', 's', 'h', '-', 'e', 'd', '2', '5', '5', '1', '9', 0, 0, 0, 0x40 };

static uint8_t key_len[4] = { 0, 0, 0, 32 };

static uint8_t newKeys[16] = { 0, 0, 0, 12, 10,
SSH_MSG_NEWKEYS, 1, 2, 3, 4, 5, 6, 7, 8, 9, 'A' };

static uint8_t serviceAccept[17] = {
SSH_MSG_SERVICE_ACCEPT, 0, 0, 0, 12, 's', 's', 'h', '-', 'u', 's', 'e', 'r', 'a', 'u', 't', 'h' };

static uint8_t passwordAuth[24] = {
SSH_MSG_USERAUTH_FAILURE, 0, 0, 0, 18, 'p', 'a', 's', 's', 'w', 'o', 'r', 'd', ',', 'p', 'u', 'b', 'l', 'i', 'c', 'k', 'e', 'y', 0 };

static uint8_t loginSuccess[1] = {
SSH_MSG_USERAUTH_SUCCESS, };

/**
 * send data.
 * Return true on success.
 */
bool mysend(int fd, void const *data, int len) {
	for (uint8_t * p = (uint8_t *)data;;) {
		int sent = send(fd, p, len, 0);
		if (sent < 0) {
			int _errno = Errno();
			if (_errno == EAGAIN) {
				logme(L_DEBUG, "failed to send %ld bytes on socket %ld: sent %ld, errno=%ld, retrying", len, fd, sent, _errno);
				Delay(2);
				continue;
			}
			logme(L_ERROR, "failed to send %ld bytes on socket %ld: sent %ld, errno=%ld", len, fd, sent, _errno);
			return false;
		}
		if (sent == 0) {
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

static void increment(uint8_t iv[12]) {
	for (int i = 11; i >= 0; --i) {
		if (++iv[i])
			break;
	}
}

void SshSession::abort() {
	for (int i = 0; i < channels.getMax(); ++i) {
		if (channels[i])
			channels[i]->abort();
	}
}

void SshSession::checkTimeout(struct timeval *tv) {
	for (int i = 0; i < channels.getMax(); ++i) {
		if (channels[i])
			channels[i]->checkTimeout(tv);
	}
}

/**
 * Callback, invoked after a command is finished.
 */
void SshSession::checkFinished() {
	for (int i = 0; i < channels.getMax(); ++i) {
		Channel *c = channels[i];
		if (c && c->isSession()) {
			ShellChannel *sc = (ShellChannel*) c;
			if (sc->isDone())
				sc->endCommand();
		}
	}
}

void SshSession::sendBreak() const {
	for (int i = 0; i < channels.getMax(); ++i) {
		if (channels[i])
			channels[i]->sendBreak();
	}
}

bool SshSession::isAlive() const {
	logme(L_DEBUG, "server has %ld channels", channels.getCount());
	if (channels.getCount()) {
		for (int i = 0; i < channels.getMax(); ++i) {
			Channel *c = channels[i];
			if (c && c->isSession()) {
				ShellChannel *sc = (ShellChannel*) c;
				return sc->isWaiting() || sc->isPending();
			}
		}
	}
	return false;
}

ShellChannel* SshSession::findShellChannelByBreakPort(struct MsgPort *mp) const {
#if BEBBOSSH_AMIGA_API
	for (int i = 0; i < channels.getMax(); ++i) {
		Channel *c = channels[i];
		if (c && c->isSession()) {
			ShellChannel *sc = (ShellChannel*) c;
			if (sc->hasBreakPort(mp))
				return sc;
		}
	}
#endif
	return 0;
}

SshSession::SshSession(int _sock) :
		state(HELLO),
		readAead(0), readBc(0), readCounterBc(0),
		writeAead(0), writeBc(0), writeCounterBc(0),
		channels(10), windowsize(CHUNKSIZE), maxsize(CHUNKSIZE),
		inpos(indatax), inChannelUse(0), inChannelSize(0), inChannelBuf(0),
		kexLen(0), username(0)
{
	sockFd = _sock;
	open = true;
	name[0] = 'S';
	name[1] = 'S';
	name[2] = 'H';
	name[3] = '-';
	utoa(++SSHNO, &name[4], 16);
	logme(L_INFO, "@%ld starting handler %s", sockFd, name);
}

SshSession::~SshSession() {
	logme(L_INFO, "@%ld stopping handler %s", sockFd, name);
	if (readAead) delete readAead;
	if (writeAead) delete writeAead;
	if (readBc) delete readBc;
	if (writeBc) delete writeBc;
	if (readCounterBc) delete readCounterBc;
	if (writeCounterBc) delete writeCounterBc;
	free(inChannelBuf);
	if (username) free(username);

	memset(name, 0xde, (char*)&readAead - (char*)&name);
}

void SshSession::start() {
	write(hello, strlen(hello));
	logme(L_FINE, "@%ld sent SSH HELLO", sockFd);
	char const * encOrder;
	if (!hasChacha)
		encOrder = "1";
	else if (!hasAes)
		encOrder = "2";
	else
		encOrder = "21";
	kexLen = fillKexInit((uint8_t *)outdata, encOrder);
	write(outdata, kexLen);
	logme(L_FINE, "@%ld sent SSH_MSG_KEX_INIT %ld", sockFd, kexLen);
}

void SshSession::close() {
	logme(L_FINE, "@%ld closing socket for %s", sockFd, name);
	abort();
	if (open) {
		CloseSocket(sockFd);
		open = false;
	}
}

int SshSession::channelWrite(uint32_t channel, void const *data, int len) {
	logme(L_FINE, "@%ld send SSH_MSG_CHANNEL_DATA %ld", sockFd, len);
	outdata[5] = SSH_MSG_CHANNEL_DATA;
	putInt32Aligned(&outdata[6], channel);
	putInt32Aligned(&outdata[10] , len);
	if (data != &outdata[14])
		memcpy(&outdata[14], data, len);
	return write(outdata + 5, len + 9) - 9;
}

void SshSession::closeChannel(Channel *channel, uint32_t exitStatus) {
	logme(L_FINE, "@%ld:%ld send SSH_MSG_CHANNEL_REQUEST exit status %ld", sockFd, channel->getChannel(), exitStatus);
	outdata[5] = SSH_MSG_CHANNEL_REQUEST;
	putInt32Aligned(&outdata[6] , channel->getChannel());
	putInt32Aligned(&outdata[10] , 11);
	strcpy(&outdata[14], "exit-status");
	outdata[25] = 0;
	putInt32Aligned(&outdata[26], exitStatus);
	write(outdata + 5, 25);

	logme(L_FINE, "@%ld:%ld send SSH_MSG_CHANNEL_EOF", sockFd, channel->getChannel());
	outdata[5] = SSH_MSG_CHANNEL_EOF;
	putInt32Aligned(&outdata[6] , channel->getChannel());
	write(outdata + 5, 5);

	logme(L_FINE, "@%ld:%ld send SSH_MSG_CHANNEL_CLOSE", sockFd, channel->getChannel());
	outdata[5] = SSH_MSG_CHANNEL_CLOSE;
	putInt32Aligned(&outdata[6] , channel->getChannel());
	write(outdata + 5, 5);

	ObtainSemaphore(&theLock);
	channels.remove(channel->getChannel());
	ReleaseSemaphore(&theLock);

	delete channel;

	if (0 == channels.getCount())
		close();
}

void SshSession::noop() {
	if (isOpen() && channels.getCount() > 0) {
		logme(L_FINE, "@%ld sending noop", sockFd);
		outdata[5] = SSH_MSG_CHANNEL_DATA;
		putInt32Aligned(&outdata[6] , channels[0]->getChannel());
		putInt32Aligned(&outdata[10] , 0);
		write(outdata + 5, 9);
	}
}

int SshSession::write(void const *data, int len) {
	int sub = 0;
	if (state >= AUTH) {
		if (isLogLevel(L_TRACE)) {
			_dump("send plain", data, len > 128 ? 128 : len);
			if (len > 128) {
				int from = (len - 32) & ~31;
				_dump("send plain last bytes", (char*)data + from, len - from);
			}
		} else
		if (isLogLevel(L_ULTRA))
			_dump("send plain", data, len);

		int outlen = len + 16 + 4 + 1;
		// copy if not in place
		if (data != outdata + 5)
			memmove(outdata + 5, data, len);

		randfill(outdata, 1);
		unsigned padSize = 16 + (outdata[0] & 0x70);
		unsigned padLen = padSize + 3 - ((len + 4) & (padSize - 1)); // 4..padSize+3 bytes

		sub = 1 + padLen;
		len += sub;
		outdata[4] = padLen;
		outlen += padLen;
		putInt32Aligned(outdata, len);

		randfill(outdata + outlen - 16 - padLen, padLen);
#ifdef DUMP_PACKETS
		_dump("writeIV", encIvWrite, 12);
	#endif
		if (writeCounterBc) {
			writeCounterBc->setNonce(keyMat.encIvWrite, 12);
			writeCounterBc->zeroCounter();
			writeCounterBc->chacha(outdata, outdata, 4);
			writeAead->init(keyMat.encIvWrite, 12);
			writeAead->encrypt(outdata + 4, outdata + 4, len);
			writeAead->updateHash(outdata, 4 + len);
		} else {
			writeAead->init(keyMat.encIvWrite, 12);
			writeAead->updateHash(outdata, 4);
			writeAead->encrypt(outdata + 4, outdata + 4, len);
		}
		writeAead->calcHash(outdata + 4 + len);
		increment(keyMat.encIvWrite);

		data = outdata;
		len += 20; // packetLen + hashLen = 4 + 16
		sub += 20;
		if (isLogLevel(L_ULTRA))
			_dump("send encrypted", outdata, len);
	}

	logme(L_TRACE, "@%ld sending length=%ld", sockFd, len);
	if (mysend(sockFd, data, len))
		return len - sub;
	return -1;
}

int SshSession::processSocketData(void *_data, int len) {
	logme(L_FINE, "processSocketData %ld", len);
	if (len > CHUNKSIZE) // can't happen...
		return false;

	char *data = (char*) _data;

	// we have data in the buffer
	int buffered = inpos - indatax;
	if (buffered) {
		if (len + buffered > CHUNKSIZE * 2)
			return false;

		// append
		memcpy(inpos, data, len);
		inpos += len;

		// use buffered data to process
		data = indatax;
		len += buffered;
	}

// process data, either _data or indatax
	do {
		int consumed = consumeSocketData(data, len);
		logme(L_FINE, "consumed %ld of %ld", consumed, len);
		// error -> return false;
		if (consumed < 0) {
			return false;
		}

		// nothing consumed: buffer and return true
		if (consumed == 0) {
			// first attempt -> copy to buffer
			if (inpos == indatax) {
				memcpy(indatax, data, len);
				inpos = indatax + len;
			} else if (data != indatax) {
				// buffered data was partial processed, move it
				memmove(indatax, data, len);
				inpos = indatax + len;
			}
			return true;
		}
		data += consumed;
		len -= consumed;
	} while (len > 0);

	// all consumed
	inpos = indatax;

	return true;
}

#if defined(DUMP_HASH)
static __far uint8_t hsd[32000];
static uint8_t * hsdp = hsd;
#define HSU(a,b,c) \
	memcpy(hsdp, a+b, c); \
	hsdp += c
#else
#define HSU(a,b,c)
#endif

int SshSession::setupEncryption(char *indata) {
	uint8_t * p = (uint8_t *)indata + 22; // start of encoding
	uint8_t * sig = sshString(p);
	uint8_t * kex = sshString(p);
	uint8_t * read = sshString(p);
	uint8_t * write = sshString(p);

//	puts((char*)read);
//	puts((char*)write);

	char *aes = strstr((char*)read, AES128);
	char *chacha = strstr((char*)read, CHACHA20);

	if (aes && chacha) {
		if (aes < chacha) {
			chacha = 0;
		} else {
			aes = 0;
		}
	}

	if (aes) {
		logme(L_DEBUG, "using %s", AES128);
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
	} else if (chacha ){
		logme(L_DEBUG, "using %s", CHACHA20);
		readAead = new ChaCha20Poly1305_SSH2();
		writeAead = new ChaCha20Poly1305_SSH2();
		readCounterBc = new ChaCha20();
		writeCounterBc = new ChaCha20();
		keyMat.ivLen = 0; // we start with zeroes
		keyMat.keyLen = 64;
	}

	logme(L_FINE, "readAead %08lx", readAead);
	logme(L_FINE, "readBc %08lx", readBc);
	logme(L_FINE, "readCounterBc %08lx", readCounterBc);
	logme(L_FINE, "writeAead %08lx", writeAead);
	logme(L_FINE, "writeBc %08lx", writeBc);
	logme(L_FINE, "writeCounterBc %08lx", writeCounterBc);

	return writeAead != 0;
}

int SshSession::consumeSocketData(char *indata, int len) {
	if (len < 8)
		return 0;

	if (state == HELLO) {
		// we need a CRLF
		int clen = strlen(indata);
		if (clen > len)
			return 0;

		char *lf = indata + clen - 1;
		if (*lf > 32)
			return 0;
		while (*lf <= 32 && lf > indata)
			--lf;
		++lf;
		*lf = 0;

		if (strncmp(hello, indata, 8)) {
			logme(L_INFO, "@%ld unsupported version %s", sockFd, indata);
			return -1;
		}

		logme(L_FINE, "@%ld got SSH_HELLO `%s`", sockFd, indata);
#ifdef DUMP_HASH
		hsdp = hsd;
#endif
		// server hello
		uint32_t len = lf - indata;
		uint32_t len_be = htonl(len);
		handshakeMD.update(&len_be, 4);
		HSU(&len_be, 0, 4);
		handshakeMD.update(indata, len);
		HSU(indata, 0, len);

		// server hello
		int slen = strlen(hello) - 2;
		len_be = htonl(slen);
		handshakeMD.update(&len_be, 4);
		HSU(&len_be, 0, 4);
		handshakeMD.update(hello, slen);
		HSU(hello, 0, slen);

		state = KEX_INIT;
		return clen;
	}

	uint32_t packetSize;
	if (readCounterBc) {
		readCounterBc->setNonce(keyMat.encIvRead, 12);
		readCounterBc->zeroCounter();
		readCounterBc->chacha(&packetSize, indata, 4);
		packetSize = htonl(packetSize);
	} else {
		packetSize = getInt32Aligned((uint8_t *)indata);
	}

	if (packetSize > CHUNKSIZE)
		return -1;
	uint32_t needed = packetSize + 4;

	if (state > NEW_KEYS)
		needed += 16; // signature

	if (len < needed) {
		logme(L_FINE, "not a full packet: len %ld < needed %ld", len, needed);
		return 0;
	}

	if (isLogLevel(L_ULTRA))
		_dump("in", indata, packetSize + 4 > 128 ? 128 : packetSize + 4);

	switch (state) {
	case KEX_INIT: {
		if (indata[5] != SSH_MSG_KEX_INIT) {
			logme(L_INFO, "@%ld expected SSH_MSG_KEX_INIT=20 - got %ld", sockFd, indata[5]);
			return -1;
		}
		logme(L_FINE, "@%ld got SSH_MSG_KEX_INIT", sockFd);

		uint8_t *p = (uint8_t*) indata + 22;
		uint8_t *kex_algorithms = sshString(p);
		if (!strstr((char*) kex_algorithms, "curve25519-sha256")) {
			logme(L_INFO, "@%ld unsupported kex_algorithms: %s", sockFd, kex_algorithms);
			return -1;
		}

		uint8_t *server_host_key_algorithms = sshString(p);
		if (!strstr((char*) server_host_key_algorithms, "ssh-ed25519")) {
			logme(L_INFO, "@%ld unsupported server_host_key_algorithms: %s", sockFd, server_host_key_algorithms);
			return -1;
		}

		uint8_t *encryption_algorithm = sshString(p);
		if (!strstr((char*) encryption_algorithm, AES128) &&
				!strstr((char*) encryption_algorithm, CHACHA20)) {
			logme(L_INFO, "@%ld unsupported encryption_algorithm: %s", sockFd, encryption_algorithm);
			return -1;
		}
		encryption_algorithm = sshString(p);
		if (!strstr((char*) encryption_algorithm, AES128) &&
				!strstr((char*) encryption_algorithm, CHACHA20)) {
			logme(L_INFO, "@%ld unsupported encryption_algorithm: %s", sockFd, encryption_algorithm);
			return -1;
		}

		uint8_t *mac_algorithm = sshString(p);
		if (!strstr((char*) mac_algorithm, "hmac-sha2-256")) {
			logme(L_INFO, "@%ld unsupported mac_algorithm: %s", sockFd, mac_algorithm);
			return -1;
		}
		mac_algorithm = sshString(p);
		if (!strstr((char*) mac_algorithm, "hmac-sha2-256")) {
			logme(L_INFO, "@%ld unsupported mac_algorithm: %s", sockFd, mac_algorithm);
			return -1;
		}

		uint8_t *compression_algorithm = sshString(p);
		if (!strstr((char*) compression_algorithm, "none")) {
			logme(L_INFO, "@%ld unsupported compression_algorithm: %s", sockFd, compression_algorithm);
			return -1;
		}
		compression_algorithm = sshString(p);
		if (!strstr((char*) compression_algorithm, "none")) {
			logme(L_INFO, "@%ld unsupported compression_algorithm: %s", sockFd, compression_algorithm);
			return -1;
		}

		memcpy(indatax + 2048, indata, packetSize + 4);

		// server KEX_INIT
		int clen = packetSize - 1 - indata[4];
		uint32_t len_be = htonl(clen);
		handshakeMD.update(&len_be, 4);
		HSU(&len_be, 0, 4);
		handshakeMD.update(indata + 5, clen);
		HSU(indata, 5, clen);

		// server KEX_INIT
		clen = kexLen - 5 - outdata[4]; // minus header, padding
		len_be = htonl(clen);
		handshakeMD.update(&len_be, 4);
		HSU(&len_be, 0, 4);
		handshakeMD.update(outdata + 5, clen); // sent packet is in buffer
		HSU(outdata, 5, clen);

		state = KEX_ECDH_INIT;
	}
		break;
	case KEX_ECDH_INIT: {
		if (indata[5] != SSH_MSG_KEX_ECDH_INIT) {
			logme(L_INFO, "@%ld, expected SSH_MSG_KEX_ECDH_INIT=30 - got %ld", sockFd, indata[5]);
			return -1;
		}
		logme(L_FINE, "@%ld got SSH_MSG_KEX_ECDH_INIT", sockFd);

		uint32_t keyLen = getInt32(indata + 6);
		if (keyLen != 32) {
			logme(L_INFO, "@%ld expected key length 32 - got %ld", sockFd, keyLen);
			return -1;
		}
		memcpy(clientPK_aka_E, indata + 10, 32);

		createKexEcdhReply();
		write(outdata, getInt32Aligned(outdata) + 4);
		logme(L_FINE, "@%ld sent SSH_MSG_KEX_ECDH_REPLY", sockFd);

		write(newKeys, sizeof(newKeys));
		logme(L_FINE, "@%ld sent SSH_MSG_NEWKEYS", sockFd);

		state = NEW_KEYS;
	}
		break;
	case NEW_KEYS:
		if (indata[5] != SSH_MSG_NEWKEYS) {
			logme(L_INFO, "@%ld expected SSH_MSG_NEWKEYS=21 - got %ld", sockFd, indata[5]);
			return -1;
		}
		logme(L_FINE, "@%ld got SSH_MSG_NEWKEYS", sockFd);

		if (!setupEncryption(indatax + 2048))
			return -1;

		deriveKeys(&keyMat, &sharedSecret_aka_K, hash, false);

		// set the keys
		if (readCounterBc) {
			memset(&keyMat.encIvWrite[0], 0, 24);
			keyMat.encIvRead[11] = 3;
			keyMat.encIvWrite[11] = 3;
			int half = keyMat.keyLen >> 1;
			if (!writeAead->setKey(keyMat.encKeyWrite, half) ||
					!readAead->setKey(keyMat.encKeyRead, half) ||
					!writeCounterBc->setKey(&keyMat.encKeyWrite[half], half) ||
					!readCounterBc->setKey(&keyMat.encKeyRead[half], half)
							) {
				logme(L_ERROR, "@%ld could not apply the keys - not enough memory", sockFd);
				return -1;
			}
		} else
		if ((!writeAead->setKey(keyMat.encKeyWrite, keyMat.keyLen) ||
			 !readAead->setKey(keyMat.encKeyRead, keyMat.keyLen))) {
			logme(L_ERROR, "@%ld could not apply the keys - not enough memory", sockFd);
			return -1;
		}

		state = AUTH;
		break;
	case LOGGEDIN:
	case AUTH: {
		uint8_t *p = (uint8_t*) indata + 6;
		// state >= AUTH -> decrypt incoming data
		int len = decryptPacket((uint8_t*) indata, packetSize);
		if (0 == len)
			return -1;

		packetSize += 16; // add signature size

		switch (indata[5]) {
		case SSH_MSG_SERVICE_REQUEST:
			logme(L_FINE, "@%ld got SSH_MSG_SERVICE_REQUEST", sockFd);
			handleServiceRequest(p);
			break;
		case SSH_MSG_USERAUTH_REQUEST:
			logme(L_FINE, "@%ld got SSH_MSG_USERAUTH_REQUEST", sockFd);
			if (handleUserAuthRequest(p)) {
				state = LOGGEDIN;
			}
			break;
		case SSH_MSG_CHANNEL_OPEN:
			logme(L_FINE, "@%ld got SSH_MSG_CHANNEL_OPEN", sockFd);
			handleOpenChannel(p);
			break;
		case SSH_MSG_CHANNEL_WINDOW_ADJUST:
			logme(L_FINE, "@%ld got SSH_MSG_CHANNEL_WINDOW_ADJUST", sockFd);
			break;
		case SSH_MSG_CHANNEL_DATA:
			logme(L_FINE, "@%ld got SSH_MSG_CHANNEL_DATA", sockFd);
			handleChannelData(p, len);
			break;
		case SSH_MSG_CHANNEL_EOF:
			logme(L_FINE, "@%ld got SSH_MSG_CHANNEL_EOF", sockFd);
			handleChannelEof(p);
			break;
		case SSH_MSG_CHANNEL_REQUEST:
			logme(L_FINE, "@%ld got SSH_MSG_CHANNEL_REQUEST", sockFd);
			handleChannelRequest(p);
			break;
		case SSH_MSG_CHANNEL_SUCCESS:
			logme(L_FINE, "@%ld got SSH_MSG_CHANNEL_SUCCESS", sockFd);
			break;
		case SSH_MSG_DISCONNECT:
			logme(L_FINE, "@%ld got SSH_MSG_DISCONNECT", sockFd);
			break;
		default:
			_dump("unknown", indata, packetSize + 4);
			logme(L_INFO, "@%ld unknown packet received %ld", sockFd, indata[5]);
			break;
		}
	}
		break;
	default:
		_dump("unknown", indata, needed + 4);
		logme(L_INFO, "@%ld unknown decrypted packet received %ld", sockFd, indata[5]);
	}
	return packetSize + 4;
}

bool SshSession::login(uint8_t *user, uint8_t *pass) {
#if BEBBOSSH_AMIGA_API
	BPTR pwd = Open(passwords, MODE_READWRITE);
	bool readOnly = false;
	if (!pwd) {
		pwd = Open(passwords, MODE_OLDFILE);
		readOnly = true;
		if (!pwd) {
			logme(L_ERROR, "can't open `%s`", passwords);
			return false;
		}
	}

	bool r = false;
	for (;;) {
		int writePos = Seek(pwd, 0, OFFSET_CURRENT);
		char *s = FGets(pwd, outdata, 256);
		if (!s)
			break;

		char *p = splitLine(s);
		if (!p)
			continue;

		if (strcmp((char*) user, s))
			continue;

		logme(L_FINE, "@%ld user `%s` found", sockFd, user);
		if (0 == strncmp(p, "{ssha256}", 9)) {
			mimeDecode(outdata, p + 9, strlen(p + 9));
			SHA256 sha;
			sha.update(pass, strlen((char*) pass));
			sha.update(outdata + 32, 32);
			sha.digest(outdata + 32);
			r = 0 == memcmp(outdata, outdata + 32, 32);
		} else {
			// unencrypted password
			logme(L_INFO, "@%ld user `%s` with unhashed password", sockFd, user);
			if (0 == strcmp(p, (char*) pass)) {
				r = true;
				if (readOnly) {
					logme(L_INFO, "@%ld password file is read-only, keeping unhashed password", sockFd);
					break;
				}

				// update password file
				randfill(outdata + 32, 32);
				SHA256 sha;
				sha.update(pass, strlen((char*) pass));
				sha.update(outdata + 32, 32);
				sha.digest(outdata);

				char *x = outdata + 64;
				strcpy(x, (char*) user);
				strcat(x, " {ssha256}");
				char *q = x + strlen(x);
				mimeEncode(q, outdata, 64);
				q += strlen(q) + 1;

				// copy line by line
				int readPos = Seek(pwd, 0, OFFSET_CURRENT);
				for (;;) {
					Seek(pwd, readPos, OFFSET_BEGINNING);
					s = FGets(pwd, q, 256);
					if (!s)
						break;
					if (!strstr(q, "\r\n"))
						strcat(q, "\r\n");

					readPos = Seek(pwd, 0, OFFSET_CURRENT);
					Seek(pwd, writePos, OFFSET_BEGINNING);
					FPuts(pwd, q);
					writePos = Seek(pwd, 0, OFFSET_CURRENT);
				}
				Seek(pwd, writePos, OFFSET_BEGINNING);
				FPuts(pwd, x);
				logme(L_INFO, "@%ld user `%s` replaced password with hash", sockFd, user);
			}
		}
		break;
	}
	Close(pwd);
	if (r)
		logme(L_INFO, "@%ld login success for user `%s`", sockFd, user);
	else
		logme(L_INFO, "@%ld login failed for user `%s`", sockFd, user);
	return r;
#elif BEBBOSSH_PAM_AUTH
    pam_handle_t *pamh = NULL;
    struct pam_conv conv = { conv_func, (void*)pass };

    int retval = pam_start("sshd", (const char*)user, &conv, &pamh);
    if (retval != PAM_SUCCESS) return false;

    retval = pam_authenticate(pamh, 0);
    if (retval != PAM_SUCCESS) {
        pam_end(pamh, retval);
        return false;
    }

    retval = pam_acct_mgmt(pamh, 0);
    pam_end(pamh, retval);

    return (retval == PAM_SUCCESS);
#else
	return false;
#endif
}

bool SshSession::handleChannelEof(uint8_t *p) {
	uint32_t channelNo = getInt32(p);
	Channel * c = channels[channelNo];
	if (c) {
		c->abort();
		return true;
	}
	return false;
}

bool SshSession::handleChannelData(uint8_t *p, int alen) {
	uint32_t channelNo = getInt32(p);
	p += 4;

	Channel * c = channels[channelNo];
	if (c) {
		uint32_t len = getInt32Aligned(p);
		p += 4;

		uint32_t toAdd = c->updateWindowSize(len);
		if (toAdd) {
			outdata[5] = SSH_MSG_CHANNEL_WINDOW_ADJUST;
			putInt32Aligned(&outdata[6] , c->getChannel());
			putInt32Aligned(&outdata[10] , toAdd);
			write(outdata + 5, 9);
			logme(L_FINE, "@%ld sent SSH_MSG_CHANNEL_WINDOW_ADJUST %ld", sockFd, toAdd);
		}

		if (inChannelUse) {
			logme(L_FINE, "applying partial channel data: inuse=%ld, len=%ld", inChannelUse, len);
			int total = len + inChannelUse;
			if (total > inChannelSize) {
				inChannelBuf = (char *)realloc(inChannelBuf, total);
				inChannelSize = total;
			}
			memcpy(inChannelBuf + inChannelUse, p, len);
			p = (uint8_t*)inChannelBuf;
			len = total;
			inChannelUse = 0;
		}

		logme(L_DEBUG, "@%ld:%ld handle %ld data", sockFd, c->getChannel(), len);
		int rest = c->handleData((char*) p, len);
		if (rest < 0) return false;

		// no data left
		if (rest == 0)
			return true;

		if (rest > 0) {
			p = p + len - rest;
			logme(L_FINE, "keeping partial channel data: inuse=%ld, len=%ld", inChannelUse, rest);
			if (rest > inChannelSize) {
				inChannelBuf = (char *)realloc(inChannelBuf, rest);
				inChannelSize = rest;
			}
			memcpy(inChannelBuf, p, rest);
			inChannelUse = rest;
			return true;
		}
	}
	return false;
}

bool SshSession::handleChannelRequest(uint8_t *p) {
	uint32_t channelNo = getInt32Aligned(p);
	p += 4;
	Channel * c = channels[channelNo];
	if (c) {
		uint8_t *s = sshString(p);
		*p = 0;
		logme(L_TRACE, "@%ld channel %ld %s", sockFd, channelNo, s);

		if (0 == strcmp((char*) s, "pty-req")) {
			if (!c->isSession()) {
				logme(L_ERROR, "@%ld pty requested but not a shell channel", sockFd);
				goto Error;
			}

			++p;
			sshString(p); // term = ...
			uint32_t numCols = getInt32(p); p+= 4;
			uint32_t numRows = getInt32(p);

			ShellChannel *sc = (ShellChannel*) c;
			sc->setPty(true);
			sc->setDimension(numCols, numRows);

			outdata[5] = SSH_MSG_CHANNEL_SUCCESS;
			putInt32Aligned((outdata + 6) , channelNo); // TODO Remote channelNo
			write(outdata + 5, 5);
			logme(L_TRACE, "@%ld sent SSH_MSG_CHANNEL_SUCCESS for pty", sockFd);
			return true;
		}

		bool isExec = 0 == strcmp((char*) s, "exec");
		if (0 == strcmp((char*) s, "shell") || isExec) {
			if (!c->isSession()) {
				logme(L_ERROR, "@%ld %s requested but not a session channel", sockFd, s);
				goto Error;
			}
			ShellChannel *sc = (ShellChannel*) c;
			if (sc->hasShell() || sc->hasExec()) {
				logme(L_ERROR, "@%ld %s requested but already has a shell/exec", sockFd);
				goto Error;
			}

			sc->setShell(!isExec);
			sc->setExec(isExec);
			outdata[5] = SSH_MSG_CHANNEL_SUCCESS;
			putInt32Aligned((outdata + 6) , channelNo); // TODO Remote channelNo
			write(outdata + 5, 5);
			logme(L_FINE, "@%ld sent SSH_MSG_CHANNEL_SUCCESS for %s", sockFd, isExec ? "shell" : "session");

			if (isExec) {
				++p;
				uint8_t *c = sshString(p);
				*p = 0;
				logme(L_DEBUG, "@%ld exec: `%s`", sockFd, c);
				sc->startCommand((char*) c);
			} else
				sc->prompt();

			return true;
		}

		if (0 == strcmp((char*) s, "subsystem")) {
			++p;
			uint8_t *sub = sshString(p);
			if (0 != strncmp((char*) s, "sftp", p - sub - 4)) {
				logme(L_ERROR, "@%ld %s unsupported subsystem %s", sockFd, sub);
				goto Error;
			}

			if (!c->isSession()) {
				logme(L_ERROR, "@%ld %s requested but not a session channel", sockFd, s);
				goto Error;
			}
			ShellChannel *sc = (ShellChannel*) c;
			if (sc->hasShell() || sc->hasExec()) {
				logme(L_ERROR, "@%ld %s requested but already has a shell/exec", sockFd);
				goto Error;
			}

			SftpChannel *sfc = new SftpChannel(c->getServer(), channelNo); // TODO Remote channelNo
			delete c;

			channels.replace(channelNo, sfc);

			outdata[5] = SSH_MSG_CHANNEL_SUCCESS;
			putInt32Aligned((outdata + 6) , channelNo); // TODO Remote channelNo
			write(outdata + 5, 5);
			logme(L_FINE, "@%ld sent SSH_MSG_CHANNEL_SUCCESS for subsystem sftp", sockFd);

			return true;
		}

		if (0 == strncmp((char*) s, "env", 3)) {
			// ignore
			return true;
		}

		if (0 == strncmp((char*) s, "window-change", 13)) {
			// ignore
			return true;
		}
	}

	Error:

	outdata[5] = SSH_MSG_CHANNEL_FAILURE;
	putInt32Aligned((outdata + 6) , channelNo); // TODO Remote channelNo
	write(outdata + 5, 5);
	logme(L_FINE, "@%ld sent SSH_MSG_CHANNEL_FAILURE", sockFd);
	return false;
}

bool SshSession::handleOpenChannel(uint8_t *p) {
	uint8_t *s = sshString(p);
	uint32_t channelNo = getInt32(p);
//	windowsize = getInt32(p + 4);
//	maxsize = getInt32(p + 8);

	windowsize = 0x7fffffff;
	maxsize = MAXPACKET < maxsize ? MAXPACKET : maxsize;

	int reason = 4; // resource shortage

	if (0 == strcmp((char*) s, "session")) {
		ShellChannel *sc = new ShellChannel(this, channelNo, C_SESSION);
		if (sc) {
			channels.add(channelNo, sc);

			sendOpenChannelConfirmation(sc, windowsize, maxsize);
			return true;
		}
	} else if (0 == strcmp((char*) s, "direct-tcpip")) {
		ForwardChannel *fc = new ForwardChannel(this, channelNo);
		if (fc) {
			p += 12;
			uint8_t *to = sshString(p);
			uint32_t toPort = getInt32(p);
			p += 4;
			uint8_t *src = sshString(p);
			uint32_t srcPort = getInt32(p);

			if (fc->init(src, srcPort, to, toPort)) {
				channels.add(channelNo, fc);
				auto * l = fc->getListener();
				listeners.add(l->getSockFd(), l);
				sendOpenChannelConfirmation(fc, windowsize, maxsize);
				return true;
			}

			reason = 2; // connect failed
			delete fc;
		}
	}

	outdata[5] = SSH_MSG_CHANNEL_OPEN_FAILURE;
	putInt32Aligned(&outdata[6] , channelNo);
	putInt32Aligned(&outdata[10] , reason); // resource
	putInt32Aligned(&outdata[14] , 0); // no description
	putInt32Aligned(&outdata[18] , 0); // no lang
	write(outdata + 5, 17);

	logme(L_FINE, "@%ld sent SSH_MSG_CHANNEL_OPEN_FAILURE for %s", sockFd, s);

	return false;
}

void SshSession::sendOpenChannelConfirmation(Channel *c, uint32_t windowsize, uint32_t maxsize) {
	outdata[5] = SSH_MSG_CHANNEL_OPEN_CONFIRMATION;
	putInt32Aligned(&outdata[6] , c->getChannel());
	putInt32Aligned(&outdata[10] , c->getChannel());
	putInt32Aligned(&outdata[14] , windowsize);
	putInt32Aligned(&outdata[18] , maxsize);
	write(outdata + 5, 17);
	logme(L_FINE, "@%ld sent SSH_MSG_CHANNEL_OPEN_CONFIRMATION for session, window=%ld, max=%ld", sockFd, windowsize, maxsize);
}

static bool authorizeKey(uint8_t *hostBase64, uint8_t *buffer) {
	extern char const * sshDotDir;
	static char const * authorized_keys;
	if (!authorized_keys) authorized_keys = concat(sshDotDir, "/authorized_keys", NULL);
	BPTR f = Open(authorized_keys, MODE_OLDFILE);
	if (!f)
		return false;

	bool r = false;
	while (!r) {
		char *p = (char*) buffer;
		if (!FGets(f, p, 256))
			break;

		// split
		while (*p && *p <= 32)
			++p;

		char *n = p;
		while (*p && *p > 32)
			++p;
		*p++ = 0;

		while (*p && *p <= 32)
			++p;
		char *c = p;

		while (*p && *p > 32)
			++p;
		*p++ = 0;

		r = 0 == strcmp(c, (char*) hostBase64);
	}
	Close(f);
	return r;
}

bool SshSession::handleUserAuthRequest(uint8_t *p) {
	uint8_t *p5 = p - 1;
	uint8_t *user = sshString(p);

	uint8_t *s = sshString(p);
	if (strcmp((char*) s, "ssh-connection"))
		return false;

	s = sshString(p);
	uint8_t auth = *p;
	*p = 0;
	if (0 == strcmp((char*) s, "password")) {
		++p;
		s = sshString(p);
		*p = 0;
		if (login(user, s)) {
			write(loginSuccess, sizeof(loginSuccess));
			logme(L_FINE, "@%ld sent SSH_MSG_USERAUTH_SUCCESS", sockFd);
			username = strdup((char *)user);
			return true;
		}
	} else if (0 == strcmp((char*) s, "publickey")) {
		*p++ = auth;
		uint8_t *blob = p;
		uint8_t *keyType = sshString(p);
		if (0 == strcmp((char*) keyType, "ssh-ed25519") && getInt32(p) == 0x33) {
			p += 4; // skip 0 0 0 0x33
			uint8_t *q = p;
			keyType = sshString(p);
			if (0 == strcmp((char*) keyType, "ssh-ed25519") && getInt32(p) == 0x20) {
				p += 4; // skip 0 0 0 0x20
				uint8_t *pk = p;
				mimeEncode(p + 200, q, 0x33);
				if (authorizeKey(p + 200, p + 300)) {
					if (auth) {
						// validate the signature
						p += 0x20;
						uint8_t *end = p;
						if (getInt32(p) == 0x53) {
							p += 4; // skip 0 0 0 0x53
							keyType = sshString(p);
							if (0 == strcmp((char*) keyType, "ssh-ed25519") && getInt32(p) == 0x40) {
								p += 4; // skip 0 0 0 0x40
								// we have a signature. create the message to verify
								uint8_t *m = p + 100;
								uint8_t *t = m;
								putAny(t, hash, 0x20);
								int len = end - p5;
								memcpy(t, p5, len);
								len += 36;
//								_dump("vfymsg", m, len);
								if (ge_verify_ed25519(m, len, p, pk)) {
									write(loginSuccess, sizeof(loginSuccess));
									logme(L_FINE, "@%ld sent SSH_MSG_USERAUTH_SUCCESS", sockFd);
									username = strdup((char *)user);
									return true;
								}
							}
						}
					} else {
						outdata[5] = SSH_MSG_USERAUTH_PK_OK;
						memcpy(&outdata[6], blob, 70);

						write(outdata + 5, 71);
						logme(L_FINE, "@%ld sent SSH_MSG_USERAUTH_PK_OK", sockFd);
						username = strdup((char *)user);
						return true;
					}
				}
			}
		}
		logme(L_DEBUG, "@%ld declined key %s", sockFd, keyType);
	} else if (0 == strcmp((char*) s, "publickey-hostbound-v00@openssh.com")) {
		++p;
		uint8_t *keyType = sshString(p);
		logme(L_DEBUG, "@%ld authorizing key %s", sockFd, keyType);

	}
	write(passwordAuth, sizeof(passwordAuth));
	logme(L_FINE, "@%ld sent SSH_MSG_USERAUTH_FAILURE", sockFd);

	return false;
}

void SshSession::handleServiceRequest(uint8_t *p) {
	uint8_t *s = sshString(p);
	if (0 == strncmp((char*) s, "ssh-userauth", 12)) {
		write(serviceAccept, sizeof(serviceAccept));
		logme(L_FINE, "@%ld sent SSH_MSG_SERVICE_ACCEPT", sockFd);
	}
}

int SshSession::decryptPacket(uint8_t *p, unsigned len) {
	readAead->init(keyMat.encIvRead, 12);

	if (readCounterBc) {
		readAead->updateHash(p, 4 + len);
	} else {
		readAead->updateHash(p, 4);
	}
	p += 4;
	readAead->decrypt(p, p, len);

	unsigned pad1 = *p + 1;
	if (pad1 >= len) {
		logme(L_ERROR, "@%ld invalid pad length received", sockFd);
		return 0;
	}

	uint8_t check[16];
	readAead->calcHash(check);
	if (0 != memcmp(check, p + len, 16)) {
		logme(L_ERROR, "@%ld packet signature mismatch", sockFd);
		return 0;
	}

	increment(keyMat.encIvRead);

	len -= pad1;
	if (isLogLevel(L_TRACE))
		_dump("received decrypted", p, len > 512 ? 512 : len);
	return len;
}

void SshSession::createKexEcdhReply() {
	struct timeval startTime;
	gettimeofday(&startTime, nullptr);

	uint8_t *start = (uint8_t*) outdata + 5;
	uint8_t *p = start;

	// host public key
	memcpy(p, kex_reply, sizeof(kex_reply));
	p += sizeof(kex_reply);
	memcpy(p, hostPK, 32);

	// add host digest
	handshakeMD.update(start + 1, sizeof(kex_reply) - 1 + 32);
	HSU(start, 1, sizeof(kex_reply) - 1 + 32);
	p += 32;

	fe_new_key_pair(serverPK_aka_F, serverSK);
	memcpy(p, key_len, 4);
	p += 4;
	memcpy(p, serverPK_aka_F, 32);
	p += 32;

	handshakeMD.update(key_len, 4);
	HSU(key_len, 0, 4);
	handshakeMD.update(clientPK_aka_E, 32);
	HSU(clientPK_aka_E, 0, 32);

	handshakeMD.update(key_len, 4);
	HSU(key_len, 0, 4);
	handshakeMD.update(serverPK_aka_F, 32);
	HSU(serverPK_aka_F, 0, 32);

	fe_scalarmult_x25519(sharedSecret_aka_K.data, serverSK, clientPK_aka_E);
	if ((int8_t) sharedSecret_aka_K.data[0] < 0) {
		sharedSecret_aka_K.size = 33;
		memmove(&sharedSecret_aka_K.data[1], &sharedSecret_aka_K.data[0], 32);
		sharedSecret_aka_K.data[0] = 0;
	} else {
		sharedSecret_aka_K.size = 32;
	}
#ifdef __AMIGA__
	handshakeMD.update(&sharedSecret_aka_K, sharedSecret_aka_K.size + 4);
	HSU(&sharedSecret_aka_K, 0, sharedSecret_aka_K.size + 4);
#else
	uint32_t len_be = htonl(sharedSecret_aka_K.size);
	handshakeMD.update(&len_be, 4);
	handshakeMD.update(&sharedSecret_aka_K.data, sharedSecret_aka_K.size);
	HSU(&len_be, 0, 4);
	HSU(&sharedSecret_aka_K.data, 0, sharedSecret_aka_K.size);
#endif
	if (isLogLevel(L_TRACE))
		_dump("shared secret", &sharedSecret_aka_K, sharedSecret_aka_K.size + 4);

#if defined(DUMP_HASH)
	_dump("hashdata", hsd, hsdp - hsd);
#endif

	handshakeMD.digest(hash);

	ge_sign_ed25519(signedMessage, hash, 32, hostSK);
	memcpy(p, kex_reply2, sizeof(kex_reply2));
	p += sizeof(kex_reply2);
	memcpy(p, signedMessage, 64);
	p += 64;

	int len = p - start;
	int padLen = 11 - ((len) & (7));
	outdata[4] = padLen;
	memset(p, 0, padLen);
	len += 1 + padLen;
	putInt32Aligned((uint8_t*)outdata, len);
	if (isLogLevel(L_TRACE))
		_dump("kexreply", outdata, len + 4);

	timing_protection(&startTime);
}

#if BEBBOSSH_POSIX_SHELL
int SshSession::getHandle() const {
	int sz = channels.getMax();
	for (int i = 0; i < sz; ++i) {
		auto c = channels[i];
		if (c && !c->isForward()) {
			ShellChannel * sc = (ShellChannel *)c;
			return sc->getHandle();
		}
	}
	return 0;
}

int SshSession::readHandle() {
	int sz = channels.getMax();
	for (int i = 0; i < sz; ++i) {
		auto c = channels[i];
		if (c && !c->isForward()) {
			ShellChannel * sc = (ShellChannel *)c;
			return sc->handleRead();
		}
	}
	return 0;
}

#endif
