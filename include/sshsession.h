/*
 * AmigaSSH - SSH session core implementation
 *
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
 * Project: AmigaSSH - SSH2 client/server suite for Amiga
 * Purpose: Define the SshSession class for managing SSH connection state,
 *          encryption, and channel lifecycle
 *
 * Features:
 *  - State machine for SSH handshake, authentication, and session phases
 *  - Integration with AES-GCM and ChaCha20-Poly1305 AEAD ciphers
 *  - Buffer management for incoming and outgoing packet data
 *  - Channel management including open, close, and data handling
 *  - Support for key exchange, authentication, and service requests
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing.
 *  - Designed for AmigaOS with explicit resource management and protocol compliance.
 *
 * Author's intent:
 *  Provide a clear, maintainable SSH session implementation to support
 *  secure communication and channel operations on Amiga systems.
 * ----------------------------------------------------------------------
 */
#ifndef SSHSESSION_H_
#define SSHSESSION_H_

#include <aes.h>
#include <gcm.h>
#include <chacha20poly1305.h>
#include "platform.h"
#include "sha256.h"
#include "ssh.h"

enum SshState {
	HELLO, KEX_INIT, KEX_ECDH_INIT, NEW_KEYS, AUTH, LOGGEDIN
};

class Channel;
class ShellChannel;
struct MsgPort;

#include <stack.h>

struct SshSession : public Listener {
	char name[16];
	SshState state;
	struct KeyMaterial keyMat;

	union {
		struct { // this is only needed during handshake, keel it later
			uint8_t clientPK_aka_E[32];
			uint8_t serverPK_aka_F[32];
			uint8_t serverSK[64];
			uint8_t hash[32];
			uint8_t signedMessage[64];
			struct SharedSecret sharedSecret_aka_K;
		};
	};

	uint32_t windowsize;
	uint32_t maxsize;

	char * inpos;                // position into indata
	char indatax[CHUNKSIZE * 2]; // incoming packet data * 2 for buffering
	char outdata[CHUNKSIZE * 2]; // outgoing packet data

	AeadBlockCipher * readAead;
	BlockCipher * readBc;
	ChaCha20 * readCounterBc;
	AeadBlockCipher * writeAead;
	BlockCipher * writeBc;
	ChaCha20 * writeCounterBc;

	SHA256 handshakeMD;
	Stack<Channel> channels;

	int inChannelUse;
	int inChannelSize;
	char * inChannelBuf;

	uint32_t kexLen;

	char * username;

	SshSession(int _sock);
	virtual ~SshSession();

	int setupEncryption(char *indata);

	void start();
	void close();

	int write(void const * data, int len);
	int processSocketData(void * data, int len);
	int consumeSocketData(char * data, int len);

	inline int remainingBufferSize() const {
		int r;
		r = sizeof(indatax) - (inpos - indatax);
		return r;
	}

	inline int getMaxSize() const {
		return windowsize < maxsize ? windowsize : maxsize;
	}

	void abort();
	void checkTimeout(struct timeval * tv);
	void sendBreak() const;
	void checkFinished();
	bool isAlive() const;
	ShellChannel * findShellChannelByBreakPort(struct MsgPort * mp) const;
	int channelWrite(uint32_t channel, void const * data, int len);
	void closeChannel(Channel * channel);

	void createKexEcdhReply();

	void sendOpenChannelConfirmation(Channel * c, uint32_t windowsize, uint32_t maxsize);

	int decryptPacket(uint8_t * p, unsigned len);
	void handleServiceRequest(uint8_t * p);
	bool handleUserAuthRequest(uint8_t * p);
	bool handleOpenChannel(uint8_t * p);
	bool handleChannelRequest(uint8_t * p);
	bool handleChannelData(uint8_t * p, int len);
	bool handleChannelEof(uint8_t * p);
	bool login(uint8_t * user, uint8_t * pass);

	virtual bool isBufferFree() const {
		return remainingBufferSize() > CHUNKSIZE;
	}

	virtual void noop();

	char const * getUser() const { return username; }

#if BEBBOSSH_POSIX_SHELL
	int getHandle() const;
	int readHandle();
#endif
};



#endif /* SSHSESSION_H_ */
