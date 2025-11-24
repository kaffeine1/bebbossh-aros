/*
 * bebbossh - key derivation and KEXINIT
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
 * Purpose: Derive encryption keys and construct KEXINIT packets
 *
 * Features:
 *  - SHA256-based key derivation for IVs and keys
 *  - Support for AES-GCM and ChaCha20-Poly1305 ciphers
 *  - Build SSH_MSG_KEX_INIT with configurable cipher order
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing.
 *  - Designed for AmigaOS; explicit buffer handling and logging included.
 *
 * Author's intent:
 *  Provide secure, maintainable key derivation and negotiation routines
 *  for SSH2 connections on classic Amiga systems.
 * ----------------------------------------------------------------------
 */
#include <string.h>
#include <stdlib.h>

#include <ssh.h>
#include <sha256.h>
#include <test.h>
#include <rand.h>
#include <log.h>

char const * const AES128 = "aes128-gcm@openssh.com";
char const * const CHACHA20 = "chacha20-poly1305@openssh.com";


uint8_t * sshString(uint8_t * &p) {
	uint32_t len = getInt32(p);
	p += 4;
	uint8_t * r = p;
	p += len;
	return r;
}

static void mkKey(uint8_t * buffer, SHA256 &sha256, SharedSecret * sharedSecret, uint8_t * hash, uint8_t c) {
	sha256.update(sharedSecret, sharedSecret->size + 4);
	sha256.update(hash, 32);
	sha256.update(&c, 1);
	sha256.update(hash, 32); // sessionId
	sha256.digest(buffer);

	sha256.update(sharedSecret, sharedSecret->size + 4);
	sha256.update(hash, 32); // hash
	sha256.update(buffer, 32); // last result
	sha256.digest(buffer + 32);
//	_dump("key", buffer, 64);
}
/**
 * Create the 4 keys, enough for GCM
 */
void deriveKeys(KeyMaterial * kd, SharedSecret * sharedSecret, uint8_t * hash, bool server) {
	SHA256 sha256;
	uint8_t buffer[64];
	mkKey(buffer, sha256, sharedSecret, hash, server ? 'A' : 'B');
	memcpy(kd->encIvWrite, buffer, kd->ivLen);
	mkKey(buffer, sha256, sharedSecret, hash, server ? 'B' : 'A');
	memcpy(kd->encIvRead, buffer, kd->ivLen);
	mkKey(buffer, sha256, sharedSecret, hash, server ? 'C' : 'D');
	memcpy(kd->encKeyWrite, buffer, kd->keyLen);
	mkKey(buffer, sha256, sharedSecret, hash, server ? 'D' : 'C');
	memcpy(kd->encKeyRead, buffer, kd->keyLen);

//	_dump("encIvWrite", kd->encIvWrite, kd->ivLen);
//	_dump("encIvRead", kd->encIvRead, kd->ivLen);
//	_dump("encKeyWrite", kd->encKeyWrite, kd->keyLen);
//	_dump("encKeyRead", kd->encKeyRead, kd->keyLen);
}

int fillKexInit(uint8_t * p, char const * encOrder) {
	uint8_t * const start = p;
	p += 5;
	*p ++ = SSH_MSG_KEX_INIT;
	// compute it before connecting,
	randfill(p, 16); p += 16;

	putString(p, "curve25519-sha256,curve25519-sha256@libssh.org");
	putString(p, "ssh-ed25519");

	char * enc = 0;
	for (char const * c = encOrder; *c; ++c) {
		char const * t;
		if (*c == '1')
			t = AES128;
		else if (*c == '2')
			t = CHACHA20;
		else {
			logme(L_ERROR, "invalid encryption order %s", encOrder);
			return 0;
		}
		if (enc) {
			char * c = concat(enc, ",", t, 0);
			free(enc);
			enc = c;
		} else {
			enc = concat(t, 0);
		}
	}

	logme(L_DEBUG, "encryption ciphers: %s", enc);

	putString(p, enc);  // order matters
	putString(p, enc);  // find the first matching in the server response
	putString(p, "hmac-sha2-256");
	putString(p, "hmac-sha2-256");
	putString(p, "none");
	putString(p, "none");
	putString(p, "");
	putString(p, "");
	*p++ = 0;
	putString(p, "");

	int lenUnpadded = p - start;
	int pad = 16 - (lenUnpadded & 0x7);
	start[4] = pad;
	for (int i = 1; i <= pad; ++i) {
		*p++ = i;
	}

	int len = p - start;
	*(uint32_t*)start = len - 4;

//	_dump("kex_init", start, len);

	return len;
}
