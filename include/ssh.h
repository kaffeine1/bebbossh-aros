/*
 * AmigaSSH - Core SSH protocol definitions
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
 * Purpose: Define SSH protocol constants, message codes, and utility functions
 *
 * Features:
 *  - SSH message type definitions for connection, authentication, and channel operations
 *  - Utility functions for encoding/decoding integers and strings
 *  - Structures for shared secrets and key material used in key exchange
 *  - External function prototypes for key derivation, encryption, and session handling
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing.
 *  - Designed for AmigaOS with explicit resource management and protocol compliance.
 *
 * Author's intent:
 *  Provide a clear, maintainable set of SSH protocol definitions
 *  to support secure communication and interoperability across platforms.
 * ----------------------------------------------------------------------
 */
#ifndef __SSH_H__
#define __SSH_H__

#include <stdint.h>
#include <string.h>

#define CHUNKSIZE (35000)
#define MAXPACKET 32768

#define D_S(type,name) char a_##name[sizeof(type)+3]; \
  type *name = (type *)((ULONG)(a_##name+3) & ~3UL)

#define SSH_MSG_DISCONNECT         1
#define SSH_MSG_DEBUG              4
#define SSH_MSG_SERVICE_REQUEST    5
#define SSH_MSG_SERVICE_ACCEPT     6
#define SSH_MSG_KEX_INIT          20
#define SSH_MSG_NEWKEYS           21
#define SSH_MSG_KEX_ECDH_INIT     30
#define SSH_MSG_KEX_ECDH_REPLY    31
#define SSH_MSG_USERAUTH_REQUEST  50
#define SSH_MSG_USERAUTH_FAILURE  51
#define SSH_MSG_USERAUTH_SUCCESS  52
#define SSH_MSG_USERAUTH_BANNER   53
#define SSH_MSG_USERAUTH_PK_OK    60

#define SSH_MSG_GLOBAL_REQUEST                  80
#define SSH_MSG_REQUEST_SUCCESS                 81
#define SSH_MSG_REQUEST_FAILURE                 82

#define SSH_MSG_CHANNEL_OPEN                    90
#define SSH_MSG_CHANNEL_OPEN_CONFIRMATION       91
#define SSH_MSG_CHANNEL_OPEN_FAILURE            92
#define SSH_MSG_CHANNEL_WINDOW_ADJUST           93
#define SSH_MSG_CHANNEL_DATA                    94
#define SSH_MSG_CHANNEL_EXTENDED_DATA           95
#define SSH_MSG_CHANNEL_EOF                     96
#define SSH_MSG_CHANNEL_CLOSE                   97
#define SSH_MSG_CHANNEL_REQUEST                 98
#define SSH_MSG_CHANNEL_SUCCESS                 99
#define SSH_MSG_CHANNEL_FAILURE                100

uint8_t * sshString(uint8_t * &p);

static inline uint32_t getInt32Aligned(uint8_t * p) {
#if (BYTE_ORDER == BIG_ENDIAN)
	return *(uint32_t*)p;
#else
	return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
#endif
}
static inline uint32_t getInt32Aligned(char * p) {
	return getInt32Aligned((uint8_t*)p);
}

static inline uint32_t getInt32(uint8_t * p) {
#if defined (__mc68020__)
	return getInt32Aligned(p);
#else
	return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
#endif
}
static inline uint32_t getInt32(char * p) {
	return getInt32((uint8_t*)p);
}

static inline void putInt32AndInc(uint8_t * &p, uint32_t l) {
#if defined (__mc68000__) || (BYTE_ORDER == LITTLE_ENDIAN)
	*p++ = l >> 24;
	*p++ = l >> 16;
	*p++ = l >> 8;
	*p++ = l;
#else
	*(uint32_t *)p = l;
	p += 4;
#endif
}

static inline void putInt32Aligned(uint8_t * p, uint32_t l) {
#if (BYTE_ORDER == LITTLE_ENDIAN)
	*p++ = l >> 24;
	*p++ = l >> 16;
	*p++ = l >> 8;
	*p++ = l;
#else
	*(uint32_t *)p = l;
#endif
}
static inline void putInt32Aligned(char * p, uint32_t l) {
	putInt32Aligned((uint8_t*)p, l);
}

void putString(uint8_t * &p, char const * s);

static void putAny(uint8_t * &p, void const * s, int slen) {
	putInt32AndInc(p, slen);
	memcpy(p, s, slen);
	p += slen;
}

struct SharedSecret {
	uint32_t size;
	uint8_t data[33];
};

struct KeyMaterial {
	uint8_t encIvWrite[12];
	uint8_t encIvRead[12];
	uint8_t encKeyWrite[64];
	uint8_t encKeyRead[64];
	uint16_t ivLen;
	uint16_t keyLen;
};

extern void deriveKeys(KeyMaterial * kd, SharedSecret * sharedSecret, uint8_t * hash, bool server);

extern "C" bool loadEd25519Key(uint8_t * pk, uint8_t * sk, char const * keyfilename);

extern bool sendEncrypted(uint8_t const *data, int len);

extern bool mysend(int fd, void const *data, int len);

extern char * splitLine(char * & s);

extern int fillKexInit(uint8_t * p, char const * encOrder);

#endif // __SSH_H__
