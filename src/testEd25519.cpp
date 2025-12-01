/* bebbossh - Ed25519 test vectors
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
 * Purpose: Validate Ed25519 implementation with signing, verification, and reduction tests
 *
 * Features:
 *  - Generate Ed25519 key pairs
 *  - Sign and verify messages using Ed25519
 *  - Test SHA512-based reduction and conversion routines
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing.
 *  - Designed for AmigaOS; uses assertArrayEquals for validation.
 *
 * Author's intent:
 *  Provide reproducible unit tests to guarantee Ed25519 correctness
 *  and auditability across platforms.
 * ----------------------------------------------------------------------
 */
#ifdef __AMIGA__
#include <proto/dos.h>
#include <amistdio.h>
#else
#include <stdio.h>
#endif
#include <stdint.h>
#include <string.h>

#include "test.h"
#include "ed25519.h"
#include "ed25519i.h"
#include "sha512.h"
#include "unhexlify.h"

void trash() {
	char x[2048];
	randfill(x, sizeof(x));
}

bool testEd25519() {
	trash();
	puts("testEd25519");
	uint8_t pk[32], sk[64];
	uint8_t sm[64];
	uint8_t m[] = "Message for Ed25519 signing";
	unsigned mlen = strlen((char*)m);

	ge_new_keypair_ed25519(pk, sk);

//	unhexlify(sk,
//	"67 C7 6B 76 55 04 50 F3  31 D6 C4 B6 FE 08 F1 55 "
//	"8C D3 66 0B 2F FD FD A4  8E 73 48 7E 4F BC E7 B9 "
//	"75 84 1C 08 8A 2F 99 F3  0B F2 46 CB 7E 06 76 D2 "
//	"B9 47 17 7D D9 14 C5 A5  54 9B 56 CF 50 3A 16 D7 ");
//
//	unhexlify(pk,
//	"75 84 1C 08 8A 2F 99 F3  0B F2 46 CB 7E 06 76 D2 "
//	"B9 47 17 7D D9 14 C5 A5  54 9B 56 CF 50 3A 16 D7 ");

	ge_sign_ed25519(sm, m, mlen, sk);

	if (!ge_verify_ed25519(m, mlen, sm, pk)) {
		puts("ge_verify_ed25519 failed");
		_dump("sk", sk, 64);
		_dump("pk", pk, 32);
		_dump("message", m, mlen);
		_dump("signed", sm, 64);
		return false;
	}

	return true;
}

bool testReduction() {
	puts("testReduction");
	static uint8_t x[32];
	unhexlify(x, "C7 FA 1E F7 56 DC 04 1A  F4 AB 84 7C 44 DC E3 95 13 10 0D A7 70 BE 16 83  2F 29 ED 3C 48 51 75 05");
	uint8_t d[64];
	uint16_t t[32];
	uint8_t r[32];
	SHA512 sha;
	sha.update("abcxyz", 6);
	sha.digest(d);
	ed25519_from64bytes(t, d);
	for (short i = 0; i < 32; ++i)
		r[i] = t[i];

	return assertArrayEquals(x, r, 32);
}

int testEd25519_vectors(void) {
	trash();
    // message (32 bytes)
    uint8_t m[32] = {
        0x12,0x37,0x09,0xD2,0x65,0x51,0xF9,0xA0,
        0x27,0x36,0xF8,0x65,0x4D,0xCB,0xC5,0x37,
        0xD5,0x1B,0xD1,0xF4,0x1B,0x64,0x97,0xD9,
        0xA2,0xF5,0xF4,0xF2,0xD7,0x1E,0xB4,0x6E
    };

    // signature (sm, 64 bytes)
    uint8_t sm[64] = {
        0x50,0x59,0x80,0xD5,0xE9,0x5B,0x71,0x80,
        0x6F,0xC9,0x89,0x0A,0xC8,0x5F,0x17,0xD2,
        0x9E,0x78,0x2A,0xE5,0x61,0x32,0xED,0x79,
        0x23,0x8B,0xE5,0x1B,0x60,0xE0,0xFA,0x6D,
        0xAC,0xF4,0x48,0xE9,0x79,0xC7,0x82,0x77,
        0xE5,0x6B,0x39,0x6F,0x43,0xCF,0x44,0x88,
        0xA1,0x4A,0x1F,0x98,0x62,0xD9,0x5F,0xA9,
        0x45,0x72,0x22,0x28,0x6F,0xE7,0x69,0x09
    };

    // public key (pk, 32 bytes)
    uint8_t pk[32] = {
        0xAB,0x2F,0x1B,0x66,0x1F,0x16,0xE0,0x23,
        0x0B,0x82,0xEE,0xF4,0x43,0xE5,0xD8,0x33,
        0x96,0x46,0x88,0x78,0xD5,0x20,0xA9,0x30,
        0x00,0xD7,0x61,0xEF,0x2C,0x51,0x5B,0x73
    };

    int ok = ge_verify_ed25519(m, sizeof(m), sm, pk);
    printf("ge_verify_ed25519 returned %d\n", ok);
    if (ok == 1) {
        printf("Signature verified successfully.\n");
    } else {
        printf("Signature verification failed.\n");
		_dump("message", m, sizeof(m));
		_dump("signed", sm, 64);
		_dump("pk", pk, 32);
    }
    return ok;
}

int testEd25519_vectors2(void) {

	trash();

    // NOTE: In ge_verify_ed25519, the first argument is the ORIGINAL MESSAGE (M).
    // Since the original message is unknown, we substitute the 32-byte hash (H(M))
    // that was involved in the failing verification, knowing this will likely
    // not verify correctly unless the library's internal hash function is skipped.

    // Original Message (m, 32 bytes) <-- Filled with the provided HASH
    uint8_t m[32] = {
        0xF9,0x12,0x0E,0x11,0xAD,0x6B,0x8E,0x38,
        0x1F,0xAC,0xD5,0x07,0x74,0x11,0x16,0xE9,
        0x17,0x4C,0x70,0x26,0xAD,0x25,0x18,0xE0,
        0x1C,0xF8,0x02,0x3F,0x8C,0x49,0x75,0x66
    };

    // Signature (sm, 64 bytes) <-- Filled with the provided 'p'
    uint8_t sm[64] = {
        0xCB,0x6F,0x0A,0x84,0x5A,0x30,0x83,0x3B,
        0x7D,0x2D,0x27,0x42,0xBF,0xFB,0x96,0x99,
        0x6E,0x55,0x46,0x08,0x6D,0x2A,0x5E,0xCC,
        0xF7,0x12,0x04,0x1E,0xCF,0x8F,0xAC,0x2C,
        0x9B,0xB8,0x4C,0x5A,0x34,0x74,0x79,0x46,
        0xF8,0x21,0x7D,0xD4,0x2A,0x90,0x2F,0x51,
        0xB7,0xEF,0x07,0xE3,0x02,0xC8,0xED,0xDD,
        0x08,0xA5,0x31,0x80,0x43,0xD7,0x04,0x0A
    };

    // Public Key (pk, 32 bytes) <-- Filled with the provided 'hpk'
    uint8_t pk[32] = {
        0x43,0xCA,0xE6,0x46,0x74,0x8B,0xB8,0xC3,
        0xB6,0x30,0x40,0x8A,0x19,0xD5,0x3B,0xEC,
        0x78,0x9E,0xF1,0xA5,0x9F,0xB2,0x6F,0x27,
        0x0B,0xEE,0x6E,0xD5,0xC0,0x57,0x15,0x85
    };

    int ok = ge_verify_ed25519(m, sizeof(m), sm, pk);
    printf("ge_verify_ed25519 returned %d\n", ok);
    if (ok == 1) {
        printf("Signature verified successfully.\n");
    } else {
        printf("Signature verification failed.\n");
		_dump("message", m, sizeof(m));
		_dump("signed", sm, 64);
		_dump("pk", pk, 32);
    }
    return ok;
}

int testEd25519_vectors3(void) {
	trash();
	puts("testEd25519");
	uint8_t pk[32], sk[64];
	uint8_t sm[64];
	uint8_t m[] = "Message for Ed25519 signing";
	unsigned mlen = strlen((char*)m);

//	ge_new_keypair_ed25519(pk, sk);

	unhexlify(sk,
			"46 D0 40 E8 FB 47 37 61  39 9F 64 23 73 4C DC 9E"
			"7B F3 34 CB 70 F2 53 B0  56 29 F5 1E 55 58 0B 05"
			"61 4A AC 88 E4 48 A1 18  81 2C 68 66 98 CF 14 D7"
			"FE E7 0F E1 5D 72 FF 92  A6 F4 81 5A 2F AC 41 6E"
			);

	unhexlify(pk,
			"61 4A AC 88 E4 48 A1 18  81 2C 68 66 98 CF 14 D7"
			"FE E7 0F E1 5D 72 FF 92  A6 F4 81 5A 2F AC 41 6E"
			);

	ge_sign_ed25519(sm, m, mlen, sk);


	if (!ge_verify_ed25519(m, mlen, sm, pk)) {
		puts("ge_verify_ed25519 failed");
		_dump("sk", sk, 64);
		_dump("pk", pk, 32);
		_dump("message", m, mlen);
		_dump("signed", sm, 64);
		return false;
	}

	return true;
}


int main() {
	return
//			testEd25519_vectors2() &&
            testEd25519_vectors() &&
//			testEd25519() &&
			testEd25519_vectors3() &&
//			testReduction() &&
			1 ? 0 : 10;
}
