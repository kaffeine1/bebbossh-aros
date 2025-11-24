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
#include <proto/dos.h>
#include <amistdio.h>
#include <stdint.h>
#include <string.h>

#include "test.h"
#include "ed25519.h"
#include "ed25519i.h"
#include "sha512.h"
#include "unhexlify.h"

bool testEd25519() {
	puts("testEd25519");
	uint8_t pk[32], sk[64];
	uint8_t sm[64];
	uint8_t m[] = "Message for Ed25519 signing";
	unsigned mlen = strlen((char*)m);

	ge_new_keypair_ed25519(pk, sk);

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

int main() {
	return  testEd25519() &&
			testReduction() ? 0 : 10;
}
