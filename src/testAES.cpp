/*
 * crypto AES / GCM test harness
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
 * Project: crypto
 * Module: AES/GCM test
 *
 * Purpose:
 *  - Provide unit tests for AES-128, AES-256, and AES-GCM implementations
 *  - Verify correctness of encryption, decryption, and authentication
 *  - Serve as regression tests for cryptographic routines
 *
 * Notes:
 *  - Uses known test vectors for AES and GCM
 *  - Returns 0 on success, 10 on failure
 *  - Designed for Amiga and cross-platform builds
 *  - Contributions must preserve author attribution and GPL licensing
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
#include "aes.h"
#include "gcm.h"
#include "unhexlify.h"

int testAES128() {
	puts("testAES128");
	AES aes(16);

	uint8_t key[16];
	unhexlify(key, "00112233445566778899aabbccddeeff");

	uint8_t iv[16];
	unhexlify(iv, "00000000000000000000000000000000");

	aes.setKey(key, 16);

	uint8_t in[16];
	unhexlify(in, "00112233445566778899aabbccddeeff");

	uint8_t enc[16];
	aes.encryptCBC(iv, enc, in, 16);
	
	unhexlify(iv, "00000000000000000000000000000000");
	uint8_t d[16];
	aes.decryptCBC(iv, d, enc, 16);

	uint8_t expected [16];
	unhexlify(expected, "00112233445566778899aabbccddeeff");

	return assertArrayEquals(expected, d, 16);
}

int testAES256() {
	puts("testAES256");
	AES aes(32);
	
	uint8_t key[32];
	unhexlify(key, "2b7e151628aed2a6abf7158809cf4f3c 2b7e151628aed2a6abf7158809cf4f3c"); // 256 bit key
		
	aes.setKey(key, 32);
		
	uint8_t in[16];
	unhexlify(in, "6bc1bee22e409f96e93d7e117393172a");
	
	uint8_t expected [16];
	unhexlify(expected, "3A A6 CB DA 29 58 0B B9  2A D9 ED 0D D4 EF 04 EB");
		
	uint8_t enc[16];
	aes.encrypt(enc, in);
	
	return assertArrayEquals(expected, enc, 16);
}

int testAESGCM() {
	puts("testAESGCM");

	// key
	uint8_t key[32];
	unhexlify(key,
			"46 6c 11 a8 5f 9b 07 92"
			"81 9a 5a 9d e1 8d b4 1e"
			"15 f9 44 67 87 24 6c 52"
			"63 12 30 43 2d 8b fb 04");
	// in plaintext
	uint8_t plain[16];
	unhexlify(plain,
	"14 00 00 0c  3b 77 0f a7  "
	"08 32 02 1d  8c 0d 05 dc  ");
	// aad
	uint8_t aad[13];
	unhexlify(aad,
	"00 00 00 00 00 00 00 00 "
	"16 03 03 00 10");
	// nonce secret + nonce public (from out)
	uint8_t nonce[12];
	unhexlify(nonce,
	"fd 58 07 37 0e 42 fc 3f "
	"ae f9 ac 29 ");

	// out expected
	// "0e 42 fc 3f ae f9 ac 29 "
	uint8_t outex[16];
	unhexlify(outex,
	"04 39 78 c6 00 54 42 06 "
	"dd 45 73 ef a0 7f 68 f8");
	// hash expected
	uint8_t hashex[16];
	unhexlify(hashex,
	"fc 3f 82 13 bb 45 ca 41 "
	"df 60 e4 3f cb b1 fb 56");


	GCM gcm(new AES(32));
	gcm.setKey(key, sizeof(key));

	gcm.init(nonce, sizeof(nonce));
	gcm.updateHash(aad, sizeof(aad));

	uint8_t cipher[16];
	gcm.encrypt(cipher, plain, sizeof(plain));
	uint8_t hash[16];
	gcm.calcHash(hash);

	return assertArrayEquals(outex, cipher, sizeof(outex)) &
			assertArrayEquals(hashex, hash, sizeof(hashex));
}

int main() {
	return  testAES128() &
			testAES256() &
			testAESGCM()
			? 0 : 10;
}
