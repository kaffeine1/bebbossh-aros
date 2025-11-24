/* bebbossh - ChaCha20 test vectors
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
 * Purpose: Validate ChaCha20 implementation against known test vectors
 *
 * Features:
 *  - Initialize ChaCha20 with specific keys and nonces
 *  - Generate keystream blocks and compare with expected outputs
 *  - Ensure correctness of counter handling and stream generation
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing.
 *  - Designed for AmigaOS; uses assertArrayEquals for validation.
 *
 * Author's intent:
 *  Provide reproducible unit tests to guarantee ChaCha20 correctness
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
#include "unhexlify.h"

#include <ssh.h>
#include <sha256.h>
#include <chacha20poly1305.h>
#include <fastmath.h>

int testChaCha20() {
	puts("testChaCha20");

	uint8_t key[32];
	unhexlify(key, "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:"
			"10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f");

	uint8_t nonce[12];
	unhexlify(nonce, "00:00:00:00:00:00:00:4a:00:00:00:00");

	ChaCha20 cc;
	cc.setKey(key, sizeof(key));
	cc.setNonce(nonce, sizeof(nonce));

	cc.nextBlock();

	uint8_t block1[64];
	unhexlify(block1, "22 4F 51 F3 40 1B D9 E1  2F DE 27 6F B8 63 1D ED"
			"8C 13 1F 82 3D 2C 06 E2  7E 4F CA EC 9E F3 CF 78"
			"8A 3B 0A A3 72 60 0A 92  B5 79 74 CD ED 2B 93 34"
			"79 4C BA 40 C6 3E 34 CD  EA 21 2C 4C F0 7D 41 B7");

	int r = assertArrayEquals(block1, cc.getStream(), 64);

	cc.nextBlock();
	uint8_t block2[64];
	unhexlify(block2, "69 A6 74 9F 3F 63 0F 41  22 CA FE 28 EC 4D C4 7E"
			"26 D4 34 6D 70 B9 8C 73  F3 E9 C5 3A C4 0C 59 45"
			"39 8B 6E DA 1A 83 2C 89  C1 67 EA CD 90 1D 7E 2B"
			"F3 63 74 03 73 20 1A A1  88 FB BC E8 39 91 C4 ED");

	r &= assertArrayEquals(block2, cc.getStream(), 64);

	memset(key, 0, sizeof(key));
	memset(nonce, 0, sizeof(nonce));
	cc.setKey(key, sizeof(key));
	cc.setNonce(nonce, sizeof(nonce));
	cc.nextBlock();
	uint8_t test1[64];
	unhexlify(test1,	"9F 07 E7 BE 55 51 38 7A  98 BA 97 7C 73 2D 08 0D "
			"CB 0F 29 A0 48 E3 65 69  12 C6 53 3E 32 EE 7A ED"
			"29 B7 21 76 9C E6 4E 43  D5 71 33 B0 74 D8 39 D5 "
			"31 ED 1F 28 51 0A FB 45  AC E1 0A 1F 4B 79 4D 6F");
	r &= assertArrayEquals(test1, cc.getStream(), 64);



	uint8_t key1[32];
	unhexlify(key1,
			"80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f"
			"90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f");
	uint8_t nonce1[12] = { 0x07, 0, 0, 0,
			0x40, 0x41, 0x42, 0x43,
			0x44, 0x45, 0x46, 0x47,
	};
	cc.setKey(key1, sizeof(key1));
	cc.setNonce(nonce1, sizeof(nonce1));
	cc.zeroCounter();
	cc.nextBlock();

	uint8_t exp1[32];
	unhexlify(exp1,
			"7b ac 2b 25 2d b4 47 af 09 b6 7a 55 a4 e9 55 84"
			"0a e1 d6 73 10 75 d9 eb 2a 93 75 78 3e d5 53 ff"
			);
	r &= assertArrayEquals(exp1, cc.getStream(), 32);

	return r;
}

int testPoly1305() {
	puts("testPoly1305");

//	uint8_t message[34];
//	/* Message to be Authenticated: */
//	unhexlify(message, "43 72 79 70 74 6f 67 72 61 70 68 69 63 20 46 6f"
//			"72 75 6d 20 52 65 73 65 61 72 63 68 20 47 72 6f"
//			"75 70");
//
//	uint8_t key[32];
//	unhexlify(key, "85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8"
//			"01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b");
//
//	Poly1305 poly;
//	poly.setKey(key, sizeof(key));
//	poly.update(message, sizeof(message));

	uint8_t res[16];

	// test 1
	uint8_t key1[32]; memset(key1, 0, sizeof(key1));
	uint8_t text1[64]; memset(text1, 0, sizeof(text1));
	uint8_t exp1[16]; memset(exp1, 0, sizeof(exp1));
	Poly1305 poly;
	poly.setKey(key1, sizeof(key1));
	poly.update(text1, sizeof(text1));
	poly.digest(res);

	int r = assertArrayEquals(exp1, res, 16);

	uint8_t key2[32];
	unhexlify(key2,
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
			"36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e"
			);
	uint8_t text2[368 + 7];
	unhexlify(text2,
			   "41 6e 79 20 73 75 62 6d 69 73 73 69 6f 6e 20 74 "
			   "6f 20 74 68 65 20 49 45 54 46 20 69 6e 74 65 6e "
			   "64 65 64 20 62 79 20 74 68 65 20 43 6f 6e 74 72 "
			   "69 62 75 74 6f 72 20 66 6f 72 20 70 75 62 6c 69 "
			   "63 61 74 69 6f 6e 20 61 73 20 61 6c 6c 20 6f 72 "
			   "20 70 61 72 74 20 6f 66 20 61 6e 20 49 45 54 46 "
			   "20 49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 20 "
			   "6f 72 20 52 46 43 20 61 6e 64 20 61 6e 79 20 73 "
			   "74 61 74 65 6d 65 6e 74 20 6d 61 64 65 20 77 69 "
			   "74 68 69 6e 20 74 68 65 20 63 6f 6e 74 65 78 74 "
			   "20 6f 66 20 61 6e 20 49 45 54 46 20 61 63 74 69 "
			   "76 69 74 79 20 69 73 20 63 6f 6e 73 69 64 65 72 "
			   "65 64 20 61 6e 20 22 49 45 54 46 20 43 6f 6e 74 "
			   "72 69 62 75 74 69 6f 6e 22 2e 20 53 75 63 68 20 "
			   "73 74 61 74 65 6d 65 6e 74 73 20 69 6e 63 6c 75 "
			   "64 65 20 6f 72 61 6c 20 73 74 61 74 65 6d 65 6e "
			   "74 73 20 69 6e 20 49 45 54 46 20 73 65 73 73 69 "
			   "6f 6e 73 2c 20 61 73 20 77 65 6c 6c 20 61 73 20 "
			   "77 72 69 74 74 65 6e 20 61 6e 64 20 65 6c 65 63 "
			   "74 72 6f 6e 69 63 20 63 6f 6d 6d 75 6e 69 63 61 "
			   "74 69 6f 6e 73 20 6d 61 64 65 20 61 74 20 61 6e "
			   "79 20 74 69 6d 65 20 6f 72 20 70 6c 61 63 65 2c "
			   "20 77 68 69 63 68 20 61 72 65 20 61 64 64 72 65"
			   "73 73 65 64 20 74 6f"
);

	uint8_t exp2[16];
	unhexlify(exp2, "36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e");

	poly.setKey(key2, sizeof(key2));
	poly.update(text2, sizeof(text2));
	poly.digest(res);

	r &= assertArrayEquals(exp2, res, 16);


	uint8_t key3[32];
	unhexlify(key3,
			"1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0 "
			"47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0"
			);
	uint8_t text3[112 + 15];
	unhexlify(text3,
			   "27 54 77 61 73 20 62 72 69 6c 6c 69 67 2c 20 61"
			   "6e 64 20 74 68 65 20 73 6c 69 74 68 79 20 74 6f"
			   "76 65 73 0a 44 69 64 20 67 79 72 65 20 61 6e 64"
			   "20 67 69 6d 62 6c 65 20 69 6e 20 74 68 65 20 77"
			   "61 62 65 3a 0a 41 6c 6c 20 6d 69 6d 73 79 20 77"
			   "65 72 65 20 74 68 65 20 62 6f 72 6f 67 6f 76 65"
			   "73 2c 0a 41 6e 64 20 74 68 65 20 6d 6f 6d 65 20"
			   "72 61 74 68 73 20 6f 75 74 67 72 61 62 65 2e" );

	uint8_t exp3[16];
	unhexlify(exp3, "45 41 66 9a 7e aa ee 61 e7 08 dc 7c bc c5 eb 62 ");

	poly.setKey(key3, sizeof(key3));
	poly.update(text3, sizeof(text3));
	poly.digest(res);

	r &= assertArrayEquals(exp3, res, 16);


	// If one uses 130-bit partial reduction, does the code
    // handle the case where partially reduced final result is not fully
    // reduced?
	uint8_t key4[32];
	unhexlify(key4,
			"02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
			);
	uint8_t text4[16];
	unhexlify(text4,
			"ff ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff"
	);

	uint8_t exp4[16];
	unhexlify(exp4, "03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");

	poly.setKey(key4, sizeof(key4));
	poly.update(text4, sizeof(text4));
	poly.digest(res);
	r &= assertArrayEquals(exp4, res, 16);

	// What happens if addition of s overflows modulo 2^128?
	uint8_t key5[32];
	unhexlify(key5,
			"02 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00"
			"ff ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff"
			);
	uint8_t text5[16];
	unhexlify(text5,
			"02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
	);

	uint8_t exp5[16];
	unhexlify(exp5, "03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");

	poly.setKey(key5, sizeof(key5));
	poly.update(text5, sizeof(text5));
	poly.digest(res);
	r &= assertArrayEquals(exp5, res, 16);

	// What happens if data limb is all ones and there is carry from lower limb?
	uint8_t key6[32];
	unhexlify(key6,
			"01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
			);
	uint8_t text6[48];
	unhexlify(text6,
			"ff ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff"
			"f0 ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff"
			"11 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
	);

	uint8_t exp6[16];
	unhexlify(exp6, "05 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");

	poly.setKey(key6, sizeof(key6));
	poly.update(text6, sizeof(text6));
	poly.digest(res);
	r &= assertArrayEquals(exp6, res, 16);


	// What happens if final result from polynomial part is exactly 2^130-5?
	uint8_t key7[32];
	unhexlify(key7,
			"01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
			);
	uint8_t text7[48];
	unhexlify(text7,
			"ff ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff"
			"fb fe fe fe fe fe fe fe  fe fe fe fe fe fe fe fe"
			"01 01 01 01 01 01 01 01  01 01 01 01 01 01 01 01"
	);

	uint8_t exp7[16];
	unhexlify(exp7, "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");

	poly.setKey(key7, sizeof(key7));
	poly.update(text7, sizeof(text7));
	poly.digest(res);
	r &= assertArrayEquals(exp7, res, 16);

	// What happens if final result from polynomial part is exactly 2^130-6?
	uint8_t key8[32];
	unhexlify(key8,
			"02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
			);
	uint8_t text8[16];
	unhexlify(text8,
			"fd ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff"
	);

	uint8_t exp8[16];
	unhexlify(exp8, "fa ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff");

	poly.setKey(key8, sizeof(key8));
	poly.update(text8, sizeof(text8));
	poly.digest(res);
	r &= assertArrayEquals(exp8, res, 16);

	//  What happens if 5*H+L-type reduction produces 131-bit final result?
	uint8_t key9[32];
	unhexlify(key9,
			"01 00 00 00 00 00 00 00  04 00 00 00 00 00 00 00"
			"00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00"
			);
	uint8_t text9[48];
	unhexlify(text9,
		"E3 35 94 D7 50 5E 43 B9 00 00 00 00 00 00 00 00"
		   "33 94 D7 50 5E 43 79 CD 01 00 00 00 00 00 00 00"
		   "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"	);

	uint8_t exp9[16];
	unhexlify(exp9, "13 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");

	poly.setKey(key9, sizeof(key9));
	poly.update(text9, sizeof(text9));
	poly.digest(res);
	r &= assertArrayEquals(exp9, res, 16);

	// from tls
	uint8_t pkey[32];
	unhexlify(pkey,
			"EA 16 55 AB 23 7E F8 A0  93 C2 5B 81 26 9B B5 B9"
			"71 76 01 88 37 C0 69 F0  52 3F B3 FD 30 09 FB 7C"
			);

	Poly1305 pl;
	pl.setKey(pkey, 32);

	uint8_t d[16];
	unhexlify(d,
			"17 03 03 00 1B 00 00 00  00 00 00 00 00 00 00 00"
			);
	pl.update(d, 16);

	unhexlify(d,
			"96 C4 DC 19 11 C9 43 58  F0 E5 2A 00 00 00 00 00"
			);
	pl.update(d, 16);

	unhexlify(d,
			"05 00 00 00 00 00 00 00  0B 00 00 00 00 00 00 00"
			);
	pl.update(d, 16);

	uint8_t to[16];
	pl.digest(to);

	uint8_t x[16];
	unhexlify(x,
			"29 09 80 EE 1B 01 DC 15  CA 5D 71 B0 2C A5 19 30");

	r &= assertArrayEquals(x, to, 16);

	return r;
}

void mkKey(uint8_t * buffer, SHA256 &sha256, SharedSecret * sharedSecret, uint8_t * hash, uint8_t c) {
	sha256.update(sharedSecret, sharedSecret->size + 4);
	sha256.update(hash, 32);
	sha256.update(&c, 1);
	sha256.update(hash, 32); // sessionId
	sha256.digest(buffer);

	sha256.update(sharedSecret, sharedSecret->size + 4);
	sha256.update(hash, 32); // hash
	sha256.update(buffer, 32); // last result
	sha256.digest(buffer + 32);
}

bool testSSH2() {
	puts("testSSH2");

	SharedSecret ss = { 0x1f};
	unhexlify(ss.data,
			"6b 7a fa be 80 e1 72 27 66 6b 0d d8"
			"4b f1 82 2b 14 76 2a 13 b8 19 3e 06 ea 2a 12 ae"
			"63 7c 4c"
			);

	uint8_t hash[32];
	unhexlify(hash,
			"ab 3a 94 60 23 e5 57 9b 0c f3 75 84 5c 82 11 3f"
			"c8 8f 70 54 c1 37 4d da d0 f7 f4 d8 2b 4d 4b 02"
			);

	SHA256 sha256;
	uint8_t buf[64];
	mkKey(buf, sha256, &ss, hash, 'D');

	uint8_t keyD[64];
	unhexlify(keyD,
			 "50 ae ce 25 b7 a5 09 b8 68 0c 21 d6 02 1c 7f b8"
			 "d9 e7 f6 54 3f fe e5 39 dc 01 de f7 01 a1 12 ae"
			 "f2 8a d5 3f ee be 55 b8 69 92 1d 12 8a 03 68 9c"
			 "7d 00 94 06 72 4a b1 13 53 23 12 41 81 22 1e c3"
			);

	bool r = assertArrayEquals(keyD, buf, 64);


	uint8_t poly_key[32];
	unhexlify(poly_key,
			"d4 67 7f c2 2d 40 7b 85 c3 ed 6f 73 7a db 90 68"
			"ff cb 7f d8 fe a2 6e 3c 04 4b ed dd ac 92 eb bf"
			);


	// create the poly key
	ChaCha20 cc;
	cc.setKey(&keyD[0], 32);
	cc.zeroCounter();	// set to -1
	cc.nextBlock();		// -1+1 = 0

	r &= assertArrayEquals(poly_key, cc.getStream(), 32);

	int len = 264;
	uint8_t src[4 + len];
	unhexlify(src,
			"00 00 01 08 0b 07 00 00 00 03 00 00 00 0f 73 65"
			"72 76 65 72 2d 73 69 67 2d 61 6c 67 73 00 00 00"
			"9f 73 73 68 2d 65 64 32 35 35 31 39 2c 65 63 64"
			"73 61 2d 73 68 61 32 2d 6e 69 73 74 70 32 35 36"
			"2c 65 63 64 73 61 2d 73 68 61 32 2d 6e 69 73 74"
			"70 33 38 34 2c 65 63 64 73 61 2d 73 68 61 32 2d"
			"6e 69 73 74 70 35 32 31 2c 73 6b 2d 73 73 68 2d"
			"65 64 32 35 35 31 39 40 6f 70 65 6e 73 73 68 2e"
			"63 6f 6d 2c 73 6b 2d 65 63 64 73 61 2d 73 68 61"
			"32 2d 6e 69 73 74 70 32 35 36 40 6f 70 65 6e 73"
			"73 68 2e 63 6f 6d 2c 72 73 61 2d 73 68 61 32 2d"
			"35 31 32 2c 72 73 61 2d 73 68 61 32 2d 32 35 36"
			"00 00 00 1f 70 75 62 6c 69 63 6b 65 79 2d 68 6f"
			"73 74 62 6f 75 6e 64 40 6f 70 65 6e 73 73 68 2e"
			"63 6f 6d 00 00 00 01 30 00 00 00 10 70 69 6e 67"
			"40 6f 70 65 6e 73 73 68 2e 63 6f 6d 00 00 00 01"
			"30 a7 14 be 73 01 00 2d 4c d1 93 e9"
			);

	uint8_t exp[4 + len + 16];
	unhexlify(exp,
			"1E AA 25 B6 D4 75 2A 82 7B 0F 2A A2 8D BB 34 26"
			"F6 AC F8 15 56 55 9C C4 37 BD 59 46 B1 B4 41 CB"
			"2E ED C3 42 48 87 F3 77 B0 4A FC E0 6F 74 36 FE"
			"5C AE F4 B2 58 42 C8 44 39 3E 30 44 DF F5 05 67"
			"26 C6 DD 96 65 2C F4 AA 8E A5 17 57 78 80 31 54"
			"9E 69 08 4C C9 75 90 37 0C C1 3C 35 F2 56 B7 9E"
			"78 C0 E5 6D E5 FA C0 16 94 DD 59 AC 21 78 89 7D"
			"C7 E6 65 C7 D6 4D 95 EE 5F 8E 08 D6 09 88 94 C6"
			"FD 5E AF DD AD 7E F1 18 1B B9 04 7F F3 13 17 FC"
			"7B 51 60 DE 43 4B 5F 04 2C 8B 7F 7D 06 3E 4B D7"
			"FD 1A 73 0E A9 87 29 04 C5 F6 63 58 9E 06 C3 DC"
			"78 3A FA ED B5 BF 05 68 20 7D E8 E2 2F 71 6F B1"
			"FE A7 FB 63 B0 BB 47 58 FD 73 8B A2 76 1E 7F 38"
			"B6 8C 04 C9 12 6C 10 18 66 1A D7 BD FA D3 BA 8B"
			"CB D4 D9 03 86 99 A6 89 8A 92 3D 61 95 FD 7F FA"
			"C8 E9 0C 0D 99 26 16 BC 24 37 93 79 E3 B5 BA C1"	// 256
			"FB 79 C0 27 9A 2F 9D 9A 7C 00 A0 C6"				// 268
			"00 BF F2 B9"
			"0B 8B A4 EF 4B A5 46 62 20 72 AB 9C"
			);

	// encrypt the counter
	ChaCha20 cc2;
	cc2.setKey(&keyD[32], 32);
	cc2.zeroCounter();
	cc2.nextBlock();

	uint8_t enc[4 + len + 16];

	for (int i = 0; i < 4; ++i) {
		enc[i] = src[i] ^ cc2.getStream()[i];
	}

	r &= assertArrayEquals(exp, enc, 4);

	uint8_t * data = &enc[4];
	uint8_t * from = &src[4];
	for (int i = 0; i < len; i += 64) {
		int count = len - i < 64 ? len - i : 64;
		cc.nextBlock(); // set counter to 1

		for (int j = 0; j < count; ++j) {
			data[i + j] = from[i + j] ^ cc.getStream()[j];
		}
	}

	r &= assertArrayEquals(exp + 4, data, len);


	Poly1305 poly;
	uint8_t digest1[16];
	poly.setKey(poly_key, sizeof(poly_key));
	poly.update(enc, len + 4);
	poly.digest(digest1);
	r &= assertArrayEquals(exp + 4 + len, digest1, 16);

// next packet - sequence counter == 1

	uint8_t src2[4 + 24];
	unhexlify(src2,
			"00 00 00 18 06 06 00 00 00 0c 73 73 68 2d 75 73"
			"65 72 61 75 74 68 fd 18 1c 13 7a 7f"
			);

	uint8_t exp2[4 + 24 + 16];
	unhexlify(exp2,
			"38 75 FB 11"
			"0D B2 FA 9F AE 92 C6 87 47 2C C5 CE FD D9 39 A4 26 9D 72 76 AC 9D C2 08"
			"98 30 FC 21 01 ED 8C 0F 95 C2 D0 3C 77 BD D7 4A"
			);


	uint8_t nonce[12] = {
			0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 1
	};
	cc2.setNonce(nonce, 12);
	cc2.zeroCounter();
	cc2.nextBlock();

	uint8_t enc2[4 + 24 + 16];

	for (int i = 0; i < 4; ++i) {
		enc2[i] = src2[i] ^ cc2.getStream()[i];
	}

	r &= assertArrayEquals(exp2, enc2, 4);


	uint8_t poly_key2[32];
	unhexlify(poly_key2,
	"3e 21 8a a9 0a 4d 75 61 3e fe dd 25 74 05 6a 28"
	"46 57 54 5e 68 1c 52 d1 9d 3d dc cb fc 93 3a af"
			);

	cc.setNonce(nonce, 12);
	cc.zeroCounter();	// set to -1
	cc.nextBlock();		// -1+1 = 0

	r &= assertArrayEquals(poly_key2, cc.getStream(), 32);


	len = 24;
	data = &enc2[4];
	from = &src2[4];
	for (int i = 0; i < len; i += 64) {
		int count = len - i < 64 ? len - i : 64;
		cc.nextBlock(); // set counter to 1

		for (int j = 0; j < count; ++j) {
			data[i + j] = from[i + j] ^ cc.getStream()[j];
		}
	}

	r &= assertArrayEquals(exp2 + 4, data, len);

	uint8_t digest2[16];
	poly.setKey(poly_key2, sizeof(poly_key2));
	poly.update(enc2, len + 4);
	poly.digest(digest2);
	r &= assertArrayEquals(exp2 + 4 + len, digest2, 16);

	return r;
}

static void increment(uint8_t iv[12]) {
	for (int i = 11; i >= 0; --i) {
		if (++iv[i])
			break;
	}
}
// same as above, but the ChaCha20Poly1305
int testChaCha20Poly1305() {
	puts("testChaCha20Poly1305");
	bool r = true;

	ChaCha20 ccc;			// counter
	ChaCha20Poly1305_SSH2 ccp;	// rest

	uint8_t keyD[64];
	unhexlify(keyD,
			 "50 ae ce 25 b7 a5 09 b8 68 0c 21 d6 02 1c 7f b8"
			 "d9 e7 f6 54 3f fe e5 39 dc 01 de f7 01 a1 12 ae"
			 "f2 8a d5 3f ee be 55 b8 69 92 1d 12 8a 03 68 9c"
			 "7d 00 94 06 72 4a b1 13 53 23 12 41 81 22 1e c3"
			);

	uint8_t nonce[12] = {
			0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0
	};

	int half = sizeof(keyD) >> 1;
	r &= ccp.setKey(keyD, half);
	r &= ccc.setKey(&keyD[half], half);

	// first packet

	int len = 264;
	uint8_t src1[4 + len + 16];
	unhexlify(src1,
			"00 00 01 08 0b 07 00 00 00 03 00 00 00 0f 73 65"
			"72 76 65 72 2d 73 69 67 2d 61 6c 67 73 00 00 00"
			"9f 73 73 68 2d 65 64 32 35 35 31 39 2c 65 63 64"
			"73 61 2d 73 68 61 32 2d 6e 69 73 74 70 32 35 36"
			"2c 65 63 64 73 61 2d 73 68 61 32 2d 6e 69 73 74"
			"70 33 38 34 2c 65 63 64 73 61 2d 73 68 61 32 2d"
			"6e 69 73 74 70 35 32 31 2c 73 6b 2d 73 73 68 2d"
			"65 64 32 35 35 31 39 40 6f 70 65 6e 73 73 68 2e"
			"63 6f 6d 2c 73 6b 2d 65 63 64 73 61 2d 73 68 61"
			"32 2d 6e 69 73 74 70 32 35 36 40 6f 70 65 6e 73"
			"73 68 2e 63 6f 6d 2c 72 73 61 2d 73 68 61 32 2d"
			"35 31 32 2c 72 73 61 2d 73 68 61 32 2d 32 35 36"
			"00 00 00 1f 70 75 62 6c 69 63 6b 65 79 2d 68 6f"
			"73 74 62 6f 75 6e 64 40 6f 70 65 6e 73 73 68 2e"
			"63 6f 6d 00 00 00 01 30 00 00 00 10 70 69 6e 67"
			"40 6f 70 65 6e 73 73 68 2e 63 6f 6d 00 00 00 01"
			"30 a7 14 be 73 01 00 2d 4c d1 93 e9"
			);

	uint8_t exp1[4 + len + 16];
	unhexlify(exp1,
			"1E AA 25 B6 D4 75 2A 82 7B 0F 2A A2 8D BB 34 26"
			"F6 AC F8 15 56 55 9C C4 37 BD 59 46 B1 B4 41 CB"
			"2E ED C3 42 48 87 F3 77 B0 4A FC E0 6F 74 36 FE"
			"5C AE F4 B2 58 42 C8 44 39 3E 30 44 DF F5 05 67"
			"26 C6 DD 96 65 2C F4 AA 8E A5 17 57 78 80 31 54"
			"9E 69 08 4C C9 75 90 37 0C C1 3C 35 F2 56 B7 9E"
			"78 C0 E5 6D E5 FA C0 16 94 DD 59 AC 21 78 89 7D"
			"C7 E6 65 C7 D6 4D 95 EE 5F 8E 08 D6 09 88 94 C6"
			"FD 5E AF DD AD 7E F1 18 1B B9 04 7F F3 13 17 FC"
			"7B 51 60 DE 43 4B 5F 04 2C 8B 7F 7D 06 3E 4B D7"
			"FD 1A 73 0E A9 87 29 04 C5 F6 63 58 9E 06 C3 DC"
			"78 3A FA ED B5 BF 05 68 20 7D E8 E2 2F 71 6F B1"
			"FE A7 FB 63 B0 BB 47 58 FD 73 8B A2 76 1E 7F 38"
			"B6 8C 04 C9 12 6C 10 18 66 1A D7 BD FA D3 BA 8B"
			"CB D4 D9 03 86 99 A6 89 8A 92 3D 61 95 FD 7F FA"
			"C8 E9 0C 0D 99 26 16 BC 24 37 93 79 E3 B5 BA C1"	// 256
			"FB 79 C0 27 9A 2F 9D 9A 7C 00 A0 C6"				// 268
			"00 BF F2 B9"
			"0B 8B A4 EF 4B A5 46 62 20 72 AB 9C"
			);

	uint8_t * buffer = src1;

	ccc.setNonce(nonce, 12);
	ccc.zeroCounter();
	ccc.chacha(buffer, buffer, 4);
	ccp.init(nonce, 12);
	ccp.encrypt(buffer + 4, buffer + 4, len);
	ccp.updateHash(buffer, 4 + len);
	ccp.calcHash(buffer + 4 + len);
	increment(nonce);

	r &= assertArrayEquals(exp1, buffer, 4 + len + 16);


	// 2nd packet
	uint8_t src2[4 + 24 + 16];
	unhexlify(src2,
			"00 00 00 18 06 06 00 00 00 0c 73 73 68 2d 75 73"
			"65 72 61 75 74 68 fd 18 1c 13 7a 7f"
			);

	uint8_t exp2[4 + 24 + 16];
	unhexlify(exp2,
			"38 75 FB 11"
			"0D B2 FA 9F AE 92 C6 87 47 2C C5 CE FD D9 39 A4 26 9D 72 76 AC 9D C2 08"
			"98 30 FC 21 01 ED 8C 0F 95 C2 D0 3C 77 BD D7 4A"
			);

	len = 24;
	buffer = src2;

	ccc.setNonce(nonce, 12);
	ccc.zeroCounter();
	ccc.chacha(buffer, buffer, 4);
	ccp.init(nonce, 12);
	ccp.encrypt(buffer + 4, buffer + 4, len);
	ccp.updateHash(buffer, 4 + len);
	ccp.calcHash(buffer + 4 + len);
	increment(nonce);

	r &= assertArrayEquals(exp2, buffer, 4 + len + 16);

	return r;
}


int main() {
	return testSSH2() & testChaCha20() & testPoly1305() & testChaCha20Poly1305() ? 0 : 10;
}
