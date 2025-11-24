/*
 * crypto SHA-256 implementation (FIPS 180-4)
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
 * Module: SHA-256
 *
 * Purpose:
 *  - Provide a straightforward implementation of SHA-256 as specified in NIST FIPS 180-4
 *  - Support digest(), update(), reset(), and clone() operations
 *  - Designed for Amiga and cross-platform builds
 *
 * Notes:
 *  - SHA-256 produces a 256-bit (32-byte) digest
 *  - This implementation follows the standard round constants and message schedule
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#include <string.h>
#include <stdio.h>
#include "sha256.h"

static inline unsigned int rol(unsigned int value, int bits) {
	return (value << bits) | (value >> (32 - bits));
}

__attribute((section(".text.256")))
const static uint32_t K256[64] = { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
		0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
		0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138,
		0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624,
		0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f,
		0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

SHA256::SHA256() :
		MessageDigest(64) {
	reset();
}

void SHA256::transform() {
	unsigned i = 0;
	uint32_t *block = _block;
	uint8_t *d = data;
	// convert to int
	for (unsigned j = 0; i < 16; j += 4, ++i) {
		block[i] = (d[j] << 24) | (d[j+1] <<16) | (d[j+2] <<8) | (d[j+3]);
	}

	for (; i < 64; ++i) {
		long s0 = rol(block[i - 15], 25) ^ rol(block[i - 15], 14) ^ (block[i - 15] >> 3);
		long s1 = rol(block[i - 2], 15) ^ rol(block[i - 2], 13) ^ (block[i - 2] >> 10);
		block[i] = block[i - 16] + s0 + block[i - 7] + s1;
	}

	/* Copy context->state[] to working vars */
	long t0, t1, t2, t3, t4, t5, t6, t7;

	t0 = state0;
	t1 = state1;
	t2 = state2;
	t3 = state3;
	t4 = state4;
	t5 = state5;
	t6 = state6;
	t7 = state7;

	uint32_t const *k = K256;
	for (i = 0; i < 64; ++i) {
		long s0 = rol(t0, 30) ^ rol(t0, 19) ^ rol(t0, 10);
		long maj = (t0 & t1) ^ (t0 & t2) ^ (t1 & t2);
		long add2 = s0 + maj;
		long s1 = rol(t4, 26) ^ rol(t4, 21) ^ rol(t4, 7);
		long ch = (t4 & t5) ^ ((~t4) & t6);
		long add1 = t7 + s1 + ch + k[i] + block[i];

		t7 = t6;
		t6 = t5;
		t5 = t4;
		t4 = t3 + add1;
		t3 = t2;
		t2 = t1;
		t1 = t0;
		t0 = add1 + add2;
	}

	/* Add the working vars back into context.state[] */
	state0 += t0; // a
	state1 += t1; // b
	state2 += t2; // c
	state3 += t3; // d
	state4 += t4; // e
	state5 += t5; // f
	state6 += t6; // g
	state7 += t7; // h
}

/**
 * Initialize new context
 */
void SHA256::reset() {
	state0 = 0x6a09e667;
	state1 = 0xbb67ae85;
	state2 = 0x3c6ef372;
	state3 = 0xa54ff53a;
	state4 = 0x510e527f;
	state5 = 0x9b05688c;
	state6 = 0x1f83d9ab;
	state7 = 0x5be0cd19;
	/**/
	count = 0;
}

void SHA256::__getDigest(unsigned char *r) {
	uint8_t *i = (uint8_t*) r;
	*i++ = state0 >> 24;
	*i++ = state0 >> 16;
	*i++ = state0 >> 8;
	*i++ = state0;
	*i++ = state1>> 24;
	*i++ = state1>> 16;
	*i++ = state1>> 8;
	*i++ = state1;
	*i++ = state2>> 24;
	*i++ = state2>> 16;
	*i++ = state2>> 8;
	*i++ = state2;
	*i++ = state3>> 24;
	*i++ = state3>> 16;
	*i++ = state3>> 8;
	*i++ = state3;
	*i++ = state4>> 24;
	*i++ = state4>> 16;
	*i++ = state4>> 8;
	*i++ = state4;
	*i++ = state5>> 24;
	*i++ = state5>> 16;
	*i++ = state5>> 8;
	*i++ = state5;
	*i++ = state6>> 24;
	*i++ = state6>> 16;
	*i++ = state6>> 8;
	*i++ = state6;
	*i++ = state7>> 24;
	*i++ = state7>> 16;
	*i++ = state7>> 8;
	*i = state7;
}

unsigned SHA256::len() const {
	return 32;
}

MessageDigest * SHA256::clone() const {
	return new SHA256(*this);
}
