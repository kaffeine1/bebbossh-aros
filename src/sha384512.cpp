/*
 * crypto SHA-384 / SHA-512 core implementation (FIPS 180-4)
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
 * Module: SHA-384 / SHA-512
 *
 * Purpose:
 *  - Provide the core compression function for SHA-384 and SHA-512
 *  - Support block transformation (1024-bit input -> updated state)
 *  - Support bit count addition for padding
 *  - Designed for Amiga and cross-platform builds
 *
 * Notes:
 *  - SHA-384 is a truncated variant of SHA-512 with different initial state values
 *  - SHA-512 produces a 512-bit (64-byte) digest; SHA-384 produces a 384-bit (48-byte) digest
 *  - This implementation follows the standard round constants and message schedule
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */
#include <string.h>
#include <stdio.h>
#include "sha384.h"

SHA384512::SHA384512(int sz):  MessageDigest(sz) { // @suppress("Class members should be properly initialized")
}

#ifdef __AMIGA__
__attribute((section(".text.K")))
#endif
const uint64_t ____K[] = { 0x428a2f98d728ae22LL, 0x7137449123ef65cdLL, 0xb5c0fbcfec4d3b2fLL, 0xe9b5dba58189dbbcLL, 0x3956c25bf348b538LL,
		0x59f111f1b605d019LL, 0x923f82a4af194f9bLL, 0xab1c5ed5da6d8118LL, 0xd807aa98a3030242LL, 0x12835b0145706fbeLL, 0x243185be4ee4b28cLL,
		0x550c7dc3d5ffb4e2LL, 0x72be5d74f27b896fLL, 0x80deb1fe3b1696b1LL, 0x9bdc06a725c71235LL, 0xc19bf174cf692694LL, 0xe49b69c19ef14ad2LL,
		0xefbe4786384f25e3LL, 0x0fc19dc68b8cd5b5LL, 0x240ca1cc77ac9c65LL, 0x2de92c6f592b0275LL, 0x4a7484aa6ea6e483LL, 0x5cb0a9dcbd41fbd4LL,
		0x76f988da831153b5LL, 0x983e5152ee66dfabLL, 0xa831c66d2db43210LL, 0xb00327c898fb213fLL, 0xbf597fc7beef0ee4LL, 0xc6e00bf33da88fc2LL,
		0xd5a79147930aa725LL, 0x06ca6351e003826fLL, 0x142929670a0e6e70LL, 0x27b70a8546d22ffcLL, 0x2e1b21385c26c926LL, 0x4d2c6dfc5ac42aedLL,
		0x53380d139d95b3dfLL, 0x650a73548baf63deLL, 0x766a0abb3c77b2a8LL, 0x81c2c92e47edaee6LL, 0x92722c851482353bLL, 0xa2bfe8a14cf10364LL,
		0xa81a664bbc423001LL, 0xc24b8b70d0f89791LL, 0xc76c51a30654be30LL, 0xd192e819d6ef5218LL, 0xd69906245565a910LL, 0xf40e35855771202aLL,
		0x106aa07032bbd1b8LL, 0x19a4c116b8d2d0c8LL, 0x1e376c085141ab53LL, 0x2748774cdf8eeb99LL, 0x34b0bcb5e19b48a8LL, 0x391c0cb3c5c95a63LL,
		0x4ed8aa4ae3418acbLL, 0x5b9cca4f7763e373LL, 0x682e6ff3d6b2b8a3LL, 0x748f82ee5defb2fcLL, 0x78a5636f43172f60LL, 0x84c87814a1f0ab72LL,
		0x8cc702081a6439ecLL, 0x90befffa23631e28LL, 0xa4506cebde82bde9LL, 0xbef9a3f7b2c67915LL, 0xc67178f2e372532bLL, 0xca273eceea26619cLL,
		0xd186b8c721c0c207LL, 0xeada7dd6cde0eb1eLL, 0xf57d4f7fee6ed178LL, 0x06f067aa72176fbaLL, 0x0a637dc5a2c898a6LL, 0x113f9804bef90daeLL,
		0x1b710b35131c471bLL, 0x28db77f523047d84LL, 0x32caab7b40c72493LL, 0x3c9ebe0a15c9bebcLL, 0x431d67c49c100d4cLL, 0x4cc5d4becb3e42b6LL,
		0x597f299cfc657e2aLL, 0x5fcb6fab3ad6faecLL, 0x6c44198c4a475817LL, };

static uint64_t roll(uint64_t value, long bits) {
	return (value << bits) | (value >> (64 - bits));
}

/**
 * Hash a single 1024-bit block. This is the core of the algorithm.
 */
void SHA384512::transform() {
	unsigned i = 0;
	uint64_t *block = _block;
	uint8_t *d = (uint8_t*) data;

	// convert to int
	for (unsigned j = 0; i < 16; j += 8, ++i) {
		block[i] = ((uint64_t)d[j] << 56) | ((uint64_t)d[j+1] << 48) | ((uint64_t)d[j+2] << 40) | ((uint64_t)d[j+3] << 32)
				| ((uint64_t)d[j+4] << 24) | ((uint64_t)d[j+5] << 16) | ((uint64_t)d[j+6] << 8) | ((uint64_t)d[j+7]);
		
	}

	for (; i < 80; ++i) {
		uint64_t s0 = roll(block[i - 15], 63) ^ roll(block[i - 15], 56) ^ (block[i - 15] >> 7);
		uint64_t s1 = roll(block[i - 2], 45) ^ roll(block[i - 2], 3) ^ (block[i - 2] >> 6);
		block[i] = block[i - 16] + s0 + block[i - 7] + s1;
	}

	/* Copy context->state[] to working vars */
	uint64_t t0, t1, t2, t3, t4, t5, t6, t7;

	t0 = state0;
	t1 = state1;
	t2 = state2;
	t3 = state3;
	t4 = state4;
	t5 = state5;
	t6 = state6;
	t7 = state7;

	uint64_t const *k = ____K;
	for (i = 0; i < 80; ++i) {
		uint64_t s0 = roll(t0, 36) ^ roll(t0, 30) ^ roll(t0, 25);
		uint64_t maj = (t0 & t1) ^ (t0 & t2) ^ (t1 & t2);
		uint64_t add2 = s0 + maj;
		uint64_t s1 = roll(t4, 50) ^ roll(t4, 46) ^ roll(t4, 23);
		uint64_t ch = (t4 & t5) ^ ((~t4) & t6);
		uint64_t add1 = t7 + s1 + ch + k[i] + block[i];

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

void SHA384512::addBitCount(uint64_t bitCount) {
	for (int i = 127;  i >= 112; --i) {
		data[i] = bitCount;
		bitCount >>= 8;
	}
}
