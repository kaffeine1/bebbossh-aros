/*
 * crypto AES implementation
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
 * Project: Cryptography for the Amiga
 * Purpose: Provide modern cryptographic primitives and protocol
 *          support on classic Amiga systems.
 *
 * Features:
 *  - AES block cipher with table-driven and macro-based implementations
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing.
 *  - Optimized for Motorola 68000/68020 CPUs with inline assembly support.
 *
 * Author's intent:
 *  Ensure Amiga developers have access to secure, maintainable,
 *  and GPL-compliant cryptographic building blocks.
 * ----------------------------------------------------------------------
 */
#include <stdlib.h>
#include <string.h>

#include "aes.h"

#ifdef __mc68000__
#define PACK(A,B,C,D,T,Y) \
	asm volatile ("move.b %1,%0" : "=d"(t) : "m"(T[Y.b[A]])); \
	asm volatile ("lsl.w #8,%0" : "+d"(t)); \
	asm volatile ("move.b %1,%0" : "+d"(t) : "m"(T[Y.b[B]])); \
	asm volatile ("lsl.l #8,%0" : "+d"(t)); \
	asm volatile ("move.b %1,%0" : "+d"(t) : "m"(T[Y.b[C]])); \
	asm volatile ("lsl.l #8,%0" : "+d"(t)); \
	asm volatile ("move.b %1,%0" : "+d"(t) : "m"(T[Y.b[D]]))

# ifdef __mc68020__
// 68020 asm
#define ONE(A,B,C,D,T,X,Y,Z) \
	asm volatile ("move.b %1,%0" : "+d"(idx) : "m"(Y.b[ A]));   \
	asm volatile ("move.l %1,%0" : "=d"(eor) : "m"(T##1[idx])); \
	asm volatile ("move.b %1,%0" : "+d"(idx) : "m"(Y.b[B]));    \
	asm volatile ("move.l %1,%0" : "=d"(t)   : "m"(T##2[idx])); \
	asm volatile ("eor.l %1,%0"  : "+d"(eor) : "d"(t));         \
	asm volatile ("move.b %1,%0" : "+d"(idx) : "m"(Y.b[C]));    \
	asm volatile ("move.l %1,%0" : "=d"(t)   : "m"(T##3[idx])); \
	asm volatile ("eor.l %1,%0"  : "+d"(eor) : "d"(t));         \
	asm volatile ("move.b %1,%0" : "+d"(idx) : "m"(Y.b[ D]));   \
	asm volatile ("move.l %1,%0" : "=d"(t)   : "m"(T##4[idx])); \
	asm volatile ("eor.l %1,%0"  : "+d"(eor) : "d"(t));         \
	asm volatile ("move.l (%1)+,%0" : "=d"(t), "+a"(rk)); \
	asm volatile ("eor.l %1,%0"  : "+d"(eor) : "d"(t));         \
	asm volatile ("move.l %1,%0" : "=m"(X.d[Z]) : "d"(eor))

# else
// 68000 asm
#define ONE(A,B,C,D,T,X,Y,Z) \
	asm volatile ("moveq #0,%0" : "=d"(idx));   \
	asm volatile ("move.b %1,%0" : "+d"(idx) : "m"(Y.b[ A]));   \
	asm volatile ("lsl.w #2,%0" : "+d"(idx));   \
	asm volatile ("move.l (%1,%2),%0" : "=d"(eor) : "a"(T##1), "d"(idx)); \
	asm volatile ("moveq #0,%0" : "=d"(idx));   \
	asm volatile ("move.b %1,%0" : "+d"(idx) : "m"(Y.b[ B]));   \
	asm volatile ("lsl.w #2,%0" : "+d"(idx));   \
	asm volatile ("move.l (%1,%2),%0" : "=d"(t) : "a"(T##2), "d"(idx)); \
	asm volatile ("eor.l %1,%0"  : "+d"(eor) : "d"(t));         \
	asm volatile ("moveq #0,%0" : "=d"(idx));   \
	asm volatile ("move.b %1,%0" : "+d"(idx) : "m"(Y.b[ C]));   \
	asm volatile ("lsl.w #2,%0" : "+d"(idx));   \
	asm volatile ("move.l (%1,%2),%0" : "=d"(t) : "a"(T##3), "d"(idx)); \
	asm volatile ("eor.l %1,%0"  : "+d"(eor) : "d"(t));         \
	asm volatile ("moveq #0,%0" : "=d"(idx));   \
	asm volatile ("move.b %1,%0" : "+d"(idx) : "m"(Y.b[ D]));   \
	asm volatile ("lsl.w #2,%0" : "+d"(idx));   \
	asm volatile ("move.l (%1,%2),%0" : "=d"(t) : "a"(T##4), "d"(idx)); \
	asm volatile ("eor.l %1,%0"  : "+d"(eor) : "d"(t));         \
	asm volatile ("move.l (%1)+,%0" : "=d"(t), "+a"(rk)); \
	asm volatile ("eor.l %1,%0"  : "+d"(eor) : "d"(t));         \
	asm volatile ("move.l %1,%0" : "=m"(X.d[Z]) : "d"(eor))
# endif
#else
// C versions
#if (BYTE_ORDER == BIG_ENDIAN)
#define PACK(A,B,C,D,T,Y) \
	t = (T[Y.b[A]] << 24) | (T[Y.b[B]] << 16) | (T[Y.b[C]] << 8) | (T[Y.b[D]] << 0)
#else
#define PACK(A,B,C,D,T,Y) \
	t = (T[Y.b[A]] << 0) | (T[Y.b[B]] << 8) | (T[Y.b[C]] << 16) | (T[Y.b[D]] << 24)
#endif

#define ONE(A,B,C,D,T,X,Y,Z) \
		X.d[Z] = T##1[Y.b[A]] ^ T##2[Y.b[B]] ^ T##3[Y.b[C]] ^ T##4[Y.b[D]] ^ *rk++
#endif

#ifdef __AMIGA__
__attribute((section(".text.const")))
#endif
const uint8_t SBOX[256] = {
		0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
		0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 
		0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
		0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 
		0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 
		0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 
		0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 
		0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 
		0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, 
		0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 
		0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 
		0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 
		0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 
		0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 
		0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 
		0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16 };

#ifdef __AMIGA__
__attribute((section(".text.const")))
#endif
const uint8_t INVSBOX[256] = {
		0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
		0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
		0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E, 
		0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25, 
		0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92, 
		0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84, 
		0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06, 
		0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B, 
		0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73, 
		0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E, 
		0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B, 
		0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4, 
		0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F, 
		0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, 
		0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61, 
		0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D };

/**
 * Apply AES S-box substitution to each byte of a 32-bit word.
 * Used during key expansion (SubWord).
 */
static inline uint32_t subWord(uint32_t d) {
	uint8_t * b = (uint8_t *)&d;
	b[0] = SBOX[b[0]];
	b[1] = SBOX[b[1]];
	b[2] = SBOX[b[2]];
	b[3] = SBOX[b[3]];
	return *(uint32_t *)b;
}

/**
 * Multiply two bytes in GF(2^8) using the AES irreducible polynomial (0x11B).
 * Implements finite field multiplication for MixColumns and InvMixColumns.
 */
static uint8_t gf_mul(uint8_t a, uint8_t b) {
	uint8_t res = 0;
	while (b) {
		if (b & 1)
			res ^= a;
		uint8_t hi = a & 0x80;
		a = (a << 1) ^ (hi ? 0x1B : 0);
		b >>= 1;
	}
	return res;
}

/**
 * Apply the inverse MixColumns transformation to the AES state.
 * Operates on a 4x4 byte matrix (DB) to reverse column mixing in decryption.
 */
static void invMixColumns(AES::DB & state)
{
    const auto temp = state;
    for ( size_t c = 0; c != 4; ++c ) {
        for ( size_t r = 0; r != 4; ++r ) {
			state.b[r + c * 4] = gf_mul(0xe, temp.b[r + c * 4]) ^ gf_mul(0xb, temp.b[(r + 1) % 4 + c * 4]) ^ gf_mul(0xd, temp.b[(r + 2) % 4 + c * 4])
					^ gf_mul(0x9, temp.b[(r + 3) % 4 + c * 4]);
        }
    }
}

/**
 * Rotate a 32-bit word right by x bits.
 * Used in key schedule depending on endian configuration.
 */
static inline uint32_t rotr(uint32_t v, int x) {
	return (v >> x) | (v << (32 - x));
}

/**
 * Rotate a 32-bit word left by x bits.
 * Used in key schedule depending on endian configuration.
 */
static inline uint32_t rotl(uint32_t v, int x) {
	return (v << x) | (v >> (32 - x));
}
/**
 * AES key scheduling routine.
 * Expands the cipher key into round keys for encryption and decryption.
 * Supports 128-, 192-, and 256-bit keys.
 */
int AES::setKey(void const *key, unsigned keylen) {
	switch (keylen) {
	case 16:
		rounds = 10;
		break;
	case 24:
		rounds = 12;
		break;
	case 32:
		rounds = 14;
		break;
	default:
		return false;
	}

// rotx = rotate left for big-endian, rotate right for little-endian, roty inversed	
#if (BYTE_ORDER == BIG_ENDIAN)
	static const uint32_t rCon[10] = { 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000 };
#define rotx rotl
#define roty rotr
#else
	static const uint32_t rCon[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };
#define rotx rotr
#define roty rotl
#endif

	ckey = (DB*)keyData;
	invckey = &ckey[rounds];

	// prepare cipher keys
	uint32_t * buffer32 = &ckey->d[0];

	// copy full 32-bit words
	const uint32_t* src32 = static_cast<const uint32_t*>(key);
	unsigned words = keylen / 4;
	for (unsigned i = 0; i < words; ++i) {
	    buffer32[i] = src32[i];
	}

	// keylen 16/24/32 -> nk 4/6/8
    const unsigned nk = keylen >> 2;          // nk = 4, 6, or 8
    const unsigned end = 4 * rounds + 4;

    unsigned ink = 0;                         // position within nk
    unsigned rci = 0;                         // index into rCon

    for (unsigned i = nk; i < end; ++i) {
        uint32_t temp = buffer32[i - 1];

        if (ink == 0) {
            temp = subWord(rotx(temp, 8)) ^ rCon[rci++];
        } else if (nk > 6 && ink == 4) {
            temp = subWord(temp);
        }

        buffer32[i] = buffer32[i - nk] ^ temp;

        // advance ink, wrap at nk
        if (++ink == nk) ink = 0;
    }

    // prepare inverse cipher keys
    for ( size_t k = 1; k < rounds; ++k ) {
        invckey[k] = ckey[rounds - k];
        invMixColumns(invckey[k]);
    }
    invckey[rounds] = ckey[0];

    // rounds is halved because the implementation performs two half-round passes per loop iteration
    rounds = rounds / 2 - 1; // 10 -> 4, 12 -> 5, 14 -> 6

	return true;
}

#ifdef __AMIGA__
__attribute((section(".text")))
#endif
uint32_t T1[256], T2[256], T3[256], T4[256],
		 Tinv1[256], Tinv2[256], Tinv3[256], Tinv4[256];


/**
 * Initialize AES T-tables for MixColumns and InvMixColumns.
 * Precomputes forward and inverse tables for optimized round transformations.
 */
extern "C"
#ifdef __AMIGA__
__attribute__((externally_visible))
#endif
void initMixTables() {
    for (int i = 0; i < 256; ++i) {
        uint8_t sb = SBOX[i];
        uint8_t m2 = gf_mul(2, sb);
        uint8_t m3 = gf_mul(3, sb);
#if (BYTE_ORDER == BIG_ENDIAN)
        uint32_t t = ((m2) << 24) | ((sb) << 16) | ((sb) << 8)  | (m3 << 0);
#else
        uint32_t t = ((m2) << 0) | ((sb) <<  8) | ((sb) << 16)  | (m3 << 24);
#endif
        T1[i] = t;
        T2[i] = roty(t, 8);
        T3[i] = roty(t, 16);
        T4[i] = roty(t, 24);
    }

#ifdef __mc68000__
    const uint8_t * INVSBOX;
	asm volatile ("lea %1,%0" : "=a"(INVSBOX) : "m"(::INVSBOX));
#endif

    for (int i = 0; i < 256; ++i) {
        uint8_t s = INVSBOX[i];

        uint8_t m0e = gf_mul(0x0e, s);
        uint8_t m0b = gf_mul(0x0b, s);
        uint8_t m0d = gf_mul(0x0d, s);
        uint8_t m09 = gf_mul(0x09, s);

        // Construct Tinv1 with correct byte order
#if (BYTE_ORDER == BIG_ENDIAN)
        uint32_t t = (m0e << 24) | (m09 << 16) | (m0d << 8) | m0b;
#else
        uint32_t t= (m0e << 0) | (m09 << 8) | (m0d << 16) | (m0b << 24);
#endif

        Tinv1[i] = t;
        Tinv2[i] = roty(t, 8);
        Tinv3[i] = roty(t, 16);
        Tinv4[i] = roty(t, 24);
    }
}

/**
 * Encrypt a single 128-bit block using AES.
 * Performs initial AddRoundKey, main rounds, and final round.
 */
void AES::encrypt(void* output_, void const* input_) {
    const uint32_t* rk = &ckey->d[0];
    DB temp;
    const uint32_t* input = static_cast<const uint32_t*>(input_);
    DB state;

    // Initial AddRoundKey
    state.d[0] = *rk++ ^ input[0];
    state.d[1] = *rk++ ^ input[1];
    state.d[2] = *rk++ ^ input[2];
    state.d[3] = *rk++ ^ input[3];

    {
#ifdef __mc68000__
		uint32_t * T1, *T2, *T3, *T4;
		asm volatile ("lea %1,%0" : "=a"(T1) : "m"(::T1));
		asm volatile ("lea %1,%0" : "=a"(T2) : "m"(::T2));
		asm volatile ("lea %1,%0" : "=a"(T3) : "m"(::T3));
		asm volatile ("lea %1,%0" : "=a"(T4) : "m"(::T4));
		uint32_t idx, eor, t;
# ifdef __mc68020__
		idx = 0;
#endif		
#endif

		// Main rounds (excluding final round)
		// ONE macro performs one column transformation using T-tables
		for (short i = rounds; i > 0; --i) {
			// Pass 1: state -> temp
	    	ONE( 0,  5, 10, 15, T, temp, state, 0);
	    	ONE( 4,  9, 14,  3, T, temp, state, 1);
	    	ONE( 8, 13,  2,  7, T, temp, state, 2);
	    	ONE(12,  1,  6, 11, T, temp, state, 3);

			// Pass 2: temp -> state
	    	ONE( 0,  5, 10, 15, T, state, temp, 0);
	    	ONE( 4,  9, 14,  3, T, state, temp, 1);
	    	ONE( 8, 13,  2,  7, T, state, temp, 2);
	    	ONE(12,  1,  6, 11, T, state, temp, 3);
		}

		// Pass 1: state -> temp
    	ONE( 0,  5, 10, 15, T, temp, state, 0);
    	ONE( 4,  9, 14,  3, T, temp, state, 1);
    	ONE( 8, 13,  2,  7, T, temp, state, 2);
    	ONE(12,  1,  6, 11, T, temp, state, 3);
    }

#ifdef __mc68000__
    const uint8_t * SBOX;
	asm volatile ("lea %1,%0" : "=a"(SBOX) : "m"(::SBOX));
#endif

    // Final round: SubBytes + ShiftRows + AddRoundKey (no MixColumns)
	uint32_t t,* output = static_cast<uint32_t*>(output_);

	PACK( 0,  5, 10, 15, SBOX, temp);
	*output++ = t ^ *rk++;
	PACK( 4,  9, 14,  3, SBOX, temp);
	*output++ = t ^ *rk++;
	PACK( 8, 13,  2,  7, SBOX, temp);
	*output++ = t ^ *rk++;
	PACK(12,  1,  6, 11, SBOX, temp);
	*output++ = t ^ *rk++;
}

/**
 * Decrypt a single 128-bit block using AES.
 * Performs inverse round transformations and final AddRoundKey.
 */
void AES::decrypt(void* output_, const void* input_) {
    const uint32_t* rk = &invckey->d[0];
    const uint32_t* input = reinterpret_cast<const uint32_t*>(input_);
    DB state, temp;

    // Load input and apply first round key
    state.d[0] = *rk++ ^ input[0];
    state.d[1] = *rk++ ^ input[1];
    state.d[2] = *rk++ ^ input[2];
    state.d[3] = *rk++ ^ input[3];

	{
#ifdef __mc68000__
		uint32_t * Tinv1, *Tinv2, *Tinv3, *Tinv4;
		asm volatile ("lea %1,%0" : "=a"(Tinv1) : "m"(::Tinv1));
		asm volatile ("lea %1,%0" : "=a"(Tinv2) : "m"(::Tinv2));
		asm volatile ("lea %1,%0" : "=a"(Tinv3) : "m"(::Tinv3));
		asm volatile ("lea %1,%0" : "=a"(Tinv4) : "m"(::Tinv4));
		uint32_t idx, eor, t;
# ifdef __mc68020__
		idx = 0;
#endif		
#endif

		// Main rounds (excluding final round)
		// ONE macro performs one column transformation using T-tables
	    for (short round = 0; round < rounds; ++round) {
	    	ONE( 0, 13, 10,  7, Tinv, temp, state, 0);
	    	ONE( 4,  1, 14, 11, Tinv, temp, state, 1);
	    	ONE( 8,  5,  2, 15, Tinv, temp, state, 2);
	    	ONE(12,  9,  6,  3, Tinv, temp, state, 3);
	
	    	ONE( 0, 13, 10,  7, Tinv, state, temp, 0);
	    	ONE( 4,  1, 14, 11, Tinv, state, temp, 1);
	    	ONE( 8,  5,  2, 15, Tinv, state, temp, 2);
	    	ONE(12,  9,  6,  3, Tinv, state, temp, 3);
	    }
	
		ONE( 0, 13, 10,  7, Tinv, temp, state, 0);
		ONE( 4,  1, 14, 11, Tinv, temp, state, 1);
		ONE( 8,  5,  2, 15, Tinv, temp, state, 2);
		ONE(12,  9,  6,  3, Tinv, temp, state, 3);
	}
#ifdef __mc68000__
    const uint8_t * INVSBOX;
	asm volatile ("lea %1,%0" : "=a"(INVSBOX) : "m"(::INVSBOX));
#endif

	uint32_t t, *output = reinterpret_cast<uint32_t*>(output_);

	// Final round: InvShiftRows + InvSubBytes + AddRoundKey
	// Column 0
	PACK(0, 13, 10, 7, INVSBOX, temp);
	*output++ = t ^ *rk++;
	PACK(4, 1, 14, 11, INVSBOX, temp);
	*output++ = t ^ *rk++;
	PACK(8, 5, 2, 15, INVSBOX, temp);
	*output++ = t ^ *rk++;
	PACK(12, 9, 6, 3, INVSBOX, temp);
	*output++ = t ^ *rk++;
}

#ifdef __AMIGA__
#include <stabs.h>
ADD2INIT(initMixTables, -21);
#endif


AES::AES(int dummy) : rounds(0), ckey(0), invckey(0) {
#ifndef __AMIGA__
	if (!Tinv1[0]) {
		initMixTables();
	}
#endif	
}

/**
 * AES destructor (no dynamic cleanup required).
 */
AES::~AES() {
}

/**
 * Return AES block size in bytes (always 16).
 */
int AES::blockSize() const {
	return 16;
}
