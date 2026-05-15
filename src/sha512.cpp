/*
 * crypto SHA-512 implementation (FIPS 180-4)
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
 * Module: SHA-512
 *
 * Purpose:
 *  - Provide a straightforward implementation of SHA-512 as specified in NIST FIPS 180-4
 *  - Support digest(), update(), reset(), and clone() operations
 *  - Designed for Amiga and cross-platform builds
 *
 * Notes:
 *  - SHA-512 produces a 512-bit (64-byte) digest
 *  - SHA-512 shares the same compression function as SHA-384, but uses different initial state values
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#include <string.h>
#include <stdio.h>
#include "sha512.h"

SHA512::SHA512() :
		SHA384512(128) {
	reset();
}

void SHA512::updateDirect(const void *_d, unsigned len) {
	unsigned char *d = (unsigned char*) _d;
	unsigned k = ((unsigned) count) & mask;
	count += len;
	if (k + len <= mask) {
		memcpy(data + k, d, len);
		return;
	}
	unsigned m1 = mask + 1;
	unsigned n = m1 - k;
	memcpy(data + k, d, n);
	len -= n;
	while (true) {
		SHA384512::transform();
		if (len <= mask)
			break;
		memcpy(data, d + n, m1);
		len -= m1;
		n += m1;
	}
	memcpy(data, d + n, len);
}

void SHA512::digestDirect(void *to_) {
	unsigned char *to = (unsigned char*) to_;
	long bitCount = count << 3;

	unsigned i = ((unsigned) count) & mask;
	data[i++] = (unsigned char) 0x80;
	unsigned end = mask + 1 - ((mask + 1) >> 3);
	if (i > end) {
		for (unsigned k = i; k <= mask; ++k)
			data[k] = 0;
		SHA384512::transform();
		i = 0;
	}
	for (; i < end; ++i)
		data[i] = 0;

	SHA384512::addBitCount(bitCount);
	SHA384512::transform();

	SHA512::__getDigest(to);
	SHA512::reset();
}

/**
 * Initialize new context
 */
void SHA512::reset() {
	state0 = 0x6a09e667f3bcc908LL;
	state1 = 0xbb67ae8584caa73bLL;
	state2 = 0x3c6ef372fe94f82bLL;
	state3 = 0xa54ff53a5f1d36f1LL;
	state4 = 0x510e527fade682d1LL;
	state5 = 0x9b05688c2b3e6c1fLL;
	state6 = 0x1f83d9abfb41bd6bLL;
	state7 = 0x5be0cd19137e2179LL;
	/**/
	count = 0;
}

void SHA512::__getDigest(unsigned char *to) {
	*to++ = state0 >> 56;
	*to++ = state0 >> 48;
	*to++ = state0 >> 40;
	*to++ = state0 >> 32;
	*to++ = state0 >> 24;
	*to++ = state0 >> 16;
	*to++ = state0 >> 8;
	*to++ = state0;
	*to++ = state1 >> 56;
	*to++ = state1 >> 48;
	*to++ = state1 >> 40;
	*to++ = state1 >> 32;
	*to++ = state1 >> 24;
	*to++ = state1 >> 16;
	*to++ = state1 >> 8;
	*to++ = state1;
	*to++ = state2 >> 56;
	*to++ = state2 >> 48;
	*to++ = state2 >> 40;
	*to++ = state2 >> 32;
	*to++ = state2 >> 24;
	*to++ = state2 >> 16;
	*to++ = state2 >> 8;
	*to++ = state2;
	*to++ = state3 >> 56;
	*to++ = state3 >> 48;
	*to++ = state3 >> 40;
	*to++ = state3 >> 32;
	*to++ = state3 >> 24;
	*to++ = state3 >> 16;
	*to++ = state3 >> 8;
	*to++ = state3;
	*to++ = state4 >> 56;
	*to++ = state4 >> 48;
	*to++ = state4 >> 40;
	*to++ = state4 >> 32;
	*to++ = state4 >> 24;
	*to++ = state4 >> 16;
	*to++ = state4 >> 8;
	*to++ = state4;
	*to++ = state5 >> 56;
	*to++ = state5 >> 48;
	*to++ = state5 >> 40;
	*to++ = state5 >> 32;
	*to++ = state5 >> 24;
	*to++ = state5 >> 16;
	*to++ = state5 >> 8;
	*to++ = state5;
	*to++ = state6 >> 56;
	*to++ = state6 >> 48;
	*to++ = state6 >> 40;
	*to++ = state6 >> 32;
	*to++ = state6 >> 24;
	*to++ = state6 >> 16;
	*to++ = state6 >> 8;
	*to++ = state6;
	*to++ = state7 >> 56;
	*to++ = state7 >> 48;
	*to++ = state7 >> 40;
	*to++ = state7 >> 32;
	*to++ = state7 >> 24;
	*to++ = state7 >> 16;
	*to++ = state7 >> 8;
	*to++ = state7;
}

unsigned SHA512::len() const {
	return 64;
}

MessageDigest * SHA512::clone() const  {
	return new SHA512(*this);
}
