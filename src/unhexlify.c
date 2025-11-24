/*
 * crypto hexlify / unhexlify utility
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
 * Module: hexlify / unhexlify
 *
 * Purpose:
 *  - Provide conversion utilities between binary data and hexadecimal strings
 *  - `unhexlify`: parse hex strings (ignoring whitespace, colons, dashes) into raw bytes
 *  - `hexlify`: convert raw bytes into uppercase hexadecimal string representation
 *
 * Notes:
 *  - Useful for test harnesses and cryptographic vector parsing
 *  - Returns dynamically allocated strings for hexlify (caller must free)
 *  - Designed for Amiga and cross-platform builds
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */
#include <stdlib.h>
#include "unhexlify.h"

void unhexlify(void * _to, char const * from) {
	char * to = (char *)_to;
	for(;;) {
		char v = *from++;
		if (!v) break;
		if (v <= 32 || v == ':' || v == '-')
			continue;
		v |= 0x20;
		char z = (v > '9' ? v - 'a' + 10 : v - '0') << 4;
		v = *from++;
		if (!v) break;
		v |= 0x20;
		z |= v > '9' ? v - 'a' + 10 : v - '0';
		*to++ = z;
	}
}


char * hexlify(void const * from_, int len) {
	char * r = malloc(len*2 + 1);
	char const * p = (char const *)from_;
	char * q = r;

	for (int i = 0; i < len; ++i) {
		char c = *p++;
		int hi = (c >> 4) & 0xf;
		*q++ = hi > 9 ? 'A' -10 + hi : '0' + hi;
		int lo = c & 0xf;
		*q++ = lo > 9 ? 'A' -10 + lo : '0' + lo;
	}
	*q = 0;

	return r;
}
