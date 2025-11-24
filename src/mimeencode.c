/*
 * crypto - MIME/Base64 encoder
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
 * Project: crypto - SSH2 client/server suite for Amiga
 * Purpose: Provide MIME/Base64 encoding routines for key and packet serialization
 *
 * Features:
 *  - Encode arbitrary binary data into Base64 with padding
 *  - Null-terminated output for easy string handling
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing.
 *  - Designed for AmigaOS; optimized for clarity and portability.
 *
 * Author's intent:
 *  Supply a simple, GPL-compliant Base64 encoder for use in
 *  cryptographic key handling and SSH packet formatting.
 * ----------------------------------------------------------------------
 */

__attribute((section(".text")))
const static unsigned char encodeTable[66] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
		
void mimeEncode(void * to_, void const * x_, unsigned length) {
	unsigned char * to = (unsigned char *)to_;
	unsigned char * x = (unsigned char *)x_;
	// read up to 3 bytes - write up to 4 bytes
	for (unsigned i = 0; i < length;) {
		unsigned a, b, c, d;
		a = x[i++];
		if (i < length) {
			b = x[i++];
			if (i < length) {
				c = x[i++];
				d = c & 0x3f;
			} else {
				c = 0;
				d = 0x40;
			}
			c = (c >> 6) | ((b << 2) & 0x3f);
		} else {
			b = 0;
			c = 0x40;
			d = 0x40;
		}
		b = (b >> 4) | ((a << 4) & 0x3f);
		a >>= 2;
		*to++ = encodeTable[a];
		*to++ = encodeTable[b];
		*to++ = encodeTable[c];
		*to++ = encodeTable[d];
	}
	*to++ = 0;
}
