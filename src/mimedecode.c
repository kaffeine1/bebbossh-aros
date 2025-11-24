/*
 * crypto MIME/Base64 decoder
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
 * Module: mimeDecode
 *
 * Purpose:
 *  - Decode MIME/Base64-encoded data into raw binary
 *  - Handle padding, end-of-line markers, and invalid characters
 *  - Designed for Amiga and cross-platform builds
 *
 * Notes:
 *  - decodeTable maps ASCII characters to Base64 values or EOF/EOL markers
 *  - mimeDecode() reads up to 4 input chars and writes up to 3 output bytes
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#define _EOF 126
#define _EOL 125

#ifdef __AMIGA__
__attribute((section(".text")))
#endif
static const unsigned char decodeTable[128] = {
	_EOF, _EOF, _EOF, _EOF, _EOF, _EOF, _EOF, _EOF, _EOF, _EOF, _EOL, _EOF, _EOF, _EOL, _EOF, _EOF,
	_EOF, _EOF, _EOF, _EOF, _EOF, _EOF, _EOF, _EOF, _EOF, _EOF, _EOF, _EOF, _EOF, _EOF, _EOF, _EOF,
	_EOL, _EOF, _EOF, _EOF, _EOF, _EOF, _EOF, _EOF, _EOF, _EOF, _EOF,  62, _EOF,  62, _EOF, 63,
	 52,  53,  54,  55,  56,  57,  58,  59,  60,  61, _EOF, _EOF, _EOF, _EOF, _EOF, 63,
	_EOF,   0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,
	 15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25, _EOF, _EOF, _EOF, _EOF,  62,
	_EOF,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,
	 41,  42,  43,  44,  45,  46,  47,  48,  49,  50,  51, _EOF, _EOF, _EOF, _EOF, _EOF,
};

int mimeDecode(void * to_, void const * x_, unsigned length) {
	unsigned char * to = (unsigned char *)to_;
	unsigned char * x = (unsigned char *)x_;
	unsigned char * start = to;
	// read up to 4 bytes - write up to 3 bytes
	unsigned i = 0;
	while (i < length) {
		int a, b;
		do {
			int c = x[i++];
			a = c < 128 ? decodeTable[c] : _EOF;
		} while (a == _EOL);
		if (a == _EOF)
			break;

		do {
			int c = x[i++];
			b = c < 128 ? decodeTable[c] : _EOF;
		} while (b == _EOL);
		if (b == _EOF)
			break;
		*to++ = (a << 2) | (b >> 4);

		do {
			int c = x[i++];
			a = c < 128 ? decodeTable[c] : _EOF;
		} while (a == _EOL);
		if (a == _EOF)
			break;
		*to++ = (b << 4) | (a >> 2);

		do {
			int c = x[i++];
			b = c < 128 ? decodeTable[c] : _EOF;
		} while (b == _EOL);
		if (b == _EOF)
			break;
		*to++ = (a << 6) | b;
	}
	return to - start;
}
	
	
