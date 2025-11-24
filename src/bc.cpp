/*
 * crypto BlockCipher
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
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing.
 *  - Optimized for Motorola 68000/68020 CPUs with inline assembly support.
 *
 * Author's intent:
 *  Ensure Amiga developers have access to secure, maintainable,
 *  and GPL-compliant cryptographic building blocks.
 * ----------------------------------------------------------------------
 */

#include <string.h>
#include <bc.h>

#include <test.h>

AeadBlockCipher::~AeadBlockCipher() {
}

BlockCipher::~BlockCipher() {
}

int BlockCipher::isAAD() const {
	return false;
}

void BlockCipher::decryptCBC(void *iv, void *_to, void const *_from, unsigned long length) {
	uint8_t *to = (uint8_t*) _to;
	uint8_t const *from = (uint8_t*) _from;
	int bs = blockSize();
	uint8_t tmp[bs];
	uint8_t *iv1 = (uint8_t*) iv;
	uint8_t *iv2 = tmp;
	for (int i = 0; i < length; i += bs, from += bs) {
		memcpy(iv2, from, bs);
		decrypt(to, from);
		for (int j = 0; j < bs; ++j) {
			*to++ ^= iv1[j];
		}
		uint8_t *t = iv1;
		iv1 = iv2;
		iv2 = t;
	}
	if (iv1 != iv)
		memcpy(iv, iv1, bs);

}
void BlockCipher::encryptCBC(void *_iv, void *_to, void const *_from, unsigned long length) {
	uint8_t *to = (uint8_t*) _to;
	uint8_t const *from = (uint8_t*) _from;
	uint8_t *iv = (uint8_t*) _iv;

	int bs = blockSize();

	for (int i = 0; i < length; i += bs, to += bs) {
		for (int j = 0; j < bs; ++j) {
			iv[j] ^= *from++;
		}
		encrypt(to, iv);
		memcpy(iv, to, bs);
	}
}
