/*
 * crypto ChaCha20 / Poly1305 implementation
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
 * Purpose: Provide ChaCha20 stream cipher and Poly1305 authenticator,
 *          combined for SSH.
 *
 * Features:
 *  - ChaCha20Poly1305_SSH2: SSH2 compatible impl.
 *
 * Notes:
 *  - Optimized for 32-bit word operations
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#include <inttypes.h>
#include <bc.h>
#include <chacha20poly1305.h>

#undef DEBUG
#ifdef DEBUG
#endif
#include <test.h>


ChaCha20Poly1305_SSH2::ChaCha20Poly1305_SSH2() {}

ChaCha20Poly1305_SSH2::~ChaCha20Poly1305_SSH2() {
}

int ChaCha20Poly1305_SSH2::setKey(const void *key, unsigned keylen) {
	return cc.setKey(key, keylen);
}

void ChaCha20Poly1305_SSH2::init(const void *nonce, int nonceLength) {
	cc.setNonce(nonce, nonceLength);
	cc.zeroCounter();
	cc.nextBlock();
//	_dump("polykey", cc.getStream(), 32);
	poly.setKey(cc.getStream(), 32);
	cc.pos = 64;
}

void ChaCha20Poly1305_SSH2::decrypt(void*, void const*) {
	// not used
}

void ChaCha20Poly1305_SSH2::encrypt(void*, void const*) {
	// not used
}

int ChaCha20Poly1305_SSH2::blockSize() const {
	return 1;
}

int ChaCha20Poly1305_SSH2::isAAD() const {
	return true;
}

void ChaCha20Poly1305_SSH2::updateHash(void const *d_, int sz) {
	poly.update(d_, sz);
}

void ChaCha20Poly1305_SSH2::calcHash(void *to) {
	poly.digest(to);
}


void ChaCha20Poly1305_SSH2::encrypt(void *cipher, void const *clear, int len) {
	cc.chacha(cipher, clear, len);
}

void ChaCha20Poly1305_SSH2::decrypt(void *clear, void const *cipher, int len) {
	cc.chacha(clear, cipher, len);
}

/*
 *
 */

