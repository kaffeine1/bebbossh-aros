/*
 * crypto GCM (Galois/Counter Mode) implementation
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
 * Module: GCM (Galois/Counter Mode)
 *
 * @see http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
 * @see http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
 * @see http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf
 *
 * Purpose:
 *  - Provide authenticated encryption using GCM
 *  - Support both encryption and decryption with integrity checks
 *  - Designed for Amiga and cross-platform builds
 *
 * Backend:
 *  - Any implementation of AeadBlockCipher can be used as the block cipher
 *    backend (e.g. AES, Camellia, etc.)
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing
 *  - Ensure nonce/IV uniqueness per key to maintain security guarantees
 * ----------------------------------------------------------------------
 */
#include <string.h>
#include <stdlib.h>

#ifdef __AMIGA__
#include <proto/exec.h>
#else
#define AllocVec(a,b) malloc(a)
#define FreeVec(a) free(a)
#endif

#include "gcm.h"

#undef DEBUG
#ifdef DEBUG
#include "test.h"
#endif

#include "test.h"

/**
 * Shift the byte array v right by 1 bit.
 *
 * @param v
 *            a byte array of length 16.
 * @return true if the lowest bit was set.
 */
#if defined(__AMIGA__)
static inline __attribute__((always_inline))
int shiftRight1Inplace(uint8_t *v) {
	uint32_t * l = (uint32_t *)v;
	register uint32_t d0 asm("d0");
	asm volatile("sub.l d0,d0" : "=d"(d0) : "d"(d0)); // clear x
	d0 = *l;
	asm volatile("roxr.l #1,d0" : "=d"(d0) : "d"(d0));
	*l++ = d0;
	d0 = *l;
	asm volatile("roxr.l #1,d0" : "=d"(d0) : "d"(d0));
	*l++ = d0;
	d0 = *l;
	asm volatile("roxr.l #1,d0" : "=d"(d0) : "d"(d0));
	*l++ = d0;
	d0 = *l;
	asm volatile("roxr.l #1,d0" : "=d"(d0) : "d"(d0));
	*l++ = d0;
	d0 = 0;
	asm volatile("addx.l d0,d0" : "=d"(d0) : "d"(d0));
	return d0;
}
#else
static inline __attribute__((always_inline))
int shiftRight1Inplace(uint8_t *v) {
	uint8_t hi = 0;
	for (int i = 0; i < 16; ++i) {
		uint8_t x = v[i];
		v[i] = (x >> 1) | hi;
		hi = x & 1 ? 0x80 : 0;
	}
	return hi;
}
#endif

/**
 * XOR the byte array from into the byte array to. The byte array to must at least have the length len.
 *
 * @param to
 *            the byte array which is XORed.
 * @param from
 *            the byte array to XOR with.
 * @param len
 *            the length to XOR.
 */
static void xorInplace(uint8_t *to, uint8_t const *from, int len) {
	for (int i = 0; i < len; ++i) {
		*to++ ^= *from++;
	}
}

static inline __attribute__((always_inline))
void memcpy12(void *to_, void const *from_) {
	uint32_t * to = (uint32_t *)to_;
	uint32_t * from = (uint32_t *)from_;
	*to++ = *from++;
	*to++ = *from++;
	*to = *from;
}

static inline __attribute__((always_inline))
void memcpy16(void *to_, void const *from_) {
	uint32_t * to = (uint32_t *)to_;
	uint32_t * from = (uint32_t *)from_;
	*to++ = *from++;
	*to++ = *from++;
	*to++ = *from++;
	*to = *from;
}

static inline __attribute__((always_inline))
void memclr16(void *to_) {
	uint32_t * to = (uint32_t *)to_;
	*to++ = 0;
	*to++ = 0;
	*to++ = 0;
	*to = 0;
}

static inline __attribute__((always_inline))
void xorInplace16(uint8_t *to_, uint8_t const *from_) {
	uint32_t * to = (uint32_t *)to_;
	uint32_t * from = (uint32_t *)from_;
	*to++ ^= *from++;
	*to++ ^= *from++;
	*to++ ^= *from++;
	*to ^= *from;
}

/**
 * Shift the bytes one slot to the right and put the result into b.
 *
 * @param data
 *            the byte array to shift.
 * @return the shifted data.
 */
static uint8_t* shiftRight8(uint8_t const*from, uint8_t * b) {
	b[0] = 0;
	for (int i = 0; i < 15; ++i) {
		b[i + 1] = from[i];
	}
	return b;
}

#define V(a,b,c,d) {0x##a, 0x##b}, {0x##c, 0x##d}
/** The lookup table R to calculate the table m. */
#ifdef __AMIGA__
__attribute((section(".text")))
#endif
const uint8_t GCM::R[256][2] = {
 V(00,00,01,C2), V(03,84,02,46),  V(07,08,06,CA), V(04,8C,05,4E),
 V(0E,10,0F,D2), V(0D,94,0C,56),  V(09,18,08,DA), V(0A,9C,0B,5E),
 V(1C,20,1D,E2), V(1F,A4,1E,66),  V(1B,28,1A,EA), V(18,AC,19,6E),
 V(12,30,13,F2), V(11,B4,10,76),  V(15,38,14,FA), V(16,BC,17,7E),
 V(38,40,39,82), V(3B,C4,3A,06),  V(3F,48,3E,8A), V(3C,CC,3D,0E),
 V(36,50,37,92), V(35,D4,34,16),  V(31,58,30,9A), V(32,DC,33,1E),
 V(24,60,25,A2), V(27,E4,26,26),  V(23,68,22,AA), V(20,EC,21,2E),
 V(2A,70,2B,B2), V(29,F4,28,36),  V(2D,78,2C,BA), V(2E,FC,2F,3E),
 V(70,80,71,42), V(73,04,72,C6),  V(77,88,76,4A), V(74,0C,75,CE),
 V(7E,90,7F,52), V(7D,14,7C,D6),  V(79,98,78,5A), V(7A,1C,7B,DE),
 V(6C,A0,6D,62), V(6F,24,6E,E6),  V(6B,A8,6A,6A), V(68,2C,69,EE),
 V(62,B0,63,72), V(61,34,60,F6),  V(65,B8,64,7A), V(66,3C,67,FE),
 V(48,C0,49,02), V(4B,44,4A,86),  V(4F,C8,4E,0A), V(4C,4C,4D,8E),
 V(46,D0,47,12), V(45,54,44,96),  V(41,D8,40,1A), V(42,5C,43,9E),
 V(54,E0,55,22), V(57,64,56,A6),  V(53,E8,52,2A), V(50,6C,51,AE),
 V(5A,F0,5B,32), V(59,74,58,B6),  V(5D,F8,5C,3A), V(5E,7C,5F,BE),
 V(E1,00,E0,C2), V(E2,84,E3,46),  V(E6,08,E7,CA), V(E5,8C,E4,4E),
 V(EF,10,EE,D2), V(EC,94,ED,56),  V(E8,18,E9,DA), V(EB,9C,EA,5E),
 V(FD,20,FC,E2), V(FE,A4,FF,66),  V(FA,28,FB,EA), V(F9,AC,F8,6E),
 V(F3,30,F2,F2), V(F0,B4,F1,76),  V(F4,38,F5,FA), V(F7,BC,F6,7E),
 V(D9,40,D8,82), V(DA,C4,DB,06),  V(DE,48,DF,8A), V(DD,CC,DC,0E),
 V(D7,50,D6,92), V(D4,D4,D5,16),  V(D0,58,D1,9A), V(D3,DC,D2,1E),
 V(C5,60,C4,A2), V(C6,E4,C7,26),  V(C2,68,C3,AA), V(C1,EC,C0,2E),
 V(CB,70,CA,B2), V(C8,F4,C9,36),  V(CC,78,CD,BA), V(CF,FC,CE,3E),
 V(91,80,90,42), V(92,04,93,C6),  V(96,88,97,4A), V(95,0C,94,CE),
 V(9F,90,9E,52), V(9C,14,9D,D6),  V(98,98,99,5A), V(9B,1C,9A,DE),
 V(8D,A0,8C,62), V(8E,24,8F,E6),  V(8A,A8,8B,6A), V(89,2C,88,EE),
 V(83,B0,82,72), V(80,34,81,F6),  V(84,B8,85,7A), V(87,3C,86,FE),
 V(A9,C0,A8,02), V(AA,44,AB,86),  V(AE,C8,AF,0A), V(AD,4C,AC,8E),
 V(A7,D0,A6,12), V(A4,54,A5,96),  V(A0,D8,A1,1A), V(A3,5C,A2,9E),
 V(B5,E0,B4,22), V(B6,64,B7,A6),  V(B2,E8,B3,2A), V(B1,6C,B0,AE),
 V(BB,F0,BA,32), V(B8,74,B9,B6),  V(BC,F8,BD,3A), V(BF,7C,BE,BE)
};

/**
 * The constructor - needs a <code>BlockCiper</code> instance with block size 16.
 *
 * @param bc
 *            the used block cipher.
 */
GCM::GCM(BlockCipher *_bc) :
		bc(_bc), _m(0), dataLen(0), aadLen(0) {
}

GCM::~GCM() {
	delete bc;
#ifdef __AMIGA__
	struct ExecBase * SysBase = *(struct ExecBase **)4;
#endif
	if (_m) { memset(_m, 0, sizeof(gcm_m_array)); FreeVec(_m); }
}

bool GCM::initM() {
#ifdef __AMIGA__
	struct ExecBase * SysBase = *(struct ExecBase **)4;
#endif
	if (!_m)
		_m = (gcm_m_array*)AllocVec(sizeof(gcm_m_array), MEMF_PUBLIC);
	if (!_m)
		return false;

	gcm_m_array &m = *this->_m;

	// create the lookup table
	uint8_t *b;

	uint32_t ZERO[4] = {0, 0, 0, 0};
	bc->encrypt(m[1][8], ZERO);

	for (unsigned i = 8; i > 1;) {
		b = m[1][i];
		i >>= 1;
		memcpy16(m[1][i], b);
		b = m[1][i];
		if (shiftRight1Inplace(b))
			b[0] ^= 0xe1;
	}

	b = m[0][8];
	memcpy16(b, m[1][1]);

	if (shiftRight1Inplace(b))
		b[0] ^= 0xe1;

	for (int i = 8; i > 1;) {
		b = m[0][i];
		i >>= 1;
		memcpy16(m[0][i], b);
		b = m[0][i];
		if (shiftRight1Inplace(b))
			b[0] ^= 0xe1;
	}

	for (int i = 0; i < 32; ++i) {
		memclr16(m[i][0]);
	}

	for (int i = 0;;) {
		for (int j = 2; j < 16; j += j) {
			for (int k = 1; k < j; ++k) {
				b = m[i][j + k];
				memcpy16(b, m[i][j]);
				xorInplace16(b, m[i][k]);
			}
		}
		if (++i == 32)
			break;
		if (i > 1) {
			for (int j = 8; j > 0; j >>= 1) {
				b = m[i - 2][j];
				int c = b[15] & 0xff;

				b = shiftRight8(b, m[i][j]);
				b[0] ^= R[c][0];
				b[1] ^= R[c][1];
			}
		}
	}

	return true;
}

/**
 * The multiplication with H using the lookup table m;
 *
 * Algorithm2 Computes Z = X · H using the tables M0 and R.
 * Z <- 0
 * for i = 15 to 0 do
 *   Z <- Z (+) M0[byte(X, i)]
 *   A <- byte(X, 15)
 *   for j = 15 to 1 do
 *     byte(X, j) <- byte(X, j - 1)
 *   end for
 *   Z <- Z (+) R[A]
 * end for
 * return Z
 *
 * @param z
 *            the byte array to multiply.
 * @param m
 *            the lookup table.
 */
void mulHInplace(uint8_t *z, gcm_m_array & m) {
	auto mp = &m[0];
	auto zp = &z[0];
	auto zz = *zp++;
	auto b = (*mp++)[zz & 0x0f];
	
	uint8_t tmp[16];
	0[(uint32_t *)tmp] = 0[(uint32_t *)b];
	1[(uint32_t *)tmp] = 1[(uint32_t *)b];
	2[(uint32_t *)tmp] = 2[(uint32_t *)b];
	3[(uint32_t *)tmp] = 3[(uint32_t *)b];

	b = (*mp++)[(zz & 0xf0) >> 4];
	xorInplace16(tmp, b);

	for (int i = 1; i < 16; ++i) {
		zz = *zp++;
		b = (*mp++)[zz & 0x0f];
		xorInplace16(tmp, b);
		b = (*mp++)[(zz & 0xf0) >> 4];
		xorInplace16(tmp, b);
	}
	memcpy16(z, tmp);
}

/**
 * Encrypt the given clearText starting at clearOffset into the cipherText buffer at cipherOffset for the given
 * length. This method also updates the hash value. Note that <code>init(byte [])</code> must have been called.
 *
 * @param clearText
 *            the clear text buffer.
 * @param cipherText
 *            the cipher text buffer.
 * @param length
 *            the length to encrypt.
 */
void GCM::encrypt(void *cipherText_, void const *clearText_, int length) {
	uint8_t tmp[16];
	uint8_t *cipherText = (uint8_t *)cipherText_;
	uint8_t *clearText = (uint8_t *)clearText_;

	for (int len = length;; cipherText += 16, clearText += 16) {
		// next counter
#if (BYTE_ORDER == BIG_ENDIAN)
		++ *(uint32_t*)&nonceCounter[12];
#else
		if (++nonceCounter[15] == 0)
			if (++nonceCounter[14] == 0)
				if (++nonceCounter[13] == 0)
					++nonceCounter[12];
#endif
		bc->encrypt(tmp, nonceCounter);
		// encrypt data
		if ((len -= 16) <= 0) {
			// handle partial data
			len += 16;

			if (len == 16) {
				xorInplace16(tmp, clearText);
				// update hash
				xorInplace16(hash, tmp);
				// copy data
				memcpy16(cipherText, tmp);
				mulHInplace(hash, *_m);
				break;
			}

			xorInplace(tmp, clearText, len);
			// update hash
			xorInplace(hash, tmp, len);
			// copy data
			memcpy(cipherText, tmp, len);
			mulHInplace(hash, *_m);

			break;
		}
		xorInplace16(tmp, clearText);

		// update hash
		xorInplace16(hash, tmp);

		// copy data
		memcpy16(cipherText, tmp);

		mulHInplace(hash, *_m);
	}

	dataLen += length;
}

/**
 * Decrypt the given cipherText starting at cipherOffset into the clearText buffer at clearOffset for the given
 * length. This method also updates the hash value. Note that <code>init(byte [])</code> must have been called.
 *
 * @param clearText
 *            the clear text buffer.
 * @param cipherText
 *            the cipher text buffer.
 * @param length
 *            the length to decrypt.
 */
void GCM::decrypt(void *clearText_, void const *cipherText_, int length) {
	uint8_t tmp[16];
	uint8_t *cipherText = (uint8_t *)cipherText_;
	uint8_t *clearText = (uint8_t *)clearText_;

	for (int i = 0;; cipherText += 16, clearText += 16) {
		// next counter
#if (BYTE_ORDER == BIG_ENDIAN)
		++ *(uint32_t*)&nonceCounter[12];
#else
		if (++nonceCounter[15] == 0)
			if (++nonceCounter[14] == 0)
				if (++nonceCounter[13] == 0)
					++nonceCounter[12];
#endif
		bc->encrypt(tmp, nonceCounter);

		// decrypt data
		int t = i + 16;
		if (t >= length) {
			// handle partial data
			int len = length - i;
			if (len == 16) {
				xorInplace16(tmp, cipherText);
				// update hash
				xorInplace16(hash, cipherText);
				// copy data
				memcpy16(clearText, tmp);
				mulHInplace(hash, *_m);
				break;
			}

			xorInplace(tmp, cipherText, len);
			// update hash
			xorInplace(hash, cipherText, len);
			// copy data
			memcpy(clearText, tmp, len);
			mulHInplace(hash, *_m);
			break;
		}
		i = t;
		xorInplace16(tmp, cipherText);

		// update hash
		xorInplace16(hash, cipherText);

		// copy data
		memcpy16(clearText, tmp);

		mulHInplace(hash, *_m);
	}
	dataLen += length;
}

/**
 * Initialize the data with the nonce. This method allows to reuse the GCM object.
 *
 * @param nonce
 *            a nonce value of 12 bytes.
 */
void GCM::init(void const *nonce, int nonceLength) {
	memclr16(hash);

	dataLen = 0;
	aadLen = 0;

	if (nonceLength == 12) {
		memcpy12(nonceCounter, nonce);
#if (BYTE_ORDER == BIG_ENDIAN)
		3[(uint32_t*)nonceCounter] = 1;
#else
		3[(uint32_t*)nonceCounter] = 0x01000000;
#endif
	} else {
		updateHash(nonce, nonceLength);
#ifdef DEBUG
_dump("hash1", hash, 16);
#endif
		dataLen = aadLen;
		aadLen = 0;
		haschisch();
		memcpy16(nonceCounter, hash);
#ifdef DEBUG
_dump("hash2", nonceCounter, 16);
#endif
		dataLen = 0;
		memclr16(hash);
	}
	memclr16(hash);
	bc->encrypt(cryptedNonceCounter1, nonceCounter);
}

/**
 * This method is used to feed Additional Authenticated Data into the hash.
 *
 * @param aad
 *            the Additional Authenticated Data
 * @param len
 *            the length
 */
void GCM::updateHash(void const *_aad, int len) {
	uint8_t const *aad = (uint8_t const *)_aad;
	aadLen += len;
	for (int i = 0; i < len / 16; ++i) {
		len -= 16;
		xorInplace16(hash, aad);
		mulHInplace(hash, *_m);
		aad += 16;
	}
	// add partial
	len &= 15;
	if (len > 0) {
		xorInplace(hash, aad, len);
		mulHInplace(hash, *_m);
	}
}

/**
 * After encrypt() or decrypt() this method calculates the hash and places it into to at toOffset.
 *
 * @param to
 *            the destination byte array for the hash
 * @param toOffset
 *            the offset into to
 */
void GCM::calcHash(void *to) {
	haschisch();
	memcpy16(to, cryptedNonceCounter1);
	xorInplace16((uint8_t*)to, hash);
}

/** internal hash without cryptedNonceCounter1. */
void GCM::haschisch() {
	uint8_t tmp[16];
	uint64_t pos = aadLen * 8;

	uint32_t hi = (uint32_t) (pos >> 32);
	uint32_t lo = (uint32_t) (pos);
#if (BYTE_ORDER == BIG_ENDIAN)
	0[(uint32_t*)tmp] = hi;
	1[(uint32_t*)tmp] = lo;
#else
	tmp[0] = hi >> 24;
	tmp[1] = hi >> 16;
	tmp[2] = hi >>  8;
	tmp[3] = hi >>  0;
	tmp[4] = lo >> 24;
	tmp[5] = lo >> 16;
	tmp[6] = lo >>  8;
	tmp[7] = lo >>  0;
#endif
	pos = dataLen * 8;

	hi = (uint32_t) (pos >> 32);
	lo = (uint32_t) (pos);
#if (BYTE_ORDER == BIG_ENDIAN)
	2[(uint32_t*)tmp] = hi;
	3[(uint32_t*)tmp] = lo;
#else
	tmp[ 8] = hi >> 24;
	tmp[ 9] = hi >> 16;
	tmp[10] = hi >>  8;
	tmp[11] = hi >>  0;
	tmp[12] = lo >> 24;
	tmp[13] = lo >> 16;
	tmp[14] = lo >>  8;
	tmp[15] = lo >>  0;
#endif
	xorInplace16(hash, tmp);
	mulHInplace(hash, *_m);
}

int GCM::setKey(void const *key, unsigned keylen) {
	if (!bc->setKey(key, keylen))
		return false;

	return initM();
}

void GCM::decrypt(void *clearText, void const *cipherText) {
	// dummy
}
void GCM::encrypt(void *cipherText, void const *clearText) {
	// dummy
}

int GCM::isAAD() const {
	return true;
}

int GCM::blockSize() const {
	return 4;
}
