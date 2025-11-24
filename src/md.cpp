/*
 * crypto SHA-256 / MessageDigest implementation
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
 * Module: MessageDigest
 *
 * Purpose:
 *  - Support digest(), update(), HMAC, MGF1, EMSA-PSS verification
 *  - Designed for Amiga and cross-platform builds
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing
 *  - This implementation is intended for cryptographic use; ensure correct padding and bit count
 * ----------------------------------------------------------------------
 */
#ifdef __AMIGA__
#include <proto/dos.h>
#include <amistdio.h>
#else
#include <stdio.h>
#endif

#include <string.h>
#include <stdarg.h>
#include <md.h>
#include <log.h>

#undef DEBUG
#ifdef DEBUG
#define _hdump(a,b,c)
#else
#define _hdump(a,b,c)
#endif
#include <test.h>

MessageDigest* MessageDigest::clone() const {
	return 0;
}

void MessageDigest::__getDigest(unsigned char*) {
}
void MessageDigest::transform() {
}
void MessageDigest::reset() {
}

void MessageDigest::digest(void *to_) {
	unsigned char *to = (unsigned char*) to_;
	long bitCount = count << 3;

	unsigned i = ((unsigned) count) & mask;
	data[i++] = (unsigned char) 0x80;
	unsigned end = mask + 1 - ((mask + 1) >> 3);
	if (i > end) {
		for (unsigned k = i; k <= mask; ++k)
			data[k] = 0;
		_hdump("transform1", data, mask + 1);
		transform();
		i = 0;
	}
	for (; i < end; ++i)
		data[i] = 0;

	addBitCount(bitCount);
	_hdump("transformX", data, mask + 1);
	transform();

	__getDigest(to);
	reset();
}

void MessageDigest::addBitCount(uint64_t bitCount) {
	for (int i = 0; i < 8; ++i) {
	    data[mask - i] = (uint8_t)bitCount;
	    bitCount >>= 8;
	}
}

void MessageDigest::update(const void *_d, unsigned len) {
	unsigned char *d = (unsigned char*) _d;
	unsigned k = ((unsigned) count) & mask;
	count += len;
	// still room?
	if (k + len <= mask) {
		memcpy(data + k, d, len);
		return;
	}
	unsigned m1 = mask + 1;
	unsigned n = m1 - k;
	memcpy(data + k, d, n);
	len -= n;
	while (true) {
		_hdump("transformU", data, mask + 1);
		transform();
		if (len <= mask)
			break;
		memcpy(data, d + n, m1);
		len -= m1;
		n += m1;
	}
	memcpy(data, d + n, len);
}

void MessageDigest::hmac(void *to, void const *k, unsigned klen, ...) {
	va_list v;
	va_start(v, klen);
	uint8_t text[mask + 1];
	uint8_t text2[mask + 1];
	reset();
	if (klen >= mask) {
		update(k, klen);
		digest(text);
		klen = len();
	} else {
		memcpy(text, k, klen);
		memset(text + klen, 0, mask + 1 - klen);
	}
	memcpy(text2, text, mask + 1);
#ifdef DEBUG
	_dump("k", k, klen);
#endif
	int i;
	for (i = 0; i < klen; ++i)
		text[i] ^= 0x36;
	for (; i <= mask; ++i)
		text[i] = 0x36;

	_hdump("0x36", x, mask + 1);

	update(text, mask + 1);

	{
	auto s = clone();
	uint8_t x[s->len()];
	s->digest(x);
	_hdump("0x36", x, s->len());
	delete s;
	}

	for (;;) {
		void *p = va_arg(v, void*);
		if (!p)
			break;
		unsigned plen = va_arg(v, unsigned);
		update(p, plen);
	}

	digest(text);
	_hdump("2", text, len());

	for (i = 0; i < klen; ++i)
		text2[i] ^= 0x5c;
	for (; i <= mask; ++i)
		text2[i] = 0x5c;

	update(text2, mask + 1);
	{
	auto s = clone();
	uint8_t x[s->len()];
	s->digest(x);
	_hdump("3", x, s->len());
	delete s;
	}

	_hdump("text", text, len());
	update(text, len());
	{
	auto s = clone();
	uint8_t x[s->len()];
	s->digest(x);
	_hdump("4", x, s->len());
	delete s;
	}

	digest(to);
	va_end(v);
}

void MessageDigest::expandLabel(uint8_t *to, unsigned toLen, uint8_t const *salt, int saltLen, char const *sid, int sidLen, uint8_t const *data, int dataLen) {
	int allLen = 4 + sidLen + dataLen;
	uint8_t all[allLen];

	all[0] = (uint8_t) (toLen >> 8);
	all[1] = (uint8_t) toLen;
	all[2] = (uint8_t) sidLen;
	memcpy(all + 3, sid, sidLen);
	all[sidLen + 3] = (uint8_t) dataLen;
	memcpy(all + 4 + sidLen, data, dataLen);

	expand(to, toLen, salt, saltLen, all, allLen);
}

void MessageDigest::expand(uint8_t *r, int toLen, uint8_t const *salt, int saltLen, uint8_t const *data, int dataLen) {
	uint8_t d[len()];
	int dlen = 0;
	uint8_t c[1] = { 0 };
	for (int off = 0; off < toLen; off += dlen) {
		++c[0];
		hmac(d, salt, saltLen, d, dlen, data, dataLen, c, 1, 0);
		dlen = len();
		int toCopy = toLen - off;
		if (toCopy > dlen)
			toCopy = dlen;
		memcpy(r + off, d, toCopy);
	}
}

unsigned MessageDigest::len() const {
	return 0;
}

void MessageDigest::mgf1(uint8_t *r, int len, uint8_t const *seed, int seedLen) {
	int l = this->len();
	uint8_t c[4] = { 0, 0, 0, 0 };
	for (int off = 0;;) {
		update(seed, seedLen);
		update(c, 4);
		if (off + l > len) {
			uint8_t d[l];
			digest(d);
			memcpy(r + off, d, len - off);
		} else {
			digest(r + off);
		}
		off += l;
		if (off >= len)
			return;

		for (int i = 3; i >= 0; --i)
			if (++c[i] != 0)
				break;
	}
}

static uint8_t Z8[8];

int MessageDigest::emsaPssVerify(uint8_t const *m, int mLen, int emBits, int saltLen, uint8_t *data, int dataLen) {
	logme(L_DEBUG, "emsaPssVerify");
	int l = len();
	int emLen = (emBits + 7) / 8;
	uint8_t mHash[l];

#ifdef DEBUG
	_dump("m", m, mLen);
#endif
	update(m, mLen);
	digest(mHash);
//	_dump("mHash", mHash, l);

	if (saltLen == -1)
		saltLen = l;


	uint8_t h[l];
	memcpy(h, data + dataLen - 1 - l, l);

	int toLen = emLen - l - 1;
	uint8_t dbMask[toLen];
	mgf1(dbMask, toLen, h, l);

	int i = 0;
	for (; i < toLen; ++i)
		data[i] ^= dbMask[i];

#ifdef DEBUG
	_dump("data", data, dataLen);
#endif

	int j = toLen - saltLen - 1;


	if (data[j++] != 1)
		return false;

#ifdef DEBUG
	_dump("Z8", Z8, 8);
	_dump("mHash", mHash, l);
	_dump("salt", data + j, saltLen);
#endif

	update (Z8, 8);
	update(mHash, l);
	update(data + j, saltLen);
	uint8_t h2[l];
	digest(h2);

#ifdef DEBUG
	_dump("h", h, l);
	_dump("h2", h2, l);
#endif

	int r = memcmp(h, h2, l) == 0;
//	printf("emsaPssVerify: %ld\n", r);
	return r;
}
