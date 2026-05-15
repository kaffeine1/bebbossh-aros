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
 *          combined as ChaCha20-Poly1305 AEAD construction.
 *
 * Features:
 *  - ChaCha20: key setup, nonce setup, block function, stream generation
 *  - Poly1305: key setup, update, digest, modular reduction
 *  - ChaCha20Poly1305: AEAD wrapper with AAD support and authentication
 *
 * Notes:
 *  - Optimized for 32-bit word operations
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */
#include <string.h>
#include "bc.h"
#include "poly1305.h"
#include "fastmath32.h"

#ifdef __AMIGA__
#include <amistdio.h>
#else
#include <stdio.h>
#endif
#include "compat_endian.h"

#undef DEBUG
#ifdef DEBUG
#endif
#include <test.h>

// ---------------- Poly1305 ----------------

int Poly1305::setKey(void const* k, int klen) {
    if (klen != 32)
        return false;
    uint8_t const* b = (uint8_t const*) k;
#ifdef DEBUG
    _dump("poly key", k, klen);
#endif
#if (BYTE_ORDER == BIG_ENDIAN)
    // Treat r and s as byte arrays (20 and 16 bytes via uint32_t views)
    uint8_t* rr = reinterpret_cast<uint8_t*>(r);
    uint8_t* ss = reinterpret_cast<uint8_t*>(s);

    rr[0]  = 0x0f & b[3];  rr[1]  = b[2];  rr[2]  = b[1];  rr[3]  = b[0];
    rr[4]  = 0x0f & b[7];  rr[5]  = b[6];  rr[6]  = b[5];  rr[7]  = 0xfc & b[4];
    rr[8]  = 0x0f & b[11]; rr[9]  = b[10]; rr[10] = b[9];  rr[11] = 0xfc & b[8];
    rr[12] = 0x0f & b[15]; rr[13] = b[14]; rr[14] = b[13]; rr[15] = 0xfc & b[12];

    r[4] = 0;

    ss[0]  = b[19]; ss[1]  = b[18]; ss[2]  = b[17]; ss[3]  = b[16];
    ss[4]  = b[23]; ss[5]  = b[22]; ss[6]  = b[21]; ss[7]  = b[20];
    ss[8]  = b[27]; ss[9]  = b[26]; ss[10] = b[25]; ss[11] = b[24];
    ss[12] = b[31]; ss[13] = b[30]; ss[14] = b[29]; ss[15] = b[28];
#else
    // Little-endian: direct word loads
    const uint32_t* w = reinterpret_cast<const uint32_t*>(b);

    r[0] = w[0] & 0x0fffffff;
    r[1] = w[1] & 0x0ffffffc;
    r[2] = w[2] & 0x0ffffffc;
    r[3] = w[3] & 0x0ffffffc;
    r[4] = 0;

    s[0] = w[4];
    s[1] = w[5];
    s[2] = w[6];
    s[3] = w[7];
#endif

    for (int i = 0; i < 10; ++i) a[i] = 0;
    return true;
}

#if defined(__mc68020__) && !defined(__mc68060__)
extern "C" {
extern void addmodmul(uint32_t* a, uint32_t const* n, uint32_t const* r);
};
#else

#ifdef __AMIGA__
extern "C" void mod5(uint32_t* t);
#else
static inline void mod5(uint32_t* t) {
    uint32_t o = 0;
    for (int i = 5; i >= 0; --i) {
        uint32_t x = t[i + 4];
        t[i + 4] = 0;
        uint32_t add = x >> 2;
        add += o;
        o = x << 30;
        uint64_t c = add;
        c <<= 2;
        c += add;
        for (int j = i; c; ++j) {
            c += t[j];
            t[j] = c;
            c >>= 32;
        }
    }
    t[4] += o >> 30;
    if (t[4] > 3 || (t[4] == 3 && t[3] == 0xffffffff && t[2] == 0xffffffff && t[1] == 0xffffffff && t[0] > 0xfffffffb)) {
        int64_t c = t[0]; c -= 0xfffffffb; t[0] = c;
        c >>= 32; c += t[1]; c -= 0xffffffff; t[1] = c;
        c >>= 32; c += t[2]; c -= 0xffffffff; t[2] = c;
        c >>= 32; c += t[3]; c -= 0xffffffff; t[3] = c;
        c >>= 32; c += t[4]; c -= 3; t[4] = c;
    }
}
#endif

#define addmodmul caddmodmul

void caddmodmul(uint32_t* a, uint32_t const* n, uint32_t const* r) {
    uint32_t t[5];

    uint64_t c = a[0]; c += n[0]; t[0] = c;
    c >>= 32; c += a[1]; c += n[1]; t[1] = c;
    c >>= 32; c += a[2]; c += n[2]; t[2] = c;
    c >>= 32; c += a[3]; c += n[3]; t[3] = c;
    c >>= 32; c += a[4]; c += n[4]; t[4] = c;

    FastMath32::mul(a, t, r, 5);
    mod5(a);
}
#endif

void Poly1305::update(void const* d, int len) {
	uint8_t const* b = (uint8_t const*) d;
#ifdef DEBUG
    _dump("poly update", d, len);
#endif
    uint32_t n[5];
    n[4] = 1;
#if (BYTE_ORDER == BIG_ENDIAN)
    uint8_t * nb = (uint8_t *)n;
#endif
    for (int nn = len / 16; nn > 0; --nn) {
#if (BYTE_ORDER == BIG_ENDIAN)
        // pack 16 bytes into 4 words
        nb[0]  = b[3];  nb[1]  = b[2];  nb[2]  = b[1];  nb[3]  = b[0];
        nb[4]  = b[7];  nb[5]  = b[6];  nb[6]  = b[5];  nb[7]  = b[4];
        nb[8]  = b[11]; nb[9]  = b[10]; nb[10] = b[9];  nb[11] = b[8];
        nb[12] = b[15]; nb[13] = b[14]; nb[14] = b[13]; nb[15] = b[12];
        addmodmul(a, n, r);
#else
        uint32_t const * bl = (uint32_t const*)b;
        n[0] = bl[0];
        n[1] = bl[1];
        n[2] = bl[2];
        n[3] = bl[3];
        addmodmul(a, n, r);
#endif
        b += 16;
    }
    len &= 15;
    if (len > 0) {
        for (int i = 0; i < 4; ++i) {
            if (len >= 4) {
                n[i] = ((uint32_t) b[0]) | ((uint32_t) b[1] << 8) | ((uint32_t) b[2] << 16) | ((uint32_t) b[3] << 24);
            } else if (len == 3) {
                n[i] = ((uint32_t) b[0]) | ((uint32_t) b[1] << 8) | ((uint32_t) b[2] << 16) | 0x1000000;
            } else if (len == 2) {
                n[i] = ((uint32_t) b[0]) | ((uint32_t) b[1] << 8) | 0x10000;
            } else if (len == 1) {
                n[i] = ((uint32_t) b[0]) | 0x100;
            } else {
                n[i] = len == 0 ? 1 : 0;
            }
            b += 4;
            len -= 4;
        }
        n[4] = (len >= 0) ? 1 : 0;
        addmodmul(a, n, r);
    }
}

void Poly1305::digest(void* to) {
    FastMath32::add(a, a, 5, s, 4);
    uint8_t* p = (uint8_t*) to;
    for (int i = 0, j = 0; i < 4; ++i, j += 4) {
        uint32_t t = a[i];
        p[j + 0] = t;
        p[j + 1] = t >> 8;
        p[j + 2] = t >> 16;
        p[j + 3] = t >> 24;
    }
}
