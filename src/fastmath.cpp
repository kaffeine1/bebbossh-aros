/*
 * crypto FastMath32 big-integer utilities
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
 * Purpose: Provide 32-bit word-based big integer math routines for
 *          cryptographic primitives (modular arithmetic, Montgomery reduction).
 *          Provide modular reduction (xmod) and precomputation helper (fill)
 *          for Montgomery exponentiation and sliding-window algorithms.
 *
 * Features:
 *  - byte2Int(): convert byte array to uint32_t array
 *  - int2Byte(): convert uint32_t array back to byte array
 *  - modInverse32Odd(): Newton iteration for modular inverse of odd 32-bit values
 *  - bitLength(): compute bit length of big integer
 *  - neg(): two's complement negation
 *  - modInverse(): extended binary GCD modular inverse
 *  - isLessThan(): compare two big integers
 *  - montgomery(): Montgomery reduction
 *  - xsub(): subtraction with carry/borrow
 *  - square(): compute square of big integer
 *  - add(): add two big integers
 *  - sub(): subtract two big integers
 *  - mul(): multiply two big integers
 *  - shiftLeft(): shift big integer left by bit count
 *  - shiftRight(): shift big integer right by bit count
 *  - xmod(): perform modular reduction of a large integer by divisor bIn
 *  - fill(): precompute powers of base for windowed exponentiation
 *  - oddModPow(): compute z^exp mod m using monthomery reduction and
 *    a 4 bit sliding window
 *
 * Notes:
 *  - Designed for Amiga and cross-platform builds
 *  - Contributions must preserve author attribution and GPL licensing
 *  - xmod aligns modulus MSW and performs division steps with correction
 *  - fill builds higher odd powers (n^3, n^5, ... n^15) from lower powers
 * ----------------------------------------------------------------------
 */


#include <string.h>
#include <math.h>

#include "fastmath32.h"
#include "test.h"
#ifdef __AMIGA__
#include <proto/dos.h>
#include <amistdio.h>
#else
#include <stdio.h>
#endif

uinta FastMath32::byte2Int(bytez const &ssrc, int minLen) {
	uint8_t *src = ssrc.begin();
    int i = 0;
    if (i == ssrc.size())
        i = 0;
    int len = ssrc.size() - i;
    if ((len & 3) == 0 && src[i] < 0)
        ++len;
    len = (len + 3) / 4;
    if (len < minLen)
        len = minLen;

    uinta dd(len);
    uint32_t *d = dd.begin();
    memset(d, 0, len * 4);

    for (int k = 0, j = ssrc.size() - 1; k < len && j >= i; ++k) {
        uint32_t v = (src[j--] & 0xff);
        if (j >= 0) v |= ((src[j--] & 0xff) << 8);
        if (j >= 0) v |= ((src[j--] & 0xff) << 16);
        if (j >= 0) v |= ((src[j--] & 0xff) << 24);
        d[k] = v;
    }
    return dd;
}

bytea FastMath32::int2Byte(uint32_t const *ssrc, int slen, int dlen) {
    bytea dst(dlen);
    memset(dst.begin(), 0, dst.size());
    uint32_t const *src = ssrc;

    for (int i = 0, j = dst.size() - 1; i < slen; ++i) {
        uint32_t v = src[i];
        if (j < 0) break;
        dst[j--] = (uint8_t) v;
        v >>= 8;
        if (j < 0) break;
        dst[j--] = (uint8_t) v;
        v >>= 8;
        if (j < 0) break;
        dst[j--] = (uint8_t) v;
        v >>= 8;
        if (j < 0) break;
        dst[j--] = (uint8_t) v;
    }
    return dst;
}

static int32_t modInverse32Odd(int32_t val) {
    int32_t t = val;
    t *= 2 - val * t;
    t *= 2 - val * t;
    t *= 2 - val * t;
    t *= 2 - val * t;
    return -t;
}

int FastMath32::bitLength(uint32_t const * m, int l) {
    while (--l >= 0) {
        int32_t t = m[l];
        if (t == 0) continue;
        int r;
        if (t < 0) {
            r = 32;
        } else {
            r = 0;
            for (;;) {
                switch (t >> 28) {
                case 0: r -= 4; t <<= 4; continue;
                case 1: r += 29; break;
                case 2:
                case 3: r += 30; break;
                case 4: case 5: case 6: case 7: r += 31; break;
                default: r += 32;
                }
                break;
            }
        }
        return l * 32 + r;
    }
    return 0;
}

void FastMath32::neg(uint32_t * u, int modLen) {
    int i = 0;
    while (i < modLen && u[i] == 0) ++i;
    u[i] = -u[i];
    for (++i; i < modLen; ++i) u[i] = ~u[i];
}

void FastMath32::modInverse(uint32_t *res, uint32_t const *a, uint32_t const *p, int len) {
    uint32_t u[len]; memcpy(u, a, len * sizeof(uint32_t));
    uint32_t v[len]; memcpy(v, p, len * sizeof(uint32_t));
    uint32_t x[len]; memset(x, 0, len * sizeof(uint32_t)); x[0] = 1;
    uint32_t y[len]; memset(y, 0, len * sizeof(uint32_t));

    uint32_t p21[len]; shiftRight(p21, p, len, 1);
    uint32_t one[1] = { 1 };
    add(p21, p21, len, one, 1);

    for (;;) {
        if (u[0] == 1 && bitLength(u, len) == 1) { memcpy(res, x, len * sizeof(uint32_t)); return; }
        if (v[0] == 1 && bitLength(v, len) == 1) { memcpy(res, y, len * sizeof(uint32_t)); return; }
        while (0 == (u[0] & 1)) {
            shiftRight(u, u, len, 1);
            int addx = 1 == (x[0] & 1);
            shiftRight(x, x, len, 1);
            if (addx) add(x, x, len, p21, len);
        }
        while (0 == (v[0] & 1)) {
            shiftRight(v, v, len, 1);
            int addy = 1 == (y[0] & 1);
            shiftRight(y, y, len, 1);
            if (addy) add(y, y, len, p21, len);
        }
        if (!isLessThan(u, v, len)) {
            sub(u, u, len, v, len);
            if (sub(x, x, len, y, len)) add(x, x, len, p, len);
        } else {
            sub(v, v, len, u, len);
            if (sub(y, y, len, x, len)) add(y, y, len, p, len);
        }
    }
}

int FastMath32::isLessThan(uint32_t const *a, uint32_t const *b, int ml) {
    int i = ml - 1;
    for (; i >= 0; --i) {
        if (b[i] != a[i]) break;
    }
    return i < 0 || b[i] > a[i];
}

static int overflow(uint32_t const *a, uint32_t const *mod, int al, int divlen) {
    if (al + 1 < divlen && a[al + 1] != 0) return true;
    for (; divlen >= 0; --divlen, --al) {
        if (a[al] != mod[divlen]) break;
    }
    return divlen < 0 || a[al] > mod[divlen];
}

static void montgomery(uint32_t *t, uint32_t const *mod, int ml, uint32_t n0) {
    int ml2 = ml + ml;
    uint64_t carry = 0;
    for (int i = 0; i < ml; ++i) {
        uint32_t m = (uint64_t) n0 * t[i];
        int k = i;
        for (int j = 0; j < ml; ++j, ++k) {
            carry += (t[k]) + (uint64_t) m * (mod[j]);
            t[k] = (uint32_t) carry;
            carry >>= 32;
        }
        for (; carry != 0 && k < ml2; ++k) {
            carry += t[k];
            t[k] = (uint32_t) carry;
            carry >>= 32;
        }
    }

    // shift right by R (ml words)
    {
        int i = 0;
        for (; i < ml; ++i)
            t[i] = t[i + ml];
        for (; i < ml2; ++i)
            t[i] = 0;
    }

    int mustSub = carry != 0;
    if (!mustSub) {
        mustSub = FastMath32::isLessThan(mod, t, ml);
    }
    if (mustSub) {
        FastMath32::sub(t, t, mod, ml);
    }
}

int xsub(uint32_t *res, uint32_t const *a, int al, uint32_t const *b, short bl) {
    int64_t carry = 0;
    int i;
    int to = MIN(al, bl);
    for (i = 0; i < to; ++i) {
        uint32_t t = a[i];
        carry = (carry + t) - b[i];
        res[i] = carry;
        carry >>= 32;
    }
    if (al < bl) {
        for (; i < bl; ++i) {
            carry = carry - b[i];
            res[i] = carry;
            carry >>= 32;
        }
    } else {
        for (; i < al; ++i) {
            uint32_t t = a[i];
            carry = (carry + t);
            res[i] = carry;
            carry >>= 32;
        }
    }
    return (uint32_t) carry != 0;
}

#if !defined(__AMIGA__)

void FastMath32::square(uint32_t *dst, uint32_t const *src, short len) {
    uint32_t *to = dst;
    uint32_t const *from = src;
    for (short i = len - 1; i >= 0; --i) {
        uint32_t s = *from++;
        uint64_t p = (uint64_t) s * s;
        *to++ = p;
        *to++ = p >> 32;
    }

    // add the mixed terms
    from = src;
    for (short i = 0; i < len; ++i) {
        uint32_t l = *from++;
        uint64_t carry = 0;
        uint32_t const *from2 = from;
        short j = i + 1;
        for (; j < len; ++j) {
            int64_t m = (uint64_t) l * *from2++;
            carry += m + m + (dst[i + j]);
            dst[i + j] = carry;
            if (m < 0)
                carry = 0x100000000LL | (carry >> 32);
            else
                carry = (carry >> 32);
        }
        for (; carry != 0; ++j) {
            carry += dst[i + j];
            dst[i + j] = carry;
            carry >>= 32;
        }
    }
}

int FastMath32::add(uint32_t *res, uint32_t const *a, int aLen, uint32_t const *b, int bLen) {
    int64_t carry = 0;
    int i = 0;
    int to = MIN(aLen, bLen);
    for (; i < to; ++i) {
        carry += a[i];
        carry += b[i];
        res[i] = carry;
        carry >>= 32;
    }
    for (; i < aLen; ++i) {
        carry += a[i];
        res[i] = carry;
        carry >>= 32;
    }
    for (; i < bLen; ++i) {
        carry += b[i];
        res[i] = carry;
        carry >>= 32;
    }
    return (uint32_t) carry != 0;
}

int FastMath32::sub(uint32_t *res, uint32_t const *a, int aLen, uint32_t const *b, int bLen) {
    int64_t carry = 0;
    int i = 0;
    int to = MIN(aLen, bLen);
    for (; i < to; ++i) {
        carry += a[i];
        carry -= b[i];
        res[i] = carry;
        carry >>= 32;
    }
    for (; i < aLen; ++i) {
        carry += a[i];
        res[i] = carry;
        carry >>= 32;
    }
    for (; i < bLen; ++i) {
        carry -= b[i];
        res[i] = carry;
        carry >>= 32;
    }
    return (uint32_t) carry != 0;
}

void FastMath32::mul(uint32_t *dst, uint32_t const *a, uint32_t const *b, int len) {
    if (len <= 0)
        return;
    uint64_t carry = 0;
    uint32_t temp = a[0];
    int i = 0;
    for (; i < len; ++i) {
        carry += (uint64_t) temp * b[i];
        dst[i] = (uint32_t) carry;
        carry >>= 32;
    }
    dst[i] = (uint32_t) carry;

    for (int q = 1; q < len; ++q) {
        carry = 0;
        temp = a[q];
        i = q;
        for (int bi = 0; bi < len; ++bi) {
            carry += (uint64_t) temp * b[bi];
            carry += dst[i];
            dst[i++] = (uint32_t) carry;
            carry >>= 32;
        }
        dst[i] = (uint32_t) carry;
    }
}
#endif

void FastMath32::shiftLeft(uint32_t *dst, uint32_t const *src, int len, int shift) {
    uint64_t carry = 0;
    int j = shift >> 5;
    shift &= 31;
    for (int i = 0; i < len; ++i) {
        carry |= ((uint64_t) src[i]) << shift;
        dst[j++] = carry;
        carry >>= 32;
    }
    if (shift)
        dst[j] = carry;
}

void FastMath32::shiftRight(uint32_t *dst, uint32_t const *src, int len, int shift) {
    uint64_t carry = 0;
    int j = len - (shift >> 5) - 1;
    shift &= 31;
    for (int i = len - 1; j >= 0; --i) {
        carry <<= 32;
        carry |= (src[i]);
        dst[j--] = (carry >> shift);
    }
}

void FastMath32::xmod(uint32_t *aInOut, uint32_t const *bIn, int al0, int bl) {
    uint32_t xtemp1[al0 + 2];
    uint32_t xtemp2[al0 + 2];
    uint32_t *temp1 = xtemp1;
    uint32_t *temp2 = xtemp2;

    int al = al0;
    uint32_t *a = aInOut;
    uint32_t const *mod = bIn;

    while (bl > 0) {
        if (mod[bl - 1] != 0)
            break;
        --bl;
    }

    int shift = 0;
    {
        int32_t x = mod[bl - 1];
        if (x < 0)
            shift = 31;
        else {
            while ((x & 0x40000000L) == 0) {
                x += x;
                ++shift;
            }
        }

        if (shift > 0) {
            FastMath32::shiftLeft(temp1, bIn, bl, shift);
            mod = temp1;
            FastMath32::shiftLeft(temp2, aInOut, al, shift);
            a = temp2;

            if (mod[bl] != 0)
                ++bl;
            if (a[al] != 0)
                ++al;
        }
    }
    int divlen = bl - 1;

    uint32_t modMSW = mod[divlen];
    uint64_t modMSW32 = (uint64_t) modMSW << 32;
    uint64_t modLSW = divlen > 0 ? mod[divlen - 1] : 0;
    int al00 = al;
    for (int i = al - bl; i >= 0;) {
        int ai;
        uint32_t a0 = al == al00 ? 0 : a[al];
        int64_t a01 = ((uint64_t) a0 << 32) | (a[--al]);
        if (a01 != 0) {
            uint32_t c0;
            if (a0 == modMSW) {
                c0 = 0xffffffffL;
            } else {
                c0 = a01 / modMSW;
                if (al > 0 && modLSW != 0) {
                    a01 -= (uint64_t) c0 * modMSW;
                    int64_t c0b1 = (uint64_t) c0 * modLSW;
                    a01 = (a01 << 32) | (a[al - 1]);
                    while ((a01 >= 0 && (c0b1 < 0 || a01 < c0b1)) ||
                           (a01 < 0 && c0b1 < 0 && a01 < c0b1)) {
                        --c0;
                        uint64_t t = a01 + modMSW32;
                        c0b1 -= modLSW;
                        if (c0b1 < 0 && a01 < 0 && t >= 0)
                            break;
                        a01 = t;
                    }
                }
            }

            int64_t carry = 0;
            if (c0 > 0) {
                ai = al - divlen;
                for (int bi = 0; bi <= divlen; ++bi) {
                    carry += (uint64_t) c0 * mod[bi];
                    uint32_t t = a[ai];
                    a[ai++] = t - (uint32_t) carry;
                    carry = (((uint64_t) carry) >> 32) + ((uint32_t) carry > t ? 1 : 0);
                }
                if (carry != 0) {
                    carry = a[ai] - carry;
                    a[ai] = carry;
                }
                carry = (int32_t) a[ai];
            }
            if (carry < 0) {
                carry = 0;
                ai = al - divlen;
                for (int bi = 0; bi <= divlen; bi++) {
                    carry += mod[bi];
                    carry += a[ai];
                    a[ai++] = carry;
                    carry = ((uint64_t) carry) >> 32;
                }
                if (carry > 0)
                    a[ai] = a[ai] + carry;
            }
            while (overflow(a, mod, al, divlen)) {
                carry = 0;
                ai = al - divlen;
                for (int bi = 0; bi <= divlen; bi++) {
                    carry += mod[bi];
                    uint32_t t = a[ai];
                    a[ai++] = t - carry;
                    carry = (((uint64_t) carry) >> 32) + ((uint32_t) carry > t ? 1 : 0);
                }
                if (carry != 0) {
                    carry = a[ai] - carry;
                    a[ai] = carry;
                }
            }
        }
        --i;
    }

    if (shift > 0) {
        FastMath32::shiftRight(aInOut, a, al0, shift);
    }
}

static uinta fill(int nibble, uinta *data, int muLen, uint32_t const *mod, int modLen, int n0) {
    uinta x(modLen + modLen + 1);
    uinta *a, *b;

    switch (nibble) {
    case 3: a = &data[1]; b = &data[2]; break;
    case 4: a = b = &data[2]; break;
    case 5:
        if (data[4].size() != 0) { a = &data[1]; b = &data[4]; break; }
        if (data[3].size() == 0) fill(3, data, muLen, mod, modLen, n0);
        a = &data[2]; b = &data[3]; break;
    case 7:
        if (data[6].size() != 0) { a = &data[6]; b = &data[1]; break; }
        if (data[3].size() == 0) fill(3, data, muLen, mod, modLen, n0);
        a = &data[4]; b = &data[3]; break;
    case 9:
        if (data[8].size() != 0) { a = &data[8]; b = &data[1]; break; }
        if (data[6].size() != 0 && data[3].size() != 0) { a = &data[6]; b = &data[3]; }
        if (data[7].size() == 0) fill(7, data, muLen, mod, modLen, n0);
        a = &data[7]; b = &data[2]; break;
    case 11:
        if (data[7].size() != 0 && data[4].size() != 0) { a = &data[7]; b = &data[4]; break; }
        if (data[9].size() == 0) fill(9, data, muLen, mod, modLen, n0);
        a = &data[9]; b = &data[2]; break;
    case 13:
        if (data[12].size() != 0) {
            a = &data[12];
            b = &data[1];
            break;
        }
        if (data[4].size() == 0)
            fill(4, data, muLen, mod, modLen, n0);
        if (data[9].size() == 0)
            fill(9, data, muLen, mod, modLen, n0);
        a = &data[4];
        b = &data[9];
        break;
    case 15:
        if (data[3].size() != 0 && data[12].size() != 0) {
            a = &data[3];
            b = &data[12];
            break;
        }
        if (data[13].size() == 0)
            fill(13, data, muLen, mod, modLen, n0);
        a = &data[2];
        b = &data[13];
        break;
    default:
        a = b = 0;
    }

    FastMath32::mul(x.begin(), a->begin(), b->begin(), muLen);
    montgomery(x.begin(), mod, modLen, n0);
    data[nibble] = x;
    return x;
}

/**
 * Compute z^exp mod mod using Montgomery reduction and a 4-bit sliding window,
 * optimized for odd moduli.
 *
 * Preconditions:
 * - mod[0] must be odd (Montgomery requires n odd). n0 = -n^{-1} mod 2^32.
 * - exp is a big-endian byte array of the exponent (MSB first).
 * - z, mod are little-endian uint32_t limbs (least-significant word first).
 *
 * Algorithm:
 * - Enter Montgomery domain: t0 = z * R mod mod, with R = 2^(32*modLen).
 * - Scan exponent bits with a 4-bit window; lazily precompute odd powers
 *   (n^1, n^3, ..., n^15) into data[] using fill(), mul(), montgomery().
 * - Square for zero runs; multiply by cached odd powers for set windows.
 * - Leave Montgomery domain with montgomery(t0, mod, modLen, n0).
 *
 * Side effects:
 * - Allocates temporary buffers (t0, t1) sized to modLen*2+1 via new/delete.
 *
 * Returns:
 * - uinta containing z^exp mod mod, little-endian limbs.
 */
uinta FastMath32::oddModPow(uinta const &z, bytez const &exp, uinta const &mod) {
	// search highest bit of exponent
	int expLen = exp.size();
	int expi = 0;
	while (expi < expLen) {
		if (exp[expi] != 0)
			break;
		++expi;
	}
	// no bit found --> ONE is the result
	if (expi == expLen) {
		uinta one(1);
		one[0] = 1;
		return one;
	}

	// preload the bits
	uint32_t expBitsLeft;
	int expBits = exp[expi++] << 24;

	// preload more bits
	if (expi < expLen) {
		expBitsLeft = 16;
		expBits |= (exp[expi++] & 0xff) << 16;
	} else {
		// exponent == ONE --> return bz
		if (expBits == 1)
			return z;
		expBitsLeft = 8;
	}

	// shift highest bit into sign bit
	while (expBits > 0) {
		expBits <<= 1;
		--expBitsLeft;
	}

	// eat the highest bit since we start with z
	// and load the next bits on underflow
	expBits <<= 1;
	if (--expBitsLeft == 8 && expi < expLen) {
		expBitsLeft = 16;
		expBits |= (exp[expi++] & 0xff) << 16;
	}

	// expBits now contains 1 to 16 bits

	// ok - we have to calculate something
	int modLen = mod.size();
	int muLen  = modLen;
	if (mod[modLen - 1] == 0)
		--muLen;
	int maxLen = modLen + modLen + 1;
	uinta data[16];

	int n0 = modInverse32Odd(mod[0]);

	// allocate two buffers once
	uinta buf0(z.size() + modLen + 1);
	uinta buf1(maxLen);

	memset(buf0.begin(), 0, buf0.size() * sizeof(uint32_t));
	memcpy(buf0.begin() + modLen, z.begin(), z.size() * sizeof(uint32_t));
	xmod(buf0.begin(), mod.begin(), buf0.size() - 1, modLen);

	/*
	 * Since the highest bit is 1 we start with n.
	 *
	 * then we square while zeros occur
	 *
	 * if we hit 1 we fill a nibble an determine when to multiply
	 *
	 * 1000 : square mul*n - loop covers the squares -> n^2, n^3, n^6, n^12
	 * 1001 : square square square square mul*n^9 -> n^2, n^4, n^8
	 * 1010 : square square square mul*n^5 - lcts -> n^2, n^4, n^8
	 * 1011 : square square square square mul*n^11 -> n^2, n^4, n^8
	 * 1100 : square square mul*n^3 - lcts -> n^2, n^4, n^7
	 * 1101 ; square square square square mul*n^13 -> n^2, n^4, n^8
	 * 1110 ; square square square mul*n^7 - lcts -> n^2, n^4, n^8
	 * 1111 ; square square square square mul*n^15 -> n^2, n^4, n^8
	 *
	 * thus the odd exponents are required since we might not need all of them, we
	 * do lazy evaluation using these rules
	 */

	uinta *t0 = &buf0;   // current
	uinta *t1 = &buf1;   // scratch

	uinta tmp(muLen);
	memset(tmp.begin(), 0, tmp.size() * sizeof(uint32_t));
	memcpy(tmp.begin(), t0->begin(), muLen * sizeof(uint32_t));
	data[1] = tmp;

	int index = 1;
	while (expBitsLeft > 0) {
		// just square
		if (expBits > 0) {
			square(t1->begin(), t0->begin(), muLen);
			montgomery(t1->begin(), mod.begin(), modLen, n0);
			// swap pointers only
			uinta *swap = t0;
			t0 = t1;
			t1 = swap;

			if (index < 16) {
				index += index;
				if (index < 16) {
					data[index] = *t0;
				}
			}

			// and load the next bits on underflow
			expBits <<= 1;
			if (--expBitsLeft == 8 && expi < expLen) {
				expBitsLeft = 16;
				expBits |= (exp[expi++] & 0xff) << 16;
			}
			continue;
		}
		// sign is set in expBits

		// how many bits to handle?
		int n = 4;
		if (expBitsLeft < n)
			n = expBitsLeft;

		// get the bits
		int32_t nibble = (uint32_t) expBits >> (32 - n);
		while (nibble > 0 && (nibble & 1) == 0) {
			nibble >>= 1;
			--n;
		}

		// and load new bits
		if (expi < expLen && expBitsLeft - n <= 8) {
			expBits = (expBits << (expBitsLeft - 8)) | ((exp[expi++] & 0xff) << 16);
			expBits <<= 8 + n - expBitsLeft;
			expBitsLeft += 8;
		} else {
			expBits <<= n;
		}
		expBitsLeft -= n;

		// now square n times
		while (n-- > 0) {
			square(t1->begin(), t0->begin(), muLen);
			montgomery(t1->begin(), mod.begin(), modLen, n0);
			uinta *swap = t0;
			t0 = t1;
			t1 = swap;
			if (index < 16) {
				index += index;
				if (index < 16) {
					data[index] = *t0;
				}
			}
		}

		if (nibble > 0) {
			uinta &x = data[nibble];
			// load the z^x
			if (x.size() == 0) {
				x = fill(nibble, data, muLen, mod.begin(), modLen, n0);
			}
			// and multiply
			mul(t1->begin(), t0->begin(), x.begin(), muLen);
			montgomery(t1->begin(), mod.begin(), modLen, n0);
			uinta *swap = t0;
			t0 = t1;
			t1 = swap;
		}
		if (index < 16) {
			index += nibble;
			if (index < 16) {
				data[index] = *t0;
			}
		}
	}

	montgomery(t0->begin(), mod.begin(), modLen, n0);
	return *t0;
}
