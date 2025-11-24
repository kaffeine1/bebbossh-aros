/*
 * crypto FastMath32 big integer utilities
 * Copyright (C) 1998, 2025  Stefan Franke <stefan@franke.ms>
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
 * Purpose: Provide fast 32-bit integer math routines for modular
 *          arithmetic, exponentiation, and conversions.
 *
 * Features:
 *  - Conversion between byte arrays and integer vectors
 *  - Modular exponentiation and inversion
 *  - Addition, subtraction, multiplication, squaring
 *  - Shifts, comparisons, bit length
 *  - Specialized modular reduction (SecP curves)
 *
 * Notes:
 *  - All methods are static; no instance state
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __FASTMATH_H__
#define __FASTMATH_H__

#include <stdint.h>

#ifndef __BYTEARRAY_H__int
#include <bytearray.h>
#endif

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

typedef mstl::vector<uint32_t> uinta;

class FastMath32 {
public:
    /// Convert byte array to integer vector
    static uinta byte2Int(bytez const& nb, int min);

    /// Modular exponentiation with odd modulus
    static uinta oddModPow(uinta const& z, bytez const& eb, uinta const& mod);

    /// Convert integer array to byte array
    static bytea int2Byte(uint32_t const* r, int rlen, int dlen);

    /// Inline overload for uinta
    static inline bytea int2Byte(uinta const& ssrc, int dlen) {
        return int2Byte(ssrc.begin(), ssrc.size(), dlen);
    }

    /// Negate integer array
    static void neg(uint32_t* u, int len);

    /// Modular inverse
    static void modInverse(uint32_t* res, uint32_t const* a, uint32_t const* m, int modLen);

    /// Square integer array
    static void square(uint32_t* res, uint32_t const* a, short len);

    /// Inline subtraction overload
    static inline int sub(uint32_t* res, uint32_t const* a, uint32_t const* b, int len) {
        return sub(res, a, len, b, len);
    }

    /// Addition
    static int add(uint32_t* res, uint32_t const* a, int alen, uint32_t const* b, int bl);

    /// Subtraction
    static int sub(uint32_t* res, uint32_t const* a, int alen, uint32_t const* b, int bl);

    /// Multiplication
    static void mul(uint32_t* dst, uint32_t const* a, uint32_t const* b, int len);

    /// Modular reduction
    static void xmod(uint32_t* aInOut, uint32_t const* bIn, int al0, int bl);

    /// Specialized modular reduction for SecP curves
    static void modSecP(uint32_t* n, uint32_t const* p, int len);

    /// Shift right
    static void shiftRight(uint32_t* res, uint32_t const* a, int len, int shift);

    /// Shift left
    static void shiftLeft(uint32_t* res, uint32_t const* a, int len, int shift);

    /// Compare arrays
    static int isLessThan(uint32_t const* mod, uint32_t const* t, int ml);

    /// Bit length
    static int bitLength(uint32_t const* m, int l);
};

#endif // __FASTMATH_H__
