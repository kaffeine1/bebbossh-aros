/*
 * crypto SHA-384/512 message digest base class
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
 * Purpose: Provide SHA-384/512 message digest base implementation
 *          derived from MessageDigest.
 *
 * Features:
 *  - Implements SHA-384/512 compression function (transform)
 *  - Maintains eight 64-bit state words
 *  - Provides addBitCount() for bit length tracking
 *  - Serves as base for SHA-384 and SHA-512 classes
 *
 * Notes:
 *  - SHA-384 is a truncated variant of SHA-512
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __SHA384512_H__
#define __SHA384512_H__

#include <md.h>

class SHA384512 : public MessageDigest { // @suppress("Class has a virtual method and non-virtual destructor")
protected:
    unsigned char data2[64];   ///< working buffer
    uint64_t state0;           ///< SHA state word
    uint64_t state1;
    uint64_t state2;
    uint64_t state3;
    uint64_t state4;
    uint64_t state5;
    uint64_t state6;
    uint64_t state7;
    uint64_t _block[80];       ///< message schedule buffer

public:
    /// Construct SHA-384/512 digest with given size
    explicit SHA384512(int sz);

protected:
    /// SHA-384/512 compression function
    void transform();

    /// Update bit count
    void addBitCount(uint64_t bitCount);
};

#endif // __SHA384512_H__
