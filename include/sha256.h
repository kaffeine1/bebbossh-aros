/*
 * crypto SHA-256 message digest interface
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
 * Purpose: Provide SHA-256 message digest implementation derived from
 *          MessageDigest base class.
 *
 * Features:
 *  - Implements SHA-256 compression function (transform)
 *  - Maintains eight 32-bit state words
 *  - Provides len(), clone(), reset(), and digest extraction
 *
 * Notes:
 *  - SHA-256 is part of the SHA-2 family and widely used in TLS, PKI,
 *    and modern cryptographic applications.
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __SHA256_H__
#define __SHA256_H__

#include <md.h>

class SHA256 : public MessageDigest { // @suppress("Class has a virtual method and non-virtual destructor")
    uint32_t _block[64];                          ///< message schedule buffer
    uint32_t state0, state1, state2, state3;      ///< SHA-256 state words
    uint32_t state4, state5, state6, state7;      ///< SHA-256 state words

public:
    /// Construct SHA-256 digest
    SHA256();

    /// Return digest length in bytes (32)
    virtual unsigned len() const;

    /// Clone this digest instance
    virtual MessageDigest* clone() const;

protected:
    /// SHA-256 compression function
    void transform();

    /// Reset internal state
    void reset();

    /// Extract digest into buffer
    void __getDigest(unsigned char* r);
};

#endif // __SHA256_H__
