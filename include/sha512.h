/*
 * crypto SHA-512 message digest interface
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
 * Purpose: Provide SHA-512 message digest implementation derived from
 *          SHA384512 base class.
 *
 * Features:
 *  - Implements SHA-512 compression and digest extraction
 *  - Maintains internal state via SHA384512 base
 *  - Provides len(), clone(), reset(), and digest extraction
 *
 * Notes:
 *  - SHA-512 is part of the SHA-2 family, widely used in TLS, PKI,
 *    and modern cryptographic applications
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __SHA512_H__
#define __SHA512_H__

#include <sha384512.h>

class SHA512 : public SHA384512 { // @suppress("Class has a virtual method and non-virtual destructor")
public:
    /// Construct SHA-512 digest
    SHA512();

    /// Add data without virtual dispatch. Used by AROS x86_64 startup/runtime workarounds.
    void updateDirect(const void* d, unsigned len);

    /// Finalize without virtual dispatch. Used by AROS x86_64 startup/runtime workarounds.
    void digestDirect(void* to);

    /// Return digest length in bytes (64)
    virtual unsigned len() const;

    /// Clone this digest instance
    MessageDigest* clone() const;

protected:
    /// Reset internal state
    void reset();

    /// Extract digest into buffer
    void __getDigest(unsigned char* r);
};

#endif // __SHA512_H__
