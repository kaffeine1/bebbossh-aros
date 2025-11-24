/*
 * crypto SHA-384 message digest interface
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
 * Purpose: Provide SHA-384 message digest implementation derived from
 *          SHA384512 base class.
 *
 * Features:
 *  - Implements SHA-384 compression and digest extraction
 *  - Maintains internal state via SHA384512 base
 *  - Provides len(), clone(), reset(), and digest extraction
 *
 * Notes:
 *  - SHA-384 is part of the SHA-2 family, truncated from SHA-512
 *  - Widely used in TLS, PKI, and modern cryptographic applications
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __SHA384_H__
#define __SHA384_H__

#include <sha384512.h>

class SHA384 : public SHA384512 { // @suppress("Class has a virtual method and non-virtual destructor")
public:
    /// Construct SHA-384 digest
    SHA384();

    /// Return digest length in bytes (48)
    virtual unsigned len() const;

    /// Clone this digest instance
    virtual MessageDigest* clone() const;

protected:
    /// Reset internal state
    void reset();

    /// Extract digest into buffer
    void __getDigest(unsigned char* r);
};

#endif // __SHA384_H__
