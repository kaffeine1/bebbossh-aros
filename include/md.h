/*
 * crypto MessageDigest interface
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
 * Purpose: Provide abstract interface for message digest algorithms
 *          (SHA, MD5, etc.) with HMAC and expansion helpers.
 *
 * Features:
 *  - Virtual interface for digest algorithms
 *  - update() and digest() for incremental hashing
 *  - hmac() helper for keyed hashing
 *  - expandLabel/expand for TLS PRF-style expansion
 *  - mgf1 and EMSA-PSS verification for RSA padding
 *
 * Notes:
 *  - Derived classes must implement transform(), __getDigest(), len()
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __MD_H__
#define __MD_H__

#include <stdint.h>

class MessageDigest { // @suppress("Class has a virtual method and non-virtual destructor")
protected:
    uint64_t count;     ///< bit count processed
    uint32_t mask;      ///< block size mask
    uint8_t data[64];   ///< working buffer

    inline MessageDigest(int sz) : count(0), mask(sz - 1) {}

    /// Update bit count
    virtual void addBitCount(uint64_t bitCount);

    /// Extract digest into buffer
    virtual void __getDigest(unsigned char*);

    /// Transform one block
    virtual void transform();

public:
    /// Clone this digest instance
    virtual MessageDigest* clone() const;

    /// Reset internal state
    virtual void reset();

    /**
     * Add the given part of the unsigned char array to the digest
     *
     * @param d   pointer to data
     * @param len number of bytes to add
     */
    void update(const void* d, unsigned len);

    /// Finalize and write digest to buffer
    void digest(void* to);

    /// Return digest length in bytes
    virtual unsigned len() const;

    /// Compute HMAC with variable arguments
    void hmac(void* to, void const* k, unsigned klen, ...);

    /// Expand label (TLS PRF style)
    void expandLabel(uint8_t* to, unsigned toLen,
                     uint8_t const* salt, int saltLen,
                     char const* sid, int sidLen,
                     uint8_t const* data, int dataLen);

    /// Expand with salt and data
    void expand(uint8_t* r, int toLen,
                uint8_t const* salt, int saltLen,
                uint8_t const* data, int dataLen);

    /// Mask generation function MGF1
    void mgf1(uint8_t* r, int len,
              uint8_t const* seed, int seedLen);

    /// EMSA-PSS verification for RSA signatures
    int emsaPssVerify(uint8_t const* m, int mLen,
                      int emBits, int saltLen,
                      uint8_t* data, int dataLen);
};

#endif // __MD_H__
