/*
 * crypto Galois/Counter Mode (GCM) AEAD interface
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
 * Purpose: Provide Galois/Counter Mode (GCM) authenticated encryption
 *          interface built on AES block cipher.
 *
 * Features:
 *  - AEAD interface with encrypt/decrypt and authentication
 *  - Nonce + counter management
 *  - Hash calculation for AAD and ciphertext
 *  - Lookup tables R and M for fast multiplication
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __GCM__H__
#define __GCM__H__

#include <aes.h>

/// Lookup table type for GCM multiplications
typedef uint8_t gcm_m_array[32][16][16];

class GCM : public AeadBlockCipher {
    /** The lookup table R to calculate the table m. */
    static const uint8_t R[256][2];

    /** The underlying AES block cipher. */
    BlockCipher* bc;

    /** The lookup table M to speed up multiplications. */
    gcm_m_array* _m;

    /** The 12 bytes of nonce plus 4-byte counter. */
    uint8_t nonceCounter[16];

    /** The encrypted nonceCounter at counter == 1. */
    uint8_t cryptedNonceCounter1[16];

    /** The running hash value. */
    uint8_t hash[16];

    /** Length of the data processed. */
    uint64_t dataLen;

    /** Length of Additional Authenticated Data (AAD). */
    uint64_t aadLen;

    /// Initialize multiplication table M
    bool initM();

    /// Internal GHASH function
    void haschisch();

public:
    /// Construct GCM with AES block cipher
    explicit GCM(BlockCipher* _bc);

    /// Virtual destructor
    virtual ~GCM();

    /// Return whether currently processing AAD
    virtual int isAAD() const;

    /// Return block size in bytes
    virtual int blockSize() const;

    /// Encrypt a buffer of given length
    virtual void encrypt(void* cipherText, void const* clearText, int length);

    /// Decrypt a buffer of given length
    virtual void decrypt(void* clearText, void const* cipherText, int length);

    /// Initialize with nonce
    virtual void init(void const* nonce, int nonceLength);

    /// Update hash with AAD
    virtual void updateHash(void const* aad, int len);

    /// Calculate final authentication tag
    virtual void calcHash(void* to);

    /// Encrypt a single block
    virtual void encrypt(void* cipherText, void const* clearText);

    /// Decrypt a single block
    virtual void decrypt(void* clearText, void const* cipherText);

    /// Set AES key
    int setKey(void const* key, unsigned keylen);
};

#endif // __GCM__H__
