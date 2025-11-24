/*
 * crypto AES block cipher interface
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
 * Purpose: Provide AES block cipher functionality as part of the
 *          crypto cryptographic library for Amiga systems.
 *
 * Features:
 *  - AES encryption and decryption of 128-bit blocks
 *  - Key expansion supporting 128-, 192-, and 256-bit keys
 *  - Round key scheduling and inverse key preparation
 *  - Integration with BlockCipher base class
 *
 * Notes:
 *  - AES rounds: 10 (128-bit), 12 (192-bit), 14 (256-bit)
 *  - DB union provides both 32-bit word and byte access to state
 *  - Caller must set key before encrypt/decrypt operations
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __AES_H__
#define __AES_H__

#include <stdint.h>

#ifndef __BC_H__
#include "bc.h"
#endif

/**
 * @class AES
 * @brief AES block cipher implementation for crypto.
 *
 * Provides encryption, decryption, and key scheduling routines
 * for AES with 128-, 192-, and 256-bit keys. Operates on 128-bit
 * blocks and integrates with the BlockCipher base class.
 */
class AES : public BlockCipher {
public:
    /**
     * @union DB
     * @brief Represents AES state as either 4 words or 16 bytes.
     */
    typedef union {
        uint32_t d[4];  ///< 4 x 32-bit words
        uint8_t  b[16]; ///< 16 x 8-bit bytes
    } DB;

private:
    short rounds;   ///< Number of AES rounds (10, 12, or 14 depending on key size)
    uint8_t keyData[(14* 2 + 1) * sizeof(DB)];  ///< Expanded key storage
    DB*   ckey;     ///< Cipher round keys
    DB*   invckey;  ///< Inverse cipher round keys

public:
    /// Constructor initializes members to safe defaults
    AES(int dummy = 0);

    /// Destructor
    virtual ~AES();

    /// Decrypt a 128-bit block
    virtual void decrypt(void* clearText, void const* cipherText);

    /// Encrypt a 128-bit block
    virtual void encrypt(void* cipherText, void const* clearText);

    /// Set AES key and expand round keys
    virtual int setKey(void const* key, unsigned keylen);

    /// Return AES block size (always 16 bytes)
    virtual int blockSize() const;
};

#endif // __AES_H__
