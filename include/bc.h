/*
 * crypto BlockCipher interface
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
 * Purpose: Define abstract interfaces for block ciphers and AEAD block ciphers
 *          used within the crypto cryptographic library.
 *
 * Features:
 *  - BlockCipher base class with pure virtual methods for encrypt/decrypt
 *  - Support for key setup and block size reporting
 *  - Optional CBC mode helpers (encryptCBC, decryptCBC)
 *  - AeadBlockCipher subclass with nonce initialization and authentication
 *    support for AEAD (Authenticated Encryption with Associated Data)
 *
 * Notes:
 *  - All cipher implementations must derive from BlockCipher or AeadBlockCipher
 *  - Caller must provide valid key material before encryption/decryption
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __BC_H__
#define __BC_H__

#include <stdint.h>

/**
 * @class BlockCipher
 * @brief Abstract interface for block cipher implementations.
 *
 * Provides pure virtual methods for encryption, decryption, key setup,
 * and block size reporting. Includes optional CBC mode helpers.
 */
class BlockCipher {
public:
    /// Virtual destructor
    virtual ~BlockCipher();

    /// Decrypt a single block
    virtual void decrypt(void* clearText, void const* cipherText) = 0;

    /// Encrypt a single block
    virtual void encrypt(void* cipherText, void const* clearText) = 0;

    /// Set cipher key
    virtual int setKey(void const* key, unsigned keylen) = 0;

    /// Return block size in bytes
    virtual int blockSize() const = 0;

    /// Indicates if cipher supports AAD (default: false)
    virtual int isAAD() const;

    /// Decrypt data in CBC mode
    virtual void decryptCBC(void* iv, void* to, void const* from, unsigned long len);

    /// Encrypt data in CBC mode
    virtual void encryptCBC(void* iv, void* to, void const* from, unsigned long len);
};

/**
 * @class AeadBlockCipher
 * @brief Abstract interface for AEAD block cipher implementations.
 *
 * Extends BlockCipher with methods for nonce initialization, AAD
 * processing, and authentication tag calculation.
 */
class AeadBlockCipher : public BlockCipher {
public:
    /// Virtual destructor
    ~AeadBlockCipher();

    /// Initialize cipher with nonce
    virtual void init(void const* nonce, int nonceLength) = 0;

    /// Update authentication hash with AAD
    virtual void updateHash(void const* aad, int len) = 0;

    /// Calculate authentication tag
    virtual void calcHash(void* to) = 0;

    /// Encrypt multiple blocks with authentication
    virtual void encrypt(void* cipherText, void const* clearText, int length) = 0;

    /// Decrypt multiple blocks with authentication
    virtual void decrypt(void* clearText, void const* cipherText, int length) = 0;
};

#endif // __BC_H__
