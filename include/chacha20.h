/*
 * crypto ChaCha20
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
 * Purpose: Provide ChaCha20 stream cipher.
 *
 * Features:
 *  - ChaCha20 stream cipher implementation
 *
 * Notes:
 *  - ChaCha20 provides encryption/decryption of arbitrary-length streams
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __CHACHA20__H__
#define __CHACHA20__H__

#include "bc.h"

/**
 * @class ChaCha20
 * @brief ChaCha20 stream cipher implementation.
 *
 * Provides encryption and decryption of data streams using
 * the ChaCha20 algorithm. Supports nonce setup and block
 * generation for stream output.
 */
class ChaCha20 : public BlockCipher {
    friend class ChaCha20Poly1305_SSH2;
    uint32_t state[16]; ///< Internal state
    uint8_t stream[64];    ///< Current keystream block
    int pos;            ///< Position within stream
public:
    /// Constructor initializes position to end of stream
    ChaCha20();
    virtual ~ChaCha20();

    /// Decrypt data using ChaCha20
    virtual void decrypt(void* clearText, void const* cipherText);

    /// Encrypt data using ChaCha20
    virtual void encrypt(void* cipherText, void const* clearText);

    /// Set key material
    virtual int setKey(void const* key, unsigned keylen);

    /// Return block size (64 uint8_ts for ChaCha20)
    virtual int blockSize() const;

    /// Encrypt/decrypt arbitrary-length stream
    void chacha(void* cipherText, void const* clearText, int length);

    /// Set nonce for stream cipher
    int setNonce(void const* nonce, unsigned nonceLen);

    /// Generate next keystream block
    void nextBlock();

    /// Access current keystream
    inline uint8_t const* getStream() const { return stream; }

    /// Reset counter to initial value
    void zeroCounter() { state[12] = 0xffffffff; }
};

#endif // __CHACHA20__H__
