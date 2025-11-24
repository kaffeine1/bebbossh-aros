#ifndef __CHACHA20POLY1305_SSH2__H__
#define __CHACHA20POLY1305_SSH2__H__
/* bebbossh - ChaCha20-Poly1305 AEAD for SSH2
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
 * Project: bebbossh - SSH2 client/server suite for Amiga
 * Purpose: Provide an AEAD cipher implementation combining ChaCha20 encryption
 *          with Poly1305 authentication for SSH2 transport
 *
 * Features:
 *  - Implements AeadBlockCipher interface
 *  - Supports encryption/decryption with authentication tags
 *  - Handles nonce initialization and AAD updates
 *
 * Notes:
 *  - Contributions must preserve author attribution and GPL licensing.
 *  - Designed for AmigaOS; explicit resource management and reproducibility.
 *
 * Author's intent:
 *  Deliver a secure, maintainable AEAD cipher for SSH2 sessions
 *  with clear separation of encryption and authentication responsibilities.
 * ----------------------------------------------------------------------
 */


#include "chacha20.h"
#include "poly1305.h"


/**
 * ChaCha20-Poly1305 AEAD implementation for SSH2.
 * Combines ChaCha20 encryption with Poly1305 authentication.
 */
class ChaCha20Poly1305_SSH2 : public AeadBlockCipher {
    ChaCha20 cc;    // ChaCha20 cipher instance
    Poly1305 poly;  // Poly1305 authenticator instance

public:
    ChaCha20Poly1305_SSH2();
    virtual ~ChaCha20Poly1305_SSH2();

    // AeadBlockCipher interface implementation
    virtual int isAAD() const;
    virtual int blockSize() const;

    /**
     * Encrypt and authenticate data.
     * @param cipherText Output buffer for encrypted data
     * @param clearText Input plaintext data
     * @param length Length of data in bytes
     */
    virtual void encrypt(void *cipherText, void const *clearText, int length);

    /**
     * Decrypt and verify data.
     * @param clearText Output buffer for decrypted data
     * @param cipherText Input ciphertext data
     * @param length Length of data in bytes
     */
    virtual void decrypt(void *clearText, void const *cipherText, int length);

    /**
     * Initialize with a nonce.
     * @param nonce Pointer to nonce data
     * @param nonceLength Length of nonce in bytes
     */
    virtual void init(void const *nonce, int nonceLength);

    /**
     * Update with additional authenticated data (AAD).
     * @param aad Pointer to AAD
     * @param len Length of AAD in bytes
     */
    virtual void updateHash(void const *aad, int len);

    /**
     * Compute the authentication tag.
     * @param to Output buffer for the tag
     */
    virtual void calcHash(void *to);

    // BlockCipher interface implementation
    virtual void decrypt(void *clearText, void const *cipherText);
    virtual void encrypt(void *cipherText, void const *clearText);

    /**
     * Set the encryption key.
     * @param key Pointer to key material
     * @param keylen Length of key in bytes
     * @return 0 on success, non-zero on error
     */
    int setKey(void const *key, unsigned keylen);
};

#endif // __CHACHA20POLY1305_SSH2__H__
