/*
 * crypto Key Encapsulation Mechanism (KEM) interface
 * Copyright (C) 2026  Stefan Franke
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version (GPLv3+).
 *
 * ----------------------------------------------------------------------
 * Project: crypto
 * Purpose: Provide abstract interface for post-quantum key encapsulation
 *          mechanisms (KEM) such as CRYSTALS-Kyber.
 *
 * Features:
 *  - Deterministic, explicit KEM interface
 *  - Keypair generation
 *  - Encapsulation producing ciphertext + shared secret
 *  - Decapsulation producing shared secret
 *
 * Notes:
 *  - Derived classes must implement all virtual methods.
 *  - No dynamic allocation required by the interface.
 * ----------------------------------------------------------------------
 */

#ifndef __KEM_H__
#define __KEM_H__

class Kem {
public:
    virtual ~Kem() {}

    /// Return public key size in bytes
    virtual unsigned publicKeySize() const = 0;

    /// Return secret key size in bytes
    virtual unsigned secretKeySize() const = 0;

    /// Return ciphertext size in bytes
    virtual unsigned cipherTextSize() const = 0;

    /// Return shared secret size in bytes
    virtual unsigned sharedSecretSize() const = 0;

    /// Generate a new keypair
    virtual int keygen(void* publicKey, void* secretKey) = 0;

    /// Encapsulate: produce ciphertext + shared secret
    virtual int encapsulate(void* cipherText,
                            void* sharedSecret,
                            void const* publicKey) = 0;

    /// Decapsulate: recover shared secret from ciphertext
    virtual int decapsulate(void* sharedSecret,
                            void const* cipherText,
                            void const* secretKey) = 0;
};

#endif // __KEM_H__
