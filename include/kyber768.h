/*
 * crypto CRYSTALS-Kyber768 KEM implementation
 * Copyright (C) 2026  Stefan Franke
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version (GPLv3+).
 *
 * ----------------------------------------------------------------------
 * Project: crypto
 * Purpose: Provide Kyber768 post-quantum key encapsulation mechanism
 *          derived from the Kem base class.
 *
 * Features:
 *  - Implements IND-CCA2 secure Kyber768 KEM
 *  - Provides keygen(), encapsulate(), decapsulate()
 *  - Public key:     1184 bytes
 *  - Secret key:     2400 bytes
 *  - Ciphertext:     1088 bytes
 *  - Shared secret:  32 bytes
 *
 * Notes:
 *  - Deterministic, explicit, buffer-based API
 *  - No dynamic allocation required by the interface
 *  - Caller must provide correctly sized buffers
 * ----------------------------------------------------------------------
 */

#ifndef __KYBER768_H__
#define __KYBER768_H__

#include <kem.h>

class Kyber768 : public Kem { // @suppress("Class has a virtual method and non-virtual destructor")
public:
    /// Construct Kyber768 KEM
    Kyber768();

    /// Return public key size in bytes (1184)
    virtual unsigned publicKeySize() const;

    /// Return secret key size in bytes (2400)
    virtual unsigned secretKeySize() const;

    /// Return ciphertext size in bytes (1088)
    virtual unsigned cipherTextSize() const;

    /// Return shared secret size in bytes (32)
    virtual unsigned sharedSecretSize() const;

    /// Generate a new Kyber768 keypair
    virtual int keygen(void* publicKey, void* secretKey);

    /// Encapsulate: produce ciphertext + shared secret
    virtual int encapsulate(void* cipherText,
                            void* sharedSecret,
                            void const* publicKey);

    /// Decapsulate: recover shared secret from ciphertext
    virtual int decapsulate(void* sharedSecret,
                            void const* cipherText,
                            void const* secretKey);

protected:
    /// Internal working buffer (size depends on implementation)
    unsigned char _buf[4096]; ///< scratch buffer for polynomial ops
};

#endif // __KYBER768_H__
