/*
 * crypto Post-Quantum Signature Scheme interface
 * Copyright (C) 2026
 *
 * ----------------------------------------------------------------------
 * Project: crypto
 * Purpose: Provide abstract interface for post-quantum signature schemes
 *          such as CRYSTALS-Dilithium.
 *
 * Features:
 *  - Deterministic, explicit signature interface
 *  - Keypair generation
 *  - Signature creation and verification
 *
 * Notes:
 *  - Derived classes must implement all virtual methods.
 * ----------------------------------------------------------------------
 */

#ifndef __SIGNATURESCHEME_H__
#define __SIGNATURESCHEME_H__

class SignatureScheme {
public:
    virtual ~SignatureScheme() {}

    virtual unsigned publicKeySize() const = 0;
    virtual unsigned secretKeySize() const = 0;
    virtual unsigned signatureSize() const = 0;

    virtual int keygen(void* publicKey, void* secretKey) = 0;

    virtual int sign(void* signature,
                     void const* message, unsigned messageLen,
                     void const* secretKey) = 0;

    virtual int verify(void const* signature,
                       void const* message, unsigned messageLen,
                       void const* publicKey) = 0;
};

#endif // __SIGNATURESCHEME_H__
