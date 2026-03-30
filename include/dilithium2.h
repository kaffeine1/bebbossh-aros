/*
 * crypto CRYSTALS-Dilithium2 signature scheme implementation
 *
 * ----------------------------------------------------------------------
 * Project: crypto
 * Purpose: Provide Dilithium2 post-quantum signature scheme.
 *
 * Features:
 *  - Implements SignatureScheme interface
 *  - Public key: 1312 bytes
 *  - Secret key: 2528 bytes
 *  - Signature: 2420 bytes
 *
 * Notes:
 *  - Deterministic, explicit, reproducible.
 * ----------------------------------------------------------------------
 */

#ifndef __DILITHIUM2_H__
#define __DILITHIUM2_H__

#include "signaturescheme.h"

class Dilithium2 : public SignatureScheme {
public:
    Dilithium2();
    virtual ~Dilithium2();

    virtual unsigned publicKeySize() const;
    virtual unsigned secretKeySize() const;
    virtual unsigned signatureSize() const;

    virtual int keygen(void* publicKey, void* secretKey);
    virtual int sign(void* signature,
                     void const* message, unsigned messageLen,
                     void const* secretKey);
    virtual int verify(void const* signature,
                       void const* message, unsigned messageLen,
                       void const* publicKey);
};

#endif // __DILITHIUM2_H__
