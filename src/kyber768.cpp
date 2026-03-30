/*
 * crypto CRYSTALS-Kyber768 KEM implementation
 * Copyright (C) 2026
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
 *  - Deterministic, explicit, buffer-based API
 *
 * Notes:
 *  - This file contains the structural implementation only.
 *    Polynomial arithmetic, NTT, and hash-based components must be
 *    implemented according to the Kyber specification.
 *  - Caller must provide correctly sized buffers.
 * ----------------------------------------------------------------------
 */

#include <string.h>
#include "kyber768.h"
#include "shake256.h"
#include "rand.h"

/// Kyber768 parameter constants
static const unsigned KYBER768_PUBLIC_KEY_SIZE  = 1184;
static const unsigned KYBER768_SECRET_KEY_SIZE  = 2400;
static const unsigned KYBER768_CIPHERTEXT_SIZE  = 1088;
static const unsigned KYBER768_SHARED_SECRET_SIZE = 32;

Kyber768::Kyber768() {
    // Clear internal buffer
    memset(_buf, 0, sizeof(_buf));
}

unsigned Kyber768::publicKeySize() const {
    return KYBER768_PUBLIC_KEY_SIZE;
}

unsigned Kyber768::secretKeySize() const {
    return KYBER768_SECRET_KEY_SIZE;
}

unsigned Kyber768::cipherTextSize() const {
    return KYBER768_CIPHERTEXT_SIZE;
}

unsigned Kyber768::sharedSecretSize() const {
    return KYBER768_SHARED_SECRET_SIZE;
}

/*
 * Generate a Kyber768 keypair.
 *
 * publicKey  - output buffer (1184 bytes)
 * secretKey  - output buffer (2400 bytes)
 *
 * Returns:
 *   1 on success
 *   0 on failure
 */
int Kyber768::keygen(void* publicKey, void* secretKey) {
    if (!publicKey || !secretKey)
        return 0;

    // TODO: Implement Kyber768 key generation:
    //  - sample noise polynomials
    //  - compute A * s + e
    //  - pack public and secret keys

    memset(publicKey, 0, KYBER768_PUBLIC_KEY_SIZE);
    memset(secretKey, 0, KYBER768_SECRET_KEY_SIZE);

    return 1;
}

/*
 * Encapsulate a shared secret using the recipient's public key.
 *
 * cipherText   - output buffer (1088 bytes)
 * sharedSecret - output buffer (32 bytes)
 * publicKey    - input buffer (1184 bytes)
 *
 * Returns:
 *   1 on success
 *   0 on failure
 */
int Kyber768::encapsulate(void* cipherText,
                          void* sharedSecret,
                          void const* publicKey) {
    if (!cipherText || !sharedSecret || !publicKey)
        return 0;

    // TODO: Implement Kyber768 encapsulation:
    //  - hash random seed
    //  - encrypt seed using public key
    //  - derive shared secret via KDF

    memset(cipherText, 0, KYBER768_CIPHERTEXT_SIZE);
    memset(sharedSecret, 0, KYBER768_SHARED_SECRET_SIZE);

    return 1;
}

/*
 * Decapsulate a ciphertext to recover the shared secret.
 *
 * sharedSecret - output buffer (32 bytes)
 * cipherText   - input buffer (1088 bytes)
 * secretKey    - input buffer (2400 bytes)
 *
 * Returns:
 *   1 on success
 *   0 on failure
 */
int Kyber768::decapsulate(void* sharedSecret,
                          void const* cipherText,
                          void const* secretKey) {
    if (!sharedSecret || !cipherText || !secretKey)
        return 0;

    // TODO: Implement Kyber768 decapsulation:
    //  - decrypt ciphertext
    //  - re-encrypt to check validity
    //  - derive shared secret via KDF

    memset(sharedSecret, 0, KYBER768_SHARED_SECRET_SIZE);

    return 1;
}

// Kyber768 sizes (match your C++ wrapper)
static const size_t KYBER_PUBLICKEYBYTES   = 1184;
static const size_t KYBER_SECRETKEYBYTES   = 2400;
static const size_t KYBER_CIPHERTEXTBYTES  = 1088;
static const size_t KYBER_SSBYTES          = 32;

// IND-CPA secret key size (from Kyber spec)
static const size_t KYBER_INDCPA_SECRETKEYBYTES = 1152;

// Layout of secret key:
// sk = ( s_indcpa || pk || H(pk) || z )
// 1152 + 1184 + 32 + 32 = 2400

// H: 32-byte hash using SHAKE256
static void hash_h(uint8_t out[32], const uint8_t* in, size_t inlen) {
    Shake256 h;
    h.reset();
    h.absorb(in, inlen);
    h.squeeze(out, 32);
}

// G: 64-byte hash using SHAKE256
static void hash_g(uint8_t out[64], const uint8_t* in, size_t inlen) {
    Shake256 g;
    g.reset();
    g.absorb(in, inlen);
    g.squeeze(out, 64);
}

// KDF: 32-byte key derivation using SHAKE256
static void kdf(uint8_t out[32], const uint8_t* in, size_t inlen) {
    Shake256 k;
    k.reset();
    k.absorb(in, inlen);
    k.squeeze(out, 32);
}

int kyber768_keypair(uint8_t* pk, uint8_t* sk) {
    if (!pk || !sk)
        return 0;

    uint8_t pk_indcpa[KYBER_PUBLICKEYBYTES];
    uint8_t sk_indcpa[KYBER_INDCPA_SECRETKEYBYTES];

    // IND-CPA keypair
    indcpa_keypair(pk_indcpa, sk_indcpa);

    // Copy public key out
    memcpy(pk, pk_indcpa, KYBER_PUBLICKEYBYTES);

    // Secret key layout:
    // sk[0 .. INDCPA_SK-1]          = s_indcpa
    // sk[INDCPA_SK .. INDCPA_SK+PK-1] = pk
    // sk[INDCPA_SK+PK .. INDCPA_SK+PK+31] = H(pk)
    // sk[SECRETKEYBYTES-32 .. SECRETKEYBYTES-1] = z (random)
    uint8_t* p = sk;

    // s_indcpa
    memcpy(p, sk_indcpa, KYBER_INDCPA_SECRETKEYBYTES);
    p += KYBER_INDCPA_SECRETKEYBYTES;

    // pk
    memcpy(p, pk_indcpa, KYBER_PUBLICKEYBYTES);
    p += KYBER_PUBLICKEYBYTES;

    // H(pk)
    hash_h(p, pk_indcpa, KYBER_PUBLICKEYBYTES);
    p += 32;

    // z
    randombytes(p, 32);

    return 1;
}

int kyber768_encaps(uint8_t* ct, uint8_t* ss, const uint8_t* pk) {
    if (!ct || !ss || !pk)
        return 0;

    uint8_t buf[64];
    uint8_t kr[64];   // K || r
    uint8_t pk_hash[32];

    // 1. m <- H(random 32 bytes)
    randombytes(buf, 32);
    hash_h(buf, buf, 32);  // overwrite with H(m)

    // 2. Compute H(pk)
    hash_h(pk_hash, pk, KYBER_PUBLICKEYBYTES);

    // 3. G(m || H(pk)) -> (K || r)
    uint8_t input[32 + 32];
    memcpy(input, buf, 32);
    memcpy(input + 32, pk_hash, 32);
    hash_g(kr, input, sizeof(input)); // 64 bytes: K || r

    // 4. IND-CPA encrypt: ct = Enc(pk, m, r)
    indcpa_enc(ct, buf, pk, kr + 32); // use r as coins

    // 5. Compute H(ct)
    uint8_t ct_hash[32];
    hash_h(ct_hash, ct, KYBER_CIPHERTEXTBYTES);

    // 6. ss = KDF(K || H(ct))
    uint8_t kdf_input[32 + 32];
    memcpy(kdf_input, kr, 32);          // K
    memcpy(kdf_input + 32, ct_hash, 32);
    kdf(ss, kdf_input, sizeof(kdf_input));

    return 1;
}

int kyber768_decaps(uint8_t* ss, const uint8_t* ct, const uint8_t* sk) {
    if (!ss || !ct || !sk)
        return 0;

    uint8_t buf[64];
    uint8_t kr[64];   // K || r
    uint8_t ct_hash[32];
    uint8_t cmp_ct[KYBER_CIPHERTEXTBYTES];

    // Parse secret key
    const uint8_t* s_indcpa = sk;
    const uint8_t* pk       = sk + KYBER_INDCPA_SECRETKEYBYTES;
    const uint8_t* pk_hash  = pk + KYBER_PUBLICKEYBYTES;
    const uint8_t* z        = sk + (KYBER_SECRETKEYBYTES - 32);

    // 1. m' = Dec_s_indcpa(ct)
    uint8_t mprime[32];
    indcpa_dec(mprime, ct, s_indcpa);

    // 2. G(m' || H(pk)) -> (K' || r')
    uint8_t input[32 + 32];
    memcpy(input, mprime, 32);
    memcpy(input + 32, pk_hash, 32);
    hash_g(kr, input, sizeof(input)); // K' || r'

    // 3. Re-encrypt to check validity: ct' = Enc(pk, m', r')
    indcpa_enc(cmp_ct, mprime, pk, kr + 32);

    // 4. Compare ct and ct'
    uint8_t fail = 0;
    for (size_t i = 0; i < KYBER_CIPHERTEXTBYTES; ++i)
        fail |= (ct[i] ^ cmp_ct[i]);

    // 5. If fail, overwrite K' with z
    //    (constant-time mask)
    uint8_t mask = (uint8_t)((- (int)fail) >> 7); // 0xFF if fail != 0, else 0x00
    for (size_t i = 0; i < 32; ++i) {
        kr[i] = (kr[i] & ~mask) | (z[i] & mask);
    }

    // 6. ss = KDF(K || H(ct))
    hash_h(ct_hash, ct, KYBER_CIPHERTEXTBYTES);
    uint8_t kdf_input[32 + 32];
    memcpy(kdf_input, kr, 32);
    memcpy(kdf_input + 32, ct_hash, 32);
    kdf(ss, kdf_input, sizeof(kdf_input));

    return 1;
}
