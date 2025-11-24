/*
 * ed25519 public domain header
 *
 * This file is released into the public domain.
 * You may use, copy, modify, and distribute it without restriction.
 *
 * ----------------------------------------------------------------------
 * Project: crypto
 * Purpose: Provide Ed25519 and X25519 interfaces for ECDH and EdDSA.
 *
 * Origin & Attribution:
 *  - Based on reference implementations from the SUPERCOP library
 *    (Daniel J. Bernstein, Tanja Lange, Peter Schwabe, et al.)
 *  - SUPERCOP is a benchmarking and cryptographic library that includes
 *    public domain implementations of Ed25519 and X25519.
 *
 * Notes:
 *  - Functions prefixed `fe_` are for ECDH (field element ops).
 *  - Functions prefixed `ge_` are for EdDSA (group element ops).
 * ----------------------------------------------------------------------
 */

#ifndef __ED25519_H__
#define __ED25519_H__

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * visible functions for
 * - ECDH  -> prefix fe
 * - EdDSA -> prefix ge
 */
extern const uint8_t fe_basePoint[32];

/**
 * Create a new key pair.
 * Both buffers need 32 bytes of size.
 */
void fe_new_key_pair(uint8_t *sk, uint8_t *pk);

/**
 * Perform scalar multiplication: scalar * point -> out using X25519 ECDH.
 * All buffers need 32 bytes of size.
 */
void fe_scalarmult_x25519(uint8_t *out, uint8_t const *scalar, const uint8_t *base);

/**
 * Validate the SSH host signature using EdDSA.
 *
 * m:    the data to verify
 * mlen: length of m
 * sig:  the signature
 * pk:   the public key
 */
int ge_verify_ed25519(uint8_t *hash, unsigned mlen, uint8_t const *sig, uint8_t const *pk);

/**
 * Sign a message with the given secret.
 *
 * sm must have 64 bytes allocated.
 */
int ge_sign_ed25519(void *sm, void const *m, unsigned mlen, uint8_t const *secret);

/**
 * Create a new key pair.
 * pk: public key, 32 bytes
 * sk: secret key seed + public key, 64 bytes
 */
void ge_new_keypair_ed25519(unsigned char *pk, unsigned char *sk);

/**
 * Derive public key from expanded secret.
 */
void ge_pubkey(unsigned char *pk, unsigned char const *az);

/**
 * Fill buffer with random bytes.
 */
void randfill(void *, unsigned);

#ifdef __cplusplus
}
#endif

#endif // __ED25519_H__
