/*
 * crypto Ed25519 internal math header
 * Public Domain - based on SUPERCOP reference implementations
 * Adapted and maintained 2024-2025 by Stefan Franke <stefan@franke.ms>
 *
 * You may use, copy, modify, and distribute this file without restriction.
 *
 * ----------------------------------------------------------------------
 * Project: crypto
 * Purpose: Provide internal field and group element operations for Ed25519.
 *
 * Origin & Attribution:
 *  - Based on reference implementations from the SUPERCOP library
 *    (Daniel J. Bernstein, Tanja Lange, Peter Schwabe, et al.)
 *  - SUPERCOP is a benchmarking and cryptographic library that includes
 *    public domain implementations of Ed25519 and X25519.
 *
 * Notes:
 *  - This header defines low-level arithmetic (addition, subtraction,
 *    multiplication, squaring, reduction) and group element structures.
 *  - Functions here are not intended for direct application use; they
 *    support higher-level EdDSA and ECDH operations.
 *  - ed_t is always unsigned:
 *      * On Amiga: ed_t = uint32_t, EDSIZE = 8 (8 × 32-bit limbs = 256 bits)
 *      * Elsewhere: ed_t = uint16_t, EDSIZE = 16 (16 × 16-bit limbs = 256 bits)
 * ----------------------------------------------------------------------
 */

#ifndef __ED25519I_H__
#define __ED25519I_H__

#include <stdint.h>

#ifndef __AMIGA__
#define __regargs
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Platform-dependent limb type and size
#ifdef __AMIGA__
typedef uint32_t ed_t;
#define EDX(a,b) ((uint32_t)((b<<16)|a))
#define EDSIZE 8   // 8 × 32-bit limbs
#else
typedef uint16_t ed_t;
#define EDX(a,b) a,b
#define EDSIZE 16  // 16 × 16-bit limbs
#endif

// A field element is represented as an array of EDSIZE limbs
typedef ed_t ed25519[EDSIZE];

// Group element structures
typedef struct {
    ed25519 x;
    ed25519 y;
    ed25519 z;
    ed25519 t;
} ge25519;

typedef struct {
    ed25519 x;
    ed25519 y;
    ed25519 z;
} ge25519_p2;

// Constant zero field element
extern const ed25519 zero;

// Reduction and conversion
void barrett_reduce(uint16_t r[32], const uint16_t x[64]);     // Reduce 512-bit input to field size
void ed25519_from32bytes(uint16_t r[32], const uint8_t x[32]);
void ed25519_from64bytes(uint16_t r[32], const uint8_t x[64]);

// Scalar multiplication (variable-time, internal use)
void precalc(ge25519 pre[16], ge25519 const *p1);
void ge25519_scalarmult_vartime_base(ge25519 *r, const uint16_t s[32]);
void ge25519_scalarmult_vartime(ge25519 *r, const ge25519 *p, const ed_t s[32]);
void ge25519_scalarmult_vartime_pre(ge25519 *r, const ge25519 pre[16], const uint16_t s1[32]);
void ge25519_scalarmult_vartime2(ge25519 *r, const ge25519 *p1, const uint16_t s1[32], const uint16_t s2[32]);

// Exponentiation helpers
void pow252_2_2(ed_t t0[16], ed_t z11[16], const ed_t z[16]);
void squeeze(uint32_t hi, ed_t a[16]);
void fe25519_pow2523(ed_t *r, const ed_t *x);

// Packing/unpacking
void ge25519_pack(uint8_t r[32], const ge25519 *p);   // Corrected to 32 bytes
void unpack16(ed_t *r, const uint8_t *in);
void pack16(uint8_t *r, const ed_t *in);

// Arithmetic operations
void edadd(ed_t *out, const ed_t *a, const ed_t *b);
void edsub(ed_t *out, const ed_t *a, const ed_t *b);
void edmul(ed_t *out, const ed_t *a, const ed_t *b);
void edmul121665(ed_t *out, const ed_t *a);
void edsquare(ed_t *out, const ed_t *a);

// Group element operations
void add_p1p1(ge25519 *r, const ge25519 *p, const ge25519 *q);
void p1p1_to_p2(ge25519_p2 *r, const ge25519 *p);

// Inversion
void recip16(ed_t *out, const ed_t *z);

// Secret expansion
void secret_expand(uint8_t *az, uint8_t const *sk);

// Inline helpers
static inline void setone(ed_t *r) {
    r[0] = 1;
    for (short i = 1; i < EDSIZE; i++)   // Fixed: loop to EDSIZE, not hardcoded 16
        r[i] = 0;
}

static inline uint8_t fe25519_getparity(const ed25519 x) {
    return x[0] & 1;
}

#ifdef __cplusplus
}
#endif

#endif // __ED25519I_H__
