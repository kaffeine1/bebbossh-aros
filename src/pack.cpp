#include "poly.h"
#include <string.h>

// Barrett reduction mod 3329
static inline int16_t barrett_reduce(int16_t a) {
    const int16_t v = ((1u << 26) + KYBER_Q / 2) / KYBER_Q;
    int32_t t = (int32_t)v * a;
    t >>= 26;
    t *= KYBER_Q;
    return a - t;
}

void poly_add(poly& r, const poly& a, const poly& b) {
    for (unsigned i = 0; i < KYBER_N; ++i) {
        int16_t t = a.coeffs[i] + b.coeffs[i];
        r.coeffs[i] = barrett_reduce(t);
    }
}

void poly_sub(poly& r, const poly& a, const poly& b) {
    for (unsigned i = 0; i < KYBER_N; ++i) {
        int16_t t = a.coeffs[i] - b.coeffs[i];
        r.coeffs[i] = barrett_reduce(t);
    }
}

void poly_frommsg(poly& r, const uint8_t m[KYBER_INDCPA_BYTES]) {
    // standard Kyber mapping: each bit -> +/- (q/2)
    for (unsigned i = 0; i < KYBER_N / 8; ++i) {
        for (unsigned j = 0; j < 8; ++j) {
            int16_t mask = -((m[i] >> j) & 1);
            r.coeffs[8 * i + j] = mask & ((KYBER_Q + 1) / 2);
        }
    }
}

void poly_tomsg(uint8_t m[KYBER_INDCPA_BYTES], const poly& a) {
    memset(m, 0, KYBER_INDCPA_BYTES);
    for (unsigned i = 0; i < KYBER_N / 8; ++i) {
        uint8_t b = 0;
        for (unsigned j = 0; j < 8; ++j) {
            int16_t t = a.coeffs[8 * i + j];
            t = barrett_reduce(t);
            // compare to q/2
            t = (t + (KYBER_Q / 4)) / (KYBER_Q / 2);
            t &= 1;
            b |= (uint8_t)t << j;
        }
        m[i] = b;
    }
}

// NTT-related functions are declared here, implemented in ntt.cpp
void poly_ntt(poly& a);
void poly_invntt(poly& a);
void poly_basemul(poly& r, const poly& a, const poly& b);

// CBD (centered binomial) samplers - you fill in the bit-twiddling
static void cbd_eta2(poly& r, const uint8_t* buf) {
    // standard Kyber cbd2 implementation
    // 128 bytes -> 256 coefficients
    // (you can copy from ref, or I can generate if you want)
}

static void cbd_eta1(poly& r, const uint8_t* buf) {
    // standard Kyber cbd3 implementation
}

// noise using Shake256
#include "shake256.h"

void poly_getnoise_eta2(poly& r,
                        const uint8_t seed[KYBER_SYMBYTES],
                        uint8_t nonce) {
    uint8_t buf[128];
    uint8_t in[KYBER_SYMBYTES + 1];
    memcpy(in, seed, KYBER_SYMBYTES);
    in[KYBER_SYMBYTES] = nonce;

    Shake256 xof;
    xof.reset();
    xof.absorb(in, sizeof(in));
    xof.squeeze(buf, sizeof(buf));

    cbd_eta2(r, buf);
}

void poly_getnoise_eta1(poly& r,
                        const uint8_t seed[KYBER_SYMBYTES],
                        uint8_t nonce) {
    uint8_t buf[160]; // cbd3 uses 160 bytes
    uint8_t in[KYBER_SYMBYTES + 1];
    memcpy(in, seed, KYBER_SYMBYTES);
    in[KYBER_SYMBYTES] = nonce;

    Shake256 xof;
    xof.reset();
    xof.absorb(in, sizeof(in));
    xof.squeeze(buf, sizeof(buf));

    cbd_eta1(r, buf);
}
