#ifndef __INDCPA_H__
#define __INDCPA_H__
#include <stdint.h>
#include <stddef.h>

static const unsigned KYBER_K   = 3;      // Kyber768
static const unsigned KYBER_N   = 256;
static const unsigned KYBER_Q   = 3329;

static const unsigned KYBER_SYMBYTES       = 32;
static const unsigned KYBER_POLYBYTES      = 384;
static const unsigned KYBER_POLYVECBYTES   = KYBER_K * KYBER_POLYBYTES;
static const unsigned KYBER_INDCPA_PUBLICKEYBYTES  = KYBER_POLYVECBYTES + KYBER_SYMBYTES;
static const unsigned KYBER_INDCPA_SECRETKEYBYTES  = KYBER_POLYVECBYTES;
static const unsigned KYBER_INDCPA_BYTES           = 32;
static const unsigned KYBER_POLYCOMPRESSEDBYTES    = 128;
static const unsigned KYBER_POLYVECCOMPRESSEDBYTES = KYBER_K * KYBER_POLYCOMPRESSEDBYTES;

struct poly {
    int16_t coeffs[KYBER_N];
};

struct polyvec {
    poly vec[KYBER_K];
};

// IND-CPA API
void indcpa_keypair(uint8_t* pk, uint8_t* sk);
void indcpa_enc(uint8_t* ct,
                const uint8_t* m,
                const uint8_t* pk,
                const uint8_t* coins);
void indcpa_dec(uint8_t* m,
                const uint8_t* ct,
                const uint8_t* sk);
#endif
