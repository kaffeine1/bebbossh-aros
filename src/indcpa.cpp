#include "indcpa.h"
#include "poly.h"
#include "polyvec.h"
#include "pack.h"
#include "shake128.h"
#include "shake256.h"
#include <string.h>

// You provide this RNG
extern "C" void randombytes(uint8_t* out, size_t outlen);

// Expand A (or A^T) from seed using Shake128
static void gen_matrix(polyvec A[KYBER_K],
                       const uint8_t seed[KYBER_SYMBYTES],
                       int transposed) {
    uint8_t extseed[KYBER_SYMBYTES + 2];
    memcpy(extseed, seed, KYBER_SYMBYTES);

    for (unsigned i = 0; i < KYBER_K; ++i) {
        for (unsigned j = 0; j < KYBER_K; ++j) {
            unsigned row = transposed ? j : i;
            unsigned col = transposed ? i : j;

            extseed[KYBER_SYMBYTES + 0] = (uint8_t)row;
            extseed[KYBER_SYMBYTES + 1] = (uint8_t)col;

            Shake128 xof;
            xof.reset();
            xof.absorb(extseed, sizeof(extseed));

            uint8_t buf[2 * KYBER_N];
            xof.squeeze(buf, sizeof(buf));

            // rejection sample into A[row].vec[col]
            poly& p = A[i].vec[j];
            unsigned ctr = 0;
            for (unsigned k = 0; k < sizeof(buf) / 2 && ctr < KYBER_N; ++k) {
                uint16_t val = buf[2 * k] | ((uint16_t)buf[2 * k + 1] << 8);
                if (val < 19 * KYBER_Q) {
                    p.coeffs[ctr++] = (int16_t)(val % KYBER_Q);
                }
            }
        }
    }
}

// IND-CPA keypair
void indcpa_keypair(uint8_t* pk, uint8_t* sk) {
    uint8_t seed[KYBER_SYMBYTES];
    uint8_t noise_seed[KYBER_SYMBYTES];
    uint8_t buf[2 * KYBER_SYMBYTES];

    randombytes(buf, sizeof(buf));

    // buf = seed || noise_seed via Shake256
    Shake256 prf;
    prf.reset();
    prf.absorb(buf, sizeof(buf));
    prf.squeeze(buf, sizeof(buf));

    memcpy(seed,       buf,                 KYBER_SYMBYTES);
    memcpy(noise_seed, buf + KYBER_SYMBYTES, KYBER_SYMBYTES);

    polyvec A[KYBER_K];
    gen_matrix(A, seed, 0);

    polyvec s, e, t;

    // sample s, e with eta1
    uint8_t nonce = 0;
    for (unsigned i = 0; i < KYBER_K; ++i)
        poly_getnoise_eta1(s.vec[i], noise_seed, nonce++);
    for (unsigned i = 0; i < KYBER_K; ++i)
        poly_getnoise_eta1(e.vec[i], noise_seed, nonce++);

    polyvec_ntt(s);
    polyvec_ntt(e);

    // t = A * s + e
    for (unsigned i = 0; i < KYBER_K; ++i) {
        polyvec_pointwise_acc(t.vec[i], A[i], s);
        poly_invntt(t.vec[i]);
        poly_add(t.vec[i], t.vec[i], e.vec[i]);
    }

    pack_pk(pk, t, seed);
    pack_sk(sk, s);
}

// IND-CPA encryption
void indcpa_enc(uint8_t* ct,
                const uint8_t* m,
                const uint8_t* pk,
                const uint8_t* coins) {
    polyvec t, r, e1;
    poly v, e2, mpoly;
    uint8_t seed[KYBER_SYMBYTES];

    unpack_pk(t, seed, pk);

    polyvec A[KYBER_K];
    gen_matrix(A, seed, 1); // transposed

    // sample r (eta1), e1 (eta2), e2 (eta2) from coins
    uint8_t nonce = 0;
    for (unsigned i = 0; i < KYBER_K; ++i)
        poly_getnoise_eta1(r.vec[i], coins, nonce++);
    for (unsigned i = 0; i < KYBER_K; ++i)
        poly_getnoise_eta2(e1.vec[i], coins, nonce++);
    poly_getnoise_eta2(e2, coins, nonce++);

    polyvec_ntt(r);

    // u = A^T * r + e1
    polyvec u;
    for (unsigned i = 0; i < KYBER_K; ++i) {
        polyvec_pointwise_acc(u.vec[i], A[i], r);
        poly_invntt(u.vec[i]);
        poly_add(u.vec[i], u.vec[i], e1.vec[i]);
    }

    // v = t^T * r + e2 + m
    polyvec_ntt(t);
    polyvec_pointwise_acc(v, t, r);
    poly_invntt(v);
    poly_add(v, v, e2);

    poly_frommsg(mpoly, m);
    poly_add(v, v, mpoly);

    pack_ciphertext(ct, u, v);
}

// IND-CPA decryption
void indcpa_dec(uint8_t* m,
                const uint8_t* ct,
                const uint8_t* sk) {
    polyvec s, u;
    poly v, mp;

    unpack_sk(s, sk);
    unpack_ciphertext(u, v, ct);

    polyvec_ntt(u);
    polyvec_ntt(s);

    polyvec_pointwise_acc(mp, u, s);
    poly_invntt(mp);

    poly_sub(mp, v, mp);
    poly_tomsg(m, mp);
}
