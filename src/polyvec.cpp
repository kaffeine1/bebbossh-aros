#include "polyvec.h"

void polyvec_add(polyvec& r, const polyvec& a, const polyvec& b) {
    for (unsigned i = 0; i < KYBER_K; ++i)
        poly_add(r.vec[i], a.vec[i], b.vec[i]);
}

void polyvec_ntt(polyvec& r) {
    for (unsigned i = 0; i < KYBER_K; ++i)
        poly_ntt(r.vec[i]);
}

void polyvec_invntt(polyvec& r) {
    for (unsigned i = 0; i < KYBER_K; ++i)
        poly_invntt(r.vec[i]);
}

void polyvec_pointwise_acc(poly& r,
                           const polyvec& a,
                           const polyvec& b) {
    poly tmp;
    // r = sum_i a_i * b_i (NTT domain)
    poly_basemul(r, a.vec[0], b.vec[0]);
    for (unsigned i = 1; i < KYBER_K; ++i) {
        poly_basemul(tmp, a.vec[i], b.vec[i]);
        poly_add(r, r, tmp);
    }
}
