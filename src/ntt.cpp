#include "poly.h"

// You need zetas[] and inv_zetas[] from Kyber ref.
// I'm leaving them as extern so you can drop them in a separate table file.

extern const int16_t zetas[128];
extern const int16_t inv_zetas[128];

static inline int16_t fqmul(int16_t a, int16_t b) {
    return 0; //barrett_reduce((int32_t)a * b);
}

void poly_ntt(poly& a) {
    // standard Kyber NTT using zetas[]
    // copy from ref; structure is fixed
}

void poly_invntt(poly& a) {
    // standard Kyber inverse NTT using inv_zetas[]
}

void poly_basemul(poly& r, const poly& a, const poly& b) {
    // standard Kyber basemul in NTT domain
}
