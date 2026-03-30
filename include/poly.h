#ifndef __POLY_H__
#define __POLY_H__
#include "indcpa.h"

// basic poly ops
void poly_add(poly& r, const poly& a, const poly& b);
void poly_sub(poly& r, const poly& a, const poly& b);

// message <-> poly
void poly_frommsg(poly& r, const uint8_t m[KYBER_INDCPA_BYTES]);
void poly_tomsg(uint8_t m[KYBER_INDCPA_BYTES], const poly& a);

// NTT domain ops
void poly_ntt(poly& a);
void poly_invntt(poly& a);
void poly_basemul(poly& r, const poly& a, const poly& b);

// noise
void poly_getnoise_eta2(poly& r,
                        const uint8_t seed[KYBER_SYMBYTES],
                        uint8_t nonce);
void poly_getnoise_eta1(poly& r,
                        const uint8_t seed[KYBER_SYMBYTES],
                        uint8_t nonce);

#endif // __POLY_H__
