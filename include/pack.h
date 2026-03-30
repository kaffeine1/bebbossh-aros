#ifndef __PACK_H__
#define __PACK_H__
#include "indcpa.h"
#include "poly.h"
#include "polyvec.h"

// pk = (t, seed)
void pack_pk(uint8_t* pk, const polyvec& t, const uint8_t seed[KYBER_SYMBYTES]);
void unpack_pk(polyvec& t, uint8_t seed[KYBER_SYMBYTES], const uint8_t* pk);

// sk = s
void pack_sk(uint8_t* sk, const polyvec& s);
void unpack_sk(polyvec& s, const uint8_t* sk);

// ct = (u, v)
void pack_ciphertext(uint8_t* ct, const polyvec& u, const poly& v);
void unpack_ciphertext(polyvec& u, poly& v, const uint8_t* ct);
#endif //__PACK_H__
