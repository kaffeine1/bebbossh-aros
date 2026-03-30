#ifndef __POLYVEC_H__
#define __POLYVEC_H__
#include "poly.h"

void polyvec_add(polyvec& r, const polyvec& a, const polyvec& b);
void polyvec_ntt(polyvec& r);
void polyvec_invntt(polyvec& r);
void polyvec_pointwise_acc(poly& r,
                           const polyvec& a,
                           const polyvec& b);
#endif //  __POLYVEC_H__
