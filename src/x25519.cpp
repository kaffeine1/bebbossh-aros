/*
 * crypto Ed25519 / X25519 arithmetic (SUPERCOP-derived)
 * Public Domain - originally from SUPERCOP / djb's ed25519 reference code
 * Adapted and maintained 2024-2025 by Stefan Franke <stefan@franke.ms>
 *
 * This file is placed in the public domain. You may use, copy, modify,
 * and distribute it without restriction.
 *
 * ----------------------------------------------------------------------
 * Project: crypto
 * Module: ed25519i.cpp (field arithmetic, scalar multiplication, key generation)
 *
 * Purpose:
 *  - Provide low-level arithmetic for Ed25519 and X25519
 *  - Implement addition, subtraction, multiplication, squaring, and constant multiplication (121665)
 *  - Support unpacking/packing of field elements
 *  - Implement pow2523, recip16, and scalar multiplication routines
 *  - Provide key pair generation using clamped private keys
 *
 * Notes:
 *  - Based on SUPERCOP's public domain ed25519 implementation
 *  - Amiga-specific assembly paths included for optimized add/sub
 *  - Cross-platform C fallback provided for portability
 *  - `fe_scalarmult_x25519` performs Diffie-Hellman scalar multiplication
 *  - `fe_new_key_pair` generates a random clamped private key and corresponding public key
 * ----------------------------------------------------------------------
 */
#include <inttypes.h>
#include <ed25519i.h>
#include <sha256.h>
#include <rand.h>
#include <test.h>

extern "C" {

static const uint8_t fe_basePoint[32] = { 9 };
const ed_t neg[EDSIZE] = { EDX(19, 0), EDX(0, 0), EDX(0, 0), EDX(0, 0), EDX(0, 0), EDX(0, 0), EDX(0, 0), EDX(0, 0x8000) };
static const ed_t pos[EDSIZE] = { EDX(0x10000 - 20, 0xffff), EDX(0xffff, 0xffff), EDX(0xffff, 0xffff), EDX(0xffff, 0xffff), EDX(0xffff, 0xffff), EDX(0xffff, 0xffff), EDX(0xffff, 0xffff), EDX(0xffff, 0x7fff)};


#if defined(__mc68000__)

void edadd(ed_t *out , const ed_t *a, const ed_t *b) {
	ed_t d0, d1;

#define K0 "move.l (%1)+,%0\n\tadd.l (%2)+,%0\n\tmove.l %0,(%3)+\n"
#define K  "\tmove.l (%1)+,%0\n\tmove.l (%2)+,%4\n\taddx.l %4,%0\n\tmove.l %0,(%3)+\n"
#define K1 "\tmove.l (%1),%0\n\tmove.l (%2),%4\n\taddx.l %4,%0\n\tmove.l %0,(%3)\n"
	asm volatile(K0 K K K K K K K1 :
    		"=d"(d0), "+a"(a), "+a"(b), "+a"(out), "=d"(d1), "=m"(*out): "m"(*a), "m"(*b));
#undef K
#undef K0
#undef K1

	if (d0 & 0x80000000) {
		edadd(out - 7, out - 7, neg);
	}
}

void edsub(ed_t *out, const ed_t *a, const ed_t *b) {
	ed_t d0, d1;

#define K0 "move.l (%1)+,%0\n\tsub.l (%2)+,%0\n\tmove.l %0,(%3)+\n"
#define K  "\tmove.l (%1)+,%0\n\tmove.l (%2)+,%4\n\tsubx.l %4,%0\n\tmove.l %0,(%3)+\n"
#define K1 "\tmove.l (%1),%0\n\tmove.l (%2),%4\n\tsubx.l %4,%0\n\tmove.l %0,(%3)\n"
	asm volatile(K0 K K K K K K K1 :
    		"=d"(d0), "+a"(a), "+a"(b), "+a"(out), "=d"(d1), "=m"(*out): "m"(*a), "m"(*b));
#undef K
#undef K0
#undef K1

  if (d0 & 0x80000000) {
		edsub(out - 7, out - 7, neg);
	}
}
#else

void edadd(ed_t *out, const ed_t *a, const ed_t *b) {
  uint32_t c = 0;
#define L c += (uint32_t)(*a++); c += (uint32_t)(*b++); *out++ = (ed_t)c; c >>= 16;
  L L L L L L L L
  L L L L L L L
  c += (uint32_t)(*a++); c += (uint32_t)(*b++); *out = (ed_t)c;
  if (c & 0x8000u) { edadd(out - 15, out - 15, neg); }
#undef L
}

void edsub(ed_t *out, const ed_t *a, const ed_t *b) {
  int32_t c = 0; // subtraction needs signed accumulator for borrow
#define L c += (int32_t)(*a++); c -= (int32_t)(*b++); *out++ = (ed_t)c; c >>= 16;
  L L L L L L L L
  L L L L L L L
  c += (int32_t)(*a++); c -= (int32_t)(*b++); *out = (ed_t)c;
  if ((uint32_t)c & 0x8000u) { edsub(out - 15, out - 15, neg); }
#undef L
}

#include <stdint.h>
#include <string.h>

void edmul(ed_t *out, const ed_t *a, const ed_t *b) {
  uint64_t u = 0;
  for (int i = 0; i < 16; ++i) {
    u >>= 16;
    const uint16_t *aj = a;
    const uint16_t *bij = b + i + 1;
    for (int j = i; j >= 0; --j) {
      uint64_t av = (uint64_t)(*aj++);
      uint64_t bv = (uint64_t)(*--bij);
      u += av * bv;
    }
    bij = b + 16;
    for (int j = i + 1; j < 16; ++j) {
      uint64_t av = (uint64_t)(*aj++);
      uint64_t bv = (uint64_t)(*--bij);
      u += 38ULL * (av * bv);
    }
    out[i] = (ed_t)u;
  }
  // squeeze...
  u >>= 15;
  if (u) {
    u *= 19ULL;
    out[15] = (ed_t)(out[15] & 0x7fffu);
    for (int j = 0; j < 15; ++j) {
      u += (uint64_t)out[j];
      out[j] = (ed_t)u;
      u >>= 16;
    }
    u += (uint64_t)out[15];
    out[15] = (ed_t)u;
  }
}

void edmul121665(ed_t *out, const ed_t *a) {
	// 121665 = 0x1DB41
	static ed_t u[16] = {
			0xdb41, 0x0001, 0, 0,
			0, 0, 0, 0,
			0, 0, 0, 0,
			0, 0, 0, 0
	};
	edmul(out, a, u);
}

void edsquare(ed_t *out, const ed_t *a) {
	edmul(out, a, a);
}

#endif

void unpack16(ed_t *r, const uint8_t *in) {
#ifdef __mc68000__
    // 8 × 32-bit limbs
    for (short i = 0; i < EDSIZE; i++) {
        uint32_t x = (uint32_t)in[0]
                   | ((uint32_t)in[1] << 8)
                   | ((uint32_t)in[2] << 16)
                   | ((uint32_t)in[3] << 24);
        r[i] = x;
        in += 4;
    }
    r[EDSIZE-1] &= 0x7fffffffU;
#else
    // 16 × 16-bit limbs
    for (short i = 0; i < EDSIZE; i++) {
        uint16_t x = (uint16_t)in[0]
                   | ((uint16_t)in[1] << 8);
        r[i] = x;
        in += 2;
    }
    r[EDSIZE-1] &= 0x7fffU;
#endif
}

void pack16(uint8_t *r, const ed_t *in) {
#ifdef __mc68000__
    // 8 × 32-bit limbs
    for (short i = 0; i < EDSIZE; i++) {
        uint32_t x = in[i];
        r[0] = (uint8_t)(x);
        r[1] = (uint8_t)(x >> 8);
        r[2] = (uint8_t)(x >> 16);
        r[3] = (uint8_t)(x >> 24);
        r += 4;
    }
#else
    // 16 × 16-bit limbs
    for (short i = 0; i < EDSIZE; i++) {
        uint16_t x = in[i];
        r[0] = (uint8_t)(x);
        r[1] = (uint8_t)(x >> 8);
        r += 2;
    }
#endif
}

void pow252_2_2(ed_t *t0, ed_t *z11, const ed_t *z) {
	ed_t temp1[16], temp2[16], temp3[16], temp4[16], temp5[16];
#define z2_5_0  temp1
#define z2_50_0 temp2
#define t1		temp3

	int i;

#define z2		temp4
#define z9		temp5
	/* 2 */edsquare(z2, z);
	/* 4 */edsquare(t1, z2);
	/* 8 */edsquare(t0, t1);
	/* 9 */edmul(z9, t0, z);
	/* 11 */edmul(z11, z9, z2);
	/* 22 */edsquare(t0, z11);
	/* 2^5 - 2^0 = 31 */edmul(z2_5_0, t0, z9);

	/* 2^6 - 2^1 */edsquare(t0, z2_5_0);
	/* 2^7 - 2^2 */edsquare(t1, t0);
	/* 2^8 - 2^3 */edsquare(t0, t1);
	/* 2^9 - 2^4 */edsquare(t1, t0);
	/* 2^10 - 2^5 */edsquare(t0, t1);
#define z2_10_0		temp4
#define z2_20_0		temp5
	/* 2^10 - 2^0 */edmul(z2_10_0, t0, z2_5_0);

	/* 2^11 - 2^1 */edsquare(t0, z2_10_0);
	/* 2^12 - 2^2 */edsquare(t1, t0);
	/* 2^20 - 2^10 */for (i = 2; i < 10; i += 2) {
		edsquare(t0, t1);
		edsquare(t1, t0);
	}
	/* 2^20 - 2^0 */edmul(z2_20_0, t1, z2_10_0);

	/* 2^21 - 2^1 */edsquare(t0, z2_20_0);
	/* 2^22 - 2^2 */edsquare(t1, t0);
	/* 2^40 - 2^20 */for (i = 2; i < 20; i += 2) {
		edsquare(t0, t1);
		edsquare(t1, t0);
	}
	/* 2^40 - 2^0 */edmul(t0, t1, z2_20_0);

	/* 2^41 - 2^1 */edsquare(t1, t0);
	/* 2^42 - 2^2 */edsquare(t0, t1);
	/* 2^50 - 2^10 */for (i = 2; i < 10; i += 2) {
		edsquare(t1, t0);
		edsquare(t0, t1);
	}
	/* 2^50 - 2^0 */edmul(z2_50_0, t0, z2_10_0);

	/* 2^51 - 2^1 */edsquare(t0, z2_50_0);
	/* 2^52 - 2^2 */edsquare(t1, t0);
	/* 2^100 - 2^50 */for (i = 2; i < 50; i += 2) {
		edsquare(t0, t1);
		edsquare(t1, t0);
	}
#define z2_100_0		temp4
	/* 2^100 - 2^0 */edmul(z2_100_0, t1, z2_50_0);

	/* 2^101 - 2^1 */edsquare(t1, z2_100_0);
	/* 2^102 - 2^2 */edsquare(t0, t1);
	/* 2^200 - 2^100 */for (i = 2; i < 100; i += 2) {
		edsquare(t1, t0);
		edsquare(t0, t1);
	}
	/* 2^200 - 2^0 */edmul(t1, t0, z2_100_0);

	/* 2^201 - 2^1 */edsquare(t0, t1);
	/* 2^202 - 2^2 */edsquare(t1, t0);
	/* 2^250 - 2^50 */for (i = 2; i < 50; i += 2) {
		edsquare(t0, t1);
		edsquare(t1, t0);
	}
	/* 2^250 - 2^0 */edmul(t0, t1, z2_50_0);

	/* 2^251 - 2^1 */edsquare(t1, t0);
	/* 2^252 - 2^2 */edsquare(t0, t1);
}

void fe25519_pow2523(ed_t *r, const ed_t *x) {
	ed_t t[16];
	ed_t z11[16];

	pow252_2_2(t, z11, x);

	/* 2^252 - 3 */edmul(r, t, x);
}

void recip16(ed_t *out, const ed_t *z) {
	ed_t t0[16];
	ed_t z11[16];

	pow252_2_2(t0, z11, z);

	ed_t t1[16];

	/* 2^253 - 2^3 */edsquare(t1, t0);
	/* 2^254 - 2^4 */edsquare(t0, t1);
	/* 2^255 - 2^5 */edsquare(t1, t0);
	/* 2^255 - 21 */edmul(out, t1, z11);
}

#ifdef __mc68000__
typedef int32_t ptr_t;
#else
typedef long long ptr_t;
#endif

static void mainloop(ed_t *xa, ed_t *xb, const uint8_t e[32]) {
	ed_t xzm1[16 * 2];
	ed_t xzm[16 * 2];

	ed_t *xzmb;
	ed_t *xzm1b;

	ed_t a0[16 * 2];
	ed_t a1[16 * 2];
	ed_t b0[16 * 2];
	ed_t c1[16 * 2];
	ed_t j;
	ed_t f;
	int pos;

	for (j = 0; j < 16; ++j)
		xzm1[j] = xa[j];
	xzm1[16] = 1;
	for (j = 16 + 1; j < 16 * 2; ++j)
		xzm1[j] = 0;

	xzm[0] = 1;
	for (j = 1; j < 16 * 2; ++j)
		xzm[j] = 0;

	for (pos = 254; pos >= 0; --pos) {
		f = e[pos / 8] >> (pos & 7);
		f &= 1;

		ptr_t mask = (ptr_t)f - 1; // 0 if b is true,0xffffffff if b is false
		ptr_t a = (ptr_t) xzm ^ ((ptr_t) xzm1 & mask); // a becomes xzm if mask is 0, a becomes xzm xor xzm1 if mask is 1
		ptr_t b = (ptr_t) xzm1 ^ (a & mask); // b becomes xzm1 if mask is 0, b becomes xzm1 xor (xzm xor xzm1) = xzm if mask is 1
		a = a ^ (b & mask); // a remains a if mask is 0, a becomes (a xor b) xor a = b if mask is 1
		xzmb = (ed_t*) a; // assign the swapped value of a to xzmb
		xzm1b = (ed_t*) b; // assign the swapped value of b to xzm1b

		edadd(a0, xzmb, xzmb + 16);
		edsub(a0 + 16, xzmb, xzmb + 16);
		edadd(a1, xzm1b, xzm1b + 16);
		edsub(a1 + 16, xzm1b, xzm1b + 16);
		edsquare(b0, a0);
		edsquare(b0 + 16, a0 + 16);
		{
			ed_t b1[16 * 2];
			edmul(b1, a1, a0 + 16);
			edmul(b1 + 16, a1 + 16, a0);
			edadd(c1, b1, b1 + 16);
			edsub(c1 + 16, b1, b1 + 16);
		}
		{
#define r a0
#define s a1
			ed_t t[16];
			ed_t u[16];
			edsquare(r, c1 + 16);
			edsub(s, b0, b0 + 16);
			edmul121665(t, s);
			edadd(u, t, b0);

			edmul(xzmb, b0, b0 + 16);
			edmul(xzmb + 16, s, u);
			edsquare(xzm1b, c1);
			edmul(xzm1b + 16, r, xa);
		}
	}

	for (j = 0; j < 16; ++j) {
		xa[j] = xzm[j];
		xb[j] = xzm[j + 16];
	}
}

void fe_scalarmult_x25519(uint8_t *to, const uint8_t *scalar, const uint8_t *base) {
	ed_t a[16], b[16], c[16];
	uint8_t e[32];
	int16_t i;

	// copy to mask without updating the original
	for (i = 31; i >= 0; --i)
		e[i] = scalar[i];
	e[0] &= 248;
	e[31] &= 127;
	e[31] |= 64;

	unpack16(a, base);
	mainloop(a, b, e);

	recip16(b, b);

	edmul(c, a, b);
	pack16(to, c);
}

void fe_new_key_pair(uint8_t *pk, uint8_t *sk) {
	SHA256 sha;
	randfill(sk, 32);
	sha.update(sk, 32);
	sha.digest(sk);
	// random clamped key
	sk[0] &= 248;
	sk[31] = (sk[31] & 127) | 64;
//	_dump("sk", sk, 32);
	fe_scalarmult_x25519(pk, sk, fe_basePoint);
}
};
