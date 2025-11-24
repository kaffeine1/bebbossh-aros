/*
 * ed25519 / curve25519 implementation for Amiga
 *
 * Based on public domain code from the SUPERCOP-20221122 suite:
 *   - Daniel J. Bernstein
 *   - Niels Duif
 *   - Tanja Lange
 *   - Peter Schwabe (lead)
 *   - Bo-Yin Yang
 *   - Matthew Dempsky
 *
 * Rewritten and extended by:
 *   - Stefan "Bebbo" Franke <s.franke@bebbosoft.de>
 *
 * This file remains in the public domain.
 * Derived from SUPERCOP public domain sources, adapted to use 16-bit integers
 * and modified for Amiga-specific requirements.
 */

#include <string.h>
#include "ed25519.h"
#include "ed25519i.h"
#include "sha512.h"

/* create the secret key + randomizer from seed. */
void secret_expand(uint8_t *az, uint8_t const *sk) {
	SHA512 sha;
	sha.update(sk, 32);
	sha.digest(az);
	az[0] &= 248;
	az[31] &= 127;
	az[31] |= 64;
}

static void mul_mod_L8(uint16_t r[32], const uint16_t *x, const uint16_t *y) {
	uint32_t u;
	uint16_t t[64];
	for (short i = 0; i < 64; i++)
		t[i] = 0;

	for (short i = 0; i < 32; i++) {
		u = 0;
		for (short j = 0; j < 32; j++) {
			u += t[i + j];
			u += x[i] * y[j];
			t[i + j] = u & 0xff;
			u >>= 8;
		}
		t[i + 32] += u;
	}
	barrett_reduce(r, t);
}

extern "C" void ed25519_reduce_add_sub(uint16_t r[32]);

void add8(uint16_t * out, const uint16_t * a, const uint16_t * b) {
#define L	u += *a++ + *b++; *out++ = u & 0xff; u >>= 8;
	uint16_t u = 0;
	for (short i = 0; i < 31; ++i) {
		L
	}
//	// 31 times
//	L L L L L L L L
//	L L L L L L L L
//	L L L L L L L L
//	L L L L L L L
	u += *a + *b; *out = u;
#undef L
}


/* from supercop-20221122/crypto_sign/ed25519/ref/sign.c
 *
 RFC 8032:
 ## The signature function works as below.

 def sign(secret, msg):
 a, prefix = secret_expand(secret)
 A = point_compress(point_mul(a, G))
 r = sha512_modq(prefix + msg)
 R = point_mul(r, G)
 Rs = point_compress(R)
 h = sha512_modq(Rs + A + msg)
 s = (r + h * a) % q
 return Rs + int.to_bytes(s, 32, "little")

 *  signature = nonce + hram * sk
 *
 * smlen = 64 + mlen
 * mlen = 32
 **/
int ge_sign_ed25519(void *sm_, void const *m_, unsigned mlen, uint8_t const *secret) {
	uint8_t *sm = (uint8_t *)sm_;
	uint8_t const *m = (uint8_t *)m_;
	uint8_t a[64];
	uint8_t r[32];
	uint8_t Rs[32];
	uint8_t hram[64];
	uint16_t rS[32], hramS[32], aS[32];

#define A (secret + 32)
#define prefix (a+32)
	secret_expand(a, secret);

	//r = sha512_modq(prefix + msg)
	SHA512 sha512;
	sha512.update(prefix, 32);
	sha512.update(m, mlen);
	sha512.digest(r);

	// R = point_mul(r, G)
	ge25519 R;
	ed25519_from64bytes(rS, r);
	ge25519_scalarmult_vartime_base(&R, rS);

	// Rs = point_compress(R)
	ge25519_pack(Rs, &R);

	// h = sha512_modq(Rs + A + msg)
	sha512.update(Rs, 32);
	sha512.update(A, 32);
	sha512.update(m, mlen);
	sha512.digest(hram);

	// s = (r + h * a) % q
	ed25519_from64bytes(hramS, hram);

	for (short i = 0; i < 32; ++i)
		aS[i] = a[i];
	mul_mod_L8(hramS, hramS, aS); // note the modulo L
	add8(hramS, hramS, rS);

	ed25519_reduce_add_sub(hramS);

	// return Rs + int.to_bytes(s, 32, "little")
	for (short i = 0; i < 32; ++i)
		sm[i] = Rs[i];
	for (short i = 0; i < 32; ++i)
		sm[i + 32] = hramS[i];

	return 0;
}

void ge_pubkey(unsigned char *pk, unsigned char const *az) {
	ge25519 gepk;
	uint16_t scsk[32];
	ed25519_from32bytes(scsk, az);
	ge25519_scalarmult_vartime_base(&gepk, scsk);
	ge25519_pack(pk, &gepk);
}

void ge_new_keypair_ed25519(unsigned char *pk, unsigned char *sk) {
	uint8_t az[64];
	randfill(sk, 32);
	secret_expand(az, sk);
	ge_pubkey(pk, az);
	memcpy(sk + 32, pk, 32);
}
