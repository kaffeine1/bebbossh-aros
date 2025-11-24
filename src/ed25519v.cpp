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

#include <amistdio.h>
#include <string.h>
#include "ed25519.h"
#include "ed25519i.h"
#include "sha512.h"
#include <stabs.h>
#include "test.h"

#ifdef __cplusplus
extern "C" {
#endif

/* d */
__attribute((section(".text")))
static const ed25519 ge25519_ecd = {EDX(0x78A3, 0x1359), EDX(0x4DCA, 0x75EB), EDX(0xD8AB, 0x4141), EDX(0x0A4D, 0x0070), EDX(0xE898, 0x7779), EDX(0x4079, 0x8CC7), EDX(0xFE73, 0x2B6F), EDX(0x6CEE, 0x5203), };

/* sqrt(-1) */

__attribute((section(".text")))
const ed25519 ge25519_sqrtm1 = {EDX(0xA0B0, 0x4A0E), EDX(0x1B27, 0xC4EE), EDX(0xE478, 0xAD2F), EDX(0x1806, 0x2F43), EDX(0xD7A7, 0x3DFB), EDX(0x0099, 0x2B4D), EDX(0xDF0B, 0x4FC1), EDX(0x2480, 0x2B83), };

static int fe25519_iseq_vartime(const ed25519 x, const ed25519 y) {
	int i;
	for (i = 0; i < EDSIZE; i++)
		if (x[i] != y[i])
			return 0;
	return 1;
}

static int crypto_verify_32(const uint8_t *x, const uint8_t *y) {
	unsigned i = 0;
	int r = (x[i] != y[i]);
	for (++i; i < 32; ++i) {
		r |= (x[i] != y[i]);
	}
	return r;
}

/* return 0 on success, -1 otherwise */
int ge25519_unpackneg_vartime(ge25519 *r, const uint8_t p[32]) {
	uint8_t par;
	ed25519 t, chk, num, den, den2, den6;
	setone(r->z);
	par = p[31] >> 7;
	unpack16(r->y, p);
	edsquare(num, r->y); /* x = y^2 */
	edmul(den, num, ge25519_ecd); /* den = dy^2 */
	edsub(num, num, r->z); /* x = y^2-1 */
	edadd(den, r->z, den); /* den = dy^2+1 */


//	{uint8_t T[32]; pack16(T, den); __dump("den", T, 32);}
	
	/* Computation of sqrt(num/den) */
	/* 1.: computation of num^((p-5)/8)*den^((7p-35)/8) = (num*den^7)^((p-5)/8) */
	edsquare(den2, den);
	{
		ed25519 den4;
		edsquare(den4, den2);
		edmul(den6, den4, den2);
	}
	edmul(t, den6, num);
	edmul(den6, t, den);

	fe25519_pow2523(t, den6);

	
//	{uint8_t T[32]; pack16(T, t); __dump("den", T, 32);}
	
	/* 2. computation of r->x = t * num * den^3 */
	edmul(chk, t, num);
	edmul(den2, chk, den);
	edmul(t, den2, den);
	edmul(r->x, t, den);

	/* 3. Check whether sqrt computation gave correct result, multiply by sqrt(-1) if not: */
	edsquare(t, r->x);
	edmul(chk, t, den);
	if (!fe25519_iseq_vartime(chk, num)) {
		edmul(t, r->x, ge25519_sqrtm1);
		memcpy(r->x, t, sizeof(t));
	}

	/* 4. Now we have one of the two square roots, except if input was not a square */
	edsquare(t, r->x);
	edmul(chk, t, den);
	if (!fe25519_iseq_vartime(chk, num))
		return -1;

	/* 5. Choose the desired square root according to parity: */
	if (fe25519_getparity(r->x) != (1 - par))
		edsub(r->x, zero, r->x);

	edmul(r->t, r->x, r->y);
	return 0;
}

int ge_verify_ed25519(uint8_t *m, unsigned mlen, uint8_t const *sm, uint8_t const *pk) {
	ge25519 pkPoint;
	uint16_t schram[32], scs[32];
#if 0
	__dump("m ", m, mlen);
	__dump("sm", sm, 32);
	__dump("pk", pk, 32);
#endif
	if (ge25519_unpackneg_vartime(&pkPoint, pk))
		return 0;

	ed25519_from32bytes(scs, sm + 32);
	{
		uint8_t hram[64];
		SHA512 sha512;
		sha512.update(sm, 32);
		sha512.update(pk, 32);
		sha512.update(m, mlen);
		sha512.digest(hram);
//		__dump("hram", hram, 64);

		ed25519_from64bytes(schram, hram);

//		__dump("hrami", schram, 64);
	}

	uint8_t rcheck[32];
	{
		ge25519 sumPoint;
		ge25519_scalarmult_vartime2(&sumPoint, &pkPoint, schram, scs);


		ge25519_pack(rcheck, &sumPoint);
	}

//	_dump("sm", sm, 32);
//	_dump("rcheck", rcheck, 32);
	return crypto_verify_32(sm, rcheck) == 0;
}

#ifdef __cplusplus
}
#endif
