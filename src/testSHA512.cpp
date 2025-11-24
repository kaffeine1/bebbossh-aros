/*
 * crypto SHA-512 test harness
 * Copyright (C) 2024-2025  Stefan Franke <stefan@franke.ms>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version (GPLv3+).
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * ----------------------------------------------------------------------
 * Project: crypto
 * Module: SHA-512 test
 *
 * Purpose:
 *  - Provide unit tests for the SHA-512 implementation
 *  - Verify correctness against known test vectors:
 *      * "abc"
 *      * "abcdbcdecdef...nopq"
 *      * "abcdefghbcdefghi...nopqrstu"
 *  - Serve as regression tests for digest output
 *
 * Notes:
 *  - SHA-512 produces a 512-bit (64-byte) digest
 *  - Returns 0 on success, non-zero on failure
 *  - Designed for Amiga and cross-platform builds
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */
#ifdef __AMIGA__
#include <proto/dos.h>
#include <amistdio.h>
#else
#include <stdio.h>
#endif
#include <stdint.h>
#include <string.h>

#include "test.h"
#include "sha256.h"
#include "sha512.h"
#include "unhexlify.h"


int testSHA512_0() {
	puts("testSHA512_0");
	SHA512 sha512;

	static uint8_t data[]    = {'a', 'b', 'c'};
	static uint8_t expected[64];
	unhexlify(expected, "ddaf35a193617aba cc417349ae204131 12e6fa4e89a97ea2 0a9eeee64b55d39a 2192992a274fc1a8 36ba3c23a3feebbd 454d4423643ce80e 2a9ac94fa54ca49f	");
	uint8_t result[64];
	sha512.update(data, sizeof(data));
	sha512.digest(result);
	return assertArrayEquals(expected, result, 64);
}

int testSHA512_1() {
	puts("testSHA512_1");
	SHA512 sha512;
	char const *txt = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	unsigned char expected[64];
	unhexlify(expected, "204a8fc6dda82f0a 0ced7beb8e08a416 57c16ef468b228a8 279be331a703c335 96fd15c13b1b07f9 aa1d3bea57789ca0 31ad85c7a71dd703 54ec631238ca3445");

	unsigned char d[64];
	sha512.update(txt, strlen(txt));
	sha512.digest(d);
	return assertArrayEquals(expected, d, 64);
}

int testSHA512_2() {
	puts("testSHA512_2");
	SHA512 sha512;
	char const *txt = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
	unsigned char expected[64];
	unhexlify(expected, "8e959b75dae313da 8cf4f72814fc143f 8f7779c6eb9f7fa1 7299aeadb6889018 501d289e4900f7e4 331b99dec4b5433a c7d329eeb6dd2654 5e96e55b874be909");

	unsigned char d[64];
	sha512.update(txt, strlen(txt));
	sha512.digest(d);
	return assertArrayEquals(expected, d, 64);
}

int main() {
	return testSHA512_0() & testSHA512_1() & testSHA512_2() ? 0 : 10;
}
