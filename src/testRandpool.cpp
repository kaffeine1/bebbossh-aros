/*
 * testRandpool - self-test of the AROS entropy pool (src/aros_randpool.cpp)
 * Copyright (C) 2026 Michele Dipace <michele.dipace@kaffeine.net>
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
 *
 *   testRandpool              seed file, flags, known answers, output checks
 *   testRandpool -raw FILE N  N (<= 16384) raw jitter deltas, 32-bit little endian
 *   testRandpool -o FILE N    N bytes of randfill() output
 *
 * The default run must be the first randfill() of the process: it checks the
 * seed file that the pool reads and replaces on first use.
 */
#if defined(__AROS__)
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <exec/types.h>
#include <dos/dos.h>
#if defined(BEBBOSSH_AROS_MINCRT)
#include "aros_mincrt_wrappers.h"
#else
#include <proto/dos.h>
#endif

#include "rand.h"
#include "sha512.h"
#include "test.h"
#include "unhexlify.h"
#include "aros_randpool.h"

extern char const *sshDotDir;

static int fails;

static void check(bool ok, const char *what) {
	if (!ok) {
		printf("FAIL: %s\n", what);
		++fails;
	}
}

static unsigned readFile(const char *name, uint8_t *buf, unsigned size) {
	BPTR fh = Open(name, MODE_OLDFILE);
	if (!fh)
		return 0;
	LONG r = Read(fh, buf, size);
	Close(fh);
	return r > 0 ? (unsigned) r : 0;
}

static bool writeFile(const char *name, const void *buf, unsigned size) {
	BPTR fh = Open(name, MODE_NEWFILE);
	if (!fh)
		return false;
	LONG w = Write(fh, buf, size);
	Close(fh);
	return w == (LONG) size;
}

static unsigned parseNum(const char *s) {
	unsigned n = 0;
	while (*s >= '0' && *s <= '9')
		n = n * 10 + (unsigned) (*s++ - '0');
	return n;
}

/* first run of the process: seed file and flags */
static void testSeed() {
	puts("testSeed");
	char seedName[128];
	uint8_t before[64], after[64], x[32];
	unsigned n = sshDotDir ? strlen(sshDotDir) : 0;
	if (!n || n + sizeof("/random_seed") > sizeof(seedName)) {
		check(false, "seed file name");
		return;
	}
	strcpy(seedName, sshDotDir); /* same name as in the pool */
	if (sshDotDir[n - 1] != ':' && sshDotDir[n - 1] != '/')
		strcat(seedName, "/");
	strcat(seedName, "random_seed");
	unsigned nb = readFile(seedName, before, 64);

	struct DateStamp d0, d1;
	DateStamp(&d0);
	randfill(x, sizeof(x));
	DateStamp(&d1);
	unsigned flags = aros_randpool_flags();
	printf("first call %u ticks, flags %u (seed read %u, saved %u, jitter ok %u, timer ok %u)\n",
			(unsigned) ((d1.ds_Minute - d0.ds_Minute) * 3000 + d1.ds_Tick - d0.ds_Tick), flags,
			(flags & AROS_RANDPOOL_SEED_READ) ? 1u : 0u, (flags & AROS_RANDPOOL_SEED_SAVED) ? 1u : 0u,
			(flags & AROS_RANDPOOL_JITTER_OK) ? 1u : 0u, (flags & AROS_RANDPOOL_TIMER_OK) ? 1u : 0u);
	check(flags & AROS_RANDPOOL_TIMER_OK, "timer.device wake-ups");
	if (!(flags & AROS_RANDPOOL_JITTER_OK))
		puts("WARNING: jitter health check failed");
	check(nb != 64 || (flags & AROS_RANDPOOL_SEED_READ), "seed file read");
	if (flags & AROS_RANDPOOL_SEED_SAVED) {
		check(readFile(seedName, after, 64) == 64, "seed file has 64 bytes");
		check(nb != 64 || memcmp(before, after, 64), "seed file replaced");
	} else {
		/* a missing seed that was not created: the directory must not be
		   writable either (an existing one may just be protected) */
		if (!nb) {
			char probe[sizeof(seedName) + 4];
			strcpy(probe, seedName);
			strcat(probe, ".tst");
			bool writable = writeFile(probe, "x", 1);
			if (writable)
				DeleteFile(probe);
			check(!writable, "seed not created although the directory is writable");
		}
		printf("note: %s not replaced (read-only volume?)\n", seedName);
	}
}

/* SHA-512 through updateDirect()/digestDirect(), the calls the pool uses */
static void testDirect() {
	puts("testDirect");
	static const unsigned lens[] = { 0, 111, 112, 127, 128, 129, 200, 300 };
	static const char *const kat[] = { "cf83e1357eefb8bdf1542850d66d8007",
			"68cffa6d0d76f309c9ce0d35280939f8", "d0865c524d1dddf7c23b799c413f5adc",
			"e0b6a20f1c0c88970a9340152cd5a1c1", "99b16f17aa0b969a5b8f08f367719d51",
			"a1556e29185778aa5991e34b8884c840", "cca3c0276046ef9f2897bdfc3ec330f7",
			"46e56ad30db9ef50f8b6762ba5583973" };
	static uint8_t msg[300];
	for (unsigned i = 0; i < sizeof(msg); ++i)
		msg[i] = (uint8_t) (i * 7 + 3);
	for (unsigned k = 0; k < sizeof(lens) / sizeof(lens[0]); ++k) {
		uint8_t expected[16], whole[64], split[64];
		unhexlify(expected, kat[k]);
		SHA512 a, b;
		a.updateDirect(msg, lens[k]);
		a.digestDirect(whole);
		for (unsigned i = 0; i < lens[k]; i += 13)
			b.updateDirect(msg + i, lens[k] - i < 13 ? lens[k] - i : 13);
		b.digestDirect(split);
		check(assertArrayEquals(expected, whole, 16), "SHA-512 direct");
		check(assertArrayEquals(whole, split, 64), "SHA-512 direct, split");
	}
}

/* the pool steps hash the same bytes on every target */
static void testFraming() {
	puts("testFraming");
	uint8_t in[64], ctr[8], out[64], expected[16];
	for (unsigned i = 0; i < 64; ++i)
		in[i] = (uint8_t) i;
	memset(ctr, 0, sizeof(ctr));
	ctr[7] = 1;
	aros_randpool_hash(out, in, "outp", ctr, 8);
	unhexlify(expected, "2cbec8ed7be8c4cbe52a7d3aaadaf962");
	check(assertArrayEquals(expected, out, 16), "outp framing");
	aros_randpool_hash(out, in, "next", ctr, 8);
	unhexlify(expected, "8edbbdda32e7426a36a009d40eadaccc");
	check(assertArrayEquals(expected, out, 16), "next framing");
}

static void testOutput() {
	puts("testOutput");
	static const unsigned lens[] = { 0, 1, 16, 63, 64, 65, 200 };
	static uint8_t buf[264];
	for (unsigned k = 0; k < sizeof(lens) / sizeof(lens[0]); ++k) {
		memset(buf, 0xa5, sizeof(buf));
		randfill(buf, lens[k]);
		bool canary = true, zero = true;
		for (unsigned i = lens[k]; i < lens[k] + 64; ++i)
			canary = canary && buf[i] == 0xa5;
		for (unsigned i = 0; i < lens[k]; ++i)
			zero = zero && buf[i] == 0;
		check(canary, "no write past the end");
		check(lens[k] < 16 || !zero, "output not zero");
	}
	static uint8_t outs[64][32];
	for (unsigned i = 0; i < 64; ++i)
		randfill(outs[i], 32);
	for (unsigned i = 0; i < 64; ++i)
		for (unsigned j = i + 1; j < 64; ++j)
			check(memcmp(outs[i], outs[j], 32) != 0, "outputs differ");
}

static uint32_t raw[16384];

static int dumpRaw(const char *name, unsigned n) {
	if (n > sizeof(raw) / sizeof(raw[0]))
		n = sizeof(raw) / sizeof(raw[0]);
	unsigned healthy = aros_randpool_sample(raw, n);
	n &= ~15u;
	uint32_t lo = 0xffffffff, hi = 0;
	unsigned count[256], best = 0, distinct = 0;
	memset(count, 0, sizeof(count));
	for (unsigned i = 0; i < n; ++i) {
		if (raw[i] < lo)
			lo = raw[i];
		if (raw[i] > hi)
			hi = raw[i];
		if (!count[raw[i] & 255]++)
			++distinct;
		if (count[raw[i] & 255] > best)
			best = count[raw[i] & 255];
	}
	printf("%u deltas: min %u max %u, %u distinct low bytes, most common %u, healthy %u\n",
			n, (unsigned) lo, (unsigned) hi, distinct, best, healthy);
#if defined(__aarch64__)
	uint64_t f;
	__asm__ __volatile__("mrs %0, cntfrq_el0" : "=r"(f));
	printf("cntfrq_el0 %u Hz\n", (unsigned) f);
#endif
	return writeFile(name, raw, n * 4) ? 0 : 10;
}

static int dumpOutput(const char *name, unsigned n) {
	BPTR fh = Open(name, MODE_NEWFILE);
	if (!fh)
		return 10;
	static uint8_t buf[4096];
	bool ok = true;
	while (ok && n) {
		unsigned l = n < sizeof(buf) ? n : sizeof(buf);
		randfill(buf, l);
		ok = Write(fh, buf, l) == (LONG) l;
		n -= l;
	}
	Close(fh);
	return ok ? 0 : 10;
}

int main(int argc, char **argv) {
#if !BEBBOSSH_RANDPOOL
	puts("testRandpool: pool disabled (BEBBOSSH_RANDPOOL=0)");
	return 0;
#endif
	if (argc == 4 && !strcmp(argv[1], "-raw"))
		return dumpRaw(argv[2], parseNum(argv[3]));
	if (argc == 4 && !strcmp(argv[1], "-o"))
		return dumpOutput(argv[2], parseNum(argv[3]));
	testSeed();
	testDirect();
	testFraming();
	testOutput();
	return fails ? 10 : 0;
}
#else
// the pool is AROS only; the upstream Makefile builds every src/test*.cpp
int main() {
	return 0;
}
#endif
