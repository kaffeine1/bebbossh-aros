/*
 * crypto random filler and unzero utility
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
 * Module: randfill / unzero
 *
 * Purpose:
 *  - Provide pseudo-random filler for buffers
 *    * Amiga: uses hardware vhposr + DateStamp ticks
 *    * POSIX: uses random()
 *    * FAKERAND: deterministic sequence for testing
 *  - Provide unzero() utility to replace zero bytes with their position index
 *
 * Notes:
 *  - Amiga has no /dev/urandom; vhposr is sufficient for entropy in this context
 *  - Not cryptographically secure; intended for filler and testing and the AMIGA
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */
#include <inttypes.h>
#include <stdlib.h>

#ifdef __AMIGA__
  #include <hardware/custom.h>
  #include <proto/dos.h>
#elif defined(__AROS__)
  #include <stdint.h>
  #include <sys/time.h>
  #include <time.h>
  #include <dos/dos.h>
  #include <exec/memory.h>
  #include <proto/dos.h>
  #include <proto/exec.h>
#elif defined(__APPLE__)
  #include <stdlib.h>
#elif defined(__unix__)
  #include <unistd.h>
  #include <sys/random.h>
  #include <fcntl.h>
  #include <sys/stat.h>
#elif defined(_WIN32)
  #include <windows.h>
  #include <bcrypt.h>
#endif

// #define FAKERAND 1

#if defined(__AROS__)
static uint64_t aros_rdtsc(void) {
#if (defined(__i386__) || defined(__x86_64__)) && defined(__GNUC__)
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#else
    return 0;
#endif
}

static uint64_t aros_mix64(uint64_t x) {
    x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
    return x ^ (x >> 31);
}
#endif

#ifndef FAKERAND
void randfill(void * _to, unsigned len) {
#ifdef __AMIGA__
	char * to = (char *)_to;
	volatile struct Custom * c = (struct Custom *)0xdff000;
	struct DateStamp ds;
	DateStamp(&ds);
	unsigned t = ds.ds_Tick;
	srand(rand() ^ t);

	for (unsigned i = 0; i < len; ++i) {
		unsigned x = rand() ^ t ^ c->vhposr;
		t = (t >> 31) | (t << 1);
		*to++ = x;
	}
#elif defined(__AROS__)
    unsigned char *to = (unsigned char *)_to;
    static uint64_t state;
    static int seeded;

#if defined(__x86_64__)
    static uint64_t counter;
    uintptr_t frame = (uintptr_t)&frame;
    uint64_t entropy = aros_rdtsc() ^
            (uint64_t)(uintptr_t)_to ^
            ((uint64_t)len << 32) ^
            (uint64_t)(uintptr_t)&state ^
            (uint64_t)frame ^
            (++counter * UINT64_C(0x9e3779b97f4a7c15));

    if (!seeded) {
        state = entropy ^ UINT64_C(0xd1b54a32d192ed03);
        seeded = 1;
    } else {
        state ^= entropy + UINT64_C(0x9e3779b97f4a7c15) + (state << 6) + (state >> 2);
    }

    for (unsigned i = 0; i < len; ++i) {
        state += UINT64_C(0x9e3779b97f4a7c15);
        uint64_t x = aros_mix64(state ^ aros_rdtsc() ^ ((uint64_t)i << 17));
        to[i] = (unsigned char)(x >> ((i & 7) * 8));
    }
#else
    struct timeval tv;
    struct DateStamp ds;
    uint64_t entropy = aros_rdtsc() ^
            (uint64_t)(uintptr_t)_to ^ ((uint64_t)len << 32);

    if (gettimeofday(&tv, 0) == 0)
        entropy ^= ((uint64_t)tv.tv_sec << 32) ^ (uint64_t)tv.tv_usec;

    DateStamp(&ds);
    entropy ^= ((uint64_t)(uint32_t)ds.ds_Days << 33) ^
            ((uint64_t)(uint32_t)ds.ds_Minute << 17) ^
            (uint32_t)ds.ds_Tick;
    entropy ^= ((uint64_t)(uintptr_t)FindTask(0) << 7) ^
            (uint64_t)(uintptr_t)&entropy;
    entropy ^= ((uint64_t)AvailMem(MEMF_LARGEST) << 29) ^
            (uint64_t)AvailMem(MEMF_ANY);
    entropy ^= ((uint64_t)(unsigned)time(0) << 21) ^
            (uint64_t)(unsigned)clock();

    if (!seeded) {
        state = entropy ^ UINT64_C(0x9e3779b97f4a7c15);
        seeded = 1;
    } else {
        state ^= entropy + UINT64_C(0x9e3779b97f4a7c15) + (state << 6) + (state >> 2);
    }

    for (unsigned i = 0; i < len; ++i) {
        if ((i & 31) == 0) {
            if (gettimeofday(&tv, 0) == 0)
                state ^= ((uint64_t)tv.tv_usec << 11) ^ (uint64_t)tv.tv_sec;
            state ^= ((uint64_t)AvailMem(MEMF_LARGEST) << 13) ^
                    (uint64_t)(uintptr_t)FindTask(0);
        }

        state += UINT64_C(0x9e3779b97f4a7c15);
        uint64_t x = aros_mix64(state ^ aros_rdtsc() ^ ((uint64_t)i << 17));
        to[i] = (unsigned char)(x >> ((i & 7) * 8));
    }
#endif
#elif defined(__APPLE__)
    arc4random_buf(_to, len);
#elif defined(__unix__)
    unsigned char *to = (unsigned char *)_to;
    if (getrandom(to, len, 0) < 0) {
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd >= 0) { read(fd, to, len); close(fd); }
    }
#elif defined(_WIN32)
    BCryptGenRandom(NULL, (PUCHAR)_to, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#else
    #error "randfill not implemented for this platform"
#endif
}
#else
void randfill(void * _to, unsigned len) {
	char * to = (char *)_to;
	for (int i = 0; i < len; ++i)
		*to++ = i;
}
#endif


void unzero(void * _to, unsigned len) {
	uint8_t * to = (uint8_t *)_to;
	while (len) {
		if (!*to)
			*to = len;
		++to;
		--len;
	}
}
