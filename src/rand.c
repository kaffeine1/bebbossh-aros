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
  #include <time.h>
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
    static int seeded;
    if (!seeded) {
        srand((unsigned)time(0) ^ (unsigned)(uintptr_t)_to);
        seeded = 1;
    }
    for (unsigned i = 0; i < len; ++i) {
        to[i] = (unsigned char)(rand() & 0xff);
    }
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
