/*
 * bebbossh test utility (assertArrayEquals)
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
 * Project: bebbossh
 * Purpose: Provide array comparison utility for unit testing.
 *
 * Features:
 *  - assertArrayEquals(): compares two byte arrays of given length
 *  - Dumps both arrays if mismatch occurs
 *  - Reports index of mismatch
 *
 * Notes:
 *  - Amiga builds use <amistdio.h>, others use <stdio.h>
 *  - Useful for validating cryptographic routines and buffer operations
 * ----------------------------------------------------------------------
 */

#include <inttypes.h>
#ifdef __AMIGA__
#include <proto/dos.h>
#include <amistdio.h>
#else
#include <stdio.h>
#endif

#include "test.h"

#ifdef __cplusplus
extern "C" {
#endif

int assertArrayEquals(void const *expected_, void const *given_, unsigned _len) {
    uint8_t const *expected = (uint8_t *)expected_;
    uint8_t const *given = (uint8_t *)given_;
    unsigned len = _len;
    while (len > 0) {
        --len;
        if (expected[len] != given[len]) {
            _dump("expected", expected, _len);
            _dump("given", given, _len);
            printf("mismatch at %ld\r\n", len);
            return false;
        }
    }
    return true;
}

#ifdef __cplusplus
}
#endif
