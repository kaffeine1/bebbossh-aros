/*
 * crypto test utilities (Amiga amistdio variant)
 * Copyright (C) 1998, 2025  Stefan Franke <stefan@franke.ms>
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
 * Purpose: Provide lightweight test utilities with optional debug
 *          output using Amiga amistdio.
 *
 * Features:
 *  - dump() macro for hex dumps in debug builds
 *  - assertArrayEquals() for buffer comparison
 *
 * Notes:
 *  - Uses <amistdio.h> on Amiga instead of <stdio.h>
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __TEST_H__
#define __TEST_H__

#ifdef __cplusplus
extern "C" {
#endif

// #define DEBUG
#ifdef DEBUG
#include <stdint.h>
#ifdef __AMIGA__
#include <amistdio.h>   /* Amiga-specific stdio replacement */
#else
#include <stdio.h>
#endif
#include <string.h>

#define dump(a,b,c) _dump(a,b,c)

#else // DEBUG
#define dump(a,b,c)
#endif

/// Hex dump utility
void _dump(char const* txt, void const* _data, unsigned len);

/// Assert that two arrays are equal
extern int assertArrayEquals(void const* expected, void const* given, unsigned len);

#ifdef __cplusplus
}
#endif

#endif // __TEST_H__
