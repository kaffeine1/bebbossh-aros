/*
 * crypto random utilities
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
 * Purpose: Provide random byte filling and buffer sanitization helpers.
 *
 * Features:
 *  - randfill(): fill buffer with random bytes
 *  - unzero(): ensure buffer is non-zero by replacing zero bytes
 *
 * Notes:
 *  - C linkage provided for C++ compatibility
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __RAND_H__
#define __RAND_H__

#ifdef __cplusplus
extern "C" {
#endif

/// Fill buffer with random bytes
void randfill(void* to, unsigned len);
inline void randombytes(void * to, unsigned len) { randfill(to, len);}

/// Replace zero bytes in buffer with random non-zero values
void unzero(void* _to, unsigned len);

#ifdef __cplusplus
}
#endif

#endif // __RAND_H__
