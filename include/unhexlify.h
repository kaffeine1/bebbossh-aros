/*
 * crypto hexlify / unhexlify utilities
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
 * Purpose: Provide utilities to convert between binary data and
 *          hexadecimal string representation.
 *
 * Features:
 *  - unhexlify(): convert hex string into binary buffer
 *  - hexlify(): convert binary buffer into hex string
 *
 * Notes:
 *  - C linkage provided for C++ compatibility
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __UNHEXLIFY_H__
#define __UNHEXLIFY_H__

#ifdef __cplusplus
extern "C" {
#endif

/// Convert hex string into binary buffer
void unhexlify(void* to, char const* from);

/// Convert binary buffer into hex string
char* hexlify(void const* from, int len);

#ifdef __cplusplus
}
#endif

#endif // __UNHEXLIFY_H__
