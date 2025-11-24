/*
 * crypto MIME encoding/decoding interface
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
 * Purpose: Provide MIME base64 encoding and decoding functions.
 *
 * Features:
 *  - mimeEncode(): encode binary data into MIME base64
 *  - mimeDecode(): decode MIME base64 into binary data
 *
 * Notes:
 *  - C linkage provided for C++ compatibility
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __MIME_H__
#define __MIME_H__

#ifdef __cplusplus
extern "C" {
#endif

/// Encode binary data into MIME base64
extern void mimeEncode(void* to, void const* from, unsigned length);

/// Decode MIME base64 into binary data
extern int mimeDecode(void* to, void const* from, unsigned length);

#ifdef __cplusplus
}
#endif

#endif // __MIME_H__
