/*
 * bebboget ByteArray definitions
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
 * Project: bebboget
 * Purpose: Provide basic byte array and integer array typedefs for use
 *          in cryptographic and utility classes within the bebboget library.
 *
 * Features:
 *  - Typedefs for common byte and integer array types
 *  - Integration with ministl::vector for dynamic storage
 *  - Convenience macro for stack-based byte buffers
 *
 * Notes:
 *  - bytea: dynamic array of bytes
 *  - bytei: dynamic array of 32-bit integers
 *  - bytez: pointer-size wrapper for raw buffers
 *  - bytes(n,s): macro to declare a stack buffer and wrap it in bytez
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __BYTEARRAY_H__
#define __BYTEARRAY_H__

#include <stdint.h>
#include "ministl/vector.h"

/// Dynamic array of bytes
typedef mstl::vector<uint8_t> bytea;

/// Dynamic array of 32-bit integers
typedef mstl::vector<uint32_t> bytei;

/// Pointer-size wrapper for raw buffers
typedef mstl::__ptr_size bytez;

/**
 * @brief Convenience macro for declaring stack-based byte buffers.
 *
 * Example:
 *   bytes(buf, 64);
 *   -> declares a 64-byte buffer and wraps it in a bytez named buf.
 */
#define bytes(n,s) \
	uint8_t __##n##__data[(s)]; \
    bytez n(__##n##__data, (s))

#endif // __BYTEARRAY_H__
