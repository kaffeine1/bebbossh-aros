/*
 * crypto ChaCha20-Poly1305 AEAD interface
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
 * Purpose: Provide AEAD (Authenticated Encryption with Associated Data)
 *          using ChaCha20 stream cipher and Poly1305 authenticator.
 *
 * Features:
 *  - Poly1305 message authentication code
 *  - Support for nonce initialization, AAD processing, and tag calculation
 *
 * Notes:
 *  - Poly1305 provides authentication over ciphertext and AAD
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __POLY1305__H__
#define __POLY1305__H__

#include "bc.h"


/**
 * @class Poly1305
 * @brief Poly1305 message authentication code.
 *
 * Provides authentication over ciphertext and AAD
 * using a one-time key derived from ChaCha20.
 */
class Poly1305 {
    uint32_t r[5]; ///< Key parameter r
    uint32_t s[4]; ///< Key parameter s
    uint32_t a[10];///< Accumulator
public:
    /// Set Poly1305 key
    int setKey(void const* k, int klen);

    /// Update MAC with data
    void update(void const* d, int len);

    /// Finalize and produce digest
    void digest(void* to);
};


#endif // __POLY1305__H__
