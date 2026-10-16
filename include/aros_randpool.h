/*
 * aros_randpool - SHA-512 entropy pool behind randfill() on AROS
 * Copyright (C) 2026 Michele Dipace <michele.dipace@kaffeine.net>
 * Based on the random pool of bebbossh 1.46.1 (patch 0008) by Matthias Muench.
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
 */
#ifndef BEBBOSSH_AROS_RANDPOOL_H
#define BEBBOSSH_AROS_RANDPOOL_H

#include <stdint.h>

#ifndef BEBBOSSH_RANDPOOL
/* 0 restores the 64-bit mixer of 1.0.6 in rand.c (rollback only) */
#define BEBBOSSH_RANDPOOL 1
#endif

/* aros_randpool_flags() bits */
#define AROS_RANDPOOL_SEED_READ  1u /* a 64-byte seed file was read */
#define AROS_RANDPOOL_SEED_SAVED 2u /* the new seed was written */
#define AROS_RANDPOOL_JITTER_OK  4u /* the cycle counter passed the health check */
#define AROS_RANDPOOL_TIMER_OK   8u /* every timer.device wake-up completed */

#ifdef __cplusplus
extern "C" {
#endif
/* randfill() on AROS */
void aros_randfill(void *to, unsigned len);
/* more timer wake-ups and jitter into the pool, for long-term keys */
void aros_randpool_stir(unsigned rounds);
unsigned aros_randpool_flags(void);
/* self-test hooks: out = SHA-512(in[64] | tag[4] | data[len]), and n raw
   jitter deltas of the production sampler (returns 1 if they look healthy) */
void aros_randpool_hash(uint8_t *out, const uint8_t *in, const char *tag,
		const void *data, unsigned len);
unsigned aros_randpool_sample(uint32_t *deltas, unsigned n);
#ifdef __cplusplus
}
#endif

#endif
