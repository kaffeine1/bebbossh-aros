#include "shake128.h"
#include <string.h>

Shake128::Shake128() {
    reset();
}

void Shake128::reset() {
    memset(state, 0, sizeof(state));
    memset(buffer, 0, sizeof(buffer));
    absorbed = false;
}

void Shake128::absorbBlock(const uint8_t* in) {
#if (BYTE_ORDER == BIG_ENDIAN)
    for (size_t i = 0; i < RATE / 8; ++i) {
        const uint8_t* p = in + 8*i;
        uint64_t w =
            ((uint64_t)p[0] <<  0) |
            ((uint64_t)p[1] <<  8) |
            ((uint64_t)p[2] << 16) |
            ((uint64_t)p[3] << 24) |
            ((uint64_t)p[4] << 32) |
            ((uint64_t)p[5] << 40) |
            ((uint64_t)p[6] << 48) |
            ((uint64_t)p[7] << 56);
        state[i] ^= w;
    }
#else
    const uint64_t* w = reinterpret_cast<const uint64_t*>(in);
    for (size_t i = 0; i < RATE / 8; ++i)
        state[i] ^= w[i];
#endif
}

void Shake128::absorb(const uint8_t* in, size_t inlen) {
    if (absorbed)
        return; // cannot absorb twice

    // Absorb full blocks
    while (inlen >= RATE) {
        absorbBlock(in);
        k(state);
        in    += RATE;
        inlen -= RATE;
    }

    // Last partial block + SHAKE padding
    memset(buffer, 0, RATE);
    if (inlen > 0)
        memcpy(buffer, in, inlen);

    buffer[inlen] ^= 0x1F;        // SHAKE domain separation
    buffer[RATE - 1] ^= 0x80;     // final bit of pad10*1

    absorbBlock(buffer);
    k(state);

    absorbed = true;
}

void Shake128::squeeze(uint8_t* out, size_t outlen) {
    if (!absorbed)
        return; // must absorb first

    while (outlen > 0) {
        size_t block = (outlen < RATE) ? outlen : RATE;

#if (BYTE_ORDER == BIG_ENDIAN)
        for (size_t i = 0; i < block; ++i) {
            size_t lane = i / 8;
            size_t off  = i % 8;
            uint64_t w  = state[lane];
            out[i] = (uint8_t)(w >> (8 * off));
        }
#else
        memcpy(out, state, block);
#endif

        out    += block;
        outlen -= block;

        if (outlen > 0)
            k(state);
    }
}
