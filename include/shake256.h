#ifndef __SHAKE256_H__
#define __SHAKE256_H__
#include <stdint.h>
#include <stddef.h>

extern "C" void k(uint64_t state[25]);   // Keccak-f[1600] permutation

class Shake256 {
public:
    static constexpr size_t RATE = 136;   // 136 bytes = 1088-bit rate

    Shake256();

    void reset();

    // Absorb input (can only be called once before squeezing)
    void absorb(const uint8_t* in, size_t inlen);

    // Squeeze arbitrary output
    void squeeze(uint8_t* out, size_t outlen);

private:
    uint64_t state[25];
    uint8_t  buffer[RATE];
    bool     absorbed;

    void absorbBlock(const uint8_t* in);
};
#endif // __SHAKE256_H__
