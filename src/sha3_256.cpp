#include <string.h>
#include <stdint.h>
#include "md.h"

extern "C" void k(uint64_t *state);

class SHA3_256 : public MessageDigest {
private:
    uint64_t state[25];

public:
    SHA3_256() : MessageDigest(136) { reset(); }
    virtual ~SHA3_256() {}

    void reset() override {
        memset(state, 0, sizeof(state));
        memset(data, 0, mask + 1);
        count = 0;
    }

    void transform() override {
		// absorb one full rate block (136 bytes)
		const unsigned lanes = (mask + 1) / 8;   // 136/8 = 17

	#if (BYTE_ORDER == BIG_ENDIAN)

		// Big-endian host -> must byte-swap each lane
		for (unsigned i = 0; i < lanes; ++i) {
			const uint8_t *p = data + 8*i;
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
		// Little-endian host -> direct cast is safe
		const uint64_t *w = reinterpret_cast<const uint64_t*>(data);
		for (unsigned i = 0; i < lanes; ++i) {
			state[i] ^= w[i];
		}

	#endif

		k(state);   // your optimized Keccak-f[1600]
	}


    void __getDigest(unsigned char *r) override {
        // squeeze 32 bytes from lanes 0..3, little-endian
        uint8_t *o = r;
        for (int i = 0; i < 4; ++i) {
            uint64_t w = state[i];
            *o++ = (uint8_t)(w      );
            *o++ = (uint8_t)(w >>  8);
            *o++ = (uint8_t)(w >> 16);
            *o++ = (uint8_t)(w >> 24);
            *o++ = (uint8_t)(w >> 32);
            *o++ = (uint8_t)(w >> 40);
            *o++ = (uint8_t)(w >> 48);
            *o++ = (uint8_t)(w >> 56);
        }
    }

    void digest(void *to_) override {
        unsigned char *to = (unsigned char*)to_;

        unsigned i = ((unsigned)count) & mask;

        // SHA-3 padding: 0x06 ... 0x80 within the rate
        data[i++] ^= 0x06;
        if (i > mask) {
            // no room for final 0x80 in this block
            memset(data + i, 0, (mask + 1) - i);
            transform();
            memset(data, 0, mask + 1);
            i = 0;
        }
        // set final bit of the rate
        data[mask] ^= 0x80;

        transform();

        __getDigest(to);
        reset();
    }
};


#if defined(__AMIGA__)

static const uint64_t KeccakF_RoundConstants[24] = {
    0x0000000000000001ULL,
    0x0000000000008082ULL,
    0x800000000000808aULL,
    0x8000000080008000ULL,
    0x000000000000808bULL,
    0x0000000080000001ULL,
    0x8000000080008081ULL,
    0x8000000000008009ULL,
    0x000000000000008aULL,
    0x0000000000000088ULL,
    0x0000000080008009ULL,
    0x000000008000000aULL,
    0x000000008000808bULL,
    0x800000000000008bULL,
    0x8000000000008089ULL,
    0x8000000000008003ULL,
    0x8000000000008002ULL,
    0x8000000000000080ULL,
    0x000000000000800aULL,
    0x800000008000000aULL,
    0x8000000080008081ULL,
    0x8000000000008080ULL,
    0x0000000080000001ULL,
    0x8000000080008008ULL
};

#define M68K_COMPUTE_Cx(state, x, Cx, Cxlo, Cxhi)                     \
    asm volatile(                                                     \
        /* load state[x] into Cx */                                   \
        "move.l  %c[o0](%[s]),d" #Cxlo "     \n\t"                    \
        "move.l  %c[o0]+4(%[s]),d" #Cxhi "   \n\t"                    \
                                                                      \
        /* XOR state[x+5] */                                          \
        "move.l  %c[o1](%[s]),d0          \n\t"                       \
        "move.l  %c[o1]+4(%[s]),d1        \n\t"                       \
        "eor.l   d0,d" #Cxlo "            \n\t"                       \
        "eor.l   d1,d" #Cxhi "            \n\t"                       \
                                                                      \
        /* XOR state[x+10] */                                         \
        "move.l  %c[o2](%[s]),d0          \n\t"                       \
        "move.l  %c[o2]+4(%[s]),d1        \n\t"                       \
        "eor.l   d0,d" #Cxlo "            \n\t"                       \
        "eor.l   d1,d" #Cxhi "            \n\t"                       \
                                                                      \
        /* XOR state[x+15] */                                         \
        "move.l  %c[o3](%[s]),d0          \n\t"                       \
        "move.l  %c[o3]+4(%[s]),d1        \n\t"                       \
        "eor.l   d0,d" #Cxlo "            \n\t"                       \
        "eor.l   d1,d" #Cxhi "            \n\t"                       \
                                                                      \
        /* XOR state[x+20] */                                         \
        "move.l  %c[o4](%[s]),d0          \n\t"                       \
        "move.l  %c[o4]+4(%[s]),d1        \n\t"                       \
        "eor.l   d0,d" #Cxlo "            \n\t"                       \
        "eor.l   d1,d" #Cxhi "            \n\t"                       \
        : "=r"(Cx)                                                    \
        : [s] "a"(state),                                             \
          [o0] "i"((x)*8),                                            \
          [o1] "i"(((x)+5)*8),                                        \
          [o2] "i"(((x)+10)*8),                                       \
          [o3] "i"(((x)+15)*8),                                       \
          [o4] "i"(((x)+20)*8)                                        \
        : "d0","d1","memory"                                          \
    )

#define M68K_D_AND_STORE(state, tmp,                                  \
                         CLo, CHi, CNextLo, CNextHi,                  \
                         DLo, DHi,                                    \
                         i0)                                          \
    asm volatile(                                                     \
        /* ---- D = ROL64(C,1) ^ Cnext ---- */                        \
        "move.l d" #CHi ",d" #DHi "        \n\t"                      \
        "move.l d" #CLo ",d" #DLo "        \n\t"                      \
        "roxl.l #1,d" #DHi "               \n\t"                      \
        "roxl.l #1,d" #DLo "               \n\t"                      \
        "eor.l  d" #CNextLo ",d" #DLo "    \n\t"                      \
        "eor.l  d" #CNextHi ",d" #DHi "    \n\t"                      \
                                                                      \
        /* ---- tmp[i0] ---- */                                       \
        "move.l %c[o0](%[s]),d6           \n\t"                       \
        "move.l %c[o0]+4(%[s]),d7         \n\t"                       \
        "eor.l  d" #DLo ",d6              \n\t"                       \
        "eor.l  d" #DHi ",d7              \n\t"                       \
        "move.l d6,%c[t0](%[t])           \n\t"                       \
        "move.l d7,%c[t0]+4(%[t])         \n\t"                       \
                                                                      \
        /* ---- tmp[i0+5] ---- */                                     \
        "move.l %c[o1](%[s]),d6           \n\t"                       \
        "move.l %c[o1]+4(%[s]),d7         \n\t"                       \
        "eor.l  d" #DLo ",d6              \n\t"                       \
        "eor.l  d" #DHi ",d7              \n\t"                       \
        "move.l d6,%c[t1](%[t])           \n\t"                       \
        "move.l d7,%c[t1]+4(%[t])         \n\t"                       \
                                                                      \
        /* ---- tmp[i0+10] ---- */                                    \
        "move.l %c[o2](%[s]),d6           \n\t"                       \
        "move.l %c[o2]+4(%[s]),d7         \n\t"                       \
        "eor.l  d" #DLo ",d6              \n\t"                       \
        "eor.l  d" #DHi ",d7              \n\t"                       \
        "move.l d6,%c[t2](%[t])           \n\t"                       \
        "move.l d7,%c[t2]+4(%[t])         \n\t"                       \
                                                                      \
        /* ---- tmp[i0+15] ---- */                                    \
        "move.l %c[o3](%[s]),d6           \n\t"                       \
        "move.l %c[o3]+4(%[s]),d7         \n\t"                       \
        "eor.l  d" #DLo ",d6              \n\t"                       \
        "eor.l  d" #DHi ",d7              \n\t"                       \
        "move.l d6,%c[t3](%[t])           \n\t"                       \
        "move.l d7,%c[t3]+4(%[t])         \n\t"                       \
                                                                      \
        /* ---- tmp[i0+20] ---- */                                    \
        "move.l %c[o4](%[s]),d6           \n\t"                       \
        "move.l %c[o4]+4(%[s]),d7         \n\t"                       \
        "eor.l  d" #DLo ",d6              \n\t"                       \
        "eor.l  d" #DHi ",d7              \n\t"                       \
        "move.l d6,%c[t4](%[t])           \n\t"                       \
        "move.l d7,%c[t4]+4(%[t])         \n\t"                       \
        :                                                             \
        : [s] "a"(state), [t] "a"(tmp),                               \
          [o0] "i"((i0)*8),                                           \
          [o1] "i"(((i0)+5)*8),                                       \
          [o2] "i"(((i0)+10)*8),                                      \
          [o3] "i"(((i0)+15)*8),                                      \
          [o4] "i"(((i0)+20)*8),                                      \
          [t0] "i"((i0)*8),                                           \
          [t1] "i"(((i0)+5)*8),                                       \
          [t2] "i"(((i0)+10)*8),                                      \
          [t3] "i"(((i0)+15)*8),                                      \
          [t4] "i"(((i0)+20)*8)                                       \
        : "d6","d7","memory"                                          \
    )


#define M68K_ROL64_LT32_INPLACE(dLo, dHi, dTmp, k) \
    asm volatile( \
        "move.l d" #dHi ",d" #dTmp "        \n\t" \
        "moveq  #32 - "#k"),d1          \n\t" \
        "lsr.l  d1,d" #dTmp "               \n\t" \
        "moveq  #"#k ",d1                  \n\t" \
        "lsl.l  d1,d" #dLo "                \n\t" \
        "or.l   d" #dTmp ",d" #dLo "        \n\t" \
        "move.l d" #dLo ",d" #dTmp "        \n\t" \
        "moveq  #(32 - "#k"),d1          \n\t" \
        "lsr.l  d1,d" #dTmp "               \n\t" \
        "moveq  #"#k ",d1                  \n\t" \
        "lsl.l  d1,d" #dHi "                \n\t" \
        "or.l   d" #dTmp ",d" #dHi "        \n\t" \
        : : : "d1","memory" )


#define M68K_ROL64_GE32_INPLACE(dLo, dHi, dTmp, k) \
    asm volatile( "exg d" #dLo ",d" #dHi "\n\t" ); \
    M68K_ROL64_LT32_INPLACE(dLo, dHi, dTmp, (k - 32))


extern "C" void k(uint64_t * state) {
uint64_t tmpState[25];

register uint64_t D0 asm("d0");   // D0 always in d0:d1
register uint64_t D2 asm("d2");   // D2 always in d2:d3
register uint64_t D4 asm("d4");   // DD4 always in d4:d5
register uint64_t D6 asm("d6");   // D6 always in d6:d7

#define C0 D4
#define C1 D2
#define C2 D6
#define C3 D4
#define C4 D2

for (register const uint64_t * konst = &KeccakF_RoundConstants[0];
     konst < &KeccakF_RoundConstants[24]; ++konst) {

// C4 and C1
M68K_COMPUTE_Cx(state, 4, C4, 2, 3);   // C4 = d2:d3
M68K_COMPUTE_Cx(state, 1, C1, 4, 5);   // C1 = d4:d5

// D0
M68K_D_AND_STORE(state, tmpState, 2,3, 4,5, 0,1, 0);   // rows 0,5,10,15,20

// C2
M68K_COMPUTE_Cx(state, 2, C2, 6, 7);   // C2 = d6:d7

// D3
M68K_D_AND_STORE(state, tmpState, 6,7, 2,3, 0,1, 3);   // rows 3,8,13,18,23

// C0
M68K_COMPUTE_Cx(state, 0, C0, 4, 5);   // C0 = d4:d5

// D1
M68K_D_AND_STORE(state, tmpState, 4,5, 6,7, 0,1, 1);   // rows 1,6,11,16,21

// C3
M68K_COMPUTE_Cx(state, 3, C3, 2, 3);   // C3 = d2:d3

// D4
M68K_D_AND_STORE(state, tmpState, 2,3, 4,5, 0,1, 4);   // rows 4,9,14,19,24

// D2
M68K_D_AND_STORE(state, tmpState, 4,5, 2,3, 0,1, 2);   // rows 2,7,12,17,22

#undef C0
#undef C1
#undef C2
#undef C3
#undef C4

#define R0 D2
#define R1 D4
#define R2 D6
#define R3 D2
#define R4 D4

    register uint64_t A0 asm("a0");
    register uint64_t A1 asm("a2");

// row 0
    R0 = tmpState[0];
    R1 = tmpState[6];
    M68K_ROL64_GE32_INPLACE(4,5,0,44);
    R2 = tmpState[12];
    M68K_ROL64_GE32_INPLACE(6,7,0,43);
    state[0] = R0 ^ ((~R1) & R2);

A0 = R0;

    R3 = tmpState[18];
    M68K_ROL64_LT32_INPLACE(4,5,0,21);
    state[1] = R1 ^ ((~R2) & R3);

A1 = R1;

    R4 = tmpState[24];
    M68K_ROL64_LT32_INPLACE(6,7,0,14);
    state[2] = R2 ^ ((~R3) & R4);

R0 = A0;
    state[3] = R3 ^ ((~R4) & R0);

R1 = A1;
    state[4] = R4 ^ ((~R0) & R1);

// row 1
R0 = tmpState[1];
M68K_ROL64_LT32_INPLACE(2,3,0,1);
R1 = tmpState[7];
M68K_ROL64_LT32_INPLACE(4,5,0,20);
R2 = tmpState[13];
M68K_ROL64_LT32_INPLACE(6,7,0,6);
state[5] = R0 ^ ((~R1) & R2);
A0 = R0;
R3 = tmpState[19];
M68K_ROL64_LT32_INPLACE(4,5,0,25);
state[6] = R1 ^ ((~R2) & R3);
A1 = R1;
R4 = tmpState[20];
M68K_ROL64_LT32_INPLACE(6,7,0,8);
state[7] = R2 ^ ((~R3) & R4);
R0 = A0;
state[8] = R3 ^ ((~R4) & R0);
R1 = A1;
state[9] = R4 ^ ((~R0) & R1);

// row 2
R0 = tmpState[2];
M68K_ROL64_GE32_INPLACE(2,3,0,62);
R1 = tmpState[8];
M68K_ROL64_GE32_INPLACE(4,5,0,55);
R2 = tmpState[14];
M68K_ROL64_GE32_INPLACE(6,7,0,39);
state[10] = R0 ^ ((~R1) & R2);
A0 = R0;
R3 = tmpState[15];
M68K_ROL64_GE32_INPLACE(4,5,0,41);
state[11] = R1 ^ ((~R2) & R3);
A1 = R1;
R4 = tmpState[21];
M68K_ROL64_GE32_INPLACE(6,7,0,45);
state[12] = R2 ^ ((~R3) & R4);
R0 = A0;
state[13] = R3 ^ ((~R4) & R0);
R1 = A1;
state[14] = R4 ^ ((~R0) & R1);

// row 3
R0 = tmpState[3];
M68K_ROL64_LT32_INPLACE(2,3,0,28);
R1 = tmpState[9];
M68K_ROL64_LT32_INPLACE(4,5,0,27);
R2 = tmpState[10];
M68K_ROL64_GE32_INPLACE(6,7,0,36);
state[15] = R0 ^ ((~R1) & R2);
A0 = R0;
R3 = tmpState[16];
M68K_ROL64_LT32_INPLACE(4,5,0,10);
state[16] = R1 ^ ((~R2) & R3);
A1 = R1;
R4 = tmpState[22];
M68K_ROL64_LT32_INPLACE(6,7,0,15);
state[17] = R2 ^ ((~R3) & R4);
R0 = A0;
state[18] = R3 ^ ((~R4) & R0);
R1 = A1;
state[19] = R4 ^ ((~R0) & R1);

// row 4
R0 = tmpState[4];
M68K_ROL64_LT32_INPLACE(2,3,0,27);
R1 = tmpState[5];
M68K_ROL64_GE32_INPLACE(4,5,0,56);
R2 = tmpState[11];
M68K_ROL64_LT32_INPLACE(6,7,0,3);
state[20] = R0 ^ ((~R1) & R2);
A0 = R0;
R3 = tmpState[17];
M68K_ROL64_LT32_INPLACE(4,5,0,18);
state[21] = R1 ^ ((~R2) & R3);
A1 = R1;
R4 = tmpState[23];
M68K_ROL64_LT32_INPLACE(6,7,0,2);
state[22] = R2 ^ ((~R3) & R4);
R0 = A0;
state[23] = R3 ^ ((~R4) & R0);
R1 = A1;
state[24] = R4 ^ ((~R0) & R1);


    state[0] ^= *konst;
}

#undef R0
#undef R1
#undef R2
#undef R3

}
#else
#include <stdint.h>

static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

static inline uint64_t rol(uint64_t x, unsigned n) {
    return (x << n) | (x >> (64 - n));
}

void k(uint64_t st[25]) {
    for (int round = 0; round < 24; ++round) {

        /* --- theta step --- */
        uint64_t C[5], D[5];

        for (int x = 0; x < 5; ++x)
            C[x] = st[x] ^ st[x+5] ^ st[x+10] ^ st[x+15] ^ st[x+20];

        for (int x = 0; x < 5; ++x)
            D[x] = rol(C[(x+4)%5], 1) ^ C[(x+1)%5];

        for (int i = 0; i < 25; i += 5) {
            st[i+0] ^= D[0];
            st[i+1] ^= D[1];
            st[i+2] ^= D[2];
            st[i+3] ^= D[3];
            st[i+4] ^= D[4];
        }

        /* --- rho + pi step --- */
        uint64_t B[25];

        B[ 0] = st[ 0];
        B[10] = rol(st[ 1],  1);
        B[ 7] = rol(st[ 2], 62);
        B[11] = rol(st[ 3], 28);
        B[17] = rol(st[ 4], 27);

        B[18] = rol(st[ 5], 36);
        B[ 3] = rol(st[ 6], 44);
        B[ 5] = rol(st[ 7],  6);
        B[16] = rol(st[ 8], 55);
        B[ 8] = rol(st[ 9], 20);

        B[21] = rol(st[10],  3);
        B[15] = rol(st[11], 10);
        B[23] = rol(st[12], 43);
        B[13] = rol(st[13], 25);
        B[ 4] = rol(st[14], 39);

        B[14] = rol(st[15], 41);
        B[24] = rol(st[16], 45);
        B[ 2] = rol(st[17], 15);
        B[20] = rol(st[18], 21);
        B[22] = rol(st[19],  8);

        B[ 9] = rol(st[20], 18);
        B[ 6] = rol(st[21],  2);
        B[ 1] = rol(st[22], 61);
        B[12] = rol(st[23], 56);
        B[19] = rol(st[24], 14);

        /* --- chi step --- */
        for (int y = 0; y < 5; ++y) {
            uint64_t r0 = B[5*y+0];
            uint64_t r1 = B[5*y+1];
            uint64_t r2 = B[5*y+2];
            uint64_t r3 = B[5*y+3];
            uint64_t r4 = B[5*y+4];

            st[5*y+0] = r0 ^ ((~r1) & r2);
            st[5*y+1] = r1 ^ ((~r2) & r3);
            st[5*y+2] = r2 ^ ((~r3) & r4);
            st[5*y+3] = r3 ^ ((~r4) & r0);
            st[5*y+4] = r4 ^ ((~r0) & r1);
        }

        /* --- iota step --- */
        st[0] ^= RC[round];
    }
}

#endif
