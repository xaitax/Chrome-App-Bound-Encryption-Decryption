// libs/chacha/chacha.h
// A public domain, self-contained ChaCha20 implementation.

#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Main ChaCha20 function. Encrypts/decrypts data in place.
void chacha20_block(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t* out);
void chacha20_xor(const uint8_t key[32], const uint8_t nonce[12], uint8_t* data, size_t data_len, uint32_t counter);

#ifdef __cplusplus
}
#endif

#endif // CHACHA20_H

#ifdef CHACHA20_IMPLEMENTATION

// Internal utility functions
static uint32_t chacha20_load32(const uint8_t *x) {
    return (uint32_t)(x[0]) | ((uint32_t)(x[1]) << 8) | ((uint32_t)(x[2]) << 16) | ((uint32_t)(x[3]) << 24);
}

static void chacha20_store32(uint8_t *x, uint32_t u) {
    x[0] = u & 0xff; u >>= 8;
    x[1] = u & 0xff; u >>= 8;
    x[2] = u & 0xff; u >>= 8;
    x[3] = u & 0xff;
}

static uint32_t chacha20_rotl(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// The ChaCha20 quarter round function
#define CHACHA20_QR(a, b, c, d) \
    a += b; d ^= a; d = chacha20_rotl(d, 16); \
    c += d; b ^= c; b = chacha20_rotl(b, 12); \
    a += b; d ^= a; d = chacha20_rotl(d, 8);  \
    c += d; b ^= c; b = chacha20_rotl(b, 7);

void chacha20_block(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t* out) {
    uint32_t x[16];
    uint32_t j[16];
    int i;

    // Constants
    x[0] = 0x61707865; 
    x[1] = 0x3320646e;
    x[2] = 0x79622d32;
    x[3] = 0x6b206574;

    // Key
    x[4] = chacha20_load32(key + 0);
    x[5] = chacha20_load32(key + 4);
    x[6] = chacha20_load32(key + 8);
    x[7] = chacha20_load32(key + 12);
    x[8] = chacha20_load32(key + 16);
    x[9] = chacha20_load32(key + 20);
    x[10] = chacha20_load32(key + 24);
    x[11] = chacha20_load32(key + 28);

    // Counter and Nonce
    x[12] = counter;
    x[13] = chacha20_load32(nonce + 0);
    x[14] = chacha20_load32(nonce + 4);
    x[15] = chacha20_load32(nonce + 8);

    for (i = 0; i < 16; ++i) j[i] = x[i];

    for (i = 0; i < 10; ++i) { // 20 rounds = 10 double rounds
        CHACHA20_QR(j[0], j[4], j[8],  j[12]);
        CHACHA20_QR(j[1], j[5], j[9],  j[13]);
        CHACHA20_QR(j[2], j[6], j[10], j[14]);
        CHACHA20_QR(j[3], j[7], j[11], j[15]);
        CHACHA20_QR(j[0], j[5], j[10], j[15]);
        CHACHA20_QR(j[1], j[6], j[11], j[12]);
        CHACHA20_QR(j[2], j[7], j[8],  j[13]);
        CHACHA20_QR(j[3], j[4], j[9],  j[14]);
    }

    for (i = 0; i < 16; ++i) x[i] += j[i];
    for (i = 0; i < 16; ++i) chacha20_store32(out + 4 * i, x[i]);
}

void chacha20_xor(const uint8_t key[32], const uint8_t nonce[12], uint8_t* data, size_t data_len, uint32_t counter) {
    uint8_t block[64];
    size_t i;

    for (; data_len >= 64; data_len -= 64, data += 64) {
        chacha20_block(key, nonce, counter++, block);
        for (i = 0; i < 64; ++i) data[i] ^= block[i];
    }

    if (data_len > 0) {
        chacha20_block(key, nonce, counter, block);
        for (i = 0; i < data_len; ++i) data[i] ^= block[i];
    }
}

#endif