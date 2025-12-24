// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "chacha20.hpp"
#include <cstring>

namespace Crypto {

    void ChaCha20::Crypt(const uint8_t key[32], const uint8_t nonce[12], std::vector<uint8_t>& data, uint32_t counter) {
        uint8_t block[64];
        size_t len = data.size();
        uint8_t* ptr = data.data();

        while (len > 0) {
            ProcessBlock(key, nonce, counter++, block);
            size_t chunk = (len < 64) ? len : 64;
            for (size_t i = 0; i < chunk; ++i) {
                ptr[i] ^= block[i];
            }
            ptr += chunk;
            len -= chunk;
        }
    }

    uint32_t ChaCha20::Rotl(uint32_t x, int n) {
        return (x << n) | (x >> (32 - n));
    }

    void ChaCha20::QuarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
        a += b; d ^= a; d = Rotl(d, 16);
        c += d; b ^= c; b = Rotl(b, 12);
        a += b; d ^= a; d = Rotl(d, 8);
        c += d; b ^= c; b = Rotl(b, 7);
    }

    void ChaCha20::ProcessBlock(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t output[64]) {
        uint32_t state[16];
        
        // Constants "expand 32-byte k"
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        // Key
        auto Load32 = [](const uint8_t* p) -> uint32_t {
            return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
        };

        for (int i = 0; i < 8; ++i) state[4 + i] = Load32(key + i * 4);

        // Counter
        state[12] = counter;

        // Nonce
        for (int i = 0; i < 3; ++i) state[13 + i] = Load32(nonce + i * 4);

        uint32_t working[16];
        std::memcpy(working, state, sizeof(state));

        for (int i = 0; i < 10; ++i) {
            QuarterRound(working[0], working[4], working[8],  working[12]);
            QuarterRound(working[1], working[5], working[9],  working[13]);
            QuarterRound(working[2], working[6], working[10], working[14]);
            QuarterRound(working[3], working[7], working[11], working[15]);
            QuarterRound(working[0], working[5], working[10], working[15]);
            QuarterRound(working[1], working[6], working[11], working[12]);
            QuarterRound(working[2], working[7], working[8],  working[13]);
            QuarterRound(working[3], working[4], working[9],  working[14]);
        }

        for (int i = 0; i < 16; ++i) {
            uint32_t val = working[i] + state[i];
            output[i * 4 + 0] = val & 0xff;
            output[i * 4 + 1] = (val >> 8) & 0xff;
            output[i * 4 + 2] = (val >> 16) & 0xff;
            output[i * 4 + 3] = (val >> 24) & 0xff;
        }
    }

}
