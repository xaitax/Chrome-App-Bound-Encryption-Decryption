// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include <cstdint>
#include <vector>

namespace Crypto {

    class ChaCha20 {
    public:
        // Encrypts/Decrypts data in place using ChaCha20
        // Key: 32 bytes
        // Nonce: 12 bytes
        // Counter: Initial block counter (usually 0 or 1)
        static void Crypt(const uint8_t key[32], const uint8_t nonce[12], std::vector<uint8_t>& data, uint32_t counter = 0);

    private:
        static void ProcessBlock(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t output[64]);
        static uint32_t Rotl(uint32_t x, int n);
        static void QuarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d);
    };

}
