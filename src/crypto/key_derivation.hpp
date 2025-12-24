// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include <Windows.h>
#include <cstdint>
#include <array>
#include <cstring>
#include "../core/version.hpp"

namespace Crypto {

    namespace Detail {

        //=====================================================================
        // Compile-Time Hash Functions
        //=====================================================================

        constexpr uint64_t FNV_OFFSET = 14695981039346656037ULL;
        constexpr uint64_t FNV_PRIME = 1099511628211ULL;

        // FNV-1a: Fast, well-distributed hash for strings
        constexpr uint64_t fnv1a(const char* str, uint64_t hash = FNV_OFFSET) {
            return (*str == 0) ? hash : fnv1a(str + 1, (hash ^ static_cast<uint64_t>(*str)) * FNV_PRIME);
        }

        // Bit rotation
        constexpr uint64_t rotl64(uint64_t x, int k) {
            return (x << k) | (x >> (64 - k));
        }

        // MurmurHash3 finalizer: Excellent avalanche properties
        constexpr uint64_t mix64(uint64_t k) {
            k ^= k >> 33;
            k *= 0xFF51AFD7ED558CCDULL;
            k ^= k >> 33;
            k *= 0xC4CEB9FE1A85EC53ULL;
            k ^= k >> 33;
            return k;
        }

        //=====================================================================
        // Build-Time Seed Generation
        //=====================================================================

        // Primary seed from version.hpp BUILD_TAG + __DATE__
        // - Changes per release (update version.hpp)
        // - Changes per daily build (__DATE__ changes)
        // - Stable within a single make.bat run
        constexpr uint64_t BUILD_SEED = mix64(
            fnv1a(Core::BUILD_TAG) ^ rotl64(fnv1a(__DATE__), 17)
        );

        // Cascade: 6 rounds of mixing for maximum diffusion
        constexpr uint64_t SEED_1 = mix64(BUILD_SEED ^ 0xDEADBEEFCAFEBABEULL);
        constexpr uint64_t SEED_2 = mix64(SEED_1 ^ 0x0123456789ABCDEFULL);
        constexpr uint64_t SEED_3 = mix64(SEED_2 ^ 0xFEDCBA9876543210ULL);
        constexpr uint64_t SEED_4 = mix64(SEED_3 ^ 0xAAAA5555AAAA5555ULL);
        constexpr uint64_t SEED_5 = mix64(SEED_4 ^ 0x1111222233334444ULL);
        constexpr uint64_t SEED_6 = mix64(SEED_5 ^ 0x5555666677778888ULL);

        //=====================================================================
        // Key Material (constexpr arrays)
        //=====================================================================

        // 32-byte key from SEED_1..SEED_4


        // Helper to extract byte from uint64_t
        constexpr uint8_t extractByte(uint64_t val, int byteIndex) {
            return static_cast<uint8_t>((val >> (byteIndex * 8)) & 0xFF);
        }

        // Compile-time generated key (32 bytes from 4 seeds)
        constexpr std::array<uint8_t, 32> makeKey() {
            return {{
                extractByte(SEED_1, 0), extractByte(SEED_1, 1), extractByte(SEED_1, 2), extractByte(SEED_1, 3),
                extractByte(SEED_1, 4), extractByte(SEED_1, 5), extractByte(SEED_1, 6), extractByte(SEED_1, 7),
                extractByte(SEED_2, 0), extractByte(SEED_2, 1), extractByte(SEED_2, 2), extractByte(SEED_2, 3),
                extractByte(SEED_2, 4), extractByte(SEED_2, 5), extractByte(SEED_2, 6), extractByte(SEED_2, 7),
                extractByte(SEED_3, 0), extractByte(SEED_3, 1), extractByte(SEED_3, 2), extractByte(SEED_3, 3),
                extractByte(SEED_3, 4), extractByte(SEED_3, 5), extractByte(SEED_3, 6), extractByte(SEED_3, 7),
                extractByte(SEED_4, 0), extractByte(SEED_4, 1), extractByte(SEED_4, 2), extractByte(SEED_4, 3),
                extractByte(SEED_4, 4), extractByte(SEED_4, 5), extractByte(SEED_4, 6), extractByte(SEED_4, 7)
            }};
        }

        // Compile-time generated nonce (12 bytes from SEED_5 + half of SEED_6)
        constexpr std::array<uint8_t, 12> makeNonce() {
            return {{
                extractByte(SEED_5, 0), extractByte(SEED_5, 1), extractByte(SEED_5, 2), extractByte(SEED_5, 3),
                extractByte(SEED_5, 4), extractByte(SEED_5, 5), extractByte(SEED_5, 6), extractByte(SEED_5, 7),
                extractByte(SEED_6, 0), extractByte(SEED_6, 1), extractByte(SEED_6, 2), extractByte(SEED_6, 3)
            }};
        }

        // The actual constexpr key material
        constexpr auto DERIVED_KEY = makeKey();
        constexpr auto DERIVED_NONCE = makeNonce();

    } // namespace Detail

    /**
     * RuntimeKeyProvider - Main interface for getting cryptographic keys
     * 
     * Despite the name, keys are derived entirely at COMPILE TIME.
     * The "runtime" aspect is just copying from constexpr storage.
     * 
     * Usage:
     *   auto km = Crypto::RuntimeKeyProvider::GetPayloadKey();
     *   // km.key  - 32 bytes
     *   // km.nonce - 12 bytes  
     *   // km.valid - always true (compile-time guarantees)
     */
    class RuntimeKeyProvider {
    public:
        struct KeyMaterial {
            std::array<uint8_t, 32> key;
            std::array<uint8_t, 12> nonce;
            bool valid;
        };

        static KeyMaterial GetPayloadKey() {
            KeyMaterial result = {};
            
            // Copy from compile-time generated arrays
            std::memcpy(result.key.data(), Detail::DERIVED_KEY.data(), 32);
            std::memcpy(result.nonce.data(), Detail::DERIVED_NONCE.data(), 12);
            result.valid = true;
            
            return result;
        }

        // Alias for clarity in encryptor tool
        static KeyMaterial DeriveFromSeed() {
            return GetPayloadKey();
        }

        // For debug output
        static uint64_t GetBuildSeed() {
            return Detail::BUILD_SEED;
        }
    };

}
