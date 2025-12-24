// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include <cstdint>
#include <cstddef>
#include <array>
#include "version.hpp"

namespace Core {

    namespace detail {
        // Compile-time FNV-1a for key generation
        constexpr uint64_t fnv1a_64(const char* str, size_t len) {
            uint64_t hash = 14695981039346656037ULL;
            for (size_t i = 0; i < len; ++i) {
                hash ^= static_cast<uint64_t>(str[i]);
                hash *= 1099511628211ULL;
            }
            return hash;
        }

        // Build-specific seed from version + date
        constexpr uint64_t BUILD_KEY = fnv1a_64(__DATE__, 11) ^ fnv1a_64(Core::BUILD_TAG, 7);

        // Generate position-dependent key byte
        constexpr uint8_t key_byte(size_t pos, uint64_t seed) {
            uint64_t mixed = seed ^ (pos * 0x9E3779B97F4A7C15ULL);
            mixed ^= mixed >> 33;
            mixed *= 0xFF51AFD7ED558CCDULL;
            mixed ^= mixed >> 33;
            return static_cast<uint8_t>(mixed);
        }
    }

    template<size_t N>
    class ObfuscatedString {
    public:
        // Compile-time constructor - encrypts the string
        constexpr ObfuscatedString(const char (&str)[N], uint64_t seed) : m_seed(seed) {
            for (size_t i = 0; i < N; ++i) {
                m_data[i] = str[i] ^ detail::key_byte(i, seed);
            }
        }

        // Runtime decryption - returns the original string
        const char* c_str() const {
            // Decrypt into thread-local buffer
            thread_local char buffer[N];
            for (size_t i = 0; i < N; ++i) {
                buffer[i] = m_data[i] ^ detail::key_byte(i, m_seed);
            }
            return buffer;
        }

        // Get decrypted string and store in provided buffer
        void decrypt_to(char* buffer) const {
            for (size_t i = 0; i < N; ++i) {
                buffer[i] = m_data[i] ^ detail::key_byte(i, m_seed);
            }
        }

        constexpr size_t size() const { return N - 1; }

    private:
        std::array<char, N> m_data{};
        uint64_t m_seed;
    };

    // Helper to create obfuscated string with unique seed per call site
    template<size_t N>
    constexpr auto make_obfuscated(const char (&str)[N], uint64_t line_seed) {
        return ObfuscatedString<N>(str, detail::BUILD_KEY ^ line_seed);
    }

}

// Macro that creates unique seed from line number
#define OBF(str) (::Core::make_obfuscated(str, __LINE__ * 0x85EBCA77C2B2AE63ULL))

// For wide strings
#define WOBF(str) (::Core::make_obfuscated_w(str, __LINE__ * 0x85EBCA77C2B2AE63ULL))
