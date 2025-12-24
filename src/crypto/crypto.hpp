// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include "../core/common.hpp"
#include "chacha20.hpp"
#include "key_derivation.hpp"

namespace Crypto {

    inline bool DecryptPayload(std::vector<uint8_t>& data) {
        auto keyMaterial = RuntimeKeyProvider::GetPayloadKey();
        if (!keyMaterial.valid) {
            return false;
        }
        
        ChaCha20::Crypt(keyMaterial.key.data(), keyMaterial.nonce.data(), data, 0);
        
        // Securely clear key material from memory
        SecureZeroMemory(keyMaterial.key.data(), keyMaterial.key.size());
        SecureZeroMemory(keyMaterial.nonce.data(), keyMaterial.nonce.size());
        
        return true;
    }

    inline void DecryptPayload(std::vector<uint8_t>& data, const uint8_t key[32], const uint8_t nonce[12]) {
        ChaCha20::Crypt(key, nonce, data, 0);
    }

}
