// encryptor.cpp
// v0.16.1 (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

// Define the implementation flag BEFORE including the header
#define CHACHA20_IMPLEMENTATION
#include "..\libs\chacha\chacha20.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>

// A 256-bit (32-byte) key.
static const uint8_t aKey[32] = {
    0x1B, 0x27, 0x55, 0x64, 0x73, 0x8B, 0x9F, 0x4D,
    0x58, 0x4A, 0x7D, 0x67, 0x8C, 0x79, 0x77, 0x46,
    0xBE, 0x6B, 0x4E, 0x0C, 0x54, 0x57, 0xCD, 0x95,
    0x18, 0xDE, 0x7E, 0x21, 0x47, 0x66, 0x7C, 0x94};

// A 96-bit (12-byte) nonce.
static const uint8_t aNonce[12] = {
    0x4A, 0x51, 0x78, 0x62, 0x8D, 0x2D, 0x4A, 0x54,
    0x88, 0xE5, 0x3C, 0x50};

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        std::cerr << "Usage: " << argv[0] << " <input_file> <output_file>" << std::endl;
        return 1;
    }

    std::ifstream inFile(argv[1], std::ios::binary);
    if (!inFile)
    {
        std::cerr << "Error opening input file: " << argv[1] << std::endl;
        return 1;
    }

    std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();

    // Encrypt the buffer in-place using our new function
    chacha20_xor(aKey, aNonce, buffer.data(), buffer.size(), 0);

    std::ofstream outFile(argv[2], std::ios::binary);
    if (!outFile)
    {
        std::cerr << "Error opening output file: " << argv[2] << std::endl;
        return 1;
    }

    outFile.write(reinterpret_cast<const char *>(buffer.data()), buffer.size());
    outFile.close();

    std::cout << "Successfully ChaCha20-encrypted " << argv[1] << " to " << argv[2] << std::endl;
    return 0;
}