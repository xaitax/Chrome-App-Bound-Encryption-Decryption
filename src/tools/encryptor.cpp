#include "../crypto/crypto.hpp"
#include "../crypto/key_derivation.hpp"
#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>

/**
 * Payload Encryptor Tool
 * 
 * This tool encrypts the payload DLL using runtime-derived keys.
 * The key derivation uses the same algorithm as the decryptor,
 * ensuring deterministic keys per build (based on __DATE__/__TIME__).
 * 
 * IMPORTANT: The encryptor and injector MUST be built in the SAME
 * compilation session (same make.bat run) for keys to match.
 * This is because BUILD_SEED changes with __DATE__ and __TIME__.
 */

void PrintKeyInfo(const Crypto::RuntimeKeyProvider::KeyMaterial& km) {
    std::cout << "\n=== Runtime Key Derivation Info ===" << std::endl;
    std::cout << "Build Seed: 0x" << std::hex << std::setfill('0') 
              << std::setw(16) << Crypto::Detail::BUILD_SEED << std::endl;
    
    std::cout << "Derived Key: ";
    for (size_t i = 0; i < km.key.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)km.key[i];
    }
    std::cout << std::endl;
    
    std::cout << "Derived Nonce: ";
    for (size_t i = 0; i < km.nonce.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)km.nonce[i];
    }
    std::cout << std::endl;
    std::cout << "==================================\n" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "ChromeElevator Payload Encryptor" << std::endl;
        std::cerr << "================================" << std::endl;
        std::cerr << "Usage: " << argv[0] << " <input.dll> <output.bin>" << std::endl;
        std::cerr << std::endl;
        std::cerr << "This tool encrypts the payload DLL using ChaCha20 with keys" << std::endl;
        std::cerr << "derived from environmental entropy + compile-time seed." << std::endl;
        std::cerr << std::endl;
        std::cerr << "NOTE: Encryptor and injector must be built together!" << std::endl;
        return 1;
    }

    std::ifstream in(argv[1], std::ios::binary);
    if (!in) {
        std::cerr << "[-] Failed to open input: " << argv[1] << std::endl;
        return 1;
    }

    std::vector<uint8_t> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    std::cout << "[*] Input file: " << argv[1] << " (" << data.size() << " bytes)" << std::endl;

    // Derive keys using the same algorithm as the decryptor
    auto keyMaterial = Crypto::RuntimeKeyProvider::GetPayloadKey();
    if (!keyMaterial.valid) {
        std::cerr << "[-] Failed to derive encryption keys!" << std::endl;
        return 1;
    }

    PrintKeyInfo(keyMaterial);

    // Encrypt using ChaCha20 (XOR-based, so same function encrypts/decrypts)
    Crypto::ChaCha20::Crypt(keyMaterial.key.data(), keyMaterial.nonce.data(), data, 0);

    // Securely clear key material
    SecureZeroMemory(keyMaterial.key.data(), keyMaterial.key.size());
    SecureZeroMemory(keyMaterial.nonce.data(), keyMaterial.nonce.size());

    std::ofstream out(argv[2], std::ios::binary);
    if (!out) {
        std::cerr << "[-] Failed to open output: " << argv[2] << std::endl;
        return 1;
    }

    out.write(reinterpret_cast<const char*>(data.data()), data.size());
    out.close();

    std::cout << "[+] Encrypted payload written to: " << argv[2] << std::endl;
    std::cout << "[+] Output size: " << data.size() << " bytes" << std::endl;
    std::cout << std::endl;
    std::cout << "[!] Remember: Injector must be compiled in same build session!" << std::endl;

    return 0;
}
