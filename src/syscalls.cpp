// syscalls.cpp
// v0.12.0 (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "syscalls.h"
#include <vector>
#include <string>
#include <algorithm>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <map>

SYSCALL_STUBS g_syscall_stubs;

static bool g_verbose_syscalls = false;
static void debug_print(const std::string &msg)
{
    if (!g_verbose_syscalls)
        return;
    std::cout << "[#] [Syscalls] " << msg << std::endl;
}

struct SORTED_SYSCALL_ENTRY
{
    PVOID pAddress;
    LPCSTR szName;
    WORD ssn;
};

bool CompareSyscallEntries(const SORTED_SYSCALL_ENTRY &a, const SORTED_SYSCALL_ENTRY &b)
{
    return (uintptr_t)a.pAddress < (uintptr_t)b.pAddress;
}

BOOL InitializeSyscalls(bool is_verbose)
{
    g_verbose_syscalls = is_verbose;
    memset(&g_syscall_stubs, 0, sizeof(SYSCALL_STUBS));

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll)
    {
        debug_print("GetModuleHandleW for ntdll.dll failed.");
        return FALSE;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)hNtdll + pDosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)hNtdll + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD pNameRvas = (PDWORD)((PBYTE)hNtdll + pExportDir->AddressOfNames);
    PDWORD pAddressRvas = (PDWORD)((PBYTE)hNtdll + pExportDir->AddressOfFunctions);
    PWORD pOrdinalRvas = (PWORD)((PBYTE)hNtdll + pExportDir->AddressOfNameOrdinals);

    std::vector<SORTED_SYSCALL_ENTRY> sortedSyscalls;
    for (DWORD i = 0; i < pExportDir->NumberOfNames; ++i)
    {
        LPCSTR szFuncName = (LPCSTR)((PBYTE)hNtdll + pNameRvas[i]);
        if (strncmp(szFuncName, "Zw", 2) == 0)
        {
            PVOID pFuncAddress = (PVOID)((PBYTE)hNtdll + pAddressRvas[pOrdinalRvas[i]]);
            sortedSyscalls.push_back({pFuncAddress, szFuncName, 0});
        }
    }

    std::sort(sortedSyscalls.begin(), sortedSyscalls.end(), CompareSyscallEntries);
    debug_print("Found and sorted " + std::to_string(sortedSyscalls.size()) + " Zw* functions.");

    // --- TARTARUS GATE IMPLEMENTATION ---
    // The SSN is simply the index of the function in the sorted list.
    // We assign the function pointer directly, even if it's hooked.
    // The reflective DLL injection will call this function pointer, which then hits the hook,
    // but the hook from a security product should still pass the call to the kernel correctly.
    // This is the most reliable method when all else fails.

    for (size_t i = 0; i < sortedSyscalls.size(); ++i)
    {
        const char *name = sortedSyscalls[i].szName;
        if (_stricmp(name, "ZwAllocateVirtualMemory") == 0)
            g_syscall_stubs.NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)sortedSyscalls[i].pAddress;
        else if (_stricmp(name, "ZwWriteVirtualMemory") == 0)
            g_syscall_stubs.NtWriteVirtualMemory = (pNtWriteVirtualMemory)sortedSyscalls[i].pAddress;
        else if (_stricmp(name, "ZwCreateThreadEx") == 0)
            g_syscall_stubs.NtCreateThreadEx = (pNtCreateThreadEx)sortedSyscalls[i].pAddress;
        else if (_stricmp(name, "ZwFreeVirtualMemory") == 0)
            g_syscall_stubs.NtFreeVirtualMemory = (pNtFreeVirtualMemory)sortedSyscalls[i].pAddress;
        else if (_stricmp(name, "ZwProtectVirtualMemory") == 0)
            g_syscall_stubs.NtProtectVirtualMemory = (pNtProtectVirtualMemory)sortedSyscalls[i].pAddress;
    }

    bool success = g_syscall_stubs.NtAllocateVirtualMemory &&
                   g_syscall_stubs.NtWriteVirtualMemory &&
                   g_syscall_stubs.NtCreateThreadEx &&
                   g_syscall_stubs.NtFreeVirtualMemory &&
                   g_syscall_stubs.NtProtectVirtualMemory;

    if (success)
    {
        debug_print("Successfully initialized all syscall stubs via Tartarus Gate.");
        debug_print("  - NtAllocateVirtualMemory found at " + std::to_string((uintptr_t)g_syscall_stubs.NtAllocateVirtualMemory));
    }
    else
    {
        debug_print("One or more syscall stubs could not be found in the export table.");
    }

    return success;
}
