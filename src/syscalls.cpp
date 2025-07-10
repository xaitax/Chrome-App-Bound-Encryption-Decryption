// syscalls.cpp
// v0.13.0 (c) Alexander 'xaitax' Hagenah
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

extern "C" NTSTATUS SyscallTrampoline(...);

struct SORTED_SYSCALL_MAPPING
{
    PVOID pAddress;
    LPCSTR szName;
    WORD ssn;
};

bool CompareSyscallMappings(const SORTED_SYSCALL_MAPPING &a, const SORTED_SYSCALL_MAPPING &b)
{
    return (uintptr_t)a.pAddress < (uintptr_t)b.pAddress;
}

PVOID FindSyscallGadget_x64(PVOID pFunction)
{
    for (DWORD i = 0; i <= 20; ++i)
    {
        if (*(PWORD)((PBYTE)pFunction + i) == 0x050F && *((PBYTE)pFunction + i + 2) == 0xC3)
        {
            return (PVOID)((PBYTE)pFunction + i);
        }
    }
    return nullptr;
}

PVOID FindSvcGadget_ARM64(PVOID pFunction)
{
    for (DWORD i = 0; i <= 20; i += 4)
    {
        DWORD instruction = *(PDWORD)((PBYTE)pFunction + i);
        if ((instruction & 0xFF000000) == 0xD4000000)
        {
            if (*(PDWORD)((PBYTE)pFunction + i + 4) == 0xD65F03C0)
            {
                return (PVOID)((PBYTE)pFunction + i);
            }
        }
    }
    return nullptr;
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

    std::vector<SORTED_SYSCALL_MAPPING> sortedSyscalls;
    for (DWORD i = 0; i < pExportDir->NumberOfNames; ++i)
    {
        LPCSTR szFuncName = (LPCSTR)((PBYTE)hNtdll + pNameRvas[i]);
        if (strncmp(szFuncName, "Zw", 2) == 0)
        {
            PVOID pFuncAddress = (PVOID)((PBYTE)hNtdll + pAddressRvas[pOrdinalRvas[i]]);
            sortedSyscalls.push_back({pFuncAddress, szFuncName, 0});
        }
    }

    std::sort(sortedSyscalls.begin(), sortedSyscalls.end(), CompareSyscallMappings);

    debug_print("Found and sorted " + std::to_string(sortedSyscalls.size()) + " Zw* functions.");

    for (WORD i = 0; i < sortedSyscalls.size(); ++i)
    {
        const char *name = sortedSyscalls[i].szName;
        PVOID pGadget = nullptr;

#if defined(_M_X64)
        pGadget = FindSyscallGadget_x64(sortedSyscalls[i].pAddress);
#elif defined(_M_ARM64)
        pGadget = FindSvcGadget_ARM64(sortedSyscalls[i].pAddress);
#endif

        if (!pGadget)
        {
            continue;
        }

        if (_stricmp(name, "ZwAllocateVirtualMemory") == 0)
        {
            g_syscall_stubs.NtAllocateVirtualMemory.ssn = i;
            g_syscall_stubs.NtAllocateVirtualMemory.pSyscallGadget = pGadget;
            g_syscall_stubs.NtAllocateVirtualMemory.nArgs = 6;
        }
        else if (_stricmp(name, "ZwWriteVirtualMemory") == 0)
        {
            g_syscall_stubs.NtWriteVirtualMemory.ssn = i;
            g_syscall_stubs.NtWriteVirtualMemory.pSyscallGadget = pGadget;
            g_syscall_stubs.NtWriteVirtualMemory.nArgs = 5;
        }
        else if (_stricmp(name, "ZwCreateThreadEx") == 0)
        {
            g_syscall_stubs.NtCreateThreadEx.ssn = i;
            g_syscall_stubs.NtCreateThreadEx.pSyscallGadget = pGadget;
            g_syscall_stubs.NtCreateThreadEx.nArgs = 11;
        }
        else if (_stricmp(name, "ZwFreeVirtualMemory") == 0)
        {
            g_syscall_stubs.NtFreeVirtualMemory.ssn = i;
            g_syscall_stubs.NtFreeVirtualMemory.pSyscallGadget = pGadget;
            g_syscall_stubs.NtFreeVirtualMemory.nArgs = 4;
        }
        else if (_stricmp(name, "ZwProtectVirtualMemory") == 0)
        {
            g_syscall_stubs.NtProtectVirtualMemory.ssn = i;
            g_syscall_stubs.NtProtectVirtualMemory.pSyscallGadget = pGadget;
            g_syscall_stubs.NtProtectVirtualMemory.nArgs = 5;
        }
    }

    bool success = g_syscall_stubs.NtAllocateVirtualMemory.pSyscallGadget &&
                   g_syscall_stubs.NtWriteVirtualMemory.pSyscallGadget &&
                   g_syscall_stubs.NtCreateThreadEx.pSyscallGadget &&
                   g_syscall_stubs.NtFreeVirtualMemory.pSyscallGadget &&
                   g_syscall_stubs.NtProtectVirtualMemory.pSyscallGadget;

    if (success)
    {
        debug_print("Successfully initialized all direct syscall stubs.");
        std::stringstream ss;
        ss << "  - NtAllocateVirtualMemory (SSN: " << g_syscall_stubs.NtAllocateVirtualMemory.ssn << ") -> Gadget: 0x" << std::hex << (uintptr_t)g_syscall_stubs.NtAllocateVirtualMemory.pSyscallGadget;
        debug_print(ss.str());
    }
    else
    {
        debug_print("One or more required syscall gadgets could not be found.");
    }

    return success;
}

NTSTATUS NtAllocateVirtualMemory_syscall(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
{
    return (NTSTATUS)SyscallTrampoline(&g_syscall_stubs.NtAllocateVirtualMemory, ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

NTSTATUS NtWriteVirtualMemory_syscall(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten)
{
    return (NTSTATUS)SyscallTrampoline(&g_syscall_stubs.NtWriteVirtualMemory, ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

NTSTATUS NtCreateThreadEx_syscall(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, LPVOID ObjectAttributes, HANDLE ProcessHandle, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, ULONG CreateFlags, ULONG_PTR ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, LPVOID AttributeList)
{
    return (NTSTATUS)SyscallTrampoline(&g_syscall_stubs.NtCreateThreadEx, ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

NTSTATUS NtFreeVirtualMemory_syscall(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG FreeType)
{
    return (NTSTATUS)SyscallTrampoline(&g_syscall_stubs.NtFreeVirtualMemory, ProcessHandle, BaseAddress, RegionSize, FreeType);
}

NTSTATUS NtProtectVirtualMemory_syscall(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect)
{
    return (NTSTATUS)SyscallTrampoline(&g_syscall_stubs.NtProtectVirtualMemory, ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}
