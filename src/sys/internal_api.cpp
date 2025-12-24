// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "internal_api.hpp"
#include <vector>
#include <algorithm>

// Global instance definition
SYSCALL_STUBS g_syscall_stubs{};

// External ASM function
extern "C" NTSTATUS SyscallTrampoline(void* entry, ...);

namespace Sys {

    namespace {
        // Compile-time DJB2 hash for function name matching
        constexpr uint32_t djb2_hash(const char* str) {
            uint32_t hash = 5381;
            while (*str) {
                hash = ((hash << 5) + hash) + static_cast<uint8_t>(*str++);
            }
            return hash;
        }

        // Runtime hash for comparing against exports
        uint32_t runtime_hash(const char* str) {
            uint32_t hash = 5381;
            while (*str) {
                hash = ((hash << 5) + hash) + static_cast<uint8_t>(*str++);
            }
            return hash;
        }

        struct SyscallMapping {
            PVOID address;
            uint32_t hash;
        };

        PVOID FindSyscallGadget(PVOID func) {
#if defined(_M_X64)
            auto bytes = reinterpret_cast<uint8_t*>(func);
            for (int i = 0; i < 64; ++i) {
                if (bytes[i] == 0x0F && bytes[i + 1] == 0x05 && bytes[i + 2] == 0xC3) {
                    return bytes + i;
                }
                // Skip over JMP hooks
                if (bytes[i] == 0xE9) i += 4;
            }
#elif defined(_M_ARM64)
            auto bytes = reinterpret_cast<uint8_t*>(func);
            for (int i = 0; i <= 64; i += 4) {
                uint32_t instr = *reinterpret_cast<uint32_t*>(bytes + i);
                if ((instr & 0xFF000000) == 0xD4000000 && 
                    *reinterpret_cast<uint32_t*>(bytes + i + 4) == 0xD65F03C0) {
                    return bytes + i;
                }
            }
#endif
            return nullptr;
        }

        // Pre-computed hashes for target syscalls (computed at compile time)
        constexpr uint32_t H_ZwAllocateVirtualMemory   = djb2_hash("ZwAllocateVirtualMemory");
        constexpr uint32_t H_ZwWriteVirtualMemory      = djb2_hash("ZwWriteVirtualMemory");
        constexpr uint32_t H_ZwReadVirtualMemory       = djb2_hash("ZwReadVirtualMemory");
        constexpr uint32_t H_ZwCreateThreadEx          = djb2_hash("ZwCreateThreadEx");
        constexpr uint32_t H_ZwFreeVirtualMemory       = djb2_hash("ZwFreeVirtualMemory");
        constexpr uint32_t H_ZwProtectVirtualMemory    = djb2_hash("ZwProtectVirtualMemory");
        constexpr uint32_t H_ZwOpenProcess             = djb2_hash("ZwOpenProcess");
        constexpr uint32_t H_ZwGetNextProcess          = djb2_hash("ZwGetNextProcess");
        constexpr uint32_t H_ZwTerminateProcess        = djb2_hash("ZwTerminateProcess");
        constexpr uint32_t H_ZwQueryInformationProcess = djb2_hash("ZwQueryInformationProcess");
        constexpr uint32_t H_ZwUnmapViewOfSection      = djb2_hash("ZwUnmapViewOfSection");
        constexpr uint32_t H_ZwGetContextThread        = djb2_hash("ZwGetContextThread");
        constexpr uint32_t H_ZwSetContextThread        = djb2_hash("ZwSetContextThread");
        constexpr uint32_t H_ZwResumeThread            = djb2_hash("ZwResumeThread");
        constexpr uint32_t H_ZwFlushInstructionCache   = djb2_hash("ZwFlushInstructionCache");
        constexpr uint32_t H_ZwClose                   = djb2_hash("ZwClose");
        constexpr uint32_t H_ZwOpenKey                 = djb2_hash("ZwOpenKey");
        constexpr uint32_t H_ZwQueryValueKey           = djb2_hash("ZwQueryValueKey");
        constexpr uint32_t H_ZwEnumerateKey            = djb2_hash("ZwEnumerateKey");
    }

    bool InitApi(bool) {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return false;

        auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hNtdll);
        auto pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uint8_t*>(hNtdll) + pDosHeader->e_lfanew);
        auto pExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<uint8_t*>(hNtdll) + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        auto pNameRvas = reinterpret_cast<DWORD*>(reinterpret_cast<uint8_t*>(hNtdll) + pExportDir->AddressOfNames);
        auto pAddressRvas = reinterpret_cast<DWORD*>(reinterpret_cast<uint8_t*>(hNtdll) + pExportDir->AddressOfFunctions);
        auto pOrdinalRvas = reinterpret_cast<WORD*>(reinterpret_cast<uint8_t*>(hNtdll) + pExportDir->AddressOfNameOrdinals);

        std::vector<SyscallMapping> sortedSyscalls;
        sortedSyscalls.reserve(pExportDir->NumberOfNames);

        // Collect Zw* exports with their hashes
        for (DWORD i = 0; i < pExportDir->NumberOfNames; ++i) {
            const char* name = reinterpret_cast<const char*>(reinterpret_cast<uint8_t*>(hNtdll) + pNameRvas[i]);
            if (name && name[0] == 'Z' && name[1] == 'w') {
                PVOID addr = reinterpret_cast<PVOID>(reinterpret_cast<uint8_t*>(hNtdll) + pAddressRvas[pOrdinalRvas[i]]);
                sortedSyscalls.push_back({addr, runtime_hash(name)});
            }
        }

        // Sort by address for SSN derivation (Hell's Gate)
        std::sort(sortedSyscalls.begin(), sortedSyscalls.end(), [](const auto& a, const auto& b) {
            return a.address < b.address;
        });

        // Target syscalls with their hash and entry pointer
        struct Target {
            uint32_t hash;
            SYSCALL_ENTRY* entry;
            UINT argCount;
        };

        Target targets[] = {
            {H_ZwAllocateVirtualMemory,   &g_syscall_stubs.NtAllocateVirtualMemory, 6},
            {H_ZwWriteVirtualMemory,      &g_syscall_stubs.NtWriteVirtualMemory, 5},
            {H_ZwReadVirtualMemory,       &g_syscall_stubs.NtReadVirtualMemory, 5},
            {H_ZwCreateThreadEx,          &g_syscall_stubs.NtCreateThreadEx, 11},
            {H_ZwFreeVirtualMemory,       &g_syscall_stubs.NtFreeVirtualMemory, 4},
            {H_ZwProtectVirtualMemory,    &g_syscall_stubs.NtProtectVirtualMemory, 5},
            {H_ZwOpenProcess,             &g_syscall_stubs.NtOpenProcess, 4},
            {H_ZwGetNextProcess,          &g_syscall_stubs.NtGetNextProcess, 5},
            {H_ZwTerminateProcess,        &g_syscall_stubs.NtTerminateProcess, 2},
            {H_ZwQueryInformationProcess, &g_syscall_stubs.NtQueryInformationProcess, 5},
            {H_ZwUnmapViewOfSection,      &g_syscall_stubs.NtUnmapViewOfSection, 2},
            {H_ZwGetContextThread,        &g_syscall_stubs.NtGetContextThread, 2},
            {H_ZwSetContextThread,        &g_syscall_stubs.NtSetContextThread, 2},
            {H_ZwResumeThread,            &g_syscall_stubs.NtResumeThread, 2},
            {H_ZwFlushInstructionCache,   &g_syscall_stubs.NtFlushInstructionCache, 3},
            {H_ZwClose,                   &g_syscall_stubs.NtClose, 1},
            {H_ZwOpenKey,                 &g_syscall_stubs.NtOpenKey, 3},
            {H_ZwQueryValueKey,           &g_syscall_stubs.NtQueryValueKey, 6},
            {H_ZwEnumerateKey,            &g_syscall_stubs.NtEnumerateKey, 6}
        };

        // Match by hash and resolve SSN from sorted position
        for (WORD i = 0; i < sortedSyscalls.size(); ++i) {
            const auto& mapping = sortedSyscalls[i];
            
            for (auto& target : targets) {
                if (mapping.hash == target.hash) {
                    PVOID gadget = FindSyscallGadget(mapping.address);
                    if (gadget) {
                        target.entry->pSyscallGadget = gadget;
                        target.entry->ssn = i;
                        target.entry->nArgs = target.argCount;
                    }
                    break;
                }
            }
        }

        // Verify all syscalls were resolved
        for (const auto& target : targets) {
            if (!target.entry->pSyscallGadget) {
                return false;
            }
        }

        return true;
    }

}

extern "C" {
    NTSTATUS NtAllocateVirtualMemory_syscall(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
        return SyscallTrampoline(&g_syscall_stubs.NtAllocateVirtualMemory, ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
    }
    NTSTATUS NtWriteVirtualMemory_syscall(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten) {
        return SyscallTrampoline(&g_syscall_stubs.NtWriteVirtualMemory, ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
    }
    NTSTATUS NtReadVirtualMemory_syscall(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead) {
        return SyscallTrampoline(&g_syscall_stubs.NtReadVirtualMemory, ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
    }
    NTSTATUS NtCreateThreadEx_syscall(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, LPVOID ObjectAttributes, HANDLE ProcessHandle, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, ULONG CreateFlags, ULONG_PTR ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, LPVOID AttributeList) {
        return SyscallTrampoline(&g_syscall_stubs.NtCreateThreadEx, ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
    }
    NTSTATUS NtFreeVirtualMemory_syscall(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG FreeType) {
        return SyscallTrampoline(&g_syscall_stubs.NtFreeVirtualMemory, ProcessHandle, BaseAddress, RegionSize, FreeType);
    }
    NTSTATUS NtProtectVirtualMemory_syscall(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect) {
        return SyscallTrampoline(&g_syscall_stubs.NtProtectVirtualMemory, ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
    }
    NTSTATUS NtOpenProcess_syscall(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
        return SyscallTrampoline(&g_syscall_stubs.NtOpenProcess, ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    }
    NTSTATUS NtGetNextProcess_syscall(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Flags, PHANDLE NewProcessHandle) {
        return SyscallTrampoline(&g_syscall_stubs.NtGetNextProcess, ProcessHandle, DesiredAccess, HandleAttributes, Flags, NewProcessHandle);
    }
    NTSTATUS NtTerminateProcess_syscall(HANDLE ProcessHandle, NTSTATUS ExitStatus) {
        return SyscallTrampoline(&g_syscall_stubs.NtTerminateProcess, ProcessHandle, ExitStatus);
    }
    NTSTATUS NtQueryInformationProcess_syscall(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength) {
        return SyscallTrampoline(&g_syscall_stubs.NtQueryInformationProcess, ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
    }
    NTSTATUS NtUnmapViewOfSection_syscall(HANDLE ProcessHandle, PVOID BaseAddress) {
        return SyscallTrampoline(&g_syscall_stubs.NtUnmapViewOfSection, ProcessHandle, BaseAddress);
    }
    NTSTATUS NtGetContextThread_syscall(HANDLE ThreadHandle, PCONTEXT pContext) {
        return SyscallTrampoline(&g_syscall_stubs.NtGetContextThread, ThreadHandle, pContext);
    }
    NTSTATUS NtSetContextThread_syscall(HANDLE ThreadHandle, PCONTEXT pContext) {
        return SyscallTrampoline(&g_syscall_stubs.NtSetContextThread, ThreadHandle, pContext);
    }
    NTSTATUS NtResumeThread_syscall(HANDLE ThreadHandle, PULONG SuspendCount) {
        return SyscallTrampoline(&g_syscall_stubs.NtResumeThread, ThreadHandle, SuspendCount);
    }
    NTSTATUS NtFlushInstructionCache_syscall(HANDLE ProcessHandle, PVOID BaseAddress, ULONG NumberOfBytesToFlush) {
        return SyscallTrampoline(&g_syscall_stubs.NtFlushInstructionCache, ProcessHandle, BaseAddress, NumberOfBytesToFlush);
    }
    NTSTATUS NtClose_syscall(HANDLE Handle) {
        return SyscallTrampoline(&g_syscall_stubs.NtClose, Handle);
    }
    NTSTATUS NtOpenKey_syscall(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
        return SyscallTrampoline(&g_syscall_stubs.NtOpenKey, KeyHandle, DesiredAccess, ObjectAttributes);
    }
    NTSTATUS NtQueryValueKey_syscall(HANDLE KeyHandle, PUNICODE_STRING_SYSCALLS ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {
        return SyscallTrampoline(&g_syscall_stubs.NtQueryValueKey, KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
    }
    NTSTATUS NtEnumerateKey_syscall(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength) {
        return SyscallTrampoline(&g_syscall_stubs.NtEnumerateKey, KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength);
    }
}
