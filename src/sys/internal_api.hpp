// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include <Windows.h>
#include "../core/common.hpp"

#ifndef NTSTATUS
using NTSTATUS = LONG;
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif

#ifndef STATUS_BUFFER_OVERFLOW
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)
#endif

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040L
#endif

// NT Structures required for syscalls
struct UNICODE_STRING_SYSCALLS
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
};
using PUNICODE_STRING_SYSCALLS = UNICODE_STRING_SYSCALLS *;

struct OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING_SYSCALLS ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
};
using POBJECT_ATTRIBUTES = OBJECT_ATTRIBUTES *;

struct CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
};
using PCLIENT_ID = CLIENT_ID *;

enum PROCESSINFOCLASS
{
    ProcessBasicInformation = 0,
    ProcessImageFileName = 27
};

struct PROCESS_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
};
using PPROCESS_BASIC_INFORMATION = PROCESS_BASIC_INFORMATION *;

struct PEB_LDR_DATA
{
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
};
using PPEB_LDR_DATA = PEB_LDR_DATA *;

struct RTL_USER_PROCESS_PARAMETERS
{
    BYTE Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STRING_SYSCALLS ImagePathName;
    UNICODE_STRING_SYSCALLS CommandLine;
};
using PRTL_USER_PROCESS_PARAMETERS = RTL_USER_PROCESS_PARAMETERS *;

struct PEB
{
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE BitField;
    BYTE Reserved3[4];
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
};
using PPEB = PEB *;

enum KEY_VALUE_INFORMATION_CLASS
{
    KeyValueBasicInformation = 0,
    KeyValueFullInformation,
    KeyValuePartialInformation
};

struct KEY_VALUE_PARTIAL_INFORMATION
{
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataLength;
    UCHAR Data[1];
};
using PKEY_VALUE_PARTIAL_INFORMATION = KEY_VALUE_PARTIAL_INFORMATION *;

enum KEY_INFORMATION_CLASS
{
    KeyBasicInformation = 0
};

inline void InitializeObjectAttributes(POBJECT_ATTRIBUTES p, PUNICODE_STRING_SYSCALLS n, ULONG a, HANDLE r, PVOID s)
{
    p->Length = sizeof(OBJECT_ATTRIBUTES);
    p->RootDirectory = r;
    p->Attributes = a;
    p->ObjectName = n;
    p->SecurityDescriptor = s;
    p->SecurityQualityOfService = nullptr;
}

// Syscall Entry Structure - MUST MATCH ASM EXPECTATIONS
struct SYSCALL_ENTRY
{
    PVOID pSyscallGadget;
    UINT nArgs;
    WORD ssn;
};

// Syscall Stubs Structure - MUST MATCH ASM EXPECTATIONS
struct SYSCALL_STUBS
{
    SYSCALL_ENTRY NtAllocateVirtualMemory;
    SYSCALL_ENTRY NtWriteVirtualMemory;
    SYSCALL_ENTRY NtReadVirtualMemory;
    SYSCALL_ENTRY NtCreateThreadEx;
    SYSCALL_ENTRY NtFreeVirtualMemory;
    SYSCALL_ENTRY NtProtectVirtualMemory;
    SYSCALL_ENTRY NtOpenProcess;
    SYSCALL_ENTRY NtGetNextProcess;
    SYSCALL_ENTRY NtTerminateProcess;
    SYSCALL_ENTRY NtQueryInformationProcess;
    SYSCALL_ENTRY NtUnmapViewOfSection;
    SYSCALL_ENTRY NtGetContextThread;
    SYSCALL_ENTRY NtSetContextThread;
    SYSCALL_ENTRY NtResumeThread;
    SYSCALL_ENTRY NtFlushInstructionCache;
    SYSCALL_ENTRY NtClose;
    SYSCALL_ENTRY NtOpenKey;
    SYSCALL_ENTRY NtQueryValueKey;
    SYSCALL_ENTRY NtEnumerateKey;
};

extern "C"
{
    // Global instance used by ASM
    extern SYSCALL_STUBS g_syscall_stubs;

    // Syscall prototypes
    NTSTATUS NtAllocateVirtualMemory_syscall(HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    NTSTATUS NtWriteVirtualMemory_syscall(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    NTSTATUS NtReadVirtualMemory_syscall(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    NTSTATUS NtCreateThreadEx_syscall(PHANDLE, ACCESS_MASK, LPVOID, HANDLE, LPTHREAD_START_ROUTINE, LPVOID, ULONG, ULONG_PTR, SIZE_T, SIZE_T, LPVOID);
    NTSTATUS NtFreeVirtualMemory_syscall(HANDLE, PVOID *, PSIZE_T, ULONG);
    NTSTATUS NtProtectVirtualMemory_syscall(HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);
    NTSTATUS NtOpenProcess_syscall(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
    NTSTATUS NtGetNextProcess_syscall(HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);
    NTSTATUS NtTerminateProcess_syscall(HANDLE, NTSTATUS);
    NTSTATUS NtQueryInformationProcess_syscall(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    NTSTATUS NtUnmapViewOfSection_syscall(HANDLE, PVOID);
    NTSTATUS NtGetContextThread_syscall(HANDLE, PCONTEXT);
    NTSTATUS NtSetContextThread_syscall(HANDLE, PCONTEXT);
    NTSTATUS NtResumeThread_syscall(HANDLE, PULONG);
    NTSTATUS NtFlushInstructionCache_syscall(HANDLE, PVOID, ULONG);
    NTSTATUS NtClose_syscall(HANDLE);
    NTSTATUS NtOpenKey_syscall(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
    NTSTATUS NtQueryValueKey_syscall(HANDLE, PUNICODE_STRING_SYSCALLS, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    NTSTATUS NtEnumerateKey_syscall(HANDLE, ULONG, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);
}

namespace Sys {
    // Initialization function
    [[nodiscard]] bool InitApi(bool verbose);
}
