// syscalls.h
// v0.16.1 (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <Windows.h>

#ifndef NTSTATUS
using NTSTATUS = LONG;
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

#ifndef REG_SZ
#define REG_SZ 1
#endif

#ifndef REG_EXPAND_SZ
#define REG_EXPAND_SZ 2
#endif

struct SYSCALL_ENTRY
{
    PVOID pSyscallGadget;
    UINT nArgs;
    WORD ssn;
};

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

struct CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
};
using PCLIENT_ID = CLIENT_ID *;

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

struct KEY_BASIC_INFORMATION
{
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG NameLength;
    WCHAR Name[1];
};
using PKEY_BASIC_INFORMATION = KEY_BASIC_INFORMATION *;

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

#ifndef KEY_QUERY_VALUE
#define KEY_QUERY_VALUE (0x0001)
#endif

#ifndef KEY_READ
#define KEY_READ (0x20019)
#endif

#ifndef KEY_WOW64_64KEY
#define KEY_WOW64_64KEY (0x0100)
#endif

#ifndef KEY_WOW64_32KEY
#define KEY_WOW64_32KEY (0x0200)
#endif

extern "C"
{
    extern SYSCALL_STUBS g_syscall_stubs;

    [[nodiscard]] BOOL InitializeSyscalls(bool is_verbose, bool enable_obfuscation = true);

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

#endif
