// syscalls.h
// v0.13.0 (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <Windows.h>

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

typedef struct _SYSCALL_ENTRY
{
    PVOID pSyscallGadget;
    UINT nArgs;
    WORD ssn;
} SYSCALL_ENTRY;

typedef struct _SYSCALL_STUBS
{
    SYSCALL_ENTRY NtAllocateVirtualMemory;
    SYSCALL_ENTRY NtWriteVirtualMemory;
    SYSCALL_ENTRY NtCreateThreadEx;
    SYSCALL_ENTRY NtFreeVirtualMemory;
    SYSCALL_ENTRY NtProtectVirtualMemory;
} SYSCALL_STUBS;

extern "C" SYSCALL_STUBS g_syscall_stubs;

BOOL InitializeSyscalls(bool is_verbose);

extern "C"
{

    NTSTATUS NtAllocateVirtualMemory_syscall(
        HANDLE ProcessHandle,
        PVOID *BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect);

    NTSTATUS NtWriteVirtualMemory_syscall(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T NumberOfBytesToWrite,
        PSIZE_T NumberOfBytesWritten);

    NTSTATUS NtCreateThreadEx_syscall(
        PHANDLE ThreadHandle,
        ACCESS_MASK DesiredAccess,
        LPVOID ObjectAttributes,
        HANDLE ProcessHandle,
        LPTHREAD_START_ROUTINE lpStartAddress,
        LPVOID lpParameter,
        ULONG CreateFlags,
        ULONG_PTR ZeroBits,
        SIZE_T StackSize,
        SIZE_T MaximumStackSize,
        LPVOID AttributeList);

    NTSTATUS NtFreeVirtualMemory_syscall(
        HANDLE ProcessHandle,
        PVOID *BaseAddress,
        PSIZE_T RegionSize,
        ULONG FreeType);

    NTSTATUS NtProtectVirtualMemory_syscall(
        HANDLE ProcessHandle,
        PVOID *BaseAddress,
        PSIZE_T RegionSize,
        ULONG NewProtect,
        PULONG OldProtect);
}

#endif
