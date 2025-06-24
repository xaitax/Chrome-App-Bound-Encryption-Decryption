// syscalls.h
// v0.12.0 (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <Windows.h>

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI *pNtFreeVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG);
typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(PHANDLE, ACCESS_MASK, LPVOID, HANDLE, LPTHREAD_START_ROUTINE, LPVOID, ULONG, ULONG_PTR, SIZE_T, SIZE_T, LPVOID);

typedef struct _SYSCALL_STUBS
{
    pNtAllocateVirtualMemory   NtAllocateVirtualMemory;
    pNtWriteVirtualMemory      NtWriteVirtualMemory;
    pNtCreateThreadEx          NtCreateThreadEx;
    pNtFreeVirtualMemory       NtFreeVirtualMemory;
    pNtProtectVirtualMemory    NtProtectVirtualMemory;
} SYSCALL_STUBS;

extern "C" SYSCALL_STUBS g_syscall_stubs;

BOOL InitializeSyscalls(bool is_verbose);

#endif
