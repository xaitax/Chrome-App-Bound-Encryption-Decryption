// reflective_loader.h
// v0.16.1 (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#ifndef REFLECTIVE_LOADER_H
#define REFLECTIVE_LOADER_H
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>

#if defined(_M_X64) || defined(_M_ARM64)
#define ENVIRONMENT64
#else
#error "Unsupported architecture: Reflective Loader is designed for 64-bit environments (x64, ARM64)."
#endif

#if defined(_MSC_VER)
#define DLLEXPORT __declspec(dllexport)
#else
#define DLLEXPORT
#endif

typedef HMODULE(WINAPI *LOADLIBRARYA_FN)(LPCSTR);
typedef FARPROC(WINAPI *GETPROCADDRESS_FN)(HMODULE, LPCSTR);
typedef LPVOID(WINAPI *VIRTUALALLOC_FN)(LPVOID, SIZE_T, DWORD, DWORD);
typedef NTSTATUS(NTAPI *NTFLUSHINSTRUCTIONCACHE_FN)(HANDLE, PVOID, ULONG);
typedef BOOL(WINAPI *DLLMAIN_FN)(HINSTANCE, DWORD, LPVOID);

#define HASH_KEY 13

#define KERNEL32DLL_HASH 0x6A4ABC5B
#define NTDLLDLL_HASH 0x3CFA685D

#define LOADLIBRARYA_HASH 0xEC0E4E8E
#define GETPROCADDRESS_HASH 0x7C0DFCAA
#define VIRTUALALLOC_HASH 0x91AFCA54
#define NTFLUSHINSTRUCTIONCACHE_HASH 0x534C0AB8

typedef struct _UNICODE_STRING_LDR
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING_LDR, *PUNICODE_STRING_LDR;

typedef struct _PEB_LDR_DATA_LDR
{
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} PEB_LDR_DATA_LDR, *PPEB_LDR_DATA_LDR;

typedef struct _LDR_DATA_TABLE_ENTRY_LDR
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING_LDR FullDllName;
    UNICODE_STRING_LDR BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union
    {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY_LDR, *PLDR_DATA_TABLE_ENTRY_LDR;

typedef struct _PEB_LDR
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN IsLongPathAware : 1;
        };
    };
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA_LDR Ldr;
    PVOID ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    union
    {
        ULONG CrossProcessFlags;
        struct
        {
            ULONG ProcessInJob : 1;
            ULONG ProcessInitializing : 1;
            ULONG ProcessUsingVEH : 1;
            ULONG ProcessUsingVCH : 1;
            ULONG ProcessUsingFTH : 1;
            ULONG ProcessPreviouslyThrottled : 1;
            ULONG ProcessCurrentlyThrottled : 1;
            ULONG ProcessImagesHotPatched : 1;
            ULONG ReservedBits0 : 24;
        };
    };
    union
    {
        PVOID KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    };
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID SharedData;
    PVOID *ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
    LARGE_INTEGER CriticalSectionTimeout;
    SIZE_T HeapSegmentReserve;
    SIZE_T HeapSegmentCommit;
    SIZE_T HeapDeCommitTotalFreeThreshold;
    SIZE_T HeapDeCommitFreeBlockThreshold;
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID *ProcessHeaps;
    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;
    PVOID LoaderLock;
    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG_PTR ActiveProcessAffinityMask;
    ULONG GdiHandleBuffer[60];
    PVOID PostProcessInitRoutine;
    PVOID TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];
    ULONG SessionId;
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    PVOID pShimData;
    PVOID AppCompatInfo;
    UNICODE_STRING_LDR CSDVersion;
    PVOID ActivationContextData;
    PVOID ProcessAssemblyStorageMap;
    PVOID SystemDefaultActivationContextData;
    PVOID SystemAssemblyStorageMap;
    SIZE_T MinimumStackCommit;
    PVOID SparePointers[2];
    PVOID PatchLoaderData;
    PVOID ChpeV2ProcessInfo;
    ULONG AppModelFeatureState;
    ULONG SpareUlongs[2];
    USHORT ActiveConsoleId;
    USHORT AppCompatVersionInfo;
    PVOID ExtendedProcessInfo;
} PEB_LDR, *PPEB_LDR;

typedef struct _IMAGE_RELOC_ENTRY
{
    WORD offset : 12;
    WORD type : 4;
} IMAGE_RELOC_ENTRY, *PIMAGE_RELOC_ENTRY;

DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpParameter);

#endif
