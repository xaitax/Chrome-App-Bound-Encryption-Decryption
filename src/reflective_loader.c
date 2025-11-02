// reflective_loader.c
// v0.16.1 (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information..

#include <windows.h>
#include "reflective_loader.h"

#pragma intrinsic(_ReturnAddress)
#pragma intrinsic(_rotr)

static DWORD ror_dword_loader(DWORD d)
{
    return _rotr(d, HASH_KEY);
}

static DWORD hash_string_loader(char *c)
{
    DWORD h = 0;
    do
    {
        h = ror_dword_loader(h);
        h += *c;
    } while (*++c);
    return h;
}

__declspec(noinline) ULONG_PTR GetIp(VOID)
{
    return (ULONG_PTR)_ReturnAddress();
}

DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpLoaderParameter)
{
    LOADLIBRARYA_FN fnLoadLibraryA = NULL;
    GETPROCADDRESS_FN fnGetProcAddress = NULL;
    VIRTUALALLOC_FN fnVirtualAlloc = NULL;
    NTFLUSHINSTRUCTIONCACHE_FN fnNtFlushInstructionCache = NULL;

    ULONG_PTR uiDllBase;
    ULONG_PTR uiPeb;
    ULONG_PTR uiKernel32Base = 0;
    ULONG_PTR uiNtdllBase = 0;

    PIMAGE_NT_HEADERS pNtHeaders_current;
    PIMAGE_DOS_HEADER pDosHeader_current;

    uiDllBase = GetIp();

    while (TRUE)
    {
        pDosHeader_current = (PIMAGE_DOS_HEADER)uiDllBase;
        if (pDosHeader_current->e_magic == IMAGE_DOS_SIGNATURE)
        {
            pNtHeaders_current = (PIMAGE_NT_HEADERS)(uiDllBase + pDosHeader_current->e_lfanew);
            if (pNtHeaders_current->Signature == IMAGE_NT_SIGNATURE)
                break;
        }
        uiDllBase--;
    }

#if defined(_M_X64)
    uiPeb = __readgsqword(0x60);
#elif defined(_M_ARM64)
    uiPeb = __readx18qword(0x60);
#else
    return 0;
#endif

    PPEB_LDR_DATA_LDR pLdr = ((PPEB_LDR)uiPeb)->Ldr;
    PLIST_ENTRY pModuleList = &(pLdr->InMemoryOrderModuleList);
    PLIST_ENTRY pCurrentEntry = pModuleList->Flink;

    while (pCurrentEntry != pModuleList && (!uiKernel32Base || !uiNtdllBase))
    {
        PLDR_DATA_TABLE_ENTRY_LDR pEntry = (PLDR_DATA_TABLE_ENTRY_LDR)CONTAINING_RECORD(pCurrentEntry, LDR_DATA_TABLE_ENTRY_LDR, InMemoryOrderLinks);
        if (pEntry->BaseDllName.Length > 0 && pEntry->BaseDllName.Buffer != NULL)
        {
            DWORD dwModuleHash = 0;
            USHORT usCounter = pEntry->BaseDllName.Length;
            BYTE *pNameByte = (BYTE *)pEntry->BaseDllName.Buffer;

            do
            {
                dwModuleHash = ror_dword_loader(dwModuleHash);
                if (*pNameByte >= 'a' && *pNameByte <= 'z')
                {
                    dwModuleHash += (*pNameByte - 0x20);
                }
                else
                {
                    dwModuleHash += *pNameByte;
                }
                pNameByte++;
            } while (--usCounter);

            if (dwModuleHash == KERNEL32DLL_HASH)
            {
                uiKernel32Base = (ULONG_PTR)pEntry->DllBase;
            }
            else if (dwModuleHash == NTDLLDLL_HASH)
            {
                uiNtdllBase = (ULONG_PTR)pEntry->DllBase;
            }
        }
        pCurrentEntry = pCurrentEntry->Flink;
    }

    if (!uiKernel32Base || !uiNtdllBase)
        return 0;

    PIMAGE_DOS_HEADER pDosKernel32 = (PIMAGE_DOS_HEADER)uiKernel32Base;
    PIMAGE_NT_HEADERS pNtKernel32 = (PIMAGE_NT_HEADERS)(uiKernel32Base + pDosKernel32->e_lfanew);
    ULONG_PTR uiExportDirK32 = uiKernel32Base + pNtKernel32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY pExportDirK32 = (PIMAGE_EXPORT_DIRECTORY)uiExportDirK32;

    ULONG_PTR uiAddressOfNamesK32 = uiKernel32Base + pExportDirK32->AddressOfNames;
    ULONG_PTR uiAddressOfFunctionsK32 = uiKernel32Base + pExportDirK32->AddressOfFunctions;
    ULONG_PTR uiAddressOfNameOrdinalsK32 = uiKernel32Base + pExportDirK32->AddressOfNameOrdinals;

    for (DWORD i = 0; i < pExportDirK32->NumberOfNames; i++)
    {
        char *sName = (char *)(uiKernel32Base + ((DWORD *)uiAddressOfNamesK32)[i]);
        DWORD dwHashVal = hash_string_loader(sName);
        if (dwHashVal == LOADLIBRARYA_HASH)
            fnLoadLibraryA = (LOADLIBRARYA_FN)(uiKernel32Base + ((DWORD *)uiAddressOfFunctionsK32)[((WORD *)uiAddressOfNameOrdinalsK32)[i]]);
        else if (dwHashVal == GETPROCADDRESS_HASH)
            fnGetProcAddress = (GETPROCADDRESS_FN)(uiKernel32Base + ((DWORD *)uiAddressOfFunctionsK32)[((WORD *)uiAddressOfNameOrdinalsK32)[i]]);
        else if (dwHashVal == VIRTUALALLOC_HASH)
            fnVirtualAlloc = (VIRTUALALLOC_FN)(uiKernel32Base + ((DWORD *)uiAddressOfFunctionsK32)[((WORD *)uiAddressOfNameOrdinalsK32)[i]]);

        if (fnLoadLibraryA && fnGetProcAddress && fnVirtualAlloc)
            break;
    }

    if (!fnLoadLibraryA || !fnGetProcAddress || !fnVirtualAlloc)
        return 0;

    PIMAGE_DOS_HEADER pDosNtdll = (PIMAGE_DOS_HEADER)uiNtdllBase;
    PIMAGE_NT_HEADERS pNtNtdll = (PIMAGE_NT_HEADERS)(uiNtdllBase + pDosNtdll->e_lfanew);
    ULONG_PTR uiExportDirNtdll = uiNtdllBase + pNtNtdll->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY pExportDirNtdll = (PIMAGE_EXPORT_DIRECTORY)uiExportDirNtdll;

    ULONG_PTR uiAddressOfNamesNtdll = uiNtdllBase + pExportDirNtdll->AddressOfNames;
    ULONG_PTR uiAddressOfFunctionsNtdll = uiNtdllBase + pExportDirNtdll->AddressOfFunctions;
    ULONG_PTR uiAddressOfNameOrdinalsNtdll = uiNtdllBase + pExportDirNtdll->AddressOfNameOrdinals;

    for (DWORD i = 0; i < pExportDirNtdll->NumberOfNames; i++)
    {
        char *sName = (char *)(uiNtdllBase + ((DWORD *)uiAddressOfNamesNtdll)[i]);
        if (hash_string_loader(sName) == NTFLUSHINSTRUCTIONCACHE_HASH)
        {
            fnNtFlushInstructionCache = (NTFLUSHINSTRUCTIONCACHE_FN)(uiNtdllBase + ((DWORD *)uiAddressOfFunctionsNtdll)[((WORD *)uiAddressOfNameOrdinalsNtdll)[i]]);
            break;
        }
    }

    if (!fnNtFlushInstructionCache)
        return 0;

    PIMAGE_NT_HEADERS pOldNtHeaders = pNtHeaders_current;
    ULONG_PTR uiNewImageBase = (ULONG_PTR)fnVirtualAlloc(NULL, pOldNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!uiNewImageBase)
        return 0;

    PBYTE pSourceBytes = (PBYTE)uiDllBase;
    PBYTE pDestinationBytes = (PBYTE)uiNewImageBase;
    DWORD dwBytesToCopy = pOldNtHeaders->OptionalHeader.SizeOfHeaders;

    while (dwBytesToCopy--)
    {
        *pDestinationBytes++ = *pSourceBytes++;
    }

    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&pOldNtHeaders->OptionalHeader + pOldNtHeaders->FileHeader.SizeOfOptionalHeader);
    for (WORD i = 0; i < pOldNtHeaders->FileHeader.NumberOfSections; i++)
    {
        pSourceBytes = (PBYTE)(uiDllBase + pSectionHeader[i].PointerToRawData);
        pDestinationBytes = (PBYTE)(uiNewImageBase + pSectionHeader[i].VirtualAddress);
        dwBytesToCopy = pSectionHeader[i].SizeOfRawData;

        while (dwBytesToCopy--)
        {
            *pDestinationBytes++ = *pSourceBytes++;
        }
    }

    ULONG_PTR uiDelta = uiNewImageBase - pOldNtHeaders->OptionalHeader.ImageBase;
    PIMAGE_DATA_DIRECTORY pRelocationData = &pOldNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (pRelocationData->Size > 0 && uiDelta != 0)
    {
        PIMAGE_BASE_RELOCATION pRelocBlock = (PIMAGE_BASE_RELOCATION)(uiNewImageBase + pRelocationData->VirtualAddress);
        while (pRelocBlock->VirtualAddress)
        {
            DWORD dwEntryCount = (pRelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            PIMAGE_RELOC_ENTRY pRelocEntry = (PIMAGE_RELOC_ENTRY)((ULONG_PTR)pRelocBlock + sizeof(IMAGE_BASE_RELOCATION));
            for (DWORD k = 0; k < dwEntryCount; k++)
            {
#if defined(_M_X64) || defined(_M_ARM64)
                if (pRelocEntry[k].type == IMAGE_REL_BASED_DIR64)
                {
                    *(ULONG_PTR *)(uiNewImageBase + pRelocBlock->VirtualAddress + pRelocEntry[k].offset) += uiDelta;
                }
#else
                if (pRelocEntry[k].type == IMAGE_REL_BASED_HIGHLOW)
                {
                    *(DWORD *)(uiNewImageBase + pRelocBlock->VirtualAddress + pRelocEntry[k].offset) += (DWORD)uiDelta;
                }
#endif
            }
            pRelocBlock = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)pRelocBlock + pRelocBlock->SizeOfBlock);
        }
    }

    PIMAGE_DATA_DIRECTORY pImportData = &pOldNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (pImportData->Size > 0)
    {
        PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(uiNewImageBase + pImportData->VirtualAddress);
        while (pImportDesc->Name)
        {
            char *sModuleName = (char *)(uiNewImageBase + pImportDesc->Name);
            HINSTANCE hModule = fnLoadLibraryA(sModuleName);
            if (hModule)
            {
                PIMAGE_THUNK_DATA pOriginalFirstThunk = (PIMAGE_THUNK_DATA)(uiNewImageBase + pImportDesc->OriginalFirstThunk);
                PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)(uiNewImageBase + pImportDesc->FirstThunk);
                if (!pOriginalFirstThunk)
                    pOriginalFirstThunk = pFirstThunk;

                while (pOriginalFirstThunk->u1.AddressOfData)
                {
                    FARPROC pfnImportedFunc;
                    if (IMAGE_SNAP_BY_ORDINAL(pOriginalFirstThunk->u1.Ordinal))
                    {
                        pfnImportedFunc = fnGetProcAddress(hModule, (LPCSTR)(pOriginalFirstThunk->u1.Ordinal & 0xFFFF));
                    }
                    else
                    {
                        PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(uiNewImageBase + pOriginalFirstThunk->u1.AddressOfData);
                        pfnImportedFunc = fnGetProcAddress(hModule, pImportByName->Name);
                    }
                    pFirstThunk->u1.Function = (ULONG_PTR)pfnImportedFunc;
                    pOriginalFirstThunk++;
                    pFirstThunk++;
                }
            }
            pImportDesc++;
        }
    }

    DLLMAIN_FN fnDllEntry = (DLLMAIN_FN)(uiNewImageBase + pOldNtHeaders->OptionalHeader.AddressOfEntryPoint);
    fnNtFlushInstructionCache((HANDLE)-1, NULL, 0);
    fnDllEntry((HINSTANCE)uiNewImageBase, DLL_PROCESS_ATTACH, lpLoaderParameter);

    return uiNewImageBase;
}
