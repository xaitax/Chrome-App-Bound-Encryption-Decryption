// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#if defined(_MSC_VER)
#define DLLEXPORT __declspec(dllexport)
#else
#define DLLEXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

DLLEXPORT ULONG_PTR WINAPI Bootstrap(LPVOID lpParameter);

#ifdef __cplusplus
}
#endif
