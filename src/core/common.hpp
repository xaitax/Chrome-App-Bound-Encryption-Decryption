// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <filesystem>

namespace Core {

    using Byte = uint8_t;
    using Bytes = std::vector<Byte>;

    // RAII wrapper for HANDLE
    struct HandleDeleter {
        void operator()(HANDLE h) const {
            if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
        }
    };
    using UniqueHandle = std::unique_ptr<void, HandleDeleter>;
    using HandlePtr = UniqueHandle;

    // RAII wrapper for HMODULE
    struct ModuleDeleter {
        void operator()(HMODULE h) const {
            if (h) FreeLibrary(h);
        }
    };
    using UniqueModule = std::unique_ptr<std::remove_pointer<HMODULE>::type, ModuleDeleter>;

    // Constants
    constexpr uint32_t TIMEOUT_MS = 60000;
    
    // Helper to convert wstring to string (UTF-8)
    inline std::string ToUtf8(std::wstring_view wstr) {
        if (wstr.empty()) return {};
        int size = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), nullptr, 0, nullptr, nullptr);
        std::string result(size, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), &result[0], size, nullptr, nullptr);
        return result;
    }

    // Helper to convert string to wstring
    inline std::wstring ToWide(std::string_view str) {
        if (str.empty()) return {};
        int size = MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), nullptr, 0);
        std::wstring result(size, 0);
        MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), &result[0], size);
        return result;
    }

}

