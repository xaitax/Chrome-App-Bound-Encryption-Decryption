// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "browser_discovery.hpp"
#include "../sys/internal_api.hpp"
#include <algorithm>
#include <map>

namespace Injector {

    namespace {
        const std::map<std::wstring, std::pair<std::wstring, std::string>> g_browserMap = {
            {L"chrome", {L"chrome.exe", "Chrome"}},
            {L"edge", {L"msedge.exe", "Edge"}},
            {L"brave", {L"brave.exe", "Brave"}}
        };
    }

    std::vector<BrowserInfo> BrowserDiscovery::FindAll() {
        std::vector<BrowserInfo> results;
        for (const auto& [type, info] : g_browserMap) {
            auto path = ResolvePath(info.first);
            if (!path.empty()) {
                results.push_back({type, info.first, path, info.second});
            }
        }
        return results;
    }

    std::optional<BrowserInfo> BrowserDiscovery::FindSpecific(const std::wstring& type) {
        std::wstring lowerType = type;
        std::transform(lowerType.begin(), lowerType.end(), lowerType.begin(), ::towlower);

        auto it = g_browserMap.find(lowerType);
        if (it == g_browserMap.end()) return std::nullopt;

        auto path = ResolvePath(it->second.first);
        if (path.empty()) return std::nullopt;

        return BrowserInfo{lowerType, it->second.first, path, it->second.second};
    }

    std::wstring BrowserDiscovery::ResolvePath(const std::wstring& exeName) {
        const std::wstring registryPaths[] = {
            L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\" + exeName,
            L"\\Registry\\Machine\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths\\" + exeName
        };

        for (const auto& regPath : registryPaths) {
            auto path = QueryRegistry(regPath);
            if (!path.empty() && std::filesystem::exists(path)) {
                return path;
            }
        }
        return L"";
    }

    std::wstring BrowserDiscovery::QueryRegistry(const std::wstring& keyPath) {
        std::vector<wchar_t> pathBuffer(keyPath.begin(), keyPath.end());
        pathBuffer.push_back(L'\0');

        UNICODE_STRING_SYSCALLS keyName;
        keyName.Buffer = pathBuffer.data();
        keyName.Length = static_cast<USHORT>(keyPath.length() * sizeof(wchar_t));
        keyName.MaximumLength = static_cast<USHORT>(pathBuffer.size() * sizeof(wchar_t));

        OBJECT_ATTRIBUTES objAttr;
        InitializeObjectAttributes(&objAttr, &keyName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

        HANDLE hKey = nullptr;
        NTSTATUS status = NtOpenKey_syscall(&hKey, KEY_READ, &objAttr);

        if (status != 0) return L""; // STATUS_SUCCESS is 0

        Core::UniqueHandle keyGuard(hKey);

        UNICODE_STRING_SYSCALLS valueName = {0, 0, nullptr};
        ULONG bufferSize = 4096;
        std::vector<BYTE> buffer(bufferSize);
        ULONG resultLength = 0;

        status = NtQueryValueKey_syscall(hKey, &valueName, KeyValuePartialInformation,
                                         buffer.data(), bufferSize, &resultLength);

        if (status == STATUS_BUFFER_TOO_SMALL || status == STATUS_BUFFER_OVERFLOW) {
            buffer.resize(resultLength);
            bufferSize = resultLength;
            status = NtQueryValueKey_syscall(hKey, &valueName, KeyValuePartialInformation,
                                             buffer.data(), bufferSize, &resultLength);
        }

        if (status != 0) return L"";

        auto kvpi = reinterpret_cast<PKEY_VALUE_PARTIAL_INFORMATION>(buffer.data());

        // REG_SZ = 1, REG_EXPAND_SZ = 2
        if (kvpi->Type != 1 && kvpi->Type != 2) return L"";
        if (kvpi->DataLength < sizeof(wchar_t) * 2) return L"";

        size_t charCount = kvpi->DataLength / sizeof(wchar_t);
        std::wstring path(reinterpret_cast<wchar_t*>(kvpi->Data), charCount);

        while (!path.empty() && path.back() == L'\0') path.pop_back();

        if (path.empty()) return L"";

        if (kvpi->Type == 2) { // REG_EXPAND_SZ
            std::vector<wchar_t> expanded(MAX_PATH * 2);
            DWORD size = ExpandEnvironmentStringsW(path.c_str(), expanded.data(), static_cast<DWORD>(expanded.size()));
            if (size > 0 && size <= expanded.size()) {
                path = std::wstring(expanded.data());
            }
        }

        return path;
    }

}
