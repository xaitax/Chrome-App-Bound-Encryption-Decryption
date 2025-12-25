// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include "../core/common.hpp"
#include <memory>
#include <filesystem>
#include <string>

namespace Injector {

    struct ExtractionStats {
        int cookies = 0;
        int cookiesTotal = 0;
        int passwords = 0;
        int cards = 0;
        int ibans = 0;
        int tokens = 0;
        int profiles = 0;
    };

    class PipeServer {
    public:
        explicit PipeServer(const std::wstring& browserType);
        void Create();
        void WaitForClient();
        void SendConfig(bool verbose, bool fingerprint, const std::filesystem::path& output);
        void ProcessMessages(bool verbose);
        std::wstring GetName() const { return m_pipeName; }
        ExtractionStats GetStats() const { return m_stats; }

    private:
        void Write(const std::string& msg);
        std::wstring GenerateName(const std::wstring& browserType);
        
        std::wstring m_pipeName;
        Core::HandlePtr m_hPipe;
        ExtractionStats m_stats;
    };

}
