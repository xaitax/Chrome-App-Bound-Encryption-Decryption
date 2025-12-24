// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include "../core/common.hpp"
#include <string>

namespace Payload {

    class PipeClient {
    public:
        explicit PipeClient(const std::wstring& pipeName);
        ~PipeClient();

        bool IsValid() const { return m_hPipe != INVALID_HANDLE_VALUE; }
        
        void Log(const std::string& msg);
        void LogDebug(const std::string& msg);
        void LogData(const std::string& key, const std::string& value);
        
        struct Config {
            bool verbose;
            bool fingerprint;
            std::string outputPath;
        };
        Config ReadConfig();

    private:
        HANDLE m_hPipe;
    };

}
