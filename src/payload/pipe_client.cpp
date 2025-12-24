// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "pipe_client.hpp"

namespace Payload {

    PipeClient::PipeClient(const std::wstring& pipeName) {
        m_hPipe = CreateFileW(pipeName.c_str(), GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    }

    PipeClient::~PipeClient() {
        if (IsValid()) {
            Log("__DLL_PIPE_COMPLETION_SIGNAL__");
            FlushFileBuffers(m_hPipe);
            CloseHandle(m_hPipe);
        }
    }

    void PipeClient::Log(const std::string& msg) {
        if (IsValid()) {
            DWORD written = 0;
            WriteFile(m_hPipe, msg.c_str(), static_cast<DWORD>(msg.length() + 1), &written, nullptr);
        }
    }

    void PipeClient::LogDebug(const std::string& msg) {
        Log("DEBUG:" + msg);
    }

    void PipeClient::LogData(const std::string& key, const std::string& value) {
        Log("DATA:" + key + "|" + value);
    }

    PipeClient::Config PipeClient::ReadConfig() {
        Config config{};
        char buffer[MAX_PATH + 1] = {0};
        DWORD read = 0;

        if (ReadFile(m_hPipe, buffer, sizeof(buffer) - 1, &read, nullptr)) {
            buffer[read] = '\0';
            config.verbose = (std::string(buffer) == "VERBOSE_TRUE");
        }

        if (ReadFile(m_hPipe, buffer, sizeof(buffer) - 1, &read, nullptr)) {
            buffer[read] = '\0';
            config.fingerprint = (std::string(buffer) == "FINGERPRINT_TRUE");
        }

        if (ReadFile(m_hPipe, buffer, sizeof(buffer) - 1, &read, nullptr)) {
            buffer[read] = '\0';
            config.outputPath = buffer;
        }

        return config;
    }

}
