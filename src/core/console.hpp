// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include <Windows.h>
#include <iostream>
#include <string>
#include <iomanip>
#include <vector>
#include "version.hpp"

namespace Core {

    class Console {
    public:
        explicit Console(bool verbose) : m_verbose(verbose) {
            m_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
            CONSOLE_SCREEN_BUFFER_INFO csbi;
            GetConsoleScreenBufferInfo(m_hConsole, &csbi);
            m_origAttrs = csbi.wAttributes;
        }

        ~Console() {
            SetConsoleTextAttribute(m_hConsole, m_origAttrs);
        }

        // Standard log messages (for syscall init, errors, etc - outside browser box)
        void Info(const std::string& msg) const { 
            Print("[*]", msg, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY); 
        }
        void Success(const std::string& msg) const { 
            Print("[+]", msg, FOREGROUND_GREEN | FOREGROUND_INTENSITY); 
        }
        void Error(const std::string& msg) const { 
            Print("[-]", msg, FOREGROUND_RED | FOREGROUND_INTENSITY); 
        }
        void Warn(const std::string& msg) const { 
            Print("[!]", msg, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY); 
        }
        
        // Debug messages - inside the browser box, connected to tree
        void Debug(const std::string& msg) const {
            if (m_verbose) {
                SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                std::cout << "  \xB3 ";
                SetConsoleTextAttribute(m_hConsole, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
                std::cout << msg << std::endl;
                SetConsoleTextAttribute(m_hConsole, m_origAttrs);
            }
        }

        // Browser section header with box drawing
        void BrowserHeader(const std::string& name) const {
            std::cout << std::endl;
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            std::cout << "  \xDA\xC4\xC4\xC4\xC4 ";
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::cout << name;
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            std::cout << " \xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4" << std::endl;
            SetConsoleTextAttribute(m_hConsole, m_origAttrs);
        }

        // AES Key display
        void KeyDecrypted(const std::string& keyHex) const {
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            std::cout << "  \xB3" << std::endl;
            std::cout << "  \xB3 ";
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::cout << "Decryption Key" << std::endl;
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            std::cout << "  \xB3 ";
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            std::cout << keyHex << std::endl;
            SetConsoleTextAttribute(m_hConsole, m_origAttrs);
        }

        // Profile section header
        void ProfileHeader(const std::string& name) const {
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            std::cout << "  \xB3" << std::endl;
            std::cout << "  \xC3\xC4\xC4 ";
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::cout << name << std::endl;
            SetConsoleTextAttribute(m_hConsole, m_origAttrs);
        }

        // Verbose data row (only shown in verbose mode)
        void DataRow(const std::string& key, const std::string& value) const {
            if (m_verbose) {
                SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                std::cout << "  \xB3   ";
                std::cout << std::left << std::setw(12) << key;
                SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
                std::cout << value << std::endl;
                SetConsoleTextAttribute(m_hConsole, m_origAttrs);
            }
        }

        // Extraction result (always shown)
        void ExtractionResult(const std::string& type, int count, int total = -1) const {
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            std::cout << "  \xB3   ";
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::cout << std::left << std::setw(12) << type;
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            std::cout << count;
            if (total > 0 && total != count) {
                SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                std::cout << "/" << total;
            }
            std::cout << std::endl;
            SetConsoleTextAttribute(m_hConsole, m_origAttrs);
        }

        // Summary line
        void Summary(int cookies, int passwords, int cards, int ibans, int profiles, const std::string& outputPath) const {
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            std::cout << "  \xB3" << std::endl;
            std::cout << "  \xC0\xC4\xC4 ";
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            
            std::vector<std::string> parts;
            if (cookies > 0) parts.push_back(std::to_string(cookies) + " cookies");
            if (passwords > 0) parts.push_back(std::to_string(passwords) + " passwords");
            if (cards > 0) parts.push_back(std::to_string(cards) + " cards");
            if (ibans > 0) parts.push_back(std::to_string(ibans) + " IBANs");
            
            for (size_t i = 0; i < parts.size(); i++) {
                std::cout << parts[i];
                if (i < parts.size() - 1) std::cout << ", ";
            }
            
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            std::cout << " (" << profiles << " profile" << (profiles != 1 ? "s" : "") << ")" << std::endl;
            
            std::cout << "      ";
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            std::cout << outputPath << std::endl;
            SetConsoleTextAttribute(m_hConsole, m_origAttrs);
        }

        void Banner() const {
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
            std::cout << R"(
_________ .__                         ___________.__                       __                
\_   ___ \|  |_________  ____   _____ \_   _____/|  |   _______  _______ _/  |_  ___________ 
/    \  \/|  |  \_  __ \/  _ \ /     \ |    __)_ |  | _/ __ \  \/ /\__  \\   __\/  _ \_  __ \
\     \___|   Y  \  | \(  <_> )  Y Y  \|        \|  |_\  ___/\   /  / __ \|  | (  <_> )  | \/
 \______  /___|  /__|   \____/|__|_|  /_______  /|____/\___  >\_/  (____  /__|  \____/|__|   
        \/     \/                   \/        \/           \/           \/                   
)";
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            std::cout << " Direct Syscall-Based Reflective Hollowing" << std::endl;
            std::cout << " x64 & ARM64 | ";
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::cout << Core::BUILD_TAG;
            SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            std::cout << " by @xaitax" << std::endl;
            SetConsoleTextAttribute(m_hConsole, m_origAttrs);
        }

        bool IsVerbose() const { return m_verbose; }

    private:
        void Print(const std::string& tag, const std::string& msg, WORD color) const {
            SetConsoleTextAttribute(m_hConsole, color);
            std::cout << tag;
            SetConsoleTextAttribute(m_hConsole, m_origAttrs);
            std::cout << " " << msg << std::endl;
        }

        HANDLE m_hConsole;
        WORD m_origAttrs;
        bool m_verbose;
    };

}
