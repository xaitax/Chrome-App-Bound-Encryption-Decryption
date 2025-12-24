// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "process_manager.hpp"
#include "../sys/internal_api.hpp"
#include <iostream>

namespace Injector {

    ProcessManager::ProcessManager(const BrowserInfo& browser) : m_browser(browser) {}

    ProcessManager::~ProcessManager() {
        // Ensure cleanup if not explicitly terminated
        if (m_hProcess) Terminate();
    }

    void ProcessManager::CreateSuspended() {
        STARTUPINFOW si{};
        PROCESS_INFORMATION pi{};
        si.cb = sizeof(si);

        if (!CreateProcessW(m_browser.fullPath.c_str(), nullptr, nullptr, nullptr,
                            FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
            throw std::runtime_error("CreateProcessW failed: " + std::to_string(GetLastError()));
        }

        m_hProcess.reset(pi.hProcess);
        m_hThread.reset(pi.hThread);
        m_pid = pi.dwProcessId;

        CheckArchitecture();
    }

    void ProcessManager::Terminate() {
        if (m_hProcess) {
            NtTerminateProcess_syscall(m_hProcess.get(), 0);
            WaitForSingleObject(m_hProcess.get(), 2000);
            m_hProcess.reset(); // Release handle
        }
    }

    void ProcessManager::CheckArchitecture() {
        USHORT processArch = 0, nativeMachine = 0;
        auto fnIsWow64Process2 = (decltype(&IsWow64Process2))GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2");
        
        if (!fnIsWow64Process2 || !fnIsWow64Process2(m_hProcess.get(), &processArch, &nativeMachine)) {
            throw std::runtime_error("Failed to determine target architecture");
        }

        m_arch = (processArch == IMAGE_FILE_MACHINE_UNKNOWN) ? nativeMachine : processArch;

        // Injector is x64 or ARM64 (native)
#if defined(_M_X64)
        constexpr USHORT injectorArch = 0x8664; // AMD64
#elif defined(_M_ARM64)
        constexpr USHORT injectorArch = 0xAA64; // ARM64
#else
        constexpr USHORT injectorArch = 0;
#endif

        if (m_arch != injectorArch) {
            throw std::runtime_error("Architecture mismatch: Target is " + std::to_string(m_arch));
        }
    }

    void ProcessManager::KillNetworkServices(const std::wstring& processName) {
        Core::UniqueHandle hCurrentProc;
        HANDLE nextProcHandle = nullptr;

        while (NtGetNextProcess_syscall(hCurrentProc.get(), PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE, 0, 0, &nextProcHandle) == 0) {
            Core::UniqueHandle hNextProc(nextProcHandle);
            hCurrentProc = std::move(hNextProc);

            std::vector<BYTE> buffer(sizeof(UNICODE_STRING_SYSCALLS) + MAX_PATH * 2);
            auto imageName = reinterpret_cast<PUNICODE_STRING_SYSCALLS>(buffer.data());
            
            if (NtQueryInformationProcess_syscall(hCurrentProc.get(), ProcessImageFileName, imageName, (ULONG)buffer.size(), NULL) != 0 || imageName->Length == 0)
                continue;

            std::wstring pPath(imageName->Buffer, imageName->Length / sizeof(wchar_t));
            std::filesystem::path p(pPath);
            
            if (_wcsicmp(p.filename().c_str(), processName.c_str()) != 0)
                continue;

            PROCESS_BASIC_INFORMATION pbi{};
            if (NtQueryInformationProcess_syscall(hCurrentProc.get(), ProcessBasicInformation, &pbi, sizeof(pbi), nullptr) != 0 || !pbi.PebBaseAddress)
                continue;

            // Read PEB to get command line
            // Note: This is a simplified version. In a real elite tool, we'd be more robust reading remote memory.
            // But for now, we follow the original logic.
            PEB peb{};
            if (NtReadVirtualMemory_syscall(hCurrentProc.get(), pbi.PebBaseAddress, &peb, sizeof(peb), nullptr) != 0) continue;
            
            RTL_USER_PROCESS_PARAMETERS params{};
            if (NtReadVirtualMemory_syscall(hCurrentProc.get(), peb.ProcessParameters, &params, sizeof(params), nullptr) != 0) continue;

            std::vector<wchar_t> cmdLine(params.CommandLine.Length / sizeof(wchar_t) + 1, 0);
            if (params.CommandLine.Length > 0 && NtReadVirtualMemory_syscall(hCurrentProc.get(), params.CommandLine.Buffer, cmdLine.data(), params.CommandLine.Length, nullptr) == 0) {
                if (wcsstr(cmdLine.data(), L"--utility-sub-type=network.mojom.NetworkService")) {
                    NtTerminateProcess_syscall(hCurrentProc.get(), 0);
                    // Wait for process to terminate and release file handles
                    WaitForSingleObject(hCurrentProc.get(), 500);
                }
            }
        }
    }

}
