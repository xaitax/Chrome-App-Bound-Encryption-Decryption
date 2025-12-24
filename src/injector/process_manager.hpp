// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include "../core/common.hpp"
#include "browser_discovery.hpp"

namespace Injector {

    class ProcessManager {
    public:
        explicit ProcessManager(const BrowserInfo& browser);
        ~ProcessManager();

        void CreateSuspended();
        void Terminate();
        HANDLE GetProcessHandle() const { return m_hProcess.get(); }
        HANDLE GetThreadHandle() const { return m_hThread.get(); }
        DWORD GetPid() const { return m_pid; }

        // Kill existing network services to free file locks
        static void KillNetworkServices(const std::wstring& processName);

    private:
        void CheckArchitecture();

        BrowserInfo m_browser;
        Core::UniqueHandle m_hProcess;
        Core::UniqueHandle m_hThread;
        DWORD m_pid = 0;
        USHORT m_arch = 0;
    };

}
