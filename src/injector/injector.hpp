// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include "../core/common.hpp"
#include "../core/console.hpp"
#include "process_manager.hpp"
#include <vector>

namespace Injector {

    class PayloadInjector {
    public:
        PayloadInjector(ProcessManager& process, const Core::Console& console);

        void Inject(const std::wstring& pipeName);

    private:
        void LoadAndDecryptPayload();
        DWORD GetExportOffset(const char* exportName);
        
        ProcessManager& m_process;
        const Core::Console& m_console;
        std::vector<uint8_t> m_payload;
    };

}
