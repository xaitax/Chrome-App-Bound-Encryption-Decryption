# Chrome App-Bound Encryption (ABE) - Technical Deep Dive & Research Notes

**Project:** [Chrome App-Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption/)  
**Author:** Alexander 'xaitax' Hagenah
**Version:** Based on v0.7.0 analysis, incorporating insights from Google's ABE design documents, public announcements, and related security research.
**Last Updated:** 11 May 2025

## 1. Introduction: The Evolution of Local Data Protection in Chrome

For years, Chromium-based browsers on Windows relied on the **Data Protection API (DPAPI)** to secure sensitive user data stored locally such as cookies, passwords, payment information, and the like. DPAPI binds data to the logged-in user's credentials, offering a solid baseline against offline attacks (e.g., a stolen hard drive) and unauthorized access by other users on the same machine. However, DPAPI's Achilles' heel has always been its permissiveness within the user's own session: _any application running as the same user, with the same privilege level as Chrome, can invoke `CryptUnprotectData` and decrypt this data._ This vulnerability has been a perennial favorite for infostealer malware.

To counter this, Google introduced **App-Bound Encryption (ABE)** in Chrome (publicly announced around version 127, July 2024). ABE is a significant architectural shift designed to dramatically raise the bar for attackers. Its core principle is to ensure that the primary decryption keys for sensitive Chrome data are only accessible to legitimate Chrome processes, thereby mitigating trivial data theft by same-user, same-privilege malware.

### 1.1. Core Tenets of ABE (as per Google's Design)

- **Primary Goal:** Prevent an attacker operating with the _same privilege level as Chrome_ from trivially calling DPAPI to decrypt sensitive data.
- **Acknowledged Limitations (Non-Goals):** ABE does not aim to prevent attackers with _higher privileges_ (Administrator, SYSTEM, kernel drivers) or those who can successfully _inject code into Chrome_. The official Google design documents explicitly recognize code injection as a potent bypass vector. A technique this project leverages for legitimate research and data recovery demonstrations.
- **Underlying Mechanism:** ABE introduces an intermediary COM service (part of Chrome's Elevation Service) that acts as a gatekeeper for the DPAPI-unwrapping of a critical session key. This service verifies the "app identity" of the caller.
- **Initial Identity Verification Method:** The first iteration relies on **path validation** of the calling executable. While digital signature validation was considered, path validation was chosen for the initial rollout to "descope the complexity" (as noted in a 2024 update to Google's design document), deemed sufficient against the immediate threat model.

Google's conceptual diagram provides a clear overview:

![Google's ABE Diagram](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEgpjkAClX2VvgsIhLi2zAmvRwVMPEeJqUhqisKHIKxbfGAwh8p8-V7Ixct5azzn_jYfJYo2izWnGcbkVh3cabbCLVQQQsJAJagvFPCFJsx4MibauJqnLVymQYdhdGGc53q3wSJSeTPQ6vyxXosJ-tJRKuaaoV7_J_E2KB9glSZ1m3NSEwEBj-duevgROHlM/s1416/Screenshot%202024-07-26%202.15.06%20PM.png)
_(Image: Google's conceptual diagram of App-Bound Encryption, illustrating the privileged service gating key access.)_

## 2. The ABE Mechanism: A Step-by-Step Breakdown

ABE employs a multi-layered strategy for key management and data encryption:

1.  **The `app_bound_key` (Session Key):**

    - A unique 32-byte AES-256 key is generated. This key appears to be scoped per Chrome user data directory, meaning it would protect data across multiple profiles within that directory.
    - This key is the ultimate symmetric workhorse, used for AES-256-GCM encryption and decryption of the actual sensitive data items (cookies, passwords, etc.).

2.  **DPAPI Wrapping of the `app_bound_key`:**

    - The AES-256 `app_bound_key` is itself encrypted using the standard Windows DPAPI (`CryptProtectData`), binding its accessibility to the user's current logon session and machine.

3.  **Storage in `Local State`:**

    - The DPAPI-wrapped `app_bound_key` is then Base64-encoded.
    - A characteristic 4-byte prefix, **`APPB`** (ASCII: `0x41 0x50 0x50 0x42`), is prepended to this Base64 string.
    - This final, prefixed string is stored in the `Local State` JSON file (typically found at `User Data\Local State`) under the key `os_crypt.app_bound_encrypted_key`.

4.  **The `IElevator` COM Service (The Gatekeeper):**

    - When Chrome needs the plaintext `app_bound_key`, its internal `OSCrypt` component no longer directly calls `CryptUnprotectData` on the blob from `Local State`.
    - Instead, it instantiates a COM object that implements an interface (referred to generically as `IElevator`). This service is an integral part of Chrome's "Elevation Service" infrastructure.
    - The CLSIDs and IIDs for this service are crucial and browser-specific:
      - **Google Chrome:**
        - CLSID: `{708860E0-F641-4611-8895-7D867DD3675B}`
        - IID: `{463ABECF-410D-407F-8AF5-0DF35A005CC8}`
      - **Brave Browser:**
        - CLSID: `{576B31AF-6369-4B6B-8560-E4B203A97A8B}`
        - IID: `{F396861E-0C8E-4C71-8256-2FAE6D759C9E}`
    - Chrome's `OSCrypt` passes the raw DPAPI-wrapped blob (post-Base64 decoding and `APPB` prefix removal) to the `IElevator::DecryptData` method.

5.  **Path Validation by `IElevator`:**

    - This is the linchpin of ABE's app-binding. The `IElevator` COM server, before proceeding with the DPAPI decryption, **verifies the executable path of the calling process.**
    - If the caller's `.exe` is not located within the browser's legitimate installation directory (e.g., `C:\Program Files\Google\Chrome\Application\`), the `DecryptData` call is designed to fail. This aims to ensure only bona fide Chrome code can request the unwrapping of the `app_bound_key`.

6.  **Data Encryption/Decryption using the `app_bound_key`:**
    - If path validation is successful and `IElevator::DecryptData` manages to unwrap the `app_bound_key` (meaning the DPAPI call within the service succeeded), the plaintext 32-byte AES key is returned to the `OSCrypt` component.
    - `OSCrypt` then employs this key for AES-256-GCM operations on cookies, passwords, etc. These encrypted data blobs are typically identifiable by a version prefix (e.g., `v20`).

## 3. Circumventing ABE Path Validation: The `chrome-inject` Strategy

The `chrome_inject.exe` and `chrome_decrypt.dll` tools developed in this project effectively bypass the ABE path validation by orchestrating the sensitive COM calls to execute _from within the legitimate browser's own process space_. This approach aligns with the "Weaknesses" section of Google's ABE design document (Page 7), which explicitly notes: _"An attacker could inject code into Chrome browser and call the IPC interface."_ This project implements such a technique, not for malicious purposes, but for security research, data recovery exploration, and, for me, as a fascinating practical learning exercise in Windows internals, COM, and process manipulation.

### 3.1. The Methodology

- **Injector (`chrome_inject.exe`):**

  1.  **Target Process Acquisition:** Identifies a running instance of the target Chromium-based browser (Chrome, Edge, Brave). It can also auto-start the browser if specified.
  2.  **Architectural Consistency:** Critically ensures that the injector and target process architectures align (e.g., x64 injector for x64 Chrome, ARM64 for ARM64 Chrome).
  3.  **DLL Path Marshalling:** Allocates memory within the target browser process's address space (`VirtualAllocEx`) and carefully writes the full path string of `chrome_decrypt.dll` into this remote memory (`WriteProcessMemory`).
  4.  **Remote Thread Execution:** Creates a new thread within the target process. The entry point for this new thread is the address of `LoadLibraryA` (from `kernel32.dll`), and its sole argument is the remote memory address where the DLL path string was written.
      - This project offers two distinct injection methods:
        - `CreateRemoteThread`: The standard, well-documented WinAPI function.
        - `NtCreateThreadEx`: A lower-level, less commonly monitored API residing in `ntdll.dll`, potentially offering a degree of stealth against some endpoint detection and response (EDR) solutions.
  5.  **Synchronization:** Employs a named event (`Global\ChromeDecryptWorkDoneEvent`) to pause execution and await a signal from the injected DLL indicating that its operations have concluded.

- **Injected Payload (`chrome_decrypt.dll`):**
  1.  **Trusted Execution Context:** When `LoadLibraryA` is invoked within the remote thread, the `DllMain` function of `chrome_decrypt.dll` (specifically, the `DLL_PROCESS_ATTACH` case) is executed. At this pivotal moment, the DLL's code is running with the full identity and, crucially, the _executable path context_ of the host browser process (e.g., `chrome.exe`). This inherently satisfies the `IElevator` path validation check.
  2.  **Dedicated Worker Thread:** To avoid blocking `DllMain` (which can lead to deadlocks and instability) and to allow `LoadLibraryA` to return promptly (signaling successful injection to the injector), `DllMain` spawns a new, dedicated worker thread. This worker thread undertakes all subsequent COM interactions and decryption tasks. The DLL's original module handle (`HMODULE`) is passed to this worker thread, enabling it to call `FreeLibraryAndExitThread` upon completion for a clean self-unload.
  3.  **COM Initialization & Security Configuration:**
      - The worker thread initializes the COM library for its use via `CoInitializeEx(NULL, COINIT_APARTMENTTHREADED)`.
      - It then instantiates the `IElevator` COM object using `CoCreateInstance`, providing the browser-specific CLSID and IID.
      - To ensure correct security context propagation for the COM calls, `CoSetProxyBlanket` is invoked on the `IElevator` proxy. This project uses `RPC_C_AUTHN_LEVEL_PKT_PRIVACY`, `RPC_C_IMP_LEVEL_IMPERSONATE`, and `EOAC_DYNAMIC_CLOAKING`.
  4.  **Retrieving and Unwrapping the `app_bound_key`:**
      - The DLL reads the `Local State` JSON file from the appropriate user data directory.
      - It parses the JSON to locate the `os_crypt.app_bound_encrypted_key` value.
      - This value is Base64-decoded, and the `APPB` prefix is stripped, yielding the raw DPAPI-wrapped blob.
      - This blob is then passed to the `IElevator::DecryptData` method.
  5.  **Data Decryption and Output:**
      - If the `IElevator::DecryptData` call succeeds, the returned plaintext 32-byte AES key is the `app_bound_key`.
      - This key is then used with Windows Cryptography API: Next Generation (CNG) functions (specifically `BCrypt*` for AES-GCM) to decrypt sensitive data retrieved from the browser's SQLite databases (Cookies, Login Data, Web Data).
      - The decrypted data items are formatted into JSON and written to separate files in the user's `%TEMP%` directory.
      - For research and verification, the plaintext `app_bound_key` (in hexadecimal format) is saved to `%TEMP%\chrome_appbound_key.txt`.
      - A detailed operational log is also generated and saved to `%TEMP%\chrome_decrypt.log`.
  6.  **Signaling Completion and Resource Cleanup:** The worker thread signals the `Global\ChromeDecryptWorkDoneEvent` named event, uninitializes COM via `CoUninitialize`, and then calls `FreeLibraryAndExitThread` to unload the DLL from the browser's process space.

### 3.2. Operational Context: User-Mode, No Administrative Rights Required

A key characteristic of this project's methodology is that it operates entirely in **user mode** and **does not require administrative privileges**. This is possible because:

- The `IElevator` COM server, while part of an "Elevation Service," performs the decryption relevant to user data by impersonating the user and leveraging the user's DPAPI context. The "privileged" nature of the service (as depicted in Google's diagram where it runs as SYSTEM) primarily pertains to its role as a gatekeeper for DPAPI access and its ability to validate callers, not necessarily that the decryption task for user keys itself requires SYSTEM-level rights.
- DLL injection into another process running as the _same user_ typically does not necessitate administrative elevation.
- All file system access (for `Local State`, SQLite databases) targets locations within the user's own profile, which are accessible without elevated rights.

## 4. Dissecting Encrypted Data Structures

### 4.1. `Local State` and the `app_bound_encrypted_key`

- **Typical Location:** `%LOCALAPPDATA%\<BrowserVendor>\<BrowserName>\User Data\Local State` (e.g., `Google\Chrome\User Data\Local State`).
- **Relevant JSON Key:** `os_crypt.app_bound_encrypted_key`.
- **Format:** A string value: `"APPB<Base64EncodedDPAPIWrappedAESKey>"`.

### 4.2. AES-GCM Blob Format (Cookies, Passwords, Payments, etc.)

Data items encrypted with the `app_bound_key` generally adhere to a consistent format:

1.  **Prefix:** A version or type prefix string. For cookies, passwords, and payment data observed thus far, this is typically **`v20`** (ASCII: `0x76 0x32 0x30`). Older data encrypted solely with DPAPI might use prefixes like `v10` or `v11`.
2.  **Nonce (IV):** A 12-byte Initialization Vector, essential for the security of AES-GCM mode.
3.  **Ciphertext:** The actual encrypted data, variable in length.
4.  **Authentication Tag:** A 16-byte GCM authentication tag, which ensures both the integrity and authenticity of the decrypted ciphertext.

**Overall Blob Structure:** `[Prefix (e.g., 3 bytes for "v20")][IV (12 bytes)][Ciphertext (variable length)][Tag (16 bytes)]`

### 4.3. Cookie Value Specifics (from `encrypted_value` in `Cookies` DB)

- A notable observation during the development of this tool is that after successfully decrypting a `v20`-prefixed cookie blob using AES-GCM with the `app_bound_key`, the first **32 bytes** of the resulting plaintext appear to be some form of metadata or padding. The actual cookie value string begins after this `DECRYPTED_COOKIE_VALUE_OFFSET` of 32 bytes.

### 4.4. Passwords (from `password_value` in `Login Data` DB) & Payment Information

- These data types also use `v20`-prefixed blobs.
- Unlike cookies, the entire decrypted plaintext (after accounting for the `v20` prefix, IV, and tag during the AES-GCM decryption process) is generally considered to be the sensitive value itself (e.g., the password string, credit card number, or CVC).

## 5. Alternative Decryption Vectors & Chrome's Evolving Defenses

### 5.1. Administrator-Level Decryption (e.g., `runassu/chrome_v20_decryption` PoC)

The proof-of-concept by `runassu` illustrates that if an attacker possesses **Administrator privileges**, the `app_bound_key` can potentially be decrypted. This aligns with ABE's stated non-goal of protecting against higher-privilege attackers. The method described involves:

1.  Decrypting the `app_bound_encrypted_key` from `Local State` first using the SYSTEM DPAPI context, and then subsequently using the user's DPAPI context. This "double DPAPI" step is an intriguing detail, possibly related to how `elevation_service.exe` internally manages or protects the key it handles.
2.  The result of this double DPAPI decryption is _not_ the final `app_bound_key`. Instead, it's reported to be another encrypted blob containing metadata (like the Chrome installation path), a flag, an IV, a 32-byte ciphertext, and an authentication tag.
3.  This intermediate blob is then purportedly decrypted using AES-256-GCM with a **key hardcoded within `elevation_service.exe` itself**.
4.  The plaintext resulting from _this_ second-stage decryption is the final 32-byte `app_bound_key`.

- **Hardcoded Keys in `elevation_service.exe`:** The PoC mentions specific hardcoded keys within `elevation_service.exe`, one for ChaCha20_Poly1305 (reportedly for Chrome 133+) and another for AES-256-GCM (e.g., `B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787`).
- **Stability Concerns:** This administrator-level method is highly dependent on the internal implementation details of `elevation_service.exe` (such as hardcoded keys and intermediate blob formats). These are undocumented and subject to change without notice in Chrome updates, making this approach inherently less stable than interacting with the defined `IElevator` COM interface. Furthermore, it necessitates administrative rights, a higher bar than the user-mode injection technique employed by this project.

### 5.2. Remote Debugging Port (`--remote-debugging-port`) and Its Mitigation

Attackers had also turned to Chrome's remote debugging capabilities as a vector to exfiltrate cookies, effectively sidestepping ABE's file-based protections.

- **Chrome's Countermeasure (Chrome 136+):** As detailed in a Chrome Developers blog post, Google addressed this by changing the behavior of the `--remote-debugging-port` and `--remote-debugging-pipe` command-line switches. Starting with Chrome 136, these switches will no longer function when Chrome is launched with its default user data directory. To enable remote debugging, users must now also specify the `--user-data-dir` switch, pointing Chrome to a _non-standard, separate_ data directory. This ensures that any debugging session operates on an isolated profile, using a different encryption key, thereby safeguarding the user's primary profile data.
- **Bypass Simplicity:** While this change adds a hurdle, it's worth noting that an attacker _can_ control Chrome's launch parameters (e.g., by modifying shortcuts or through malware that relaunches Chrome), they could potentially still launch Chrome with both `--remote-debugging-port` and a temporary `--user-data-dir`, then attempt to import or access data if Chrome allows such operations into a fresh, debuggable profile. The effectiveness of the debug port mitigation hinges on preventing unauthorized modification of launch parameters and on Chrome's policies regarding data access in such scenarios.

### 5.3. Device Bound Session Credentials (DBSC)

As an overlapping and complementary security effort, Google has been developing **Device Bound Session Credentials (DBSC)**, available for Origin Trial in Chrome 135. DBSC aims to combat cookie theft by cryptographically binding session cookies to the device.

- **Mechanism:** When a DBSC session is initiated, the browser generates a public-private key pair, storing the private key securely (ideally using hardware like a TPM). The server associates the session with the public key. Periodically, the browser proves possession of the private key to refresh the (typically short-lived) session cookie.
- **Relevance to ABE:** While ABE protects data at rest on the user's device, DBSC focuses on making stolen session cookies useless if exfiltrated and used on another device. They are two distinct but synergistic layers of defense against session hijacking. An attacker bypassing ABE to get cookies might still find those cookies unusable elsewhere if they are DBSC-protected.

## 6. Key Insights from Google's ABE Design Document ("Chrome app-bound encryption Service")

Google's internal design document for ABE (formerly "Chrome Elevated Data Service") provides invaluable context:

- **Original Intent vs. Implemented Reality (Path vs. Signature Validation):** The initial proposal (Page 4 of the design doc) contemplated validating the _digital signature_ of both the calling process and the `IElevator` service executable. However, an "Update (2024)" note clarifies that the project was descoped to use **path validation** for the initial implementation, primarily for simplicity, with the assessment that it offered "equivalent protection against a non-admin attacker" for the prevailing threat models at the time.
- **`OSCrypt` Module Modifications:** The core `components/os_crypt` module within Chromium was slated to be augmented. Instead of making direct DPAPI calls, it would use new IPC mechanisms to communicate with the Elevation Service (Pages 2, 5). The design proposed that `OSCrypt` would iterate through a list of "key encryption delegates" - one for legacy DPAPI keys, another for ABE-protected keys via IPC - to find a delegate capable of decrypting a given key (Page 6).
- **Stateless Nature of the Service:** The `IElevator` service, in its role for ABE, is designed as a largely stateless encrypt/decrypt primitive. It doesn't require its own persistent storage for ABE operations (Page 4).
- **Explicit Acknowledgment of Injection as a Bypass:** Page 7 ("Weaknesses") of the design document candidly states: _"An attacker could inject code into Chrome browser and call the IPC interface. It would be hard to defeat a determined attacker using this technique..."_ This project serves as a practical validation of this assessment.
- **Considerations for Future Enhancements ("Follow-up work," Page 11):**
  - Implementing stronger caller provenance checks (e.g., thread stack examination, code integrity checks on the calling module).
  - Potentially moving the service to run as LocalSystem for increased isolation (though user-data decryption would still rely on user-context DPAPI).
  - Using `CryptProtectMemory` for the in-memory `os_crypt` master key to protect it from inter-process reads (marked as "done" in the document).
  - Emitting event logs for unauthorized IPC calls (marked as "done"). This corresponds to the Event ID 257 (Source: 'Chrome') in the Windows Application Log, mentioned in Google's public blog post, which signals a failed ABE verification.

## 7. Operational Considerations and Limitations of this tool

### 7.1. Browser Process Termination (`KillBrowserProcesses`)

The `chrome_decrypt.dll` currently includes logic to terminate existing browser processes of the target type before proceeding.

- **Rationale:** This is primarily to ensure that SQLite database files (`Cookies`, `Login Data`, `Web Data`) are not locked by live browser instances and that the `IElevator` COM server can initialize in a clean state, potentially avoiding conflicts or issues if existing browser instances have the service in an unusual state.
- **User Impact:** This is a disruptive action. Future enhancements to this tool could explore less intrusive methods, such as attempting to copy the database files to a temporary location and operating on those copies, or implementing a more conditional termination strategy (e.g., only if initial COM instantiation or DB access fails).

### 7.2. Multi-Profile Support

Currently, this tool primarily targets the `Default` user profile within the browser's user data directory. Comprehensive support for environments with multiple Chrome profiles would involve:

1.  Enumerating all active profile directories (e.g., `Profile 1`, `Profile 2`, etc.) within the main `User Data` folder.
2.  Applying the (likely single, shared per `User Data` instance) `app_bound_key` to decrypt data from each profile's respective SQLite databases, as the key is tied to the overall user data directory, not individual sub-profiles.

### 7.3. Roaming Profiles and Enterprise Environments

Google's public communications on ABE explicitly state that it "will not function correctly in environments where Chrome profiles roam between multiple machines." This is because the underlying DPAPI protection for the `app_bound_key` is inherently machine-bound (and user-bound). If an enterprise requires support for roaming profiles, they are encouraged to follow existing best practices. For scenarios where ABE might cause incompatibility, Chrome provides the `ApplicationBoundEncryptionEnabled` enterprise policy to configure or disable this feature.

## 8. Conclusion and Future Directions for ABE Research

App-Bound Encryption marks a commendable and significant enhancement in securing locally stored Chrome data on the Windows platform. By fundamentally tying decryption capabilities to a path-validated COM service, Google has effectively "moved the goalposts" for attackers, compelling them to resort to either privilege escalation or code injection into Chrome itself - both of which are generally "noisier" and more readily detectable actions than straightforward, unprivileged DPAPI calls.

This project, through its implementation of a user-mode DLL injection technique, serves multiple purposes:

1.  It provides a practical, working demonstration of the bypass vector that Google's own design documents acknowledged.
2.  It functions as a valuable tool for legitimate data recovery scenarios and for security researchers aiming to understand ABE's intricacies.
3.  It stands as a reference implementation for interacting with the ABE system from within the trusted browser context.

The ongoing evolution of Chrome and its security mechanisms means that ABE research will remain a dynamic field. Future areas of focus will likely include:

- **Monitoring the `IElevator` service:** Tracking any changes to its CLSIDs, IIDs, interface methods, or the core validation logic (e.g., a potential future shift from path validation to digital signature validation, as originally contemplated).
- **Deep Analysis of Undocumented Structures:** Further reverse engineering efforts to understand elements like the 32-byte prefix observed in decrypted cookie plaintext.
- **Chrome's Detection and Mitigation of Injection Techniques:** As Google and security vendors work to make code injection "more detectable," understanding these evolving detection strategies and their impact will be crucial.
- **Impact of Further OS-Level Hardening:** Investigating how improvements in Windows process integrity, application isolation primitives, or EDR technologies might affect ABE and bypass techniques.

The landscape of browser security is one of constant flux. App-Bound Encryption is a critical new defensive layer, and the continued efforts of the research community will be essential for a comprehensive understanding of its strengths, its limitations, and its trajectory in the face of ever-adapting threats.

## 9. References and Further Reading

- **Google Security Blog:** [Improving the security of Chrome cookies on Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html) (July 30, 2024)
- **Google Design Document:** [Chrome app-bound encryption Service (formerly: Chrome Elevated Data Service)](https://drive.google.com/file/d/1xMXmA0UJifXoTHjHWtVir2rb94OsxXAI/view) (Original: Jan 25, 2021, with later updates)
- **Chrome Developers Blog (Remote Debugging):** [Changes to remote debugging switches to improve security](https://developer.chrome.com/blog/remote-debugging-port) (Example: March 17, 2025)
- **Chrome Developers Blog (DBSC):** [Origin trial: Device Bound Session Credentials in Chrome](https://developer.chrome.com/blog/dbsc-origin-trial)
- **runassu's PoC (Admin-level decryption):** [chrome_v20_decryption](https://github.com/runassu/chrome_v20_decryption)
- **Related Research/Tools:**
  - [snovvcrash's X/Twitter Profile (Security Researcher)](https://x.com/snovvcrash)
  - [SilentDev33's ChromeAppBound-key-injection (Similar PoC)](https://github.com/SilentDev33/ChromeAppBound-key-injection)
