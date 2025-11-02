# Chrome App-Bound Encryption Decryption

## 🆕 Changelog

### v0.16.1
- **New Feature: IBAN Extraction**: Added support for extracting International Bank Account Numbers (IBANs) (thanks [raphaelthief](https://github.com/raphaelthief)!)
  - Extracts encrypted IBAN values and associated nicknames.
  - Outputs to `iban.json` in the browser profile directory.

### v0.16.0
- **Syscall Obfuscation**: Added runtime protection for the syscall engine.
  - Syscall Service Numbers (SSNs) and gadget pointers are XOR-encrypted in memory.
  - Encryption keys are derived from runtime system state, making each execution unique.
  - Protects all syscalls from memory scanning.
- **IPC Hardening**: Replaced GUID-based pipe names with browser-specific patterns.
  - Names generated from process/thread IDs and tick count.
- **Browser Fingerprinting**: Optional extraction of comprehensive browser metadata (use `--fingerprint` or `-f` flag).
  - Browser version, executable path, user data path, and profile count.
  - Update channel (stable/beta/dev/canary) and default search engine.
  - Security features: autofill status, password manager, safe browsing.
  - Extension details: count and IDs of all installed extensions.
  - System information: computer name, Windows username, extraction timestamp.
  - Sync/sign-in status and enterprise management detection.
  - Outputs JSON report to `fingerprint.json`.
  - Mimics legitimate browser IPC to evade monitoring tools.
- **Bug Fixes**: 
  - Fixed race condition in pipe communication that caused extraction failures in non-verbose mode.
  - Multi-profile extraction now continues on individual profile failures.

### v0.15.0
- **Multi-Browser Extraction with "all" Option**: New command-line option to automatically enumerate and extract data from all installed browsers in a single run.
  - Added `chromelevator.exe all` option that discovers all installed browsers (Chrome, Edge, Brave).
  - Automatically handles any combination of installed browsers, gracefully skipping those not found.
- **Dynamic Browser Path Discovery via Registry Syscalls**: Eliminated all hard-coded browser installation paths in favor of runtime Registry enumeration using direct syscalls.
  - Added new Registry syscalls: `NtOpenKey`, `NtQueryValueKey`, and `NtEnumerateKey` to the direct syscall engine, enabling stealthy Registry access without Win32 API dependencies.
  - Implemented `BrowserPathResolver` class that queries `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\<browser.exe>` using NT native paths (`\Registry\Machine\...`).
  - Supports both 64-bit and 32-bit (WOW6432Node) Registry views to ensure browser discovery across all installation types.
- **Advanced Gadget Detection**: Extended search to 64 bytes, added hook pattern skipping (e.g., jmp detection) for better evasion of inline EDR hooks.
- **Redesigned Output Formatting**: Completely redesigned the console output for cleaner, more professional appearance.
- **Resilient Decryption**: Implemented graceful error handling for GCM blobs, skipping invalid prefixes (e.g., non-"v20") to prevent process termination.
- **Conditional File Output**: Modified data extractor to write JSON files only if decrypted data is present, eliminating empty `[]` files from the output.

### v0.14.2
- **Bug Fix: Corrected Cookie Decryption Payload Handling**: Resolved a critical regression where encrypted cookie values were not being correctly parsed after decryption.
  - The recent architectural refactor inadvertently omitted a crucial processing step specific to cookie payloads. Unlike passwords or payment data, the decrypted plaintext for a cookie contains a 32-byte metadata header that must be stripped to reveal the actual cookie value.
- **Feature Enhancement: Expanded Cookie Data Extraction**: The tool now extracts a richer set of cookie attributes, providing a more comprehensive data set for analysis.
  - The SQLite query for cookies has been expanded to include `path`, `expires_utc`, `is_secure`, and `is_httponly`.
  - The JSON output has been updated accordingly to include these new fields, converting the boolean flags to proper `true`/`false` values for improved usability.

### v0.14.1
- **Architecture-Specific Stability Fix for x64 Syscall Trampoline**: Overhauled the x64 assembly trampoline to resolve a critical stability bug that caused a silent crash in the payload thread immediately after injection on x64 systems.
  - The previous dynamic, argument-aware loop created a complex code path that resulted in the assembler (`ml64.exe`) generating incorrect stack unwind data. This faulty data led to stack corruption and a silent crash when the new thread was initialized by the OS, causing the injector to hang indefinitely.
  - The x64 trampoline has been re-architected to mirror the robust, simplified design of the working ARM64 version. The dynamic loop has been replaced with a simple, unconditional `rep movsq` that copies a fixed, oversized block of stack arguments. This guarantees a linear code path, ensures the generation of correct unwind data, and makes the x64 injection process as reliable as the ARM64 one.
- **Enhanced Evasion for Parameter Passing**: Reworked the method for passing the pipe name parameter to the payload to bypass modern behavioral security heuristics, specifically Microsoft Defender's Controlled Folder Access (CFA).
  - The previous method of using a separate `NtWriteVirtualMemory` call for the parameter was flagged by CFA when the injector was run from a protected location (e.g., the Desktop).
  - This has been replaced with an "argument smuggling" technique. A single, larger memory region is now allocated in the target process for both the payload DLL and its pipe name parameter. Both are written into this contiguous block, presenting a more organic and less suspicious memory I/O pattern that is not blocked by CFA.
- **Bug Fix: Resolved Post-Injection Hang**: Corrected a logical desynchronization between the injector and the payload that caused the tool to hang after successfully creating the payload thread.
  - The payload's entry point was expecting a parameter in an outdated format from a previous, unsuccessful bypass attempt, while the injector was correctly passing a direct pointer using the new argument smuggling technique.
  - The payload's parameter handling logic has been reverted and fixed to correctly interpret the direct pointer, re-establishing communication with the injector and resolving the hang.

### v0.14.0
- **Direct Syscall-Based Reflective Hollowing & Evasion**: Migrated the entire injection strategy from a live process "attach" model to a classic "hollowing" technique.
  - The injector now launches the target browser via `CreateProcessW` in a `CREATE_SUSPENDED` state, providing full and uncontested control over the target's address space before any of its own code can execute.
  - The payload is injected into this suspended process, a new thread is created for its execution using `NtCreateThreadEx`, and the target is cleanly terminated by the injector upon completion. The original, suspended main thread is never resumed.
  - This fundamentally improves operational stealth by avoiding interaction with a running, monitored application and ensuring a clean injection environment.
- **Network Service Termination**: Replaced the payload's indiscriminate `KillProcesses` function with a far more intelligent `KillBrowserNetworkService` routine within the injector itself.
  - Using an expanded set of direct syscalls (`NtGetNextProcess`, `NtQueryInformationProcess`, `NtReadVirtualMemory`), the injector now enumerates all running instances of the target browser.
  - It inspects the command-line arguments of each process by reading its PEB and terminates *only* the specific utility process responsible for the Network Service (`--utility-sub-type=network.mojom.NetworkService`).
  - This surgical approach reliably releases file locks on the target SQLite databases without the collateral damage of closing the user's main browser windows, making the tool's operation significantly stealthier.
- **Massive Syscall Engine Expansion**: The direct syscall engine was significantly expanded to eliminate dependencies on nearly all high-level Win32 process management APIs, further hardening the tool against user-land hooking.
  - New syscall wrappers were added for process enumeration, information querying, memory reading, and termination, including: `NtGetNextProcess`, `NtQueryInformationProcess`, `NtReadVirtualMemory`, `NtTerminateProcess`, `NtUnmapViewOfSection`, `NtGetContextThread`, `NtSetContextThread`, `NtResumeThread`, and `NtFlushInstructionCache`.
- **Complete Code Modernization and Refactoring**: The C++ codebases for both the injector and the payload were re-architected into a more modular design that adheres to modern C++ best practices.
  - **Injector**: Logic was segregated into distinct classes (`Console`, `TargetProcess`, `PipeCommunicator`, `InjectionManager`), and the custom `HandleGuard` was replaced with the safer `std::unique_ptr` with a custom deleter.
  - **Payload**: The monolithic `DecryptionSession` was broken down into a suite of specialized classes (`PipeLogger`, `BrowserManager`, `MasterKeyDecryptor`, `DataExtractor`, etc.) managed by a central `DecryptionOrchestrator`. This greatly improves code clarity and follows the Single Responsibility Principle.

### v0.13.0
- **True Direct Syscall Engine**: Replaced the previous "Tartarus Gate" (direct `ntdll.dll` export invocation) with a true direct syscall engine for both x64 and ARM64 architectures.
  - The injector now resolves syscall numbers (SSNs) at runtime by sorting `ntdll.dll`'s `Zw*` export table by address ("Hell's Gate" technique).
  - It then finds the executable `syscall` (x64) or `svc` (ARM64) instruction gadget within the function's body, completely bypassing the function prologue and any user-land hooks placed by EDR/AV solutions.
  - A custom assembly trampoline (`syscall_trampoline_x64.asm` & `syscall_trampoline_arm64.asm`) was created for each architecture to correctly marshal arguments from the C calling convention to the kernel's syscall convention, including full support for stack-based arguments.
  - This change dramatically increases the tool's stealth and resilience against modern security monitoring.
- **Reflective Loader Memory Optimization**: Replaced manual byte-by-byte memory copying with optimized `memcpy` operations for headers and sections during reflective injection. This improves the speed and efficiency of the payload's in-memory mapping.
- **Post-Injection Memory Hardening**: After the payload DLL is written to the target process's allocated memory, its permissions are now explicitly changed from `PAGE_EXECUTE_READWRITE` to `PAGE_EXECUTE_READ` using a direct syscall to `NtProtectVirtualMemory`. This reduces the memory region's "suspiciousness" to Endpoint Detection and Response (EDR) solutions that monitor for writable and executable memory, thereby improving overall stealth and limiting the attack surface.
- **Headless Browser Auto-Launch**: When the `--start-browser` option is used, the injector now launches the target browser (Chrome, Brave, Edge) in **headless mode**. This ensures that no visible browser window appears during the operation, reducing user detection and improving operational stealth.

### v0.12.1
- **Enhanced Profile Detection**: Made profile discovery more robust by comprehensively scanning `User Data` subdirectories for characteristic browser database files, ensuring custom-named user profiles are correctly identified and processed alongside default profiles.
- **Critical Bug Fix / Compatibility**: Resolved crashes and improved compatibility with newer Chromium versions by gracefully handling specific 31-byte empty or placeholder encrypted blobs that previously caused `GCM blob is invalid` errors. The decryption logic now correctly interprets these as empty values instead of throwing exceptions.
- **Improved Database Access Robustness**: Re-implemented and enhanced the `SQLite nolock=1` mechanism for accessing browser databases (e.g., Cookies, Login Data, Web Data). This ensures highly robust and stable read access to SQLite files, even when they might be concurrently locked by other processes, by leveraging SQLite's URI filename feature to bypass OS-level file locking.

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