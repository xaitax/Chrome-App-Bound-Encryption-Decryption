# Chrome App-Bound Encryption Decryption

## 🆕 Changelog

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