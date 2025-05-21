## COMrade ABE: Your Field Manual for App-Bound Encryption's COM Underbelly

So, you've stared into the abyss of Chromium's App-Bound Encryption (ABE). You know the drill: Google (and now others in the Chromium family) decided that just letting any old process poke at DPAPI-protected goodies wasn't cutting it anymore. Fair enough. They introduced a COM-based gatekeeper, usually an `elevation_service.exe`, that's supposed to ensure only the *real* browser gets to decrypt the master `app_bound_key`. My own `Chrome-App-Bound-Encryption-Decryption` tool showed we can often talk our way past the bouncer with a well-placed DLL. Good times.

But then reality bites. Chrome updates. Edge does its own thing (as chronicled in my [Cantankerous COM](https://medium.com/@xaitax/the-curious-case-of-the-cantankerous-com-decrypting-microsoft-edges-app-bound-encryption-266cc52bc417) saga). Brave has its flavor. New browsers might join the ABE party. Suddenly, your carefully crafted CLSIDs, IIDs, and C++ interface stubs become relics of a bygone era. Back to registry spelunking? Not if I can help it.

That's where **COMrade ABE** comes in. Forget manual recon; this script is your automated advance scout, designed to map out the ABE COM landscape for any given Chromium-based browser. It's born out of the sheer necessity of not wanting to reinvent the wheel (or re-reverse engineer it) every few months. This isn't just about *what* COMrade ABE spits out, but *why* those arcane GUIDs and VTable offsets are the difference between triumphantly extracting data and staring at an `E_INVALIDARG` HRESULT with a rising sense of dread.

* **You can grab COMrade ABE in the project's GitHub repository:**
[**Chrome-App-Bound-Encryption-Decryption (featuring COMrade ABE)**](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption/blob/main/comrade_abe.py).

### The Name of the Game: CLSIDs, IIDs, and the VTable Shuffle

To make sense of COMrade ABE's intel, let's quickly recap the COM essentials we're wrestling with:

1.  **CLSID (Class Identifier):** This is the unique "phone number" for the COM server itself – the ABE elevation service. Your first call, `CoCreateInstance`, needs this GUID to even get the server on the line. If the browser vendor changes this, you're dialing a dead number.

2.  **IID (Interface Identifier):** Once COM has rustled up an instance of the server object, you need to tell it *which specific set of services* you want to use. That's the interface, identified by its IID. For ABE, we're hunting for the interface that offers up `DecryptData` (and its sibling, `EncryptData`). A single COM object can expose multiple interfaces, each with its own IID. Picking the wrong one means you get a polite "sorry, wrong department" (`E_NOINTERFACE`) or, worse, an interface that looks similar but has a different method layout.

3.  **VTable (Virtual Method Table):** This is where the C++ rubber meets the COM road. An interface pointer in C++ is, under the hood, a pointer to an array of function pointers – the VTable. The first three are *always* `QueryInterface`, `AddRef`, and `Release` from `IUnknown`. After that, it's the methods of the interface itself, in a specific, compiler-defined order. If your C++ code expects `DecryptData` at VTable slot 5, but due to some quirky inheritance shenanigans it's actually at slot 8 (looking at you, Edge!), you're in for a world of pain (`E_INVALIDARG` is a common symptom).

COMrade ABE's mission is to dynamically figure out these crucial pieces for you.

### COMrade ABE: Mission Debrief – Decoding the Output

When you start COMrade ABE (e.g., `python comrade_abe.py chrome --scan`), it goes to work. Here’s how to interpret the report it files:

**The Standard Output – The Executive Summary:**

```text
--- 💡 Analysis Summary ---
  Browser Target    : Chrome
  Service Executable: C:\Program Files\Google\Chrome\Application\136.0.7103.114\elevation_service.exe
  Discovered CLSID  : {708860E0-F641-4611-8895-7D867DD3675B}
      (C++ Style)   : {0x708860E0,0xF641,0x4611,{0x88,0x95,0x7D,0x86,0x7D,0xD3,0x67,0x5B}}

  Found 6 ABE-Capable Interface(s):

  Candidate 1:
    Interface Name: IElevator
    IID           : {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C}
      (C++ Style) : {0xA949CB4E,0xC4F9,0x44C4,{0xB2,0x13,0x6B,0xF8,0xAA,0x9A,0xC6,0x9C}}

  Candidate 2: 💡 (Likely primary for tool)
    Interface Name: IElevatorChrome
    IID           : {463ABECF-410D-407F-8AF5-0DF35A005CC8}
      (C++ Style) : {0x463ABECF,0x410D,0x407F,{0x8A,0xF5,0x0D,0xF3,0x5A,0x00,0x5C,0xC8}}
  ... etc. ...
```

*   **`Browser Target` & `Service Executable`**: Self-explanatory. Verifies COMrade ABE looked at the right binary.
*   **`Discovered CLSID`**: This is your entry point. The script hunts through the registry for CLSIDs tied to the browser's known elevation service name (like `GoogleChromeElevationService`).
    *   The string format (`{7088...}`) is for reference.
    *   The `(C++ Style)` (`{0x708860E0,...}`) is pure gold – ready to be slapped into a C++ `GUID` struct definition. This is the `clsid` parameter for `CoCreateInstance`.
*   **`Found X ABE-Capable Interface(s)`**: ABE services can be surprisingly chatty, offering the same core functionality through multiple interface "personalities." COMrade ABE lists every interface found in the Type Library that passes its signature checks for `DecryptData` and `EncryptData`.
    *   **`Interface Name`**: The human-readable name from the Type Library (e.g., `IElevator`, `IElevatorChrome`, `IEdgeElevatorFinal`). Gives you a hint about its intended purpose or variant.
    *   **`IID`**: The Interface ID for *this specific candidate*. This is the `riid` you'd pass to `CoCreateInstance` or `QueryInterface`. Again, both string and C++ struct formats are provided.
    *   **`💡 (Likely primary for tool)`**: My little heuristic. It tries to flag the IID that's most likely the "main" one your C++ tool should target, often by matching against known IIDs for specific browser channels (like the `IElevatorChrome` one for Chrome Stable). This is usually the most derived interface in a chain that provides the target methods.

**Why so many IIDs?** Often, a base interface (e.g., `IElevator`) defines the core methods, and then browser-specific or channel-specific interfaces (`IElevatorChrome`, `IElevatorEdge`) inherit from it, sometimes adding nothing new but acting as distinct "access points." COMrade ABE shows them all because, technically, any of them *might* work if they correctly expose the ABE methods.

**The `-v` Verbose Output – The Full Schematics**

Alright, the standard summary from COMrade ABE gives you the essentials: CLSID, a list of potential IIDs. That's often enough to get you started. But when things get weird – when your C++ calls inexplicably fail with `E_INVALIDARG`, when a new browser version suddenly breaks your working code, or when you're just plain curious about how a vendor like Microsoft decided to layer their `IElevator` – that's when you unleash the Kraken: the `-v` (verbose) flag.

The verbose output is COMrade ABE laying bare the entire internal structure of each ABE-capable interface it finds, along with its complete ancestry. Let's dissect a verbose entry, using Chrome's `IElevatorChrome` as our specimen, because it nicely illustrates how inheritance plays out:

```text
--- ℹ️ Verbose Candidate Details ---
  --- Verbose for Candidate 3: 'IElevatorChrome' (IID: {463ABECF-410D-407F-8AF5-0DF35A005CC8}) 💡 (Likely primary for tool) ---
    Methods (relevant to ABE):
      - Method 'EncryptData': VTable Offset: 32 (Slot ~4), Defined in: 'IElevator' (IID: {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C})
      - Method 'DecryptData': VTable Offset: 40 (Slot ~5), Defined in: 'IElevator' (IID: {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C})
    Inheritance Chain: IUnknown -> IElevator -> IElevatorChrome
      Interface in chain: 'IUnknown' (IID: {00000000-0000-0000-C000-000000000046}) - Defines 3 method(s):
        (Standard IUnknown methods)
        - HRESULT QueryInterface(GUID* riid, void** ppvObj) (oVft: 0)
        - ULONG AddRef(void) (oVft: 8)
        - ULONG Release(void) (oVft: 16)
      Interface in chain: 'IElevator' (IID: {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C}) - Defines 3 method(s):
        (cFuncs: 3 from verbose log)
        - HRESULT RunRecoveryCRXElevated(LPWSTR crx_path, LPWSTR browser_appid, LPWSTR browser_version, LPWSTR session_id, ULONG caller_proc_id, ULONG_PTR* proc_handle) (oVft: 24)
        - HRESULT EncryptData(ProtectionLevel protection_level, BSTR plaintext, BSTR* ciphertext, ULONG* last_error) (oVft: 32)
        - HRESULT DecryptData(BSTR ciphertext, BSTR* plaintext, ULONG* last_error) (oVft: 40)
      Interface in chain: 'IElevatorChrome' (IID: {463ABECF-410D-407F-8AF5-0DF35A005CC8}) - Defines 0 method(s):
        (cFuncs: 0 from verbose log)
        (No methods directly defined in this block for 'IElevatorChrome')
--- End of Verbose Details ---
```

Let's break this down piece by piece:

**1. The Candidate Header:**
   `--- Verbose for Candidate X: 'InterfaceName' (IID: {GUID-HERE}) 💡 (Likely primary for tool) ---`
   This just identifies which of the ABE-capable interfaces (from the summary list) these detailed verbose notes pertain to. The `💡` flag is the same heuristic as in the summary.

**2. `Methods (relevant to ABE):`**
   This is a quick-glance summary for *this candidate interface* (e.g., `IElevatorChrome`) showing where the core ABE methods you care about (`EncryptData`, `DecryptData`) actually come from.

   *   **`Method 'EncryptData': VTable Offset: 32 (Slot ~4), Defined in: 'IElevator' (IID: {A949...})`**
        *   **`VTable Offset: 32`**: This is the `FUNCDESC.oVft` (offset in vtable) value *from the perspective of the defining interface*. So, `EncryptData` is 32 bytes from the start of `IElevator`'s vtable section.
        *   **`Slot ~4`**: This is a calculated convenience: `oVft / sizeof(void*)`. On a 64-bit system where pointers are 8 bytes, `32 / 8 = 4`. This means it's the method at index 4 (the 5th method pointer overall) within the `IElevator` vtable structure.
        *   **`Defined in: 'IElevator' (IID: {A949...})`**: This is crucial. It tells you that if you have an `IElevatorChrome` pointer, the `EncryptData` method it exposes is actually inherited from its base class, `IElevator`. Your C++ stub for `IElevatorChrome` *must* correctly inherit from an `IElevator` stub that defines `EncryptData` at its 4th slot (after its own `IUnknown` methods, or after any methods from *its* base).
        *   **Why this matters so much**: If `IElevatorChrome` didn't inherit from `IElevator` but redefined `EncryptData` itself at a different `oVft` (say, as its *first* new method), the VTable slot would be different. Or, if an intermediate, unexpected base class was injected between `IElevator` and `IElevatorChrome` (like `IElevatorEdgeBase` in Edge's case), that would *also* shift the final VTable slot for `EncryptData` when accessed via an `IElevatorChrome` pointer. This "Defined in" tells you where to look for the original definition and its `oVft`.

**3. `Inheritance Chain: IUnknown -> IElevator -> IElevatorChrome`**
   This is the COM family tree, from the universal ancestor `IUnknown` down to the specific candidate interface.
   *   **Importance**: This chain *is* the blueprint for the VTable layout. In C++, when `IElevatorChrome` inherits `IElevator`, which inherits `IUnknown`, the VTable layout for an `IElevatorChrome` object will be:
        1.  `IUnknown::QueryInterface`
        2.  `IUnknown::AddRef`
        3.  `IUnknown::Release`
        4.  `IElevator::RunRecoveryCRXElevated` (first *new* method in `IElevator`)
        5.  `IElevator::EncryptData` (second *new* method in `IElevator`)
        6.  `IElevator::DecryptData` (third *new* method in `IElevator`)
        7.  Any *new* methods defined directly by `IElevatorChrome` itself (in this case, zero).
    Knowing this exact order is non-negotiable for writing C++ stubs that will call the correct functions. COMrade ABE derives this chain by repeatedly calling `ITypeInfo::GetRefTypeOfImplType(0)` until it hits `IUnknown` or an interface with no further base.

**4. `Interface in chain: '...' - Defines X method(s):`**
   This is the most granular part. For *each* interface in the chain shown above, COMrade ABE lists the methods that are *directly defined within that specific interface's declaration* (as per `TYPEATTR.cFuncs`).

   *   **`Interface in chain: 'IUnknown' (IID: {...}) - Defines 3 method(s):`**
        *   `(Standard IUnknown methods)` - a note that these are the universal three.
        *   `- HRESULT QueryInterface(GUID* riid, void** ppvObj) (oVft: 0)`
        *   `- ULONG AddRef(void) (oVft: 8)`
        *   `- ULONG Release(void) (oVft: 16)`
        *   **`oVft: 0, 8, 16`**: These are the standard, unchanging VTable offsets for `IUnknown` methods *relative to the start of any COM interface pointer*. `QueryInterface` is always the first.
        *   **Signatures**: COMrade ABE shows the full C-style signature. This is to ensure your C++ stubs declare the methods correctly. Mismatched parameter types or return types are a common source of crashes.

   *   **`Interface in chain: 'IElevator' (IID: {A949...}) - Defines 3 method(s):`**
        *   `(cFuncs: 3 from verbose log)`: This internal debug note from my Python script indicates the `TYPEATTR.cFuncs` value for `IElevator` is 3. This means `IElevator` *itself* introduces three new methods beyond what it inherits.
        *   `- HRESULT RunRecoveryCRXElevated(...) (oVft: 24)`
        *   `- HRESULT EncryptData(...) (oVft: 32)`
        *   `- HRESULT DecryptData(...) (oVft: 40)`
        *   **`oVft` values (24, 32, 40)**: These offsets are *relative to the start of the `IElevator` interface pointer*. Since `IElevator` inherits `IUnknown` (whose methods occupy offsets 0, 8, 16), its *own* new methods start after that. So, `RunRecoveryCRXElevated` is at offset `0 + 3*8 = 24`. `EncryptData` is at `24 + 8 = 32`, and `DecryptData` at `32 + 8 = 40`.
        *   **Signatures**: Again, the full C-style signatures. Note the `ProtectionLevel` enum for `EncryptData`. If COMrade ABE finds this UDT in the Type Library, it will attempt to generate a `typedef enum ProtectionLevel { ... };` for your C++ stubs.

   *   **`Interface in chain: 'IElevatorChrome' (IID: {463A...}) - Defines 0 method(s):`**
        *   `(cFuncs: 0 from verbose log)`: `IElevatorChrome` itself declares no *new* methods. It purely inherits its functionality.
        *   `(No methods directly defined in this block for 'IElevatorChrome')`
        *   **Importance**: This tells you that `IElevatorChrome` is essentially an alias or a specific "brand" of `IElevator`. Its VTable will be identical to `IElevator`'s up to the end of `IElevator`'s methods.

**The Edge Case (Pun Intended): How This Decodes Complexity**

Remember the "Cantankerous COM" with Edge? Its chain looked something like:
`IUnknown -> IElevatorEdgeBase -> IElevator -> IElevatorEdge`

COMrade ABE's verbose output would show:
*   `IElevatorEdgeBase` defining 3 (unknown to us, but COM-wise present) methods. These would occupy `oVft: 24, 32, 40`.
*   `IElevator` (inheriting `IElevatorEdgeBase`) would then define its 3 ABE methods. Its *first* method, `RunRecoveryCRXElevated`, would now have an `oVft` of `40 + 8 = 48` (slot 6), not 24! `DecryptData` would be at `oVft: 64` (slot 8).
*   `IElevatorEdge` would define 0 new methods.

Without this verbose breakdown, trying to call `DecryptData` on an `IElevatorEdge` pointer using a C++ stub that assumed it was at slot 5 (like `IOriginalBaseElevator`) would hit the wrong function in `IElevatorEdgeBase`'s VTable section, leading to `E_INVALIDARG`. The verbose output makes this VTable shifting explicitly clear.

**Practical Applications of Verbose Intel:**

1.  **Debugging Failed COM Calls:** If your `DecryptData` call is failing, the verbose output is your first stop.
    *   Is the IID you're using actually listed as ABE-capable?
    *   Does the inheritance chain in your C++ stub match what COMrade ABE reports?
    *   Do the `oVft` values and method signatures for `DecryptData` in its *defining interface* match your expectations or previous findings? A change here is a red flag.

2.  **Crafting Precise C++ Stubs (When `--output-cpp-stub` Isn't Enough or for Understanding):**
    While the auto-generated stubs are great, understanding *why* they're structured that way comes from this verbose output. You can see exactly which interface defines which method and how the VTable slots add up.

3.  **Advanced COM Hijacking/Interception Research (Offensive Security):**
    Knowing the exact VTable layout and method signatures is fundamental for more advanced techniques like VTable hooking if you were trying to intercept calls to these ABE methods from within the browser process.

4.  **Identifying Undocumented Functionality:**
    The verbose output lists *all* methods defined by interfaces in the ABE service's Type Library, not just `EncryptData`/`DecryptData`. You might stumble upon other intriguing methods. What does `IElevator::RunRecoveryCRXElevated` actually do? What are its `crx_path` or `session_id` parameters used for? Could it be leveraged for something unexpected? COMrade ABE gives you the starting point – the method name and its signature.

In essence, COMrade ABE's verbose mode hands you the decompiler's view of the COM interface structure, neatly organized and interpreted. It turns opaque GUIDs and binary layouts into a human-readable (well, geek-readable) specification. It's the difference between fumbling in the dark and having a detailed schematic when you're trying to hotwire a complex system like App-Bound Encryption.

Okay, let's give the `--output-cpp-stub` section the detailed treatment it deserves, focusing on *why* it's such a game-changer and *what exactly* it provides, keeping that more direct, engineer-to-engineer tone.

---

*(Continuing from the previous article structure)*

**The Real Power: `--output-cpp-stub` – Your Auto-Generated C++ Blueprints**

Alright, so COMrade ABE has dutifully scanned the Type Library, identified the likely CLSID your browser's ABE service responds to, and listed out all the `IElevator`-esque interfaces that smell like they can do the `DecryptData` dance. That's great intel. But now you actually have to *talk* to these things from C++.

This is where you'd normally roll up your sleeves, fire up `OleView.NET` or a disassembler if you're truly desperate, and start the painstaking process of transcribing interface definitions into C++ `MIDL_INTERFACE` blocks. You'd be meticulously copying GUIDs, ensuring inheritance lines up, and getting every `STDMETHODCALLTYPE` and parameter type *exactly* right. One typo – a `ULONG*` where it should be `ULONG`, a misplaced comma in a GUID – and you're rewarded with cryptic compiler errors or, worse, runtime crashes that send you back to square one.

This is precisely the headache the `--output-cpp-stub FILE_PATH` option is designed to eliminate. A massive accelerator and an error-reduction mechanism.

When you use this flag, COMrade ABE takes the "Likely primary for tool" candidate (or the first viable one if that heuristic doesn't pinpoint a specific known IID for your target browser) and does the heavy lifting of translating its entire discovered structure into C++ code. Here's what you get in that output file:

1.  **Header Information:**
    The file starts with comments clearly indicating which browser and service executable the stubs were generated for, along with the target CLSID and the primary IID chosen for stub generation. This is your immediate sanity check:

    ```cpp
    // --- COM Stubs for Browser: Chrome ---
    // Generated by COMrade ABE
    // Service Executable: C:\Program Files\Google\Chrome\Application\136.0.7103.114\elevation_service.exe
    // Target CLSID for CoCreateInstance: {0x708860E0,0xF641,0x4611,{0x88,0x95,0x7D,0x86,0x7D,0xD3,0x67,0x5B}} // Original: {708860E0-F641-4611-8895-7D867DD3675B}
    // Target IID for CoCreateInstance: {0x463ABECF,0x410D,0x407F,{0x8A,0xF5,0x0D,0xF3,0x5A,0x00,0x5C,0xC8}} // Original: {463ABECF-410D-407F-8AF5-0DF35A005CC8} (Primary Interface: IElevatorChrome)
    ```
    Notice it provides both the C++ struct style and the original string GUID for quick reference.

2.  **User-Defined Type (Enum) Definitions:**
    If the interface methods use custom enumerations (like `ProtectionLevel` for `EncryptData`), COMrade ABE attempts to find their definitions in the Type Library (`TKIND_ENUM`) and generate the corresponding C++ `typedef enum`:

    ```cpp
    // Enum: ProtectionLevel
    typedef enum ProtectionLevel {
        None = 0,
        PathValidationOld = 1,
        PathValidation = 2,
        Max = 3,
    } ProtectionLevel;
    ```
    Getting these enum values right is important, as passing an incorrect integer to `EncryptData` could lead to unexpected behavior or failed encryption.

3.  **Full Inheritance Chain as `MIDL_INTERFACE` Blocks:**
    This is the core of the generated stubs. COMrade ABE takes the *entire* inheritance chain for the chosen primary interface (e.g., `IUnknown` -> `IElevatorEdgeBase` -> `IElevator` -> `IEdgeElevatorFinal` for Edge) and defines each one in order, from the most base to the most derived.

    *   **Correct GUIDs:** Each `MIDL_INTERFACE("GUID_STRING_HERE")` uses the exact IID discovered for that interface in the chain. The C++ style GUID is also helpfully commented.
    *   **Correct Inheritance:** Each interface correctly specifies its direct base class: `InterfaceName : public BaseInterfaceName`. This is non-negotiable for the C++ compiler to generate a VTable layout that matches the COM object's actual binary layout.
    *   **Method Declarations:** For every method *directly defined* by an interface in the chain (i.e., not inherited by *it* from *its* base, but new at that level), COMrade ABE generates the pure virtual function declaration:
        `virtual HRESULT STDMETHODCALLTYPE MethodName(PARAM_TYPE param1, PARAM_TYPE2 param2, ...) = 0;`

        *   **Return Type and Calling Convention:** `HRESULT STDMETHODCALLTYPE` is standard.
        *   **Method Name:** Pulled directly from the Type Library.
        *   **Parameters:** The real magic is here. COMrade ABE meticulously translates the `VARTYPE` and parameter flags from the Type Library's `FUNCDESC` and `ELEMDESC` structures into their C++ equivalents:
            *   `VT_BSTR` with `PARAMFLAG_FIN` becomes `BSTR plaintext`.
            *   `VT_BSTR | VT_BYREF` with `PARAMFLAG_FOUT` becomes `BSTR* ciphertext`.
            *   `VT_UI4 | VT_BYREF` with `PARAMFLAG_FOUT` becomes `ULONG* last_error`.
            *   `VT_LPWSTR` becomes `LPWSTR`.
            *   Pointers to user-defined types are also handled.
            *   The parameter names are also extracted if available in the Type Library.

    Here's an example snippet for Edge's more complex chain, as generated by COMrade ABE:

    ```cpp
    // Stubs for Edge would look something like this:

    // Enum: ProtectionLevel (defined as above) ...

    MIDL_INTERFACE("00000000-0000-0000-C000-000000000046") // C++ style: {0x00000000,0x0000,0x0000,{0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}}
    IUnknown : public IUnknown // Base IUnknown methods are implicit
    {
    public:
        // Standard IUnknown methods are typically not explicitly re-declared in MIDL_INTERFACE
        // but are understood by the MIDL compiler and C++ when inheriting from IUnknown.
        // For clarity, one might add them, but COMrade ABE follows common practice of letting
        // the base IUnknown handle this. If the type library explicitly lists them for some reason,
        // COMrade ABE will list them. Let's assume it lists them for this example for illustration:
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(
            REFIID riid,
            void** ppvObject) = 0;
        virtual ULONG STDMETHODCALLTYPE AddRef(void) = 0;
        virtual ULONG STDMETHODCALLTYPE Release(void) = 0;
    };

    MIDL_INTERFACE("E12B779C-CDB8-4F19-95A0-9CA19B31A8F6") // C++ style: {0xE12B779C,0xCDB8,0x4F19,{0x95,0xA0,0x9C,0xA1,0x9B,0x31,0xA8,0xF6}}
    IEdgeElevatorBase_Placeholder : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE EdgeBaseMethod1_Unknown(void) = 0; // Placeholder names if real names absent
        virtual HRESULT STDMETHODCALLTYPE EdgeBaseMethod2_Unknown(void) = 0;
        virtual HRESULT STDMETHODCALLTYPE EdgeBaseMethod3_Unknown(void) = 0;
    };

    MIDL_INTERFACE("A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C") // C++ style: {0xA949CB4E,0xC4F9,0x44C4,{0xB2,0x13,0x6B,0xF8,0xAA,0x9A,0xC6,0x9C}}
    IEdgeIntermediateElevator : public IEdgeElevatorBase_Placeholder // Note: Edge's IElevator inherits from its Base
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(
            LPWSTR crx_path,
            LPWSTR browser_appid,
            LPWSTR browser_version,
            LPWSTR session_id,
            ULONG caller_proc_id,
            ULONG_PTR* proc_handle
        ) = 0;
        virtual HRESULT STDMETHODCALLTYPE EncryptData(
            ProtectionLevel protection_level,
            BSTR plaintext,
            BSTR* ciphertext,
            ULONG* last_error
        ) = 0;
        virtual HRESULT STDMETHODCALLTYPE DecryptData(
            BSTR ciphertext,
            BSTR* plaintext,
            ULONG* last_error
        ) = 0;
    };

    MIDL_INTERFACE("C9C2B807-7731-4F34-81B7-44FF7779522B") // C++ style: {0xC9C2B807,0x7731,0x4F34,{0x81,0xB7,0x44,0xFF,0x77,0x79,0x52,0x2B}}
    IEdgeElevatorFinal : public IEdgeIntermediateElevator // This is the IID you'd request for Edge
    {
    public:
        // This interface directly defines 0 methods; all are inherited.
    };
    ```

**The Payoff:**

*   Manual transcription of GUIDs and complex C++ method signatures is a minefield. COMrade ABE does it programmatically from the Type Library, the "source of truth" for the COM server's binary interface.
*   If Edge version X.Y.Z changes its `IEdgeElevatorFinal` to inherit from a new `IEdgeElevatorBase_V2`, running COMrade ABE with `--output-cpp-stub` immediately gives you the updated C++ definitions reflecting this new reality. No painful debugging of `E_NOINTERFACE` or VTable call crashes because your C++ stubs are suddenly out of sync.
*   You can spend your time writing the actual logic to *use* these interfaces (like in `chrome_decrypt.cpp` to call `DecryptData`) rather than wrestling with getting the declarations right.
*   The generated stub file itself becomes excellent documentation of the exact binary interface you're targeting for a specific version of a browser service.

This is an *enormous* timesaver and error-reducer. Manually transcribing these from `OleView.NET` or a disassembler is tedious and prone to typos that lead to subtle runtime bugs.

### Why COMrade ABE Belongs in Your ABE Toolkit

1.  **Future-Proofing (Mostly):** Browsers evolve. CLSIDs might change, IIDs might get versioned, or (as with Edge) inheritance structures might get funky. COMrade ABE gives you a fighting chance to quickly re-analyze and adapt your tools or research without days of RE.
2.  **New Browser Recon:** A new Chromium fork appears with ABE? Point COMrade ABE at its `elevation_service.exe` (if you can find it). It'll give you the lay of the COM land.
3.  **Taming Vendor Quirks:** The Edge example is paramount. COMrade ABE's chain analysis is what reveals those vendor-specific intermediate base classes that shift VTable layouts. Without this, you're shooting in the dark.
4.  **Beyond `DecryptData`:** The verbose output lists *all* methods. That `RunRecoveryCRXElevated` on `IElevator`? What are its exact parameters (COMrade ABE tells you!)? What could it do? Are there other, undocumented methods on these privileged interfaces? COMrade ABE is your starting point for such investigations.
5.  **Sanity Checking and Validation:** If you *do* have source code (like parts of Chromium's IDL), you can use COMrade ABE to validate that the compiled binary on a user's system actually matches the IDL you expect. Discrepancies could indicate tampering or unexpected build variations.

COMrade ABE isn't a magic bullet though – if a Type Library is missing or heavily obfuscated, its job gets much harder. But for the common case where browsers *do* ship this metadata with their service executables, it's an incredibly powerful ally. It automates the grunt work of COM interface discovery and mapping, letting you focus on the more interesting parts of understanding and interacting with App-Bound Encryption. So, next time you're gearing up to wrestle with ABE, make sure your COMrade is by your side. It makes the COM_plicated world a little less daunting.

## Appendix: Python Script - Regular Output

```
PS C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption> python .\comrade_abe.py

-------------------------------------------------------------------------------------------

_________  ________      _____                    .___          _____ _____________________
\_   ___ \ \_____  \    /     \____________     __| _/____     /  _  \\______   \_   _____/
/    \  \/  /   |   \  /  \ /  \_  __ \__  \   / __ |/ __ \   /  /_\  \|    |  _/|    __)_
\     \____/    |    \/    Y    \  | \// __ \_/ /_/ \  ___/  /    |    \    |   \|        \
 \______  /\_______  /\____|__  /__|  (____  /\____ |\___  > \____|__  /______  /_______  /
        \/         \/         \/           \/      \/    \/          \/       \/        \/

                  by Alexander 'xaitax' Hagenah
-------------------------------------------------------------------------------------------

usage: comrade_abe.py TARGET [options]

COMrade ABE: Your friendly helper for discovering and detailing COM App-Bound Encryption (ABE)
interfaces in Chromium-based browsers. It identifies service executables, CLSIDs, relevant IIDs,
and generates C++ stubs for security research and development.

positional arguments:
  TARGET                Either the direct path to an executable (e.g., elevation_service.exe)
                        OR a browser key ('chrome', 'edge', 'brave') when using --scan mode.

options:
  -h, --help            show this help message and exit
  -v, --verbose         Enable detailed verbose output during the analysis process.
  --output-cpp-stub FILE_PATH
                        If specified, C++ interface stubs for the 'primary' identified ABE interface
                        will be written to this file.
  --target-method-names TARGET_METHOD_NAMES
                        Comma-separated list of essential method names to identify a potential ABE interface
                        (default: DecryptData,EncryptData).
  --decrypt-params COUNT
                        Expected parameter count for the 'DecryptData' method (default: 3).
  --encrypt-params COUNT
                        Expected parameter count for the 'EncryptData' method (default: 4).
  --known-clsid {CLSID-GUID}
                        Manually provide a CLSID (e.g., {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}) to use.
                        This can supplement or override discovery, especially useful when analyzing a
                        direct executable path without --scan, or if registry scan fails.
  --scan                Enable scan mode. In this mode, TARGET should be a browser key ('chrome', 'edge', 'brave').
                        The script will attempt to find the service executable and CLSID from the registry.

Examples:
  Scan for Chrome ABE interface:
    comrade_abe.py chrome --scan

  Scan for Edge, verbose output, and save C++ stubs:
    comrade_abe.py edge --scan -v --output-cpp-stub edge_abe_stubs.cpp

  Analyze a specific executable directly:
    comrade_abe.py "C:\Program Files\Google\Chrome\Application\1xx.x.xxxx.xx\elevation_service.exe"

  Analyze executable with a known CLSID:
    comrade_abe.py "C:\path\to\service.exe" --known-clsid {YOUR-CLSID-HERE-IN-BRACES}
```

## Appendix: Python Script - Regular Output

```
PS C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption> python .\comrade_abe.py chrome --scan

-------------------------------------------------------------------------------------------

_________  ________      _____                    .___          _____ _____________________
\_   ___ \ \_____  \    /     \____________     __| _/____     /  _  \\______   \_   _____/
/    \  \/  /   |   \  /  \ /  \_  __ \__  \   / __ |/ __ \   /  /_\  \|    |  _/|    __)_
\     \____/    |    \/    Y    \  | \// __ \_/ /_/ \  ___/  /    |    \    |   \|        \
 \______  /\_______  /\____|__  /__|  (____  /\____ |\___  > \____|__  /______  /_______  /
        \/         \/         \/           \/      \/    \/          \/       \/        \/

                  by Alexander 'xaitax' Hagenah
-------------------------------------------------------------------------------------------

⚙️ COM ABE Interface Analyzer Initializing...
⚙️ Scan mode enabled for: chrome
🔍 Scanning registry for service details of 'chrome'...
  ℹ️ Service ImagePath: C:\Program Files\Google\Chrome\Application\136.0.7103.114\elevation_service.exe
  ✅ Discovered CLSID: {708860E0-F641-4611-8895-7D867DD3675B}
🔍 Attempting to load type library from: C:\Program Files\Google\Chrome\Application\136.0.7103.114\elevation_service.exe
✅ Successfully loaded type library: 'ElevatorLib'
  ⚙️ Analyzing all TKIND_INTERFACE entries from TypeLib...
ℹ️ Debug: analyzer.results has 6 items before printing.

--- 💡 Analysis Summary ---
  Browser Target    : Chrome
  Service Executable: C:\Program Files\Google\Chrome\Application\136.0.7103.114\elevation_service.exe
  Discovered CLSID  : {708860E0-F641-4611-8895-7D867DD3675B}
      (C++ Style)   : {0x708860E0,0xF641,0x4611,{0x88,0x95,0x7D,0x86,0x7D,0xD3,0x67,0x5B}}

  Found 6 ABE-Capable Interface(s):

  Candidate 1:
    Interface Name: IElevator
    IID           : {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C}
      (C++ Style) : {0xA949CB4E,0xC4F9,0x44C4,{0xB2,0x13,0x6B,0xF8,0xAA,0x9A,0xC6,0x9C}}

  Candidate 2:
    Interface Name: IElevatorChromium
    IID           : {B88C45B9-8825-4629-B83E-77CC67D9CEED}
      (C++ Style) : {0xB88C45B9,0x8825,0x4629,{0xB8,0x3E,0x77,0xCC,0x67,0xD9,0xCE,0xED}}

  Candidate 3: 💡 (Likely primary for tool)
    Interface Name: IElevatorChrome
    IID           : {463ABECF-410D-407F-8AF5-0DF35A005CC8}
      (C++ Style) : {0x463ABECF,0x410D,0x407F,{0x8A,0xF5,0x0D,0xF3,0x5A,0x00,0x5C,0xC8}}

  Candidate 4:
    Interface Name: IElevatorChromeBeta
    IID           : {A2721D66-376E-4D2F-9F0F-9070E9A42B5F}
      (C++ Style) : {0xA2721D66,0x376E,0x4D2F,{0x9F,0x0F,0x90,0x70,0xE9,0xA4,0x2B,0x5F}}

  Candidate 5:
    Interface Name: IElevatorChromeDev
    IID           : {BB2AA26B-343A-4072-8B6F-80557B8CE571}
      (C++ Style) : {0xBB2AA26B,0x343A,0x4072,{0x8B,0x6F,0x80,0x55,0x7B,0x8C,0xE5,0x71}}

  Candidate 6:
    Interface Name: IElevatorChromeCanary
    IID           : {4F7CE041-28E9-484F-9DD0-61A8CACEFEE4}
      (C++ Style) : {0x4F7CE041,0x28E9,0x484F,{0x9D,0xD0,0x61,0xA8,0xCA,0xCE,0xFE,0xE4}}

✅ Analysis complete.
```

## Appendix: Python Script - Verbose Output

```
PS C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption> python .\comrade_abe.py chrome --scan --verbose

-------------------------------------------------------------------------------------------

_________  ________      _____                    .___          _____ _____________________
\_   ___ \ \_____  \    /     \____________     __| _/____     /  _  \\______   \_   _____/
/    \  \/  /   |   \  /  \ /  \_  __ \__  \   / __ |/ __ \   /  /_\  \|    |  _/|    __)_
\     \____/    |    \/    Y    \  | \// __ \_/ /_/ \  ___/  /    |    \    |   \|        \
 \______  /\_______  /\____|__  /__|  (____  /\____ |\___  > \____|__  /______  /_______  /
        \/         \/         \/           \/      \/    \/          \/       \/        \/

                  by Alexander 'xaitax' Hagenah
-------------------------------------------------------------------------------------------

⚙️ COM ABE Interface Analyzer Initializing...
⚙️ Scan mode enabled for: chrome
🔍 Scanning registry for service details of 'chrome'...
  Targeting service name: 'GoogleChromeElevationService'
  ℹ️ Service ImagePath: C:\Program Files\Google\Chrome\Application\136.0.7103.114\elevation_service.exe
  🔍 Searching for CLSIDs linked to LocalService 'GoogleChromeElevationService'...
    ℹ️ Found matching CLSID '{708860E0-F641-4611-8895-7D867DD3675B}' via AppID 'SOFTWARE\Classes\AppID'
    ℹ️ Registry path not found: HKCU\SOFTWARE\WOW6432Node\Classes\AppID
  ✅ Discovered CLSID: {708860E0-F641-4611-8895-7D867DD3675B}
🔍 Attempting to load type library from: C:\Program Files\Google\Chrome\Application\136.0.7103.114\elevation_service.exe
✅ Successfully loaded type library: 'ElevatorLib'
  ⚙️ Analyzing all TKIND_INTERFACE entries from TypeLib...
    Scanning Interface: 'IElevator' (IID: {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C})
      Tracing inheritance for 'IElevator'
        Processing interface in chain: 'IElevator' (IID: {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C}), cFuncs: 3
        Processing interface in chain: 'IUnknown' (IID: {00000000-0000-0000-C000-000000000046}), cFuncs: 3
          Performing signature check for 'EncryptData'...
            Expected param count: 4, Actual: 4
            Return type VT: 25 (HRESULT)
            Param 0: Type='ProtectionLevel', Raw VT=0x1D, Flags=0x1 (in)
            Param 1: Type='BSTR', Raw VT=0x8, Flags=0x1 (in)
            Param 2: Type='BSTR*', Raw VT=0x1A, Flags=0x2 (out)
            Param 3: Type='ULONG*', Raw VT=0x1A, Flags=0x2 (out)
          ✅ Signature check result for 'EncryptData': True
        💡 'EncryptData' matched signature in 'IElevator'.
          Performing signature check for 'DecryptData'...
            Expected param count: 3, Actual: 3
            Return type VT: 25 (HRESULT)
            Param 0: Type='BSTR', Raw VT=0x8, Flags=0x1 (in)
            Param 1: Type='BSTR*', Raw VT=0x1A, Flags=0x2 (out)
            Param 2: Type='ULONG*', Raw VT=0x1A, Flags=0x2 (out)
          ✅ Signature check result for 'DecryptData': True
        💡 'DecryptData' matched signature in 'IElevator'.
      ✅ Interface 'IElevator' (IID: {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C}) IS ABE-capable.
    Scanning Interface: 'IElevatorChromium' (IID: {B88C45B9-8825-4629-B83E-77CC67D9CEED})
      Tracing inheritance for 'IElevatorChromium'
        Processing interface in chain: 'IElevatorChromium' (IID: {B88C45B9-8825-4629-B83E-77CC67D9CEED}), cFuncs: 0
        Processing interface in chain: 'IElevator' (IID: {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C}), cFuncs: 3
        Processing interface in chain: 'IUnknown' (IID: {00000000-0000-0000-C000-000000000046}), cFuncs: 3
          Performing signature check for 'EncryptData'...
            Expected param count: 4, Actual: 4
            Return type VT: 25 (HRESULT)
            Param 0: Type='ProtectionLevel', Raw VT=0x1D, Flags=0x1 (in)
            Param 1: Type='BSTR', Raw VT=0x8, Flags=0x1 (in)
            Param 2: Type='BSTR*', Raw VT=0x1A, Flags=0x2 (out)
            Param 3: Type='ULONG*', Raw VT=0x1A, Flags=0x2 (out)
          ✅ Signature check result for 'EncryptData': True
        💡 'EncryptData' matched signature in 'IElevator'.
          Performing signature check for 'DecryptData'...
            Expected param count: 3, Actual: 3
            Return type VT: 25 (HRESULT)
            Param 0: Type='BSTR', Raw VT=0x8, Flags=0x1 (in)
            Param 1: Type='BSTR*', Raw VT=0x1A, Flags=0x2 (out)
            Param 2: Type='ULONG*', Raw VT=0x1A, Flags=0x2 (out)
          ✅ Signature check result for 'DecryptData': True
        💡 'DecryptData' matched signature in 'IElevator'.
      ✅ Interface 'IElevatorChromium' (IID: {B88C45B9-8825-4629-B83E-77CC67D9CEED}) IS ABE-capable.
    Scanning Interface: 'IElevatorChrome' (IID: {463ABECF-410D-407F-8AF5-0DF35A005CC8})
      Tracing inheritance for 'IElevatorChrome'
        Processing interface in chain: 'IElevatorChrome' (IID: {463ABECF-410D-407F-8AF5-0DF35A005CC8}), cFuncs: 0
        Processing interface in chain: 'IElevator' (IID: {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C}), cFuncs: 3
        Processing interface in chain: 'IUnknown' (IID: {00000000-0000-0000-C000-000000000046}), cFuncs: 3
          Performing signature check for 'EncryptData'...
            Expected param count: 4, Actual: 4
            Return type VT: 25 (HRESULT)
            Param 0: Type='ProtectionLevel', Raw VT=0x1D, Flags=0x1 (in)
            Param 1: Type='BSTR', Raw VT=0x8, Flags=0x1 (in)
            Param 2: Type='BSTR*', Raw VT=0x1A, Flags=0x2 (out)
            Param 3: Type='ULONG*', Raw VT=0x1A, Flags=0x2 (out)
          ✅ Signature check result for 'EncryptData': True
        💡 'EncryptData' matched signature in 'IElevator'.
          Performing signature check for 'DecryptData'...
            Expected param count: 3, Actual: 3
            Return type VT: 25 (HRESULT)
            Param 0: Type='BSTR', Raw VT=0x8, Flags=0x1 (in)
            Param 1: Type='BSTR*', Raw VT=0x1A, Flags=0x2 (out)
            Param 2: Type='ULONG*', Raw VT=0x1A, Flags=0x2 (out)
          ✅ Signature check result for 'DecryptData': True
        💡 'DecryptData' matched signature in 'IElevator'.
      ✅ Interface 'IElevatorChrome' (IID: {463ABECF-410D-407F-8AF5-0DF35A005CC8}) IS ABE-capable.
    Scanning Interface: 'IElevatorChromeBeta' (IID: {A2721D66-376E-4D2F-9F0F-9070E9A42B5F})
      Tracing inheritance for 'IElevatorChromeBeta'
        Processing interface in chain: 'IElevatorChromeBeta' (IID: {A2721D66-376E-4D2F-9F0F-9070E9A42B5F}), cFuncs: 0
        Processing interface in chain: 'IElevator' (IID: {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C}), cFuncs: 3
        Processing interface in chain: 'IUnknown' (IID: {00000000-0000-0000-C000-000000000046}), cFuncs: 3
          Performing signature check for 'EncryptData'...
            Expected param count: 4, Actual: 4
            Return type VT: 25 (HRESULT)
            Param 0: Type='ProtectionLevel', Raw VT=0x1D, Flags=0x1 (in)
            Param 1: Type='BSTR', Raw VT=0x8, Flags=0x1 (in)
            Param 2: Type='BSTR*', Raw VT=0x1A, Flags=0x2 (out)
            Param 3: Type='ULONG*', Raw VT=0x1A, Flags=0x2 (out)
          ✅ Signature check result for 'EncryptData': True
        💡 'EncryptData' matched signature in 'IElevator'.
          Performing signature check for 'DecryptData'...
            Expected param count: 3, Actual: 3
            Return type VT: 25 (HRESULT)
            Param 0: Type='BSTR', Raw VT=0x8, Flags=0x1 (in)
            Param 1: Type='BSTR*', Raw VT=0x1A, Flags=0x2 (out)
            Param 2: Type='ULONG*', Raw VT=0x1A, Flags=0x2 (out)
          ✅ Signature check result for 'DecryptData': True
        💡 'DecryptData' matched signature in 'IElevator'.
      ✅ Interface 'IElevatorChromeBeta' (IID: {A2721D66-376E-4D2F-9F0F-9070E9A42B5F}) IS ABE-capable.
    Scanning Interface: 'IElevatorChromeDev' (IID: {BB2AA26B-343A-4072-8B6F-80557B8CE571})
      Tracing inheritance for 'IElevatorChromeDev'
        Processing interface in chain: 'IElevatorChromeDev' (IID: {BB2AA26B-343A-4072-8B6F-80557B8CE571}), cFuncs: 0
        Processing interface in chain: 'IElevator' (IID: {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C}), cFuncs: 3
        Processing interface in chain: 'IUnknown' (IID: {00000000-0000-0000-C000-000000000046}), cFuncs: 3
          Performing signature check for 'EncryptData'...
            Expected param count: 4, Actual: 4
            Return type VT: 25 (HRESULT)
            Param 0: Type='ProtectionLevel', Raw VT=0x1D, Flags=0x1 (in)
            Param 1: Type='BSTR', Raw VT=0x8, Flags=0x1 (in)
            Param 2: Type='BSTR*', Raw VT=0x1A, Flags=0x2 (out)
            Param 3: Type='ULONG*', Raw VT=0x1A, Flags=0x2 (out)
          ✅ Signature check result for 'EncryptData': True
        💡 'EncryptData' matched signature in 'IElevator'.
          Performing signature check for 'DecryptData'...
            Expected param count: 3, Actual: 3
            Return type VT: 25 (HRESULT)
            Param 0: Type='BSTR', Raw VT=0x8, Flags=0x1 (in)
            Param 1: Type='BSTR*', Raw VT=0x1A, Flags=0x2 (out)
            Param 2: Type='ULONG*', Raw VT=0x1A, Flags=0x2 (out)
          ✅ Signature check result for 'DecryptData': True
        💡 'DecryptData' matched signature in 'IElevator'.
      ✅ Interface 'IElevatorChromeDev' (IID: {BB2AA26B-343A-4072-8B6F-80557B8CE571}) IS ABE-capable.
    Scanning Interface: 'IElevatorChromeCanary' (IID: {4F7CE041-28E9-484F-9DD0-61A8CACEFEE4})
      Tracing inheritance for 'IElevatorChromeCanary'
        Processing interface in chain: 'IElevatorChromeCanary' (IID: {4F7CE041-28E9-484F-9DD0-61A8CACEFEE4}), cFuncs: 0
        Processing interface in chain: 'IElevator' (IID: {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C}), cFuncs: 3
        Processing interface in chain: 'IUnknown' (IID: {00000000-0000-0000-C000-000000000046}), cFuncs: 3
          Performing signature check for 'EncryptData'...
            Expected param count: 4, Actual: 4
            Return type VT: 25 (HRESULT)
            Param 0: Type='ProtectionLevel', Raw VT=0x1D, Flags=0x1 (in)
            Param 1: Type='BSTR', Raw VT=0x8, Flags=0x1 (in)
            Param 2: Type='BSTR*', Raw VT=0x1A, Flags=0x2 (out)
            Param 3: Type='ULONG*', Raw VT=0x1A, Flags=0x2 (out)
          ✅ Signature check result for 'EncryptData': True
        💡 'EncryptData' matched signature in 'IElevator'.
          Performing signature check for 'DecryptData'...
            Expected param count: 3, Actual: 3
            Return type VT: 25 (HRESULT)
            Param 0: Type='BSTR', Raw VT=0x8, Flags=0x1 (in)
            Param 1: Type='BSTR*', Raw VT=0x1A, Flags=0x2 (out)
            Param 2: Type='ULONG*', Raw VT=0x1A, Flags=0x2 (out)
          ✅ Signature check result for 'DecryptData': True
        💡 'DecryptData' matched signature in 'IElevator'.
      ✅ Interface 'IElevatorChromeCanary' (IID: {4F7CE041-28E9-484F-9DD0-61A8CACEFEE4}) IS ABE-capable.
ℹ️ Debug: analyzer.results has 6 items before printing.

--- 💡 Analysis Summary ---
  Browser Target    : Chrome
  Service Executable: C:\Program Files\Google\Chrome\Application\136.0.7103.114\elevation_service.exe
  Discovered CLSID  : {708860E0-F641-4611-8895-7D867DD3675B}
      (C++ Style)   : {0x708860E0,0xF641,0x4611,{0x88,0x95,0x7D,0x86,0x7D,0xD3,0x67,0x5B}}

  Found 6 ABE-Capable Interface(s):

  Candidate 1:
    Interface Name: IElevator
    IID           : {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C}
      (C++ Style) : {0xA949CB4E,0xC4F9,0x44C4,{0xB2,0x13,0x6B,0xF8,0xAA,0x9A,0xC6,0x9C}}

  Candidate 2:
    Interface Name: IElevatorChromium
    IID           : {B88C45B9-8825-4629-B83E-77CC67D9CEED}
      (C++ Style) : {0xB88C45B9,0x8825,0x4629,{0xB8,0x3E,0x77,0xCC,0x67,0xD9,0xCE,0xED}}

  Candidate 3: 💡 (Likely primary for tool)
    Interface Name: IElevatorChrome
    IID           : {463ABECF-410D-407F-8AF5-0DF35A005CC8}
      (C++ Style) : {0x463ABECF,0x410D,0x407F,{0x8A,0xF5,0x0D,0xF3,0x5A,0x00,0x5C,0xC8}}

  Candidate 4:
    Interface Name: IElevatorChromeBeta
    IID           : {A2721D66-376E-4D2F-9F0F-9070E9A42B5F}
      (C++ Style) : {0xA2721D66,0x376E,0x4D2F,{0x9F,0x0F,0x90,0x70,0xE9,0xA4,0x2B,0x5F}}

  Candidate 5:
    Interface Name: IElevatorChromeDev
    IID           : {BB2AA26B-343A-4072-8B6F-80557B8CE571}
      (C++ Style) : {0xBB2AA26B,0x343A,0x4072,{0x8B,0x6F,0x80,0x55,0x7B,0x8C,0xE5,0x71}}

  Candidate 6:
    Interface Name: IElevatorChromeCanary
    IID           : {4F7CE041-28E9-484F-9DD0-61A8CACEFEE4}
      (C++ Style) : {0x4F7CE041,0x28E9,0x484F,{0x9D,0xD0,0x61,0xA8,0xCA,0xCE,0xFE,0xE4}}

--- ℹ️ Verbose Candidate Details ---

  --- Verbose for Candidate 1: 'IElevator' (IID: {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C}) ---
    Methods (relevant to ABE):
      - Method 'EncryptData': VTable Offset: 32 (Slot ~4), Defined in: 'IElevator' (IID: {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C})
      - Method 'DecryptData': VTable Offset: 40 (Slot ~5), Defined in: 'IElevator' (IID: {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C})
    Inheritance Chain: IUnknown -> IElevator
      Interface in chain: 'IUnknown' (IID: {00000000-0000-0000-C000-000000000046}) - Defines 3 method(s):
        (Standard IUnknown methods)
        - HRESULT QueryInterface(GUID* riid, void** ppvObj) (oVft: 0)
        - ULONG AddRef(void) (oVft: 8)
        - ULONG Release(void) (oVft: 16)
      Interface in chain: 'IElevator' (IID: {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C}) - Defines 3 method(s):
        - HRESULT RunRecoveryCRXElevated(LPWSTR crx_path, LPWSTR browser_appid, LPWSTR browser_version, LPWSTR session_id, ULONG caller_proc_id, ULONG_PTR* proc_handle) (oVft: 24)
        - HRESULT EncryptData(ProtectionLevel protection_level, BSTR plaintext, BSTR* ciphertext, ULONG* last_error) (oVft: 32)
        - HRESULT DecryptData(BSTR ciphertext, BSTR* plaintext, ULONG* last_error) (oVft: 40)

  --- Verbose for Candidate 2: 'IElevatorChromium' (IID: {B88C45B9-8825-4629-B83E-77CC67D9CEED}) ---
    Methods (relevant to ABE):
      - Method 'EncryptData': VTable Offset: 32 (Slot ~4), Defined in: 'IElevator' (IID: {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C})
      - Method 'DecryptData': VTable Offset: 40 (Slot ~5), Defined in: 'IElevator' (IID: {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C})
    Inheritance Chain: IUnknown -> IElevator -> IElevatorChromium
      Interface in chain: 'IUnknown' (IID: {00000000-0000-0000-C000-000000000046}) - Defines 3 method(s):
        (Standard IUnknown methods)
        - HRESULT QueryInterface(GUID* riid, void** ppvObj) (oVft: 0)
        - ULONG AddRef(void) (oVft: 8)
        - ULONG Release(void) (oVft: 16)
      Interface in chain: 'IElevator' (IID: {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C}) - Defines 3 method(s):
        - HRESULT RunRecoveryCRXElevated(LPWSTR crx_path, LPWSTR browser_appid, LPWSTR browser_version, LPWSTR session_id, ULONG caller_proc_id, ULONG_PTR* proc_handle) (oVft: 24)
        - HRESULT EncryptData(ProtectionLevel protection_level, BSTR plaintext, BSTR* ciphertext, ULONG* last_error) (oVft: 32)
        - HRESULT DecryptData(BSTR ciphertext, BSTR* plaintext, ULONG* last_error) (oVft: 40)
      Interface in chain: 'IElevatorChromium' (IID: {B88C45B9-8825-4629-B83E-77CC67D9CEED}) - Defines 0 method(s):
        (No methods directly defined in this block for 'IElevatorChromium')

  --- Verbose for Candidate 3: 'IElevatorChrome' (IID: {463ABECF-410D-407F-8AF5-0DF35A005CC8}) 💡 (Likely primary for tool) ---
    Methods (relevant to ABE):
      - Method 'EncryptData': VTable Offset: 32 (Slot ~4), Defined in: 'IElevator' (IID: {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C})
      - Method 'DecryptData': VTable Offset: 40 (Slot ~5), Defined in: 'IElevator' (IID: {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C})
    Inheritance Chain: IUnknown -> IElevator -> IElevatorChrome
      Interface in chain: 'IUnknown' (IID: {00000000-0000-0000-C000-000000000046}) - Defines 3 method(s):
        (Standard IUnknown methods)
        - HRESULT QueryInterface(GUID* riid, void** ppvObj) (oVft: 0)
        - ULONG AddRef(void) (oVft: 8)
        - ULONG Release(void) (oVft: 16)
      Interface in chain: 'IElevator' (IID: {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C}) - Defines 3 method(s):
        - HRESULT RunRecoveryCRXElevated(LPWSTR crx_path, LPWSTR browser_appid, LPWSTR browser_version, LPWSTR session_id, ULONG caller_proc_id, ULONG_PTR* proc_handle) (oVft: 24)
        - HRESULT EncryptData(ProtectionLevel protection_level, BSTR plaintext, BSTR* ciphertext, ULONG* last_error) (oVft: 32)
        - HRESULT DecryptData(BSTR ciphertext, BSTR* plaintext, ULONG* last_error) (oVft: 40)
      Interface in chain: 'IElevatorChrome' (IID: {463ABECF-410D-407F-8AF5-0DF35A005CC8}) - Defines 0 method(s):
        (No methods directly defined in this block for 'IElevatorChrome')

  --- Verbose for Candidate 4: 'IElevatorChromeBeta' (IID: {A2721D66-376E-4D2F-9F0F-9070E9A42B5F}) ---
    Methods (relevant to ABE):
      - Method 'EncryptData': VTable Offset: 32 (Slot ~4), Defined in: 'IElevator' (IID: {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C})
      - Method 'DecryptData': VTable Offset: 40 (Slot ~5), Defined in: 'IElevator' (IID: {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C})
    Inheritance Chain: IUnknown -> IElevator -> IElevatorChromeBeta
      Interface in chain: 'IUnknown' (IID: {00000000-0000-0000-C000-000000000046}) - Defines 3 method(s):
        (Standard IUnknown methods)
        - HRESULT QueryInterface(GUID* riid, void** ppvObj) (oVft: 0)
        - ULONG AddRef(void) (oVft: 8)
        - ULONG Release(void) (oVft: 16)
      Interface in chain: 'IElevator' (IID: {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C}) - Defines 3 method(s):
        - HRESULT RunRecoveryCRXElevated(LPWSTR crx_path, LPWSTR browser_appid, LPWSTR browser_version, LPWSTR session_id, ULONG caller_proc_id, ULONG_PTR* proc_handle) (oVft: 24)
        - HRESULT EncryptData(ProtectionLevel protection_level, BSTR plaintext, BSTR* ciphertext, ULONG* last_error) (oVft: 32)
        - HRESULT DecryptData(BSTR ciphertext, BSTR* plaintext, ULONG* last_error) (oVft: 40)
      Interface in chain: 'IElevatorChromeBeta' (IID: {A2721D66-376E-4D2F-9F0F-9070E9A42B5F}) - Defines 0 method(s):
        (No methods directly defined in this block for 'IElevatorChromeBeta')

  --- Verbose for Candidate 5: 'IElevatorChromeDev' (IID: {BB2AA26B-343A-4072-8B6F-80557B8CE571}) ---
    Methods (relevant to ABE):
      - Method 'EncryptData': VTable Offset: 32 (Slot ~4), Defined in: 'IElevator' (IID: {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C})
      - Method 'DecryptData': VTable Offset: 40 (Slot ~5), Defined in: 'IElevator' (IID: {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C})
    Inheritance Chain: IUnknown -> IElevator -> IElevatorChromeDev
      Interface in chain: 'IUnknown' (IID: {00000000-0000-0000-C000-000000000046}) - Defines 3 method(s):
        (Standard IUnknown methods)
        - HRESULT QueryInterface(GUID* riid, void** ppvObj) (oVft: 0)
        - ULONG AddRef(void) (oVft: 8)
        - ULONG Release(void) (oVft: 16)
      Interface in chain: 'IElevator' (IID: {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C}) - Defines 3 method(s):
        - HRESULT RunRecoveryCRXElevated(LPWSTR crx_path, LPWSTR browser_appid, LPWSTR browser_version, LPWSTR session_id, ULONG caller_proc_id, ULONG_PTR* proc_handle) (oVft: 24)
        - HRESULT EncryptData(ProtectionLevel protection_level, BSTR plaintext, BSTR* ciphertext, ULONG* last_error) (oVft: 32)
        - HRESULT DecryptData(BSTR ciphertext, BSTR* plaintext, ULONG* last_error) (oVft: 40)
      Interface in chain: 'IElevatorChromeDev' (IID: {BB2AA26B-343A-4072-8B6F-80557B8CE571}) - Defines 0 method(s):
        (No methods directly defined in this block for 'IElevatorChromeDev')

  --- Verbose for Candidate 6: 'IElevatorChromeCanary' (IID: {4F7CE041-28E9-484F-9DD0-61A8CACEFEE4}) ---
    Methods (relevant to ABE):
      - Method 'EncryptData': VTable Offset: 32 (Slot ~4), Defined in: 'IElevator' (IID: {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C})
      - Method 'DecryptData': VTable Offset: 40 (Slot ~5), Defined in: 'IElevator' (IID: {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C})
    Inheritance Chain: IUnknown -> IElevator -> IElevatorChromeCanary
      Interface in chain: 'IUnknown' (IID: {00000000-0000-0000-C000-000000000046}) - Defines 3 method(s):
        (Standard IUnknown methods)
        - HRESULT QueryInterface(GUID* riid, void** ppvObj) (oVft: 0)
        - ULONG AddRef(void) (oVft: 8)
        - ULONG Release(void) (oVft: 16)
      Interface in chain: 'IElevator' (IID: {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C}) - Defines 3 method(s):
        - HRESULT RunRecoveryCRXElevated(LPWSTR crx_path, LPWSTR browser_appid, LPWSTR browser_version, LPWSTR session_id, ULONG caller_proc_id, ULONG_PTR* proc_handle) (oVft: 24)
        - HRESULT EncryptData(ProtectionLevel protection_level, BSTR plaintext, BSTR* ciphertext, ULONG* last_error) (oVft: 32)
        - HRESULT DecryptData(BSTR ciphertext, BSTR* plaintext, ULONG* last_error) (oVft: 40)
      Interface in chain: 'IElevatorChromeCanary' (IID: {4F7CE041-28E9-484F-9DD0-61A8CACEFEE4}) - Defines 0 method(s):
        (No methods directly defined in this block for 'IElevatorChromeCanary')
--- End of Verbose Details ---

✅ Analysis complete.
```