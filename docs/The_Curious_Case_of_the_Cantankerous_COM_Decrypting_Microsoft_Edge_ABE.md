# The Curious Case of the Cantankerous COM: Decrypting Microsoft Edge's App-Bound Encryption

**By Alexander 'xaitax' Hagenah**

So, you've heard about Google Chrome's App-Bound Encryption (ABE)? That nifty security feature rolled out around Chrome 127 to make life harder for cookie thieves by tying data decryption to the legitimate browser process. My project, [Chrome App-Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption/), tackles this for Chrome and its Chromium cousin, Brave, using a user-mode DLL injection technique. Life was good. Data was flowing. Then came Microsoft Edge.

What started as a "should be straightforward" port to support Edge turned into a delightful (read: occasionally hair-pulling) expedition into the nuances of COM, type libraries, and browser-specific implementations. This is the tale of that little adventure.

## The Premise: App-Bound Encryption & The `IElevator`

A quick recap for the uninitiated: ABE's core idea is that a special AES-256 key (the `app_bound_key`), used for encrypting cookies, passwords, etc., is itself DPAPI-wrapped and stored in the browser's `Local State` file (prefixed with `APPB`). To unwrap this key, Chrome doesn't just call `CryptUnprotectData` directly. Instead, it invokes a method (commonly `DecryptData`) on a COM object, whose interface is often generically referred to as `IElevator`. This COM service, typically part of the browser's "Elevation Service" infrastructure, performs a crucial **path validation**: it only proceeds if the calling executable resides in the browser's legitimate installation directory.

My tool's approach is conceptually simple: inject a DLL into the target browser process. Running from within the browser's address space, our DLL inherently satisfies the path validation check. It then instantiates the `IElevator` COM object, calls its `DecryptData` method, retrieves the plaintext `app_bound_key`, and subsequently uses this key to decrypt the user's sensitive data (cookies, passwords, payment methods). This strategy worked flawlessly for Google Chrome and Brave Browser, each requiring their specific `IElevator`-equivalent CLSIDs (Class IDs) and IIDs (Interface IDs).

## Enter Edge: The First Sign of Trouble

With Chrome and Brave successfully addressed, extending support to Microsoft Edge *should* have been a relatively simple matter of identifying its corresponding `IElevator` CLSID/IID and incorporating them into the project's configuration. My `chrome_decrypt.dll` utilizes a C++ interface stub for `IElevator`, structured based on common Chromium patterns and the publicly available `elevation_service_idl.idl` from the Chromium source:

```cpp
// Our C++ stub for the base IElevator interface, used for Chrome/Brave
// and as the expected base for Edge's variant.
MIDL_INTERFACE("A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C") // Base IElevator IID from Chromium IDL
IOriginalBaseElevator : public IUnknown
{
public:
  // VTable slot 3 (0 relative to this interface's custom methods)
  virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(
      const WCHAR *crx_path, const WCHAR *browser_appid,
      const WCHAR *browser_version, const WCHAR *session_id,
      DWORD caller_proc_id, ULONG_PTR *proc_handle) = 0; 
  
  // VTable slot 4 (1 relative)
  virtual HRESULT STDMETHODCALLTYPE EncryptData(
      ProtectionLevel protection_level, const BSTR plaintext,
      BSTR *ciphertext, DWORD *last_error) = 0;          
  
  // VTable slot 5 (2 relative)
  virtual HRESULT STDMETHODCALLTYPE DecryptData(
      const BSTR ciphertext, BSTR *plaintext, DWORD *last_error) = 0;          
};
```

Initial attempts to apply this to Edge, however, revealed a peculiar behavior: decryption for Edge *only* succeeded if Brave Browser was also installed on the system, and even then, only if I configured my tool to use *Brave's* CLSID and IID while targeting an Edge process. This was... unexpected, to say the least. It hinted at some complex interplay or fallback mechanism in COM component registration but was clearly not a robust or standalone solution for Edge.

When I attempted to use what seemed to be Edge's *native* identifiers (discovered through registry & [OleView.NET](https://github.com/tyranid/oleviewdotnet) spelunking):
*   **Edge CLSID:** `{1FCBE96C-1697-43AF-9140-2897C7C69767}`
*   **Edge IID (for its `IElevatorEdge` interface):** `{C9C2B807-7731-4F34-81B7-44FF7779522B}` (let's call this `IID_IElevatorEdge`)

...the call to `elevator->DecryptData(...)` within my injected DLL (now running inside `msedge.exe`) would fail with `HRESULT: 0x80070057` (`E_INVALIDARG` - "One or more arguments are invalid."). The `CoCreateInstance` call using these Edge-specific GUIDs would succeed in creating the COM object, but the subsequent `DecryptData` method call was being rejected.

## The COM Detective Work: Unraveling Edge's Secrets

The `E_INVALIDARG` error became the central mystery. If the CLSID correctly activated Edge's `elevation_service.exe`, and the IID correctly identified an interface it provided, why were the arguments to a seemingly standard method invalid? The prime suspect quickly became a potential binary incompatibility between my C++ `IOriginalBaseElevator` interface stub and the actual vtable layout of the interface exposed by Edge's `elevation_service.exe` when queried with its native `IID_IElevatorEdge`.

### Registry and Type Library Safari: The Python Chronicles

To get to the bottom of this, direct introspection of Edge's `elevation_service.exe` type library was necessary. After a few iterations (and some amusing Python script errors involving `comtypes`'s nuances!), a working Python script yielded the crucial insights:

1.  **`IElevatorEdge` (IID `{C9C2...}`):**
    *   The Python script confirmed this IID corresponds to an interface named `IElevatorEdge` within Edge's type library.
    *   Crucially, this `IElevatorEdge` interface itself defines **zero new methods** (`cFuncs: 0`).
    *   It **inherits from** another interface named `IElevator`, which has the IID `{A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C}` (let's call this `IID_BaseElevator`). This IID matched the one used in my C++ `IOriginalBaseElevator` stub and in Chromium's generic `elevation_service_idl.idl`.

    This was promising! It suggested `IElevatorEdge` was merely a vendor-specific "alias" for the standard `IID_BaseElevator` functionality. The logical next step was to instruct `CoCreateInstance` to use Edge's CLSID but request `IID_BaseIElevator`.
    The result: `CoCreateInstance failed: 0x80004002 (E_NOINTERFACE)`.

    This was a setback. Edge's COM object, when activated by its CLSID, refused to directly provide a pointer for `IID_BaseIElevator`, even though its own type library declared that its specific `IElevatorEdge` interface inherited from it.

2.  **The VTable Twist – Inspecting `IElevator` (IID `{A949...}`) *within Edge's Type Library***
    The Python script was then aimed at the `ITypeInfo` for `IID_BaseIElevator` *as defined within Edge's type library*. This revealed:
    *   This interface (named `IElevator`, IID `{A949...}`) indeed defined **3 methods**.
    *   Their names were `RunRecoveryCRXElevated`, `EncryptData`, and `DecryptData`.
    *   The parameters for `DecryptData` (`BSTR ciphertext [in]`, `BSTR* plaintext [out]`, `DWORD* last_error [out]`) perfectly matched my C++ stub.
    *   **The "Aha!" Moment:** This `IElevator` (IID `{A949...}`) itself **inherited from yet another interface named `IElevatorEdgeBase` (IID `{E12B779C-CDB8-4F19-95A0-9CA19B31A8F6}`).**
    *   The vtable byte offsets for `RunRecoveryCRXElevated`, `EncryptData`, and `DecryptData` within *this specific definition* of `IElevator` (IID `{A949...}`) were 48, 56, and 64 bytes respectively (these correspond to vtable slots 6, 7, and 8 after the `IUnknown` methods of its ultimate base, assuming 8-byte pointers).

**Decoding the VTable Anomaly:**

My C++ `IOriginalBaseElevator` stub (associated with IID `{A949...}`) assumes its methods (`RunRecoveryCRXElevated`, `EncryptData`, `DecryptData`) are at vtable slots 3, 4, and 5 (0-indexed, immediately following `IUnknown`'s 3 methods).

However, Edge's type library effectively defines the following inheritance chain for the interface we care about:
`IUnknown` -> `IElevatorEdgeBase` (adds 3 unknown methods, occupying slots 3,4,5) -> `IElevator` (IID `{A949...}`, adds the 3 known methods, now at slots 6,7,8) -> `IElevatorEdge` (IID `{C9C2...}`, adds 0 new methods but is the "public" IID for Edge's elevator).

When my code previously:
1.  Requested `IID_IElevatorEdge` (`{C9C2...}`) from Edge's CLSID.
2.  Stored the resulting pointer in a `ComPtr<IOriginalBaseElevator>`.
3.  Called `DecryptData()`.

It was attempting to call the method at vtable slot 5 (as per `IOriginalBaseElevator`'s definition). But for the `IElevatorEdge` object, slot 5 was one of the unknown methods from `IElevatorEdgeBase`. The actual `DecryptData` was at slot 8. This vtable mismatch was the source of the `E_INVALIDARG` (or `E_NOTIMPL` when testing `RunRecoveryCRXElevated`, which would be slot 3 in my stub vs slot 6 in reality).

### The Fix: Tailoring the C++ Interface Stubs for Edge

With the vtable layout clarified, the solution was to define a new chain of C++ interface stubs specifically for Edge that accurately mirror this discovered structure:

1.  **`IEdgeElevatorBase_Placeholder`**: Inherits `IUnknown`, adds 3 placeholder methods (matching IID `{E12B...}`).
2.  **`IEdgeIntermediateElevator`**: Inherits `IEdgeElevatorBase_Placeholder`, adds `RunRecoveryCRXElevated`, `EncryptData`, `DecryptData`. This interface corresponds to IID `{A949...}` *as defined by Edge's type library's definition of what IElevator (A949...) is*.
3.  **`IEdgeElevatorFinal`**: Inherits `IEdgeIntermediateElevator`, adds no new methods. This interface corresponds to Edge's public `IElevatorEdge` IID `{C9C2...}`.

In `chrome_decrypt.cpp`, the `BrowserConfig` for Edge now uses its CLSID `{1FCB...}` and its specific IID `{C9C2...}`. The COM interaction logic then uses a `Microsoft::WRL::ComPtr<IEdgeElevatorFinal>`:

```cpp
// For Edge in DecryptionThreadWorker:
Microsoft::WRL::ComPtr<IEdgeElevatorFinal> edgeElevator;
hr_create = CoCreateInstance(cfg.clsid, // Edge's CLSID
                           nullptr, 
                           CLSCTX_LOCAL_SERVER, 
                           cfg.iid,   // Edge's specific IID for IEdgeElevatorFinal
                           &edgeElevator);
// ...
if (SUCCEEDED(hr_proxy)) { // Assuming hr_proxy is set after CoSetProxyBlanket on edgeElevator
  hr_decrypt = edgeElevator->DecryptData(bstrEncKey, &bstrPlainKey, &lastComError);
}
```
For Chrome/Brave, the original `IOriginalBaseElevator` stub is used, as their services expose interfaces compatible with methods at vtable slots 3,4,5 when their respective IIDs are queried.

This finally allowed the tool to correctly call `DecryptData` on Edge's `IElevator` service using its native COM identifiers, successfully decrypting the data without relying on Brave's presence.

## Challenges and Lessons Learned

This investigation into Edge's ABE internals was a journey filled with interesting technical hurdles and valuable lessons:

*   **COM Can Be Fickle:** The Component Object Model, while powerful, has layers of subtlety. Type library declarations of interface inheritance don't always guarantee that a COM object will respond to `QueryInterface` for all its declared base IIDs directly via `CoCreateInstance`, nor that the vtable layout for a specific derived IID will be naively callable as its simpler base type without precise C++ stubs that match the true vtable structure for that IID.
*   **Browser-Specific Quirks:** Even within the Chromium family, vendors can and do make subtle changes to internal COM components that require specific handling. Edge's unique vtable structure for its `IElevatorEdge` service, compared to the more direct structure apparently used by Chrome and Brave for their equivalents, exemplifies this.
*   **The Indispensability of Introspection Tools:** When source code for a specific COM server implementation isn't readily available or when observed behavior deviates from expectations based on shared codebases (like Chromium), tools for type library introspection (like the Python `comtypes` library, once the scripting iterations were complete) become absolutely essential for dissecting the true interface contracts.
*   **Methodical Debugging:** Tackling opaque COM errors such as `E_INVALIDARG`, `E_NOINTERFACE`, or `E_NOTIMPL` requires a systematic approach: isolating variables, forming hypotheses, and testing them step-by-step (e.g., verifying CLSIDs, then IIDs, then method call compatibility through vtable analysis).

This deep dive into Microsoft Edge's App-Bound Encryption was a challenging but ultimately rewarding endeavor. Hope you enjoyed reading it!

## Appendix: Python Script for Type Library Introspection

```python
import comtypes
import comtypes.client
import comtypes.typeinfo
import comtypes.automation
import ctypes

IID_EdgeElevatorInterface_str = "{C9C2B807-7731-4F34-81B7-44FF7779522B}"
IID_EdgeElevatorInterface_guid = comtypes.GUID(IID_EdgeElevatorInterface_str)

IID_BaseElevator_str = "{A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C}"
IID_BaseElevator_guid = comtypes.GUID(IID_BaseElevator_str)

# Obviously change this to the correct version 
typelib_path = r"C:\Program Files (x86)\Microsoft\Edge\Application\136.0.3240.64\elevation_service.exe"


def get_vt_name(vt_code):
    mapping = {
        comtypes.automation.VT_EMPTY: "VT_EMPTY", comtypes.automation.VT_NULL: "VT_NULL",
        comtypes.automation.VT_I2: "VT_I2 (short)", comtypes.automation.VT_I4: "VT_I4 (LONG)",
        comtypes.automation.VT_R4: "VT_R4 (float)", comtypes.automation.VT_R8: "VT_R8 (double)",
        comtypes.automation.VT_CY: "VT_CY (CURRENCY)", comtypes.automation.VT_DATE: "VT_DATE",
        comtypes.automation.VT_BSTR: "VT_BSTR", comtypes.automation.VT_DISPATCH: "VT_DISPATCH (IDispatch*)",
        comtypes.automation.VT_ERROR: "VT_ERROR (SCODE)", comtypes.automation.VT_BOOL: "VT_BOOL",
        comtypes.automation.VT_VARIANT: "VT_VARIANT", comtypes.automation.VT_UNKNOWN: "VT_UNKNOWN (IUnknown*)",
        comtypes.automation.VT_DECIMAL: "VT_DECIMAL", comtypes.automation.VT_UI1: "VT_UI1 (BYTE)",
        comtypes.automation.VT_I1: "VT_I1 (char)", comtypes.automation.VT_UI2: "VT_UI2 (USHORT)",
        comtypes.automation.VT_UI4: "VT_UI4 (DWORD/ULONG)", comtypes.automation.VT_I8: "VT_I8 (LONGLONG)",
        comtypes.automation.VT_UI8: "VT_UI8 (ULONGLONG)", comtypes.automation.VT_INT: "VT_INT",
        comtypes.automation.VT_UINT: "VT_UINT", comtypes.automation.VT_VOID: "VT_VOID",
        comtypes.automation.VT_HRESULT: "VT_HRESULT", comtypes.automation.VT_PTR: "VT_PTR",
        comtypes.automation.VT_SAFEARRAY: "VT_SAFEARRAY", comtypes.automation.VT_CARRAY: "VT_CARRAY",
        comtypes.automation.VT_USERDEFINED: "VT_USERDEFINED", comtypes.automation.VT_LPSTR: "VT_LPSTR",
        comtypes.automation.VT_LPWSTR: "VT_LPWSTR", comtypes.automation.VT_RECORD: "VT_RECORD",
        64: "VT_FILETIME", 65: "VT_BLOB", 66: "VT_STREAM", 67: "VT_STORAGE",
        68: "VT_STREAMED_OBJECT", 69: "VT_STORED_OBJECT", 70: "VT_BLOB_OBJECT",
        71: "VT_CF (Clipboard Format)", 72: "VT_CLSID", 73: "VT_VERSIONED_STREAM"
    }
    is_byref = bool(vt_code & comtypes.automation.VT_BYREF)
    is_array = bool(vt_code & comtypes.automation.VT_ARRAY)
    base_vt = vt_code & ~(comtypes.automation.VT_BYREF |
                          comtypes.automation.VT_ARRAY)
    name = mapping.get(base_vt, f"Unknown VARTYPE_Base({base_vt})")
    if is_array:
        name = f"ARRAY_OF({name})"
    if is_byref:
        name = f"POINTER_TO({name})"
    return name


def get_tkind_name(tkind_code):
    mapping = {
        comtypes.typeinfo.TKIND_ENUM: "TKIND_ENUM",
        comtypes.typeinfo.TKIND_RECORD: "TKIND_RECORD (struct)",
        comtypes.typeinfo.TKIND_MODULE: "TKIND_MODULE",
        comtypes.typeinfo.TKIND_INTERFACE: "TKIND_INTERFACE (pure vtable)",
        comtypes.typeinfo.TKIND_DISPATCH: "TKIND_DISPATCH (IDispatch based)",
        comtypes.typeinfo.TKIND_COCLASS: "TKIND_COCLASS (instantiable class)",
        comtypes.typeinfo.TKIND_ALIAS: "TKIND_ALIAS (typedef)",
        comtypes.typeinfo.TKIND_UNION: "TKIND_UNION",
        comtypes.typeinfo.TKIND_MAX: "TKIND_MAX (not a kind)"
    }
    return mapping.get(tkind_code, f"Unknown TKIND ({tkind_code})")


def get_param_flags_string(flags):
    flag_map = {
        comtypes.typeinfo.PARAMFLAG_FIN: "in",
        comtypes.typeinfo.PARAMFLAG_FOUT: "out",
        comtypes.typeinfo.PARAMFLAG_FLCID: "lcid",
        comtypes.typeinfo.PARAMFLAG_FRETVAL: "retval",
        comtypes.typeinfo.PARAMFLAG_FOPT: "optional",
        comtypes.typeinfo.PARAMFLAG_FHASDEFAULT: "hasdefault",
        comtypes.typeinfo.PARAMFLAG_FHASCUSTDATA: "hascustomdata"
    }
    active_flags = [name for flag_val,
                    name in flag_map.items() if flags & flag_val]
    return ", ".join(active_flags) if active_flags else f"none (raw: {flags})"


def get_type_name_recursive(type_desc, containing_type_info):
    vt = type_desc.vt
    if vt & comtypes.automation.VT_BYREF:
        base_tdesc = comtypes.typeinfo.TYPEDESC()
        base_tdesc.vt = vt & ~comtypes.automation.VT_BYREF
        if base_tdesc.vt == comtypes.automation.VT_PTR:
            base_tdesc.lptdesc = type_desc.lptdesc
        elif base_tdesc.vt == comtypes.automation.VT_USERDEFINED:
            base_tdesc.hreftype = type_desc.hreftype
        base_name = get_type_name_recursive(base_tdesc, containing_type_info)
        return f"POINTER_TO({base_name})"

    if vt == comtypes.automation.VT_PTR:
        if type_desc.lptdesc:
            pointed_tdesc = type_desc.lptdesc.contents
            pointed_name = get_type_name_recursive(
                pointed_tdesc, containing_type_info)
            return f"POINTER_TO({pointed_name})"
        else:
            return "POINTER_TO(void)"
    elif vt == comtypes.automation.VT_USERDEFINED:
        try:
            ref_type_info = containing_type_info.GetRefTypeInfo(
                type_desc.hreftype)
            udt_name, _, _, _ = ref_type_info.GetDocumentation(-1)
            return f"{udt_name}"
        except Exception:
            return f"USERDEFINED(hreftype={type_desc.hreftype})"
    elif vt == comtypes.automation.VT_SAFEARRAY:
        if type_desc.lptdesc:
            element_tdesc = type_desc.lptdesc.contents
            element_name = get_type_name_recursive(
                element_tdesc, containing_type_info)
            return f"SAFEARRAY_OF({element_name})"
        else:
            return "SAFEARRAY_OF(UNKNOWN)"
    else:
        return get_vt_name(vt)


def print_interface_details(type_info_interface_to_print, interface_name_override=None):
    attr = type_info_interface_to_print.GetTypeAttr()
    try:
        actual_iface_name, iface_doc_string, _, _ = type_info_interface_to_print.GetDocumentation(
            -1)
        guid_str = str(attr.guid)
        print(
            f"\n--- Interface: {interface_name_override or actual_iface_name} ---")
        print(f"  TLB Name: {actual_iface_name}")
        if iface_doc_string:
            print(f"  Doc: '{iface_doc_string}'")
        print(f"  IID: {guid_str}")
        print(
            f"  Type Kind: {attr.typekind} ({get_tkind_name(attr.typekind)})")
        print(f"  Methods in this definition (cFuncs): {attr.cFuncs}")
        print(
            f"  Inherited/Implemented Interfaces (cImplTypes): {attr.cImplTypes}")

        for i in range(attr.cImplTypes):
            hRefType = type_info_interface_to_print.GetRefTypeOfImplType(i)
            ref_type_info = type_info_interface_to_print.GetRefTypeInfo(
                hRefType)
            ref_attr = ref_type_info.GetTypeAttr()
            try:
                base_iface_name, _, _, _ = ref_type_info.GetDocumentation(-1)
                print(
                    f"    Inherits [{i}]: {base_iface_name} (IID: {str(ref_attr.guid)})")
            finally:
                pass

        if attr.cFuncs > 0:
            print("\n  Methods (defined in this interface):")
        for i in range(attr.cFuncs):
            func_desc = type_info_interface_to_print.GetFuncDesc(i)
            try:
                names = type_info_interface_to_print.GetNames(
                    func_desc.memid, func_desc.cParams + 1)
                func_name = names[0] if names else "(Unknown Name)"
                vtable_slot_index = func_desc.oVft // ctypes.sizeof(
                    ctypes.c_void_p)

                print(f"    [{i}] Method: {func_name}")
                print(
                    f"      VTable Slot (absolute in COM object): {vtable_slot_index} (Offset: {func_desc.oVft} bytes from IFace start)")
                print(
                    f"      Member ID: {func_desc.memid}, Invoke Kind: {func_desc.invkind}, CallConv: {func_desc.callconv}, FuncFlags: {func_desc.wFuncFlags}")

                ret_type_name = get_type_name_recursive(
                    func_desc.elemdescFunc.tdesc, type_info_interface_to_print)
                print(f"      Return Type: {ret_type_name}")

                if func_desc.cParams > 0:
                    print(f"      Parameters ({func_desc.cParams}):")
                for j in range(func_desc.cParams):
                    param_name = names[j +
                                       1] if len(names) > j + 1 else f"param{j}"

                    elem_desc_param = func_desc.lprgelemdescParam[j]

                    param_flags_value = elem_desc_param._.paramdesc.wParamFlags

                    param_flags_str = get_param_flags_string(param_flags_value)
                    param_type_desc = elem_desc_param.tdesc
                    param_type_name = get_type_name_recursive(
                        param_type_desc, type_info_interface_to_print)

                    print(
                        f"        [{j}] '{param_name}': {param_type_name} (Flags: {param_flags_str})")
            finally:
                pass
    finally:
        pass


try:
    comtypes.CoInitialize()
    print(f"Attempting to load type library from: {typelib_path}")
    type_lib = comtypes.typeinfo.LoadTypeLibEx(typelib_path)
    lib_name, lib_doc, _, _ = type_lib.GetDocumentation(-1)
    print(f"Successfully loaded type library: {lib_name} (Doc: '{lib_doc}')")

    print("\nInspecting IElevatorEdge (IID: {C9C2...}) directly:")
    type_info_edge_elevator = type_lib.GetTypeInfoOfGuid(
        IID_EdgeElevatorInterface_guid)
    print_interface_details(type_info_edge_elevator, "IElevatorEdge")

    print(
        "\nInspecting base IElevator (IID: {A949...}) as defined in Edge's TypeLib:")
    try:
        type_info_base_elevator = type_lib.GetTypeInfoOfGuid(
            IID_BaseElevator_guid)
        print_interface_details(type_info_base_elevator, "BaseIElevator")
    except comtypes.COMError as e:
        if e.hresult == comtypes.hresult.TYPE_E_ELEMENTNOTFOUND:
            print(
                f"  Interface with IID {IID_BaseElevator_guid} not found directly in this TypeLib.")
        else:
            print(
                f"  COMError finding base IElevator: HRESULT {hex(e.hresult)}, Text: {e.text if e.text else ''}")

except OSError as e:
    print(f"OSError trying to load type library: {e}")
except comtypes.COMError as e:
    print(
        f"A COM Error occurred: HRESULT {hex(e.hresult)}, Text: {e.text if e.text else ''}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")
    import traceback
    traceback.print_exc()
finally:
    comtypes.CoUninitialize()
```

Resulting in:

```powershell
PS C:\Users\ah\Documents\GitHub\Chrome-App-Bound-Encryption-Decryption> python .\edge_com_abe.py
Attempting to load type library from: C:\Program Files (x86)\Microsoft\Edge\Application\136.0.3240.64\elevation_service.exe
Successfully loaded type library: ElevatorLib (Doc: 'Elevator 1.0 Type Library')

Inspecting IElevatorEdge (IID: {C9C2...}) directly:

--- Interface: IElevatorEdge ---
  TLB Name: IElevatorEdge
  Doc: 'IElevatorEdge Interface'
  IID: {C9C2B807-7731-4F34-81B7-44FF7779522B}
  Type Kind: 3 (TKIND_INTERFACE (pure vtable))
  Methods in this definition (cFuncs): 0
  Inherited/Implemented Interfaces (cImplTypes): 1
    Inherits [0]: IElevator (IID: {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C})

Inspecting base IElevator (IID: {A949...}) as defined in Edge's TypeLib:

--- Interface: BaseIElevator ---
  TLB Name: IElevator
  Doc: 'IElevator Interface'
  IID: {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C}
  Type Kind: 3 (TKIND_INTERFACE (pure vtable))
  Methods in this definition (cFuncs): 3
  Inherited/Implemented Interfaces (cImplTypes): 1
    Inherits [0]: IElevatorEdgeBase (IID: {E12B779C-CDB8-4F19-95A0-9CA19B31A8F6})

  Methods (defined in this interface):
    [0] Method: RunRecoveryCRXElevated
      VTable Slot (absolute in COM object): 6 (Offset: 48 bytes from IFace start)
      Member ID: 1610743808, Invoke Kind: 1, CallConv: 4, FuncFlags: 0
      Return Type: VT_HRESULT
      Parameters (6):
        [0] 'crx_path': VT_LPWSTR (Flags: in)
        [1] 'browser_appid': VT_LPWSTR (Flags: in)
        [2] 'browser_version': VT_LPWSTR (Flags: in)
        [3] 'session_id': VT_LPWSTR (Flags: in)
        [4] 'caller_proc_id': VT_UI4 (DWORD/ULONG) (Flags: in)
        [5] 'proc_handle': POINTER_TO(ULONG_PTR) (Flags: out)
    [1] Method: EncryptData
      VTable Slot (absolute in COM object): 7 (Offset: 56 bytes from IFace start)
      Member ID: 1610743809, Invoke Kind: 1, CallConv: 4, FuncFlags: 0
      Return Type: VT_HRESULT
      Parameters (4):
        [0] 'protection_level': ProtectionLevel (Flags: in)
        [1] 'plaintext': VT_BSTR (Flags: in)
        [2] 'ciphertext': POINTER_TO(VT_BSTR) (Flags: out)
        [3] 'last_error': POINTER_TO(VT_UI4 (DWORD/ULONG)) (Flags: out)
    [2] Method: DecryptData
      VTable Slot (absolute in COM object): 8 (Offset: 64 bytes from IFace start)
      Member ID: 1610743810, Invoke Kind: 1, CallConv: 4, FuncFlags: 0
      Return Type: VT_HRESULT
      Parameters (3):
        [0] 'ciphertext': VT_BSTR (Flags: in)
        [1] 'plaintext': POINTER_TO(VT_BSTR) (Flags: out)
        [2] 'last_error': POINTER_TO(VT_UI4 (DWORD/ULONG)) (Flags: out)
```