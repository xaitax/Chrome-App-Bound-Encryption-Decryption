#!/usr/bin/env python3

import argparse
import ctypes
import os
import sys
import comtypes
import comtypes.typeinfo
import comtypes.automation
import winreg
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

try:
    import pefile
except ImportError:
    pefile = None

EMOJI_SUCCESS = "✅"
EMOJI_FAILURE = "❌"
EMOJI_INFO = "ℹ️"
EMOJI_SEARCH = "🔍"
EMOJI_GEAR = "⚙️"
EMOJI_FILE = "📄"
EMOJI_LIGHTBULB = "💡"
EMOJI_WARNING = "⚠️"


@dataclass
class MethodDetail:
    name: str
    ret_type: str
    params: List[str]
    ovft: int
    memid: int
    index_in_interface: int


@dataclass
class InterfaceInfo:
    name: str
    iid: str
    type_info_obj: Any
    type_attr_obj: Any
    methods_defined: List[MethodDetail] = field(default_factory=list)
    base_interface_name: Optional[str] = None


@dataclass
class AnalyzedMethod:
    name: str
    ovft: int
    memid: int
    defining_interface_name: str
    defining_interface_iid: str


@dataclass
class AbeCandidate:
    clsid: str
    interface_name: str
    interface_iid: str
    methods: Dict[str, AnalyzedMethod]
    inheritance_chain_info: List[InterfaceInfo]


def get_vt_name(vt_code, type_info_context=None, hreftype_or_tdesc_for_ptr=None):
    mapping = {
        comtypes.automation.VT_EMPTY: "void", comtypes.automation.VT_NULL: "void*",
        comtypes.automation.VT_I2: "SHORT", comtypes.automation.VT_I4: "LONG",
        comtypes.automation.VT_R4: "FLOAT", comtypes.automation.VT_R8: "DOUBLE",
        comtypes.automation.VT_CY: "CURRENCY", comtypes.automation.VT_DATE: "DATE",
        comtypes.automation.VT_BSTR: "BSTR", comtypes.automation.VT_DISPATCH: "IDispatch*",
        comtypes.automation.VT_ERROR: "SCODE", comtypes.automation.VT_BOOL: "VARIANT_BOOL",
        comtypes.automation.VT_VARIANT: "VARIANT", comtypes.automation.VT_UNKNOWN: "IUnknown*",
        comtypes.automation.VT_DECIMAL: "DECIMAL", comtypes.automation.VT_UI1: "BYTE",
        comtypes.automation.VT_I1: "CHAR", comtypes.automation.VT_UI2: "USHORT",
        comtypes.automation.VT_UI4: "ULONG", comtypes.automation.VT_I8: "hyper",
        comtypes.automation.VT_UI8: "uhyper",
        comtypes.automation.VT_INT: "INT", comtypes.automation.VT_UINT: "UINT",
        comtypes.automation.VT_VOID: "void", comtypes.automation.VT_HRESULT: "HRESULT",
        comtypes.automation.VT_PTR: "void*",
        comtypes.automation.VT_SAFEARRAY: "SAFEARRAY",
        comtypes.automation.VT_CARRAY: "CARRAY",
        comtypes.automation.VT_USERDEFINED: "USER_DEFINED",
        comtypes.automation.VT_LPSTR: "LPSTR", comtypes.automation.VT_LPWSTR: "LPWSTR",
        64: "FILETIME", 65: "BLOB",
    }
    is_byref = bool(vt_code & comtypes.automation.VT_BYREF)
    is_array = bool(vt_code & comtypes.automation.VT_ARRAY)
    is_vector = bool(vt_code & comtypes.automation.VT_VECTOR)
    base_vt = vt_code & ~(comtypes.automation.VT_BYREF |
                          comtypes.automation.VT_ARRAY | comtypes.automation.VT_VECTOR)
    name = mapping.get(base_vt, f"Unknown_VT_0x{base_vt:X}")

    if base_vt == comtypes.automation.VT_USERDEFINED and type_info_context and isinstance(hreftype_or_tdesc_for_ptr, int):
        ref_type_info_local = ref_attr_local = None
        try:
            ref_type_info_local = type_info_context.GetRefTypeInfo(
                hreftype_or_tdesc_for_ptr)
            udt_name, _, _, _ = ref_type_info_local.GetDocumentation(-1)
            ref_attr_local = ref_type_info_local.GetTypeAttr()
            name = udt_name
        except comtypes.COMError:
            name = f"UserDefined_hreftype_{hreftype_or_tdesc_for_ptr}"
        finally:
            if ref_attr_local and ref_type_info_local:
                ref_type_info_local.ReleaseTypeAttr(ref_attr_local)
    elif base_vt == comtypes.automation.VT_PTR and type_info_context and hasattr(hreftype_or_tdesc_for_ptr, 'lptdesc') and hreftype_or_tdesc_for_ptr.lptdesc:
        pointed_tdesc = hreftype_or_tdesc_for_ptr.lptdesc.contents
        next_arg_for_recursive_call = pointed_tdesc.hreftype if pointed_tdesc.vt == comtypes.automation.VT_USERDEFINED else pointed_tdesc
        pointed_name = get_vt_name(
            pointed_tdesc.vt, type_info_context, next_arg_for_recursive_call)
        name = f"{pointed_name}*"

    if is_array:
        name = f"SAFEARRAY({name})"
    if is_vector:
        name = f"VECTOR_OF({name})"
    if is_byref and not name.endswith("*"):
        name = f"{name}*"
    return name


def get_param_flags_string(flags):
    flag_map = {
        comtypes.typeinfo.PARAMFLAG_FIN: "in",
        comtypes.typeinfo.PARAMFLAG_FOUT: "out",
        comtypes.typeinfo.PARAMFLAG_FLCID: "lcid",
        comtypes.typeinfo.PARAMFLAG_FRETVAL: "retval",
        comtypes.typeinfo.PARAMFLAG_FOPT: "optional",
        comtypes.typeinfo.PARAMFLAG_FHASDEFAULT: "hasdefault",
    }
    active_flags = [name for flag_val,
                    name in flag_map.items() if flags & flag_val]
    return ", ".join(active_flags) if active_flags else f"none (raw: 0x{flags:X})"


def get_typekind_name(tkind_code):
    mapping = {
        comtypes.typeinfo.TKIND_ENUM: "TKIND_ENUM", comtypes.typeinfo.TKIND_RECORD: "TKIND_RECORD",
        comtypes.typeinfo.TKIND_MODULE: "TKIND_MODULE", comtypes.typeinfo.TKIND_INTERFACE: "TKIND_INTERFACE",
        comtypes.typeinfo.TKIND_DISPATCH: "TKIND_DISPATCH", comtypes.typeinfo.TKIND_COCLASS: "TKIND_COCLASS",
        comtypes.typeinfo.TKIND_ALIAS: "TKIND_ALIAS", comtypes.typeinfo.TKIND_UNION: "TKIND_UNION",
        comtypes.typeinfo.TKIND_MAX: "TKIND_MAX (Not a kind)"
    }
    return mapping.get(tkind_code, f"Unknown TKIND (0x{tkind_code:X})")


def format_guid_for_cpp(guid_str_or_obj):
    default_zero_guid_cpp = "{0x00000000,0x0000,0x0000,{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}}"
    if not guid_str_or_obj:
        return default_zero_guid_cpp

    g_obj = None
    if isinstance(guid_str_or_obj, str):
        guid_str_lower = guid_str_or_obj.lower()
        if guid_str_lower in ["unknown", "unknown (not discoverable from tlb)",
                              "n/a (direct interface scan)",
                              "unknown (not explicitly found for this interface)",
                              "unknown (not explicitly found for this coclass)"]:
            return default_zero_guid_cpp
        try:
            g_obj = comtypes.GUID(guid_str_or_obj)
        except ValueError:
            return f"{{ /* Error: Invalid GUID string format: '{guid_str_or_obj}' */ }}"
        except Exception as e:
            return f"{{ /* Error parsing GUID string '{guid_str_or_obj}': {e} */ }}"
    elif isinstance(guid_str_or_obj, comtypes.GUID):
        g_obj = guid_str_or_obj
    else:
        return f"{{ /* Error: Invalid input type for GUID formatting. Expected str or comtypes.GUID. */ }}"

    if not g_obj:
        return default_zero_guid_cpp

    data4_raw_elements = g_obj.Data4
    data4_unsigned_bytes = []
    try:
        if len(data4_raw_elements) != 8:
            return f"{{ /* Error: Data4 for GUID object '{str(g_obj)}' does not have length 8 (Len: {len(data4_raw_elements)}) */ }}"
        for i in range(8):
            data4_unsigned_bytes.append(data4_raw_elements[i] & 0xFF)
    except (TypeError, IndexError):
        return f"{{ /* Error: Data4 for GUID object '{str(g_obj)}' is not a proper 8-byte sequence (Type: {type(data4_raw_elements)}) */ }}"

    return (f"{{0x{g_obj.Data1:08X},0x{g_obj.Data2:04X},0x{g_obj.Data3:04X},"
            f"{{0x{data4_unsigned_bytes[0]:02X},0x{data4_unsigned_bytes[1]:02X},0x{data4_unsigned_bytes[2]:02X},0x{data4_unsigned_bytes[3]:02X},"
            f"0x{data4_unsigned_bytes[4]:02X},0x{data4_unsigned_bytes[5]:02X},0x{data4_unsigned_bytes[6]:02X},0x{data4_unsigned_bytes[7]:02X}}}}}")


class ComInterfaceAnalyzer:
    def __init__(self, executable_path=None, verbose=False, target_method_names=None,
                 expected_decrypt_param_count=3, expected_encrypt_param_count=4):
        self.executable_path = executable_path
        self.args_verbose = verbose
        self.type_lib: Optional[comtypes.POINTER(
            comtypes.typeinfo.ITypeLib)] = None  # type: ignore
        self.results: List[AbeCandidate] = []
        self.discovered_clsid: Optional[str] = None
        self.browser_key: Optional[str] = None
        self.target_method_names = target_method_names if target_method_names else [
            "DecryptData", "EncryptData"]
        self.expected_param_counts = {
            "DecryptData": expected_decrypt_param_count, "EncryptData": expected_encrypt_param_count}

    def _log(self, message: str, indent: int = 0, verbose_only: bool = False, status_emoji: Optional[str] = None):
        if verbose_only and not self.args_verbose:
            return
        prefix = f"{status_emoji} " if status_emoji else ""
        print(f"{'  ' * indent}{prefix}{message}")

    def load_type_library(self) -> bool:
        if not self.executable_path:
            self._log("Executable path not set for TypeLib loading.",
                      status_emoji=EMOJI_FAILURE)
            return False
        self._log(
            f"{EMOJI_SEARCH} Attempting to load type library from: {self.executable_path}")
        try:
            self.type_lib = comtypes.typeinfo.LoadTypeLibEx(
                self.executable_path)
            lib_name, _, _, _ = self.type_lib.GetDocumentation(-1)
            self._log(
                f"{EMOJI_SUCCESS} Successfully loaded type library: '{lib_name}'")
            return True
        except comtypes.COMError as e:
            self._log(f"{EMOJI_FAILURE} COMError loading type library: {e}", 1)
        except Exception as e_gen:
            self._log(
                f"{EMOJI_FAILURE} Generic error loading type library: {e_gen}", 1)
        return False

    def find_details_from_registry_by_service_name(self, browser_name_key: str) -> bool:
        self.browser_key = browser_name_key.lower()
        self._log(
            f"{EMOJI_SEARCH} Scanning registry for service details of '{self.browser_key}'...")
        service_map = {"chrome": "GoogleChromeElevationService",
                       "edge": "MicrosoftEdgeElevationService", "brave": "BraveElevationService"}
        service_name = service_map.get(self.browser_key, browser_name_key)
        self._log(
            f"Targeting service name: '{service_name}'", indent=1, verbose_only=True)

        exe_path_found = None
        clsids_found = []
        try:
            service_reg_path = rf"SYSTEM\CurrentControlSet\Services\{service_name}"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, service_reg_path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                image_path_raw = winreg.QueryValueEx(key, "ImagePath")[0]
                exe_path_found = os.path.normpath(os.path.expandvars(image_path_raw.split(
                    '"')[1] if image_path_raw.startswith('"') else image_path_raw.split(' ')[0]))
                self._log(
                    f"{EMOJI_INFO} Service ImagePath: {exe_path_found}", indent=1)
                self.executable_path = exe_path_found
        except FileNotFoundError:
            self._log(
                f"{EMOJI_WARNING} Service registry key not found: '{service_reg_path}'", indent=1)
        except Exception as e:
            self._log(
                f"{EMOJI_FAILURE} Error reading service ImagePath for '{service_name}': {e}", indent=1)
            return False

        self._log(f"{EMOJI_SEARCH} Searching for CLSIDs linked to LocalService '{service_name}'...",
                  indent=1, verbose_only=True)
        for hkey_root, root_name in [(winreg.HKEY_LOCAL_MACHINE, "HKLM"), (winreg.HKEY_CURRENT_USER, "HKCU")]:
            for appid_path_segment in [r"SOFTWARE\Classes\AppID", r"SOFTWARE\WOW6432Node\Classes\AppID"]:
                try:
                    with winreg.OpenKey(hkey_root, appid_path_segment, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as appid_root_key:
                        for i in range(winreg.QueryInfoKey(appid_root_key)[0]):
                            try:
                                appid_name = winreg.EnumKey(appid_root_key, i)
                                with winreg.OpenKey(appid_root_key, appid_name, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as appid_entry_key:
                                    try:
                                        if winreg.QueryValueEx(appid_entry_key, "LocalService")[0].lower() == service_name.lower():
                                            if appid_name.startswith("{") and appid_name not in clsids_found:
                                                clsids_found.append(appid_name)
                                                self._log(
                                                    f"{EMOJI_INFO} Found matching CLSID '{appid_name}' via AppID '{appid_path_segment}'", indent=2, verbose_only=True)
                                    except FileNotFoundError:
                                        pass
                                    except Exception as e_val:
                                        self._log(
                                            f"{EMOJI_WARNING} Error reading LocalService for AppID '{appid_name}': {e_val}", indent=3, verbose_only=True)
                            except OSError:
                                break
                except FileNotFoundError:
                    self._log(
                        f"{EMOJI_INFO} Registry path not found: {root_name}\\{appid_path_segment}", indent=2, verbose_only=True)

        if clsids_found:
            self.discovered_clsid = clsids_found[0]
            self._log(
                f"{EMOJI_SUCCESS} Discovered CLSID: {self.discovered_clsid}", indent=1)
            if len(clsids_found) > 1:
                self._log(
                    f"{EMOJI_WARNING} Multiple CLSIDs found ({', '.join(clsids_found)}), using the first one.", indent=2)
        else:
            self._log(
                f"{EMOJI_WARNING} Could not discover CLSID for service '{service_name}' via AppID LocalService linkage.", indent=1)
            self._log(f"{EMOJI_SEARCH} Attempting fallback CLSID discovery via HKCR\\CLSID for executable '{self.executable_path}'...",
                      indent=2, verbose_only=True)
            try:
                with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, "CLSID", 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as clsid_root:
                    for i in range(winreg.QueryInfoKey(clsid_root)[0]):
                        try:
                            clsid_val = winreg.EnumKey(clsid_root, i)
                            with winreg.OpenKey(clsid_root, clsid_val + r"\LocalServer32", 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as server_key:
                                server_path_raw, _ = winreg.QueryValueEx(
                                    server_key, None)
                                server_exe = os.path.normpath(server_path_raw.split(
                                    '"')[1] if server_path_raw.startswith('"') else server_path_raw.split(' ')[0])
                                if server_exe.lower() == self.executable_path.lower():
                                    self.discovered_clsid = clsid_val
                                    self._log(
                                        f"{EMOJI_SUCCESS} Discovered CLSID '{clsid_val}' via HKCR\\CLSID\\...\\LocalServer32 match.", indent=1)
                                    break
                        except FileNotFoundError:
                            pass
                        except OSError:
                            break
                    if not self.discovered_clsid:
                        self._log(
                            f"{EMOJI_WARNING} HKCR CLSID scan did not yield a CLSID for the executable.", indent=2, verbose_only=True)
            except FileNotFoundError:
                self._log(
                    f"{EMOJI_INFO} HKCR\\CLSID not found (unusual).", indent=2, verbose_only=True)

        if not self.executable_path:
            self._log(
                f"{EMOJI_FAILURE} Failed to determine executable path for '{browser_name_key}'. Cannot proceed.", indent=1)
            return False
        return True

    def _original_check_method_signature(self, method_name, func_desc, type_info_context):
        try:
            if method_name == "DecryptData":
                if func_desc.cParams != 3 or func_desc.elemdescFunc.tdesc.vt != comtypes.automation.VT_HRESULT:
                    return False
                p0, p1, p2 = func_desc.lprgelemdescParam[
                    0], func_desc.lprgelemdescParam[1], func_desc.lprgelemdescParam[2]
                if not (p0.tdesc.vt == comtypes.automation.VT_BSTR and (p0._.paramdesc.wParamFlags & comtypes.typeinfo.PARAMFLAG_FIN)):
                    return False
                if not (((p1.tdesc.vt == (comtypes.automation.VT_BSTR | comtypes.automation.VT_BYREF)) or
                         (p1.tdesc.vt == comtypes.automation.VT_PTR and hasattr(p1.tdesc, 'lptdesc') and p1.tdesc.lptdesc and p1.tdesc.lptdesc.contents.vt == comtypes.automation.VT_BSTR)) and
                        (p1._.paramdesc.wParamFlags & comtypes.typeinfo.PARAMFLAG_FOUT)):
                    return False
                if not (((p2.tdesc.vt == (comtypes.automation.VT_UI4 | comtypes.automation.VT_BYREF)) or
                         (p2.tdesc.vt == comtypes.automation.VT_PTR and hasattr(p2.tdesc, 'lptdesc') and p2.tdesc.lptdesc and p2.tdesc.lptdesc.contents.vt == comtypes.automation.VT_UI4)) and
                        (p2._.paramdesc.wParamFlags & comtypes.typeinfo.PARAMFLAG_FOUT)):
                    return False
                return True
            elif method_name == "EncryptData":
                if func_desc.cParams != 4 or func_desc.elemdescFunc.tdesc.vt != comtypes.automation.VT_HRESULT:
                    return False
                p0, p1, p2, p3 = func_desc.lprgelemdescParam[0], func_desc.lprgelemdescParam[
                    1], func_desc.lprgelemdescParam[2], func_desc.lprgelemdescParam[3]
                is_p0_ok = (p0.tdesc.vt == comtypes.automation.VT_USERDEFINED) or (
                    p0.tdesc.vt == comtypes.automation.VT_I4) or (p0.tdesc.vt == comtypes.automation.VT_INT)
                if not (is_p0_ok and (p0._.paramdesc.wParamFlags & comtypes.typeinfo.PARAMFLAG_FIN)):
                    return False
                if not (p1.tdesc.vt == comtypes.automation.VT_BSTR and (p1._.paramdesc.wParamFlags & comtypes.typeinfo.PARAMFLAG_FIN)):
                    return False
                if not (((p2.tdesc.vt == (comtypes.automation.VT_BSTR | comtypes.automation.VT_BYREF)) or
                         (p2.tdesc.vt == comtypes.automation.VT_PTR and hasattr(p2.tdesc, 'lptdesc') and p2.tdesc.lptdesc and p2.tdesc.lptdesc.contents.vt == comtypes.automation.VT_BSTR)) and
                        (p2._.paramdesc.wParamFlags & comtypes.typeinfo.PARAMFLAG_FOUT)):
                    return False
                if not (((p3.tdesc.vt == (comtypes.automation.VT_UI4 | comtypes.automation.VT_BYREF)) or
                         (p3.tdesc.vt == comtypes.automation.VT_PTR and hasattr(p3.tdesc, 'lptdesc') and p3.tdesc.lptdesc and p3.tdesc.lptdesc.contents.vt == comtypes.automation.VT_UI4)) and
                        (p3._.paramdesc.wParamFlags & comtypes.typeinfo.PARAMFLAG_FOUT)):
                    return False
                return True
        except Exception as e:
            self._log(f"{EMOJI_WARNING} Exception during original signature check for '{method_name}': {e}",
                      indent=5, verbose_only=True)
            return False
        return False

    def check_method_signature(self, method_name: str, func_desc, type_info_context) -> bool:
        self._log(
            f"Performing signature check for '{method_name}'...", indent=5, verbose_only=True)
        self._log(
            f"Expected param count: {self.expected_param_counts.get(method_name, 'N/A')}, Actual: {func_desc.cParams}", indent=6, verbose_only=True)
        self._log(
            f"Return type VT: {func_desc.elemdescFunc.tdesc.vt} ({get_vt_name(func_desc.elemdescFunc.tdesc.vt, type_info_context, func_desc.elemdescFunc.tdesc)})", indent=6, verbose_only=True)
        for i in range(func_desc.cParams):
            p_tdesc = func_desc.lprgelemdescParam[i].tdesc
            p_flags = func_desc.lprgelemdescParam[i]._.paramdesc.wParamFlags
            arg_for_recursive_call = p_tdesc.hreftype if p_tdesc.vt == comtypes.automation.VT_USERDEFINED else p_tdesc
            param_type_name_for_log = get_vt_name(
                p_tdesc.vt, type_info_context, arg_for_recursive_call)
            self._log(
                f"Param {i}: Type='{param_type_name_for_log}', Raw VT=0x{p_tdesc.vt:X}, Flags=0x{p_flags:X} ({get_param_flags_string(p_flags)})", indent=6, verbose_only=True)

        check_result = self._original_check_method_signature(
            method_name, func_desc, type_info_context)
        self._log(f"Signature check result for '{method_name}': {check_result}", indent=5,
                  verbose_only=True, status_emoji=EMOJI_SUCCESS if check_result else EMOJI_FAILURE)
        return check_result

    def get_inheritance_chain(self, interface_type_info_to_trace: comtypes.typeinfo.ITypeInfo) -> List[InterfaceInfo]:
        chain: List[InterfaceInfo] = []
        current_ti_obj: Optional[comtypes.typeinfo.ITypeInfo] = interface_type_info_to_trace
        visited_iids = set()

        initial_iface_name_for_log = "UnknownInterface"
        try:
            initial_iface_name_for_log, _, _, _ = interface_type_info_to_trace.GetDocumentation(
                -1)
        except Exception:
            pass
        self._log(
            f"Tracing inheritance for '{initial_iface_name_for_log}'", indent=3, verbose_only=True)

        while current_ti_obj:
            current_attr_ptr = None
            try:
                current_attr_ptr = current_ti_obj.GetTypeAttr()
                if not current_attr_ptr:
                    self._log(
                        f"{EMOJI_WARNING} GetTypeAttr returned NULL for an ITypeInfo in chain. Stopping trace here.", indent=4, verbose_only=True)
                    break

                current_attrs = current_attr_ptr

                iid_str = str(current_attrs.guid)
                if iid_str in visited_iids:
                    self._log(
                        f"{EMOJI_WARNING} Loop detected in inheritance chain at IID: {iid_str}. Stopping trace.", indent=4, verbose_only=True)
                    break
                visited_iids.add(iid_str)

                name, _, _, _ = current_ti_obj.GetDocumentation(-1)
                self._log(
                    f"Processing interface in chain: '{name}' (IID: {iid_str}), cFuncs: {current_attrs.cFuncs}", indent=4, verbose_only=True)

                methods_defined = []
                for i_method_idx in range(current_attrs.cFuncs):
                    func_desc_ptr = None
                    try:
                        func_desc_ptr = current_ti_obj.GetFuncDesc(
                            i_method_idx)
                        if not func_desc_ptr:
                            self._log(
                                f"{EMOJI_WARNING} GetFuncDesc returned NULL for method index {i_method_idx} in '{name}'. Skipping method.", indent=5, verbose_only=True)
                            continue

                        current_func_attrs = func_desc_ptr

                        m_names = current_ti_obj.GetNames(
                            current_func_attrs.memid, current_func_attrs.cParams + 1)
                        m_name = m_names[
                            0] if m_names else f"UnknownMethod_memid_{current_func_attrs.memid}"

                        params_list = []
                        if current_func_attrs.cParams > 0 and current_func_attrs.lprgelemdescParam:
                            for j in range(current_func_attrs.cParams):
                                try:
                                    param_elem_desc = current_func_attrs.lprgelemdescParam[j]
                                    param_tdesc = param_elem_desc.tdesc
                                    p_name = m_names[j+1] if len(
                                        m_names) > (j+1) else f"param{j}"
                                    p_type_arg = param_tdesc.hreftype if param_tdesc.vt == comtypes.automation.VT_USERDEFINED else param_tdesc
                                    params_list.append(
                                        f"{get_vt_name(param_tdesc.vt, current_ti_obj, p_type_arg)} {p_name}")
                                except Exception as e_param_detail:
                                    self._log(
                                        f"{EMOJI_WARNING} Err param detail for '{m_name}', idx {j}: {e_param_detail}", indent=6, verbose_only=True)
                                    params_list.append(
                                        f"UNKNOWN_PARAM_TYPE param{j}")
                        elif current_func_attrs.cParams > 0:
                            self._log(
                                f"{EMOJI_WARNING} Method '{m_name}' in '{name}' cParams={current_func_attrs.cParams} but lprgelemdescParam is NULL.", indent=5, verbose_only=True)
                            for _ in range(current_func_attrs.cParams):
                                params_list.append(
                                    f"UNKNOWN_PARAM_TYPE paramN")

                        ret_tdesc_obj = current_func_attrs.elemdescFunc.tdesc
                        ret_type_arg = ret_tdesc_obj.hreftype if ret_tdesc_obj.vt == comtypes.automation.VT_USERDEFINED else ret_tdesc_obj
                        methods_defined.append(MethodDetail(m_name, get_vt_name(
                            ret_tdesc_obj.vt, current_ti_obj, ret_type_arg), params_list, current_func_attrs.oVft, current_func_attrs.memid, i_method_idx))

                    except comtypes.COMError as e_getfuncdesc:
                        hresult = getattr(e_getfuncdesc, 'hresult', 0)
                        if hresult == -2147319765:
                            self._log(
                                f"{EMOJI_WARNING} GetFuncDesc failed (ELEMENTNOTFOUND) for method index {i_method_idx} in '{name}'. Skipping.", indent=5, verbose_only=True)
                        else:
                            self._log(
                                f"{EMOJI_WARNING} COMError getting FuncDesc for method index {i_method_idx} in '{name}': {e_getfuncdesc}", indent=5, verbose_only=True)
                        continue
                    except Exception as e_gen_funcdesc:
                        self._log(
                            f"{EMOJI_WARNING} Generic error processing method index {i_method_idx} in '{name}': {e_gen_funcdesc}", indent=5, verbose_only=True)
                        continue
                    finally:
                        if func_desc_ptr and current_ti_obj:
                            try:
                                current_ti_obj.ReleaseFuncDesc(func_desc_ptr)
                            except:
                                pass

                base_name = "IUnknown"
                next_base_ti_obj_for_doc = None
                if current_attrs.cImplTypes > 0:
                    try:
                        next_base_ti_obj_for_doc = current_ti_obj.GetRefTypeInfo(
                            current_ti_obj.GetRefTypeOfImplType(0))
                        if next_base_ti_obj_for_doc:
                            base_name, _, _, _ = next_base_ti_obj_for_doc.GetDocumentation(
                                -1)
                    except:
                        self._log(
                            f"{EMOJI_WARNING} Could not get base name for '{name}'. Default IUnknown.", indent=5, verbose_only=True)

                chain.append(InterfaceInfo(name, iid_str, current_ti_obj,
                             current_attr_ptr, methods_defined, base_name))

                if name == "IUnknown" or current_attrs.cImplTypes == 0:
                    break

                try:
                    next_ti_candidate = current_ti_obj.GetRefTypeInfo(
                        current_ti_obj.GetRefTypeOfImplType(0))
                    current_ti_obj = next_ti_candidate
                    current_attr_ptr = None
                except comtypes.COMError:
                    self._log(
                        f"{EMOJI_WARNING} Could not get base ITypeInfo for '{name}'. Stopping trace.", indent=4, verbose_only=True)
                    break

            finally:
                if current_attr_ptr and current_ti_obj:
                    try:
                        current_ti_obj.ReleaseTypeAttr(current_attr_ptr)
                    except:
                        pass
        return chain

    def analyze_interfaces_directly(self):
        if not self.type_lib:
            self._log(f"{EMOJI_FAILURE} Type library not loaded. Cannot analyze interfaces.",
                      status_emoji=EMOJI_FAILURE)
            return

        self._log(
            f"{EMOJI_GEAR} Analyzing all TKIND_INTERFACE entries from TypeLib...", indent=1)
        self.results = []

        num_type_infos = 0
        try:
            num_type_infos = self.type_lib.GetTypeInfoCount()
        except Exception as e_count:
            self._log(
                f"{EMOJI_FAILURE} Error getting TypeInfo count: {e_count}", indent=2)
            return

        for i in range(num_type_infos):
            type_info_obj_main_iter = None
            attr_main_iter_ptr = None
            interface_name_for_log = f"TypeInfo index {i}"

            try:
                type_info_obj_main_iter = self.type_lib.GetTypeInfo(i)
                attr_main_iter_ptr = type_info_obj_main_iter.GetTypeAttr()

                try:
                    doc_name, _, _, _ = type_info_obj_main_iter.GetDocumentation(
                        -1)
                    if doc_name:
                        interface_name_for_log = doc_name
                except Exception:
                    pass

                if not attr_main_iter_ptr or attr_main_iter_ptr.typekind != comtypes.typeinfo.TKIND_INTERFACE:
                    continue

                interface_iid_str = str(attr_main_iter_ptr.guid)
                self._log(
                    f"Scanning Interface: '{interface_name_for_log}' (IID: {interface_iid_str})", indent=2, verbose_only=True)

                current_interface_chain = self.get_inheritance_chain(
                    type_info_obj_main_iter)
                methods_found_in_chain = {}

                for iface_in_chain_info in current_interface_chain:
                    for method_detail in iface_in_chain_info.methods_defined:
                        method_name = method_detail.name
                        if method_name in self.target_method_names and method_name not in methods_found_in_chain:
                            func_desc_ptr_check = None
                            try:
                                func_desc_ptr_check = iface_in_chain_info.type_info_obj.GetFuncDesc(
                                    method_detail.index_in_interface)
                                if func_desc_ptr_check and \
                                   func_desc_ptr_check.cParams == self.expected_param_counts.get(method_name, -1) and \
                                   self.check_method_signature(method_name, func_desc_ptr_check, iface_in_chain_info.type_info_obj):
                                    methods_found_in_chain[method_name] = AnalyzedMethod(
                                        name=method_name, ovft=func_desc_ptr_check.oVft, memid=func_desc_ptr_check.memid,
                                        defining_interface_name=iface_in_chain_info.name,
                                        defining_interface_iid=iface_in_chain_info.iid
                                    )
                                    self._log(f"'{method_name}' matched signature in '{iface_in_chain_info.name}'.",
                                              indent=4, verbose_only=True, status_emoji=EMOJI_LIGHTBULB)
                            except comtypes.COMError as e_fd_check:
                                hresult_fd = getattr(e_fd_check, 'hresult', 0)
                                if hresult_fd != -2147319765:
                                    self._log(
                                        f"{EMOJI_WARNING} COMError checking method '{method_name}' in '{iface_in_chain_info.name}': {e_fd_check}", indent=5, verbose_only=True)
                            finally:
                                if func_desc_ptr_check and iface_in_chain_info.type_info_obj:
                                    try:
                                        iface_in_chain_info.type_info_obj.ReleaseFuncDesc(
                                            func_desc_ptr_check)
                                    except:
                                        pass

                if all(name in methods_found_in_chain for name in self.target_method_names):
                    self._log(
                        f"{EMOJI_INFO} Found ABE-capable: '{interface_name_for_log}' (IID: {interface_iid_str})", indent=3)
                    self.results.append(AbeCandidate(
                        clsid=self.discovered_clsid or "Unknown CLSID",
                        interface_name=interface_name_for_log,
                        interface_iid=interface_iid_str,
                        methods=methods_found_in_chain,
                        inheritance_chain_info=current_interface_chain
                    ))
                else:
                    self._log(
                        f"Interface '{interface_name_for_log}' did not meet all target method criteria.", indent=3, verbose_only=True)

            except comtypes.COMError as e_com_loop:
                self._log(
                    f"{EMOJI_FAILURE} COMError processing {interface_name_for_log}: {e_com_loop}", indent=2)
            except Exception as e_gen_loop:
                self._log(
                    f"{EMOJI_FAILURE} Generic error processing {interface_name_for_log}: {e_gen_loop}", indent=2)
                if self.args_verbose:
                    import traceback
                    traceback.print_exc()
            finally:
                if attr_main_iter_ptr and type_info_obj_main_iter:
                    try:
                        type_info_obj_main_iter.ReleaseTypeAttr(
                            attr_main_iter_ptr)
                    except:
                        pass

        if not self.results:
            self._log(
                f"{EMOJI_INFO} No ABE-capable interfaces were found after scanning all TypeInfo entries.", indent=1)

    def analyze_interfaces_directly(self):
        if not self.type_lib:
            self._log(f"{EMOJI_FAILURE} Type library not loaded. Cannot analyze interfaces.",
                      status_emoji=EMOJI_FAILURE)
            return

        self._log(
            f"{EMOJI_GEAR} Analyzing all TKIND_INTERFACE entries from TypeLib...", indent=1)
        self.results = []

        num_type_infos = 0
        try:
            num_type_infos = self.type_lib.GetTypeInfoCount()
        except Exception as e_count:
            self._log(
                f"{EMOJI_FAILURE} Error getting TypeInfo count: {e_count}", indent=2)
            return

        for i in range(num_type_infos):
            type_info = attr = None
            interface_name_for_log = f"TypeInfo index {i}"
            try:
                type_info = self.type_lib.GetTypeInfo(i)
                attr = type_info.GetTypeAttr()

                try:
                    interface_name_for_log, _, _, _ = type_info.GetDocumentation(
                        -1)
                except Exception:
                    pass

                if not attr or attr.typekind != comtypes.typeinfo.TKIND_INTERFACE:
                    continue

                interface_iid_str = str(attr.guid)
                self._log(
                    f"Scanning Interface: '{interface_name_for_log}' (IID: {interface_iid_str})", indent=2, verbose_only=True)

                current_interface_chain = self.get_inheritance_chain(type_info)
                methods_found_in_chain = {}

                for iface_in_chain_info in current_interface_chain:
                    for method_detail in iface_in_chain_info.methods_defined:
                        method_name = method_detail.name
                        if method_name in self.target_method_names and method_name not in methods_found_in_chain:
                            func_desc_check = None
                            try:
                                func_desc_check = iface_in_chain_info.type_info_obj.GetFuncDesc(
                                    method_detail.index_in_interface)
                                if func_desc_check and \
                                   func_desc_check.cParams == self.expected_param_counts.get(method_name, -1) and \
                                   self.check_method_signature(method_name, func_desc_check, iface_in_chain_info.type_info_obj):
                                    methods_found_in_chain[method_name] = AnalyzedMethod(
                                        name=method_name, ovft=method_detail.ovft, memid=method_detail.memid,
                                        defining_interface_name=iface_in_chain_info.name,
                                        defining_interface_iid=iface_in_chain_info.iid
                                    )
                                    self._log(f"'{method_name}' matched signature in '{iface_in_chain_info.name}'.",
                                              indent=4, verbose_only=True, status_emoji=EMOJI_LIGHTBULB)
                            except comtypes.COMError as e_fd_check:
                                self._log(
                                    f"{EMOJI_WARNING} COMError checking method '{method_name}' in '{iface_in_chain_info.name}': {e_fd_check}", indent=5, verbose_only=True)
                            finally:
                                if func_desc_check and iface_in_chain_info.type_info_obj:
                                    try:
                                        iface_in_chain_info.type_info_obj.ReleaseFuncDesc(
                                            func_desc_check)
                                    except:
                                        pass  # Best effort

                if all(name in methods_found_in_chain for name in self.target_method_names):
                    self._log(f"Interface '{interface_name_for_log}' (IID: {interface_iid_str}) IS ABE-capable.",
                              indent=3, verbose_only=True, status_emoji=EMOJI_SUCCESS)
                    self.results.append(AbeCandidate(
                        clsid=self.discovered_clsid or "Unknown CLSID",
                        interface_name=interface_name_for_log,
                        interface_iid=interface_iid_str,
                        methods=methods_found_in_chain,
                        inheritance_chain_info=current_interface_chain
                    ))
                else:
                    self._log(
                        f"Interface '{interface_name_for_log}' did not meet all target method criteria.", indent=3, verbose_only=True)

            except comtypes.COMError as e_com_loop:
                self._log(
                    f"{EMOJI_FAILURE} COMError processing {interface_name_for_log}: {e_com_loop}", indent=2)
            except Exception as e_gen_loop:
                self._log(
                    f"{EMOJI_FAILURE} Generic error processing {interface_name_for_log}: {e_gen_loop}", indent=2)
                import traceback
                if self.args_verbose:
                    traceback.print_exc()
            finally:
                if attr and type_info:
                    try:
                        type_info.ReleaseTypeAttr(attr)
                    except Exception as e_release_loop_attr:
                        self._log(
                            f"{EMOJI_WARNING} Error releasing TYPEATTR for '{interface_name_for_log}': {e_release_loop_attr}", indent=3, verbose_only=True)

        if not self.results:
            self._log(
                f"{EMOJI_INFO} No ABE-capable interfaces were found or added to results after scanning all TypeInfo entries.", indent=1)

    def analyze(self, scan_mode=False, browser_key_for_scan=None, user_provided_clsid=None):
        comtypes.CoInitialize()
        try:
            if scan_mode and browser_key_for_scan:
                self._log(
                    f"{EMOJI_GEAR} Scan mode enabled for: {browser_key_for_scan}")
                if not self.find_details_from_registry_by_service_name(browser_key_for_scan):
                    self._log(
                        f"{EMOJI_FAILURE} Scan mode: Could not find critical details for '{browser_key_for_scan}'.", status_emoji=EMOJI_FAILURE)
                    return
                if user_provided_clsid and not self.discovered_clsid:
                    self.discovered_clsid = user_provided_clsid
                    self._log(
                        f"{EMOJI_INFO} Using user-provided CLSID: {self.discovered_clsid}", indent=1)
                elif user_provided_clsid and self.discovered_clsid and user_provided_clsid.lower() != self.discovered_clsid.lower():
                    self._log(
                        f"{EMOJI_WARNING} User CLSID '{user_provided_clsid}' differs from scanned '{self.discovered_clsid}'. Using user-provided.", indent=1)
                    self.discovered_clsid = user_provided_clsid
            elif user_provided_clsid:
                self.discovered_clsid = user_provided_clsid
                self._log(
                    f"{EMOJI_INFO} Using user-provided CLSID: {self.discovered_clsid}")

            if not self.executable_path or not os.path.exists(self.executable_path):
                self._log(
                    f"Executable path not determined or invalid: '{self.executable_path}'.", status_emoji=EMOJI_FAILURE)
                return
            if not self.load_type_library():
                return
            self.analyze_interfaces_directly()
        finally:
            comtypes.CoUninitialize()

    def generate_cpp_stub_for_chain(self, chain_info_list: List[InterfaceInfo], main_abe_interface_iid: str) -> str:
        output_cpp = ""
        processed_iids = set()
        udt_names_generated = set()
        all_udts_to_define = set()

        for iface_info in chain_info_list:
            for method_data in iface_info.methods_defined:
                for type_str_base in [method_data.ret_type.replace("*", "").strip()] + \
                                     [p.split(" ")[0].replace("*", "").strip() for p in method_data.params]:
                    if type_str_base not in udt_names_generated and \
                       not any(kw in type_str_base.lower() for kw in ["hresult", "bstr", "long", "int", "byte", "short", "void", "char", "float", "double", "currency", "date", "scode", "variant_bool", "variant", "iunknown", "idispatch", "decimal", "hyper", "uhyper", "filetime", "blob", "lpwstr", "ulong", "safearray", "lpstr"]):
                        all_udts_to_define.add(type_str_base)

        self._log(f"{EMOJI_GEAR} Generating UDT (Enum) definitions...",
                  indent=1, verbose_only=True)
        for udt_name in sorted(list(all_udts_to_define)):
            if udt_name in udt_names_generated or not udt_name:
                continue
            udt_ti = udt_attr = None
            try:
                for i_ti_idx in range(self.type_lib.GetTypeInfoCount()):
                    ti, attr = self.type_lib.GetTypeInfo(
                        i_ti_idx), self.type_lib.GetTypeInfo(i_ti_idx).GetTypeAttr()
                    name, _, _, _ = ti.GetDocumentation(-1)
                    if name == udt_name and attr.typekind == comtypes.typeinfo.TKIND_ENUM:
                        udt_ti, udt_attr = ti, attr
                        break
                    if ti and attr:
                        ti.ReleaseTypeAttr(attr)

                if udt_ti and udt_attr:
                    self._log(
                        f"Defining enum: {udt_name}", indent=2, verbose_only=True)
                    output_cpp += f"// Enum: {udt_name}\ntypedef enum {udt_name} {{\n"
                    for k_enum in range(udt_attr.cVars):
                        var_desc = udt_ti.GetVarDesc(k_enum)
                        enum_val_name = udt_ti.GetNames(var_desc.memid, 1)[0]
                        val = k_enum
                        if var_desc.varkind == comtypes.typeinfo.VAR_CONST and var_desc._.lpvarValue:
                            try:
                                val = ctypes.cast(var_desc._.lpvarValue, ctypes.POINTER(
                                    comtypes.automation.VARIANT)).contents.value
                            except:
                                self._log(
                                    f"{EMOJI_WARNING} Could not get val for enum {enum_val_name}", indent=3, verbose_only=True)
                        output_cpp += f"    {enum_val_name} = {val},\n"
                        udt_ti.ReleaseVarDesc(var_desc)
                    output_cpp += f"}} {udt_name};\n\n"
                    udt_names_generated.add(udt_name)
                else:
                    self._log(
                        f"{EMOJI_INFO} UDT '{udt_name}' not found as enum. Skipping.", indent=2, verbose_only=True)
            finally:
                if udt_attr and udt_ti:
                    udt_ti.ReleaseTypeAttr(udt_attr)

        self._log(f"{EMOJI_GEAR} Generating MIDL_INTERFACE definitions...",
                  indent=1, verbose_only=True)
        for iface_info in reversed(chain_info_list):
            if iface_info.iid in processed_iids:
                continue
            self._log(
                f"Defining interface: {iface_info.name} (IID: {iface_info.iid}) : {iface_info.base_interface_name}", indent=2, verbose_only=True)
            output_cpp += f"MIDL_INTERFACE(\"{iface_info.iid}\") // C++ style: {format_guid_for_cpp(iface_info.iid)}\n"
            output_cpp += f"{iface_info.name} : public {iface_info.base_interface_name}\n{{\npublic:\n"

            if not iface_info.methods_defined:
                if iface_info.name == "IUnknown":
                    output_cpp += "    // Standard IUnknown methods.\n"
                elif iface_info.iid == main_abe_interface_iid:
                    output_cpp += "    // Primary ABE Interface: All methods inherited.\n"
                elif iface_info.type_attr_obj and iface_info.type_attr_obj.cFuncs > 0:
                    self._log(
                        f"{EMOJI_WARNING} Interface '{iface_info.name}' cFuncs={iface_info.type_attr_obj.cFuncs}, but no methods parsed. Placeholders generated.", indent=3, verbose_only=True)
                    for idx_m in range(iface_info.type_attr_obj.cFuncs):
                        m_name_ph, params_ph_f, ret_type_ph = f"AbstractMethod_slot{idx_m}_in_{iface_info.name.replace(' ', '_')}", "(void)", "HRESULT"
                        fd_ph = None
                        try:
                            fd_ph = iface_info.type_info_obj.GetFuncDesc(idx_m)
                            if fd_ph:
                                names_ph = iface_info.type_info_obj.GetNames(
                                    fd_ph.memid, fd_ph.cParams + 1)
                                m_name_ph = names_ph[0] if names_ph else m_name_ph
                                params_list_ph = [f"{get_vt_name(fd_ph.lprgelemdescParam[p_idx].tdesc.vt, iface_info.type_info_obj, fd_ph.lprgelemdescParam[p_idx].tdesc.hreftype if fd_ph.lprgelemdescParam[p_idx].tdesc.vt == comtypes.automation.VT_USERDEFINED else fd_ph.lprgelemdescParam[p_idx].tdesc)} {names_ph[p_idx+1] if names_ph and len(names_ph) > p_idx+1 else f'p{p_idx}'}" for p_idx in range(
                                    fd_ph.cParams)] if fd_ph.lprgelemdescParam else ["UNKNOWN_TYPE pN" for _ in range(fd_ph.cParams)]
                                ret_tdesc_ph_obj = fd_ph.elemdescFunc.tdesc
                                ret_type_ph = get_vt_name(ret_tdesc_ph_obj.vt, iface_info.type_info_obj,
                                                          ret_tdesc_ph_obj.hreftype if ret_tdesc_ph_obj.vt == comtypes.automation.VT_USERDEFINED else ret_tdesc_ph_obj)
                                if params_list_ph:
                                    params_ph_f = f"(\n        {params_list_ph[0]}" + (",\n        " + ",\n        ".join(
                                        params_list_ph[1:]) if len(params_list_ph) > 1 else "") + "\n    )"
                        except Exception as e_ph:
                            self._log(
                                f"{EMOJI_WARNING} Err detail placeholder {iface_info.name} slot {idx_m}: {e_ph}", indent=4, verbose_only=True)
                        finally:
                            if fd_ph and iface_info.type_info_obj:
                                iface_info.type_info_obj.ReleaseFuncDesc(fd_ph)
                        output_cpp += f"    virtual {ret_type_ph} STDMETHODCALLTYPE {m_name_ph}{params_ph_f} = 0;\n"
                else:
                    output_cpp += "    // No methods directly defined (cFuncs is 0).\n"

            for md in iface_info.methods_defined:
                params_f = f"(\n        {md.params[0]}" + (",\n        " + ",\n        ".join(
                    md.params[1:]) if len(md.params) > 1 else "") + "\n    )" if md.params else "(void)"
                output_cpp += f"    virtual {md.ret_type} STDMETHODCALLTYPE {md.name}{params_f} = 0;\n"
            output_cpp += "};\n\n"
            processed_iids.add(iface_info.iid)
        return output_cpp

    def print_results(self, output_cpp_stub_file=None):
        if not self.results:
            self._log(f"{EMOJI_FAILURE} No ABE Interface candidates found.",
                      status_emoji=EMOJI_FAILURE)
            return

        browser_name_print = (
            self.browser_key or "unknown_browser").capitalize()
        exe_path_print = self.executable_path or "PATH_NOT_DETERMINED"
        common_clsid_str = self.results[0].clsid
        common_clsid_cpp = format_guid_for_cpp(common_clsid_str)

        print(f"\n--- {EMOJI_LIGHTBULB} Analysis Summary ---")
        print(f"  Browser Target    : {browser_name_print}")
        print(f"  Service Executable: {exe_path_print}")
        print(f"  Discovered CLSID  : {common_clsid_str}")
        if common_clsid_cpp != format_guid_for_cpp(None):
            print(f"      (C++ Style)   : {common_clsid_cpp}")

        print(f"\n  Found {len(self.results)} ABE-Capable Interface(s):")
        chrome_known_good_iid = "{463ABECF-410D-407F-8AF5-0DF35A005CC8}".lower()
        edge_known_good_iid = "{C9C2B807-7731-4F34-81B7-44FF7779522B}".lower()
        brave_known_good_iid = "{F396861E-0C8E-4C71-8256-2FAE6D759CE9}".lower()

        primary_candidate_for_stub = self.results[0]
        if self.browser_key == "chrome":
            for r in self.results:
                if r.interface_iid.lower() == chrome_known_good_iid:
                    primary_candidate_for_stub = r
                    break
        elif self.browser_key == "edge":
            for r in self.results:
                if r.interface_iid.lower() == edge_known_good_iid:
                    primary_candidate_for_stub = r
                    break
        elif self.browser_key == "brave":
            for r in self.results:
                if r.interface_iid.lower() == brave_known_good_iid:
                    primary_candidate_for_stub = r
                    break

        for i, res_candidate in enumerate(self.results):
            is_primary_for_tool = (res_candidate.interface_iid.lower(
            ) == primary_candidate_for_stub.interface_iid.lower())
            primary_marker = f" {EMOJI_LIGHTBULB} (Likely primary for tool)" if is_primary_for_tool else ""
            print(f"\n  Candidate {i+1}:{primary_marker}")
            print(
                f"    Interface Name: {res_candidate.interface_name or 'Unknown'}")
            print(
                f"    IID           : {res_candidate.interface_iid or 'Unknown'}")
            if format_guid_for_cpp(res_candidate.interface_iid) != format_guid_for_cpp(None):
                print(
                    f"      (C++ Style) : {format_guid_for_cpp(res_candidate.interface_iid)}")

        if self.args_verbose:
            print(f"\n--- {EMOJI_INFO} Verbose Candidate Details ---")
            for i, res_candidate in enumerate(self.results):
                is_primary_for_tool = (res_candidate.interface_iid.lower(
                ) == primary_candidate_for_stub.interface_iid.lower())
                primary_marker = f" {EMOJI_LIGHTBULB} (Likely primary for tool)" if is_primary_for_tool else ""
                print(
                    f"\n  --- Verbose for Candidate {i+1}: '{res_candidate.interface_name}' (IID: {res_candidate.interface_iid}){primary_marker} ---")
                print(f"    Methods (relevant to ABE):")
                for name, details in res_candidate.methods.items():
                    slot = details.ovft // ctypes.sizeof(
                        ctypes.c_void_p) if ctypes.sizeof(ctypes.c_void_p) > 0 else "N/A"
                    print(
                        f"      - Method '{name}': VTable Offset: {details.ovft} (Slot ~{slot}), Defined in: '{details.defining_interface_name}' (IID: {details.defining_interface_iid})")
                print(
                    f"    Inheritance Chain: {' -> '.join(iface.name for iface in reversed(res_candidate.inheritance_chain_info))}")
                for iface_in_chain in reversed(res_candidate.inheritance_chain_info):
                    print(
                        f"      Interface in chain: '{iface_in_chain.name}' (IID: {iface_in_chain.iid}) - Defines {len(iface_in_chain.methods_defined)} method(s):")
                    if not iface_in_chain.methods_defined and iface_in_chain.name != "IUnknown":
                        print(
                            f"        (No methods directly defined in this block for '{iface_in_chain.name}')")
                    elif iface_in_chain.name == "IUnknown":
                        print(f"        (Standard IUnknown methods)")
                    for md in iface_in_chain.methods_defined:
                        print(
                            f"        - {md.ret_type} {md.name}({', '.join(md.params) if md.params else 'void'}) (oVft: {md.ovft})")
            print("--- End of Verbose Details ---")

        if output_cpp_stub_file and self.results:
            self._log(
                f"\n{EMOJI_GEAR} Generating C++ stubs for interface: '{primary_candidate_for_stub.interface_name}'...", status_emoji="")
            header = f"// --- COM Stubs for Browser: {browser_name_print} ---\n// Generated by COM ABE Analyzer\n"
            header += f"// Service Executable: {exe_path_print}\n"
            header += f"// Target CLSID for CoCreateInstance: {format_guid_for_cpp(primary_candidate_for_stub.clsid)} // Original: {primary_candidate_for_stub.clsid}\n"
            header += f"// Target IID for CoCreateInstance: {format_guid_for_cpp(primary_candidate_for_stub.interface_iid)} // Original: {primary_candidate_for_stub.interface_iid} (Primary Interface: {primary_candidate_for_stub.interface_name})\n\n"
            content = self.generate_cpp_stub_for_chain(
                primary_candidate_for_stub.inheritance_chain_info, primary_candidate_for_stub.interface_iid)
            try:
                with open(output_cpp_stub_file, "w", encoding="utf-8") as f:
                    f.write(header + content)
                self._log(
                    f"{EMOJI_FILE} C++ stubs written to: {output_cpp_stub_file}", status_emoji=EMOJI_SUCCESS)
            except IOError as e:
                self._log(f"{EMOJI_FILE} Error writing C++ stubs: {e}",
                          status_emoji=EMOJI_FAILURE)
                
def print_banner():
    banner_art = rf"""
-------------------------------------------------------------------------------------------

_________  ________      _____                    .___          _____ _____________________
\_   ___ \ \_____  \    /     \____________     __| _/____     /  _  \\______   \_   _____/
/    \  \/  /   |   \  /  \ /  \_  __ \__  \   / __ |/ __ \   /  /_\  \|    |  _/|    __)_ 
\     \____/    |    \/    Y    \  | \// __ \_/ /_/ \  ___/  /    |    \    |   \|        \
 \______  /\_______  /\____|__  /__|  (____  /\____ |\___  > \____|__  /______  /_______  /
        \/         \/         \/           \/      \/    \/          \/       \/        \/ 

                  by Alexander 'xaitax' Hagenah
-------------------------------------------------------------------------------------------
    """
    print(banner_art)


if __name__ == "__main__":
    print_banner()

    examples = """Examples:
  Scan for Chrome ABE interface:
    %(prog)s chrome --scan

  Scan for Edge, verbose output, and save C++ stubs:
    %(prog)s edge --scan -v --output-cpp-stub edge_abe_stubs.cpp

  Analyze a specific executable directly:
    %(prog)s "C:\\Program Files\\Google\\Chrome\\Application\\1xx.x.xxxx.xx\\elevation_service.exe"

  Analyze executable with a known CLSID:
    %(prog)s "C:\\path\\to\\service.exe" --known-clsid {YOUR-CLSID-HERE-IN-BRACES}
"""

    parser = argparse.ArgumentParser(
        usage="%(prog)s TARGET [options]",
        description=f"COMrade ABE: Your friendly helper for discovering and detailing COM App-Bound Encryption (ABE)\n"
                    "interfaces in Chromium-based browsers. It identifies service executables, CLSIDs, relevant IIDs,\n"
                    "and generates C++ stubs for security research and development.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=examples
    )

    parser.add_argument(
        "executable_path_or_browser_key",
        metavar="TARGET",
        help="Either the direct path to an executable (e.g., elevation_service.exe)\n"
             "OR a browser key ('chrome', 'edge', 'brave') when using --scan mode."
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable detailed verbose output during the analysis process."
    )
    parser.add_argument(
        "--output-cpp-stub",
        metavar="FILE_PATH",
        help="If specified, C++ interface stubs for the 'primary' identified ABE interface\n"
             "will be written to this file."
    )
    parser.add_argument(
        "--target-method-names",
        default="DecryptData,EncryptData",
        help="Comma-separated list of essential method names to identify a potential ABE interface\n"
             "(default: DecryptData,EncryptData)."
    )
    parser.add_argument(
        "--decrypt-params",
        type=int, default=3,
        metavar="COUNT",
        help="Expected parameter count for the 'DecryptData' method (default: 3)."
    )
    parser.add_argument(
        "--encrypt-params",
        type=int, default=4,
        metavar="COUNT",
        help="Expected parameter count for the 'EncryptData' method (default: 4)."
    )
    parser.add_argument(
        "--known-clsid",
        metavar="{CLSID-GUID}",
        help="Manually provide a CLSID (e.g., {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}) to use.\n"
             "This can supplement or override discovery, especially useful when analyzing a\n"
             "direct executable path without --scan, or if registry scan fails."
    )
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Enable scan mode. In this mode, TARGET should be a browser key ('chrome', 'edge', 'brave').\n"
             "The script will attempt to find the service executable and CLSID from the registry."
    )
    
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    if sys.platform != "win32":
        print(f"{EMOJI_FAILURE} This script relies on Windows-specific COM and registry functions and cannot run on this platform.")
        sys.exit(1)
        
    print(f"{EMOJI_GEAR} COM ABE Interface Analyzer Initializing...")

    analyzer = ComInterfaceAnalyzer(
        verbose=args.verbose,
        target_method_names=[name.strip() for name in args.target_method_names.split(',')],
        expected_decrypt_param_count=args.decrypt_params,
        expected_encrypt_param_count=args.encrypt_params
    )

    if args.scan:
        if not args.executable_path_or_browser_key:
            parser.error("Scan mode requires a browser key (chrome, edge, brave) as TARGET.")
        analyzer.analyze(scan_mode=True, browser_key_for_scan=args.executable_path_or_browser_key,
                         user_provided_clsid=args.known_clsid)
    else:
        if not os.path.exists(args.executable_path_or_browser_key):
            parser.error(f"Executable path not found: {args.executable_path_or_browser_key}")
        analyzer.executable_path = args.executable_path_or_browser_key
        if args.known_clsid:
            analyzer.discovered_clsid = args.known_clsid 
            analyzer.browser_key = "manual_path_input" 
        analyzer.analyze(scan_mode=False, user_provided_clsid=args.known_clsid)
    
    if analyzer.results or args.verbose:
        print(f"{EMOJI_INFO} Debug: analyzer.results has {len(analyzer.results)} items before printing.")
    
    analyzer.print_results(output_cpp_stub_file=args.output_cpp_stub)
    print(f"\n{EMOJI_SUCCESS} Analysis complete.")
