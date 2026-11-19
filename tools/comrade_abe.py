#!/usr/bin/env python3
"""
COMrade ABE - COM App-Bound Encryption Interface Analyzer
Discovers and analyzes COM interfaces for Chromium-based browser elevation services.
"""

import argparse
import ctypes
import io
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# Configure stdout encoding for Windows to support Unicode emoji output
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, 'buffer') and getattr(sys.stdout, 'encoding', '').lower() not in ('utf-8', 'utf8'):
            sys.stdout = io.TextIOWrapper(
                sys.stdout.buffer, encoding='utf-8', errors='replace')
        if hasattr(sys.stderr, 'buffer') and getattr(sys.stderr, 'encoding', '').lower() not in ('utf-8', 'utf8'):
            sys.stderr = io.TextIOWrapper(
                sys.stderr.buffer, encoding='utf-8', errors='replace')
    except Exception:
        pass

import comtypes
import comtypes.automation
import comtypes.typeinfo
import winreg

try:
    import pefile
except ImportError:
    pefile = None


# =============================================================================
# ctypes Function Definitions (must be set up once at module level for 64-bit)
# =============================================================================
def _setup_ctypes_functions():
    """Set up ctypes function signatures for Windows API calls."""
    from ctypes import wintypes

    # Crypt32 functions for certificate handling
    crypt32 = ctypes.windll.crypt32

    crypt32.CryptQueryObject.argtypes = [
        wintypes.DWORD,      # dwObjectType
        ctypes.c_void_p,     # pvObject
        wintypes.DWORD,      # dwExpectedContentTypeFlags
        wintypes.DWORD,      # dwExpectedFormatTypeFlags
        wintypes.DWORD,      # dwFlags
        ctypes.POINTER(wintypes.DWORD),  # pdwMsgAndCertEncodingType
        ctypes.POINTER(wintypes.DWORD),  # pdwContentType
        ctypes.POINTER(wintypes.DWORD),  # pdwFormatType
        ctypes.POINTER(ctypes.c_void_p),  # phCertStore
        ctypes.POINTER(ctypes.c_void_p),  # phMsg
        ctypes.POINTER(ctypes.c_void_p),  # ppvContext
    ]
    crypt32.CryptQueryObject.restype = wintypes.BOOL

    crypt32.CertEnumCertificatesInStore.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p]
    crypt32.CertEnumCertificatesInStore.restype = ctypes.c_void_p

    crypt32.CertGetNameStringW.argtypes = [
        ctypes.c_void_p,     # pCertContext
        wintypes.DWORD,      # dwType
        wintypes.DWORD,      # dwFlags
        ctypes.c_void_p,     # pvTypePara
        wintypes.LPWSTR,     # pszNameString
        wintypes.DWORD,      # cchNameString
    ]
    crypt32.CertGetNameStringW.restype = wintypes.DWORD

    crypt32.CertFreeCertificateContext.argtypes = [ctypes.c_void_p]
    crypt32.CertFreeCertificateContext.restype = wintypes.BOOL

    crypt32.CertCloseStore.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    crypt32.CertCloseStore.restype = wintypes.BOOL

    crypt32.CryptMsgClose.argtypes = [ctypes.c_void_p]
    crypt32.CryptMsgClose.restype = wintypes.BOOL

    # WinTrust function for signature verification
    wintrust = ctypes.windll.wintrust
    wintrust.WinVerifyTrust.argtypes = [
        wintypes.HWND,       # hwnd
        ctypes.c_void_p,     # pgActionID
        ctypes.c_void_p,     # pWVTData
    ]
    wintrust.WinVerifyTrust.restype = wintypes.LONG


# Initialize ctypes on module load
if sys.platform == "win32":
    try:
        _setup_ctypes_functions()
    except Exception:
        pass  # Will fall back to defaults if setup fails


def _supports_unicode() -> bool:
    """Check if terminal supports Unicode output."""
    if sys.platform != "win32":
        return True
    try:
        # Check if we're in Windows Terminal or other Unicode-capable terminal
        return os.environ.get("WT_SESSION") is not None or os.environ.get("TERM_PROGRAM") is not None
    except Exception:
        return False


# Use ASCII fallbacks if Unicode not supported
_USE_UNICODE = _supports_unicode()

# Constants
EMOJI = {
    "success": "[+]" if not _USE_UNICODE else "✅",
    "failure": "[-]" if not _USE_UNICODE else "❌",
    "info": "[i]" if not _USE_UNICODE else "ℹ️",
    "search": "[?]" if not _USE_UNICODE else "🔍",
    "gear": "[*]" if not _USE_UNICODE else "⚙️",
    "file": "[F]" if not _USE_UNICODE else "📄",
    "lightbulb": "[!]" if not _USE_UNICODE else "💡",
    "warning": "[!]" if not _USE_UNICODE else "⚠️"
}

START_TYPE_MAP = {0: "Boot", 1: "System",
                  2: "Automatic", 3: "Manual", 4: "Disabled"}

# Known browser service patterns
BROWSER_SERVICES = {
    "chrome": ["GoogleChromeElevationService", "GoogleChromeCanaryElevationService",
               "GoogleChromeBetaElevationService", "GoogleChromeDevElevationService"],
    "edge": ["MicrosoftEdgeElevationService", "MicrosoftEdgeCanaryElevationService",
             "MicrosoftEdgeBetaElevationService", "MicrosoftEdgeDevElevationService"],
    "brave": ["BraveElevationService", "BraveBetaElevationService", "BraveNightlyElevationService"],
    "avast": ["AvastSecureBrowserElevationService"],
}

# Known interface IIDs for primary detection (v1 and v2 where applicable)
# Note: These are the IIDs that have proper TypeLib registration for COM marshaling
KNOWN_PRIMARY_IIDS = {
    "chrome": ["{463ABECF-410D-407F-8AF5-0DF35A005CC8}"],
    "edge": ["{05EB264E-4D60-4F34-ADB7-1F983E930A79}",
             "{8F7B6792-784D-4047-845D-1782EFBEF205}",
             "{C9C2B807-7731-4F34-81B7-44FF7779522B}"],   # IElevatorEdge3 (v3), IElevator2Edge (v2), IElevatorEdge (v1)
    "brave": ["{F396861E-0C8E-4C71-8256-2FAE6D759CE9}",
              "{1BF5208B-295F-4992-B5F4-3A9BB6494838}"],   # IElevatorChrome (v1), IElevator2Chrome (v2)
    # Avast uses IElevatorChrome IID (base IElevator has broken TypeLib registration)
    "avast": ["{7737BB9F-BAC1-4C71-A696-7C82D7994B6F}"],
}

VERSION = "2.2.0"

# Unified VT type code -> C++ type name mapping (used by get_vt_name and resolve_type_deep)
# Lazy-initialized on first access since comtypes.automation constants
# aren't available until after the comtypes import above
_VT_TYPE_MAP = None

def _get_vt_type_map():
    global _VT_TYPE_MAP
    if _VT_TYPE_MAP is None:
        vt = comtypes.automation
        _VT_TYPE_MAP = {
            vt.VT_EMPTY: "void", vt.VT_NULL: "void*",
            vt.VT_I2: "SHORT", vt.VT_I4: "LONG",
            vt.VT_R4: "FLOAT", vt.VT_R8: "DOUBLE",
            vt.VT_CY: "CURRENCY", vt.VT_DATE: "DATE",
            vt.VT_BSTR: "BSTR", vt.VT_DISPATCH: "IDispatch*",
            vt.VT_ERROR: "SCODE", vt.VT_BOOL: "VARIANT_BOOL",
            vt.VT_VARIANT: "VARIANT", vt.VT_UNKNOWN: "IUnknown*",
            vt.VT_DECIMAL: "DECIMAL", vt.VT_UI1: "BYTE",
            vt.VT_I1: "CHAR", vt.VT_UI2: "USHORT",
            vt.VT_UI4: "ULONG", vt.VT_I8: "LONGLONG",
            vt.VT_UI8: "ULONGLONG", vt.VT_INT: "INT",
            vt.VT_UINT: "UINT", vt.VT_VOID: "void",
            vt.VT_HRESULT: "HRESULT", vt.VT_PTR: "void*",
            vt.VT_SAFEARRAY: "SAFEARRAY", vt.VT_CARRAY: "CARRAY",
            vt.VT_USERDEFINED: "USER_DEFINED",
            vt.VT_LPSTR: "LPSTR", vt.VT_LPWSTR: "LPWSTR",
            64: "FILETIME", 65: "BLOB",
        }
    return _VT_TYPE_MAP


# =============================================================================
# Data Classes
# =============================================================================

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
    num_funcs: int = 0
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


@dataclass
class VtableSlotInfo:
    method_name: str
    slot_index: int
    offset_x64: int
    offset_x86: int
    defining_interface: str
    memid: int = 0


@dataclass
class CoclassInfo:
    name: str
    clsid: str
    implemented_interfaces: List[Dict[str, Any]] = field(default_factory=list)
    threading_model: Optional[str] = None
    server_type: Optional[str] = None
    server_path: Optional[str] = None


@dataclass
class ProxyDllSecurityInfo:
    """Security analysis of a Proxy/Stub DLL."""
    dll_path: str
    exists: bool = False
    aslr: bool = False
    dep: bool = False
    cfg: bool = False
    high_entropy_aslr: bool = False
    is_signed: bool = False
    signature_valid: bool = False
    signer_name: Optional[str] = None
    same_signer_as_main: bool = False
    analysis_error: Optional[str] = None


@dataclass
class ProxyStubInfo:
    iid: str
    name: Optional[str] = None
    registered: bool = True
    marshaling_type: str = "unknown"
    proxy_stub_clsid: Optional[str] = None
    proxy_stub_dll: Optional[str] = None
    typelib_id: Optional[str] = None
    typelib_version: Optional[str] = None
    dll_security: Optional[ProxyDllSecurityInfo] = None


@dataclass
class ComSecurityInfo:
    clsid: str
    appid: Optional[str] = None
    runas: Optional[str] = None
    dll_surrogate: Optional[str] = None
    local_service: Optional[str] = None
    has_launch_permission: bool = False
    has_access_permission: bool = False
    launch_permission_size: int = 0
    access_permission_size: int = 0
    launch_permission_sddl: Optional[str] = None
    access_permission_sddl: Optional[str] = None


@dataclass
class PeTypelibInfo:
    machine: Optional[str] = None
    machine_name: Optional[str] = None
    timestamp: Optional[str] = None
    has_embedded_typelib: bool = False
    typelib_count: int = 0
    uses_rpc: bool = False
    uses_ole: bool = False
    imports: List[str] = field(default_factory=list)
    hardening_apis: List[str] = field(default_factory=list)
    pe_error: Optional[str] = None
    # Security mitigations
    aslr: bool = False
    dep: bool = False
    cfg: bool = False
    high_entropy_aslr: bool = False
    guard_rf: bool = False  # Return Flow Guard
    # Digital signature
    is_signed: bool = False
    signature_valid: bool = False
    signer_name: Optional[str] = None
    signature_error: Optional[str] = None


@dataclass
class ServiceSecurityInfo:
    """Windows Service security descriptor analysis."""
    service_name: str
    dacl_sddl: Optional[str] = None
    owner: Optional[str] = None
    has_weak_permissions: bool = False
    weak_permission_details: List[str] = field(default_factory=list)
    dangerous_trustees: List[str] = field(default_factory=list)
    query_error: Optional[str] = None


@dataclass
class ElevationServiceInfo:
    service_name: str
    display_name: Optional[str] = None
    executable_path: Optional[str] = None
    description: Optional[str] = None
    start_type: Optional[str] = None
    status: Optional[str] = None
    pid: Optional[int] = None
    browser_vendor: Optional[str] = None


@dataclass
class ServiceRuntimeInfo:
    service_name: str
    status: str = "unknown"
    pid: Optional[int] = None
    start_type: str = "unknown"
    can_stop: bool = False
    can_pause: bool = False
    dependencies: List[str] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class TypeLibRegistryInfo:
    typelib_id: str
    name: Optional[str] = None
    version: Optional[str] = None
    lcid: Optional[str] = None
    win32_path: Optional[str] = None
    win64_path: Optional[str] = None
    helpdir: Optional[str] = None
    flags: Optional[int] = None


# =============================================================================
# Registry Helpers
# =============================================================================

def reg_read_value(hkey: int, subkey: str, value_name: Optional[str] = None,
                   wow64_64: bool = True) -> Optional[Any]:
    """Read a single registry value, returning None if not found."""
    try:
        access = winreg.KEY_READ | (winreg.KEY_WOW64_64KEY if wow64_64 else 0)
        with winreg.OpenKey(hkey, subkey, 0, access) as key:
            return winreg.QueryValueEx(key, value_name)[0]
    except (FileNotFoundError, OSError):
        return None


def reg_enum_subkeys(hkey: int, subkey: str, wow64_64: bool = True) -> List[str]:
    """Enumerate subkeys under a registry key."""
    result = []
    try:
        access = winreg.KEY_READ | (winreg.KEY_WOW64_64KEY if wow64_64 else 0)
        with winreg.OpenKey(hkey, subkey, 0, access) as key:
            i = 0
            while True:
                try:
                    result.append(winreg.EnumKey(key, i))
                    i += 1
                except OSError:
                    break
    except (FileNotFoundError, OSError):
        pass
    return result


def clean_executable_path(raw_path: str) -> str:
    """Extract executable path from ImagePath or LocalServer32 value."""
    if not raw_path:
        return ""
    path = raw_path.strip()
    if path.startswith('"'):
        parts = path.split('"')
        return os.path.normpath(parts[1]) if len(parts) > 1 else ""
    return os.path.normpath(path.split()[0])


# =============================================================================
# COM Type Helpers
# =============================================================================

def get_vt_name(vt_code: int, type_info_context=None, hreftype_or_tdesc=None) -> str:
    """Convert VARIANT type code to C++ type name."""
    VT_MAP = _get_vt_type_map()

    is_byref = bool(vt_code & comtypes.automation.VT_BYREF)
    is_array = bool(vt_code & comtypes.automation.VT_ARRAY)
    base_vt = vt_code & ~(comtypes.automation.VT_BYREF | comtypes.automation.VT_ARRAY |
                          comtypes.automation.VT_VECTOR)
    name = VT_MAP.get(base_vt, f"Unknown_VT_0x{base_vt:X}")

    if base_vt == comtypes.automation.VT_USERDEFINED and type_info_context and isinstance(hreftype_or_tdesc, int):
        try:
            ref_ti = type_info_context.GetRefTypeInfo(hreftype_or_tdesc)
            udt_name, _, _, _ = ref_ti.GetDocumentation(-1)
            ref_attr = ref_ti.GetTypeAttr()
            name = udt_name
            ref_ti.ReleaseTypeAttr(ref_attr)
        except comtypes.COMError:
            name = f"UserDefined_hreftype_{hreftype_or_tdesc}"
    elif base_vt == comtypes.automation.VT_PTR and type_info_context:
        if hasattr(hreftype_or_tdesc, 'lptdesc') and hreftype_or_tdesc.lptdesc:
            pointed = hreftype_or_tdesc.lptdesc.contents
            next_arg = pointed.hreftype if pointed.vt == comtypes.automation.VT_USERDEFINED else pointed
            name = f"{get_vt_name(pointed.vt, type_info_context, next_arg)}*"

    if is_array:
        name = f"SAFEARRAY({name})"
    if is_byref and not name.endswith("*"):
        name = f"{name}*"
    return name


def get_param_flags_string(flags: int) -> str:
    """Convert parameter flags to string."""
    FLAG_MAP = {
        comtypes.typeinfo.PARAMFLAG_FIN: "in",
        comtypes.typeinfo.PARAMFLAG_FOUT: "out",
        comtypes.typeinfo.PARAMFLAG_FLCID: "lcid",
        comtypes.typeinfo.PARAMFLAG_FRETVAL: "retval",
        comtypes.typeinfo.PARAMFLAG_FOPT: "optional",
        comtypes.typeinfo.PARAMFLAG_FHASDEFAULT: "hasdefault",
    }
    active = [name for flag, name in FLAG_MAP.items() if flags & flag]
    return ", ".join(active) if active else f"none (0x{flags:X})"


def resolve_type_deep(type_info_context, tdesc, history: set = None, depth: int = 0) -> str:
    """
    Recursively resolve type definitions including struct/enum internals.

    For structs (TKIND_RECORD), returns: struct { field1_type field1; field2_type field2; }
    For enums (TKIND_ENUM), returns: enum EnumName
    For pointers, recursively resolves the pointed-to type.

    Args:
        type_info_context: ITypeInfo for resolving references
        tdesc: TYPEDESC structure describing the type
        history: Set of already-visited type names to prevent infinite recursion
        depth: Current recursion depth (max 3 to prevent excessive nesting)
    """
    if history is None:
        history = set()

    MAX_DEPTH = 3
    if depth > MAX_DEPTH:
        return "..."

    vt = tdesc.vt
    is_byref = bool(vt & comtypes.automation.VT_BYREF)
    base_vt = vt & ~(comtypes.automation.VT_BYREF | comtypes.automation.VT_ARRAY |
                     comtypes.automation.VT_VECTOR)

    VT_MAP = _get_vt_type_map()

    # Handle pointer types
    if base_vt == comtypes.automation.VT_PTR:
        if hasattr(tdesc, 'lptdesc') and tdesc.lptdesc:
            pointed = tdesc.lptdesc.contents
            inner = resolve_type_deep(
                type_info_context, pointed, history, depth + 1)
            return f"{inner}*"
        return "void*"

    # Handle user-defined types (structs, enums, interfaces)
    if base_vt == comtypes.automation.VT_USERDEFINED:
        try:
            href = tdesc.hreftype
            ref_ti = type_info_context.GetRefTypeInfo(href)
            ref_attr = ref_ti.GetTypeAttr()
            udt_name, _, _, _ = ref_ti.GetDocumentation(-1)
            type_kind = ref_attr.typekind

            # Prevent infinite recursion for self-referential types
            if udt_name in history:
                ref_ti.ReleaseTypeAttr(ref_attr)
                suffix = "*" if is_byref else ""
                return f"{udt_name}{suffix} /*recursive*/"

            history_copy = history | {udt_name}

            # TKIND_RECORD = struct
            if type_kind == comtypes.typeinfo.TKIND_RECORD:
                fields = []
                for i in range(ref_attr.cVars):
                    try:
                        vardesc = ref_ti.GetVarDesc(i)
                        var_names = ref_ti.GetNames(vardesc.memid, 1)
                        var_name = var_names[0] if var_names else f"field{i}"
                        var_type = resolve_type_deep(ref_ti, vardesc.elemdescVar.tdesc,
                                                     history_copy, depth + 1)
                        fields.append(f"{var_type} {var_name}")
                        ref_ti.ReleaseVarDesc(vardesc)
                    except comtypes.COMError:
                        fields.append(f"? field{i}")

                ref_ti.ReleaseTypeAttr(ref_attr)
                if fields:
                    suffix = "*" if is_byref else ""
                    return f"struct {udt_name} {{ {'; '.join(fields)}; }}{suffix}"
                else:
                    suffix = "*" if is_byref else ""
                    return f"struct {udt_name}{suffix}"

            # TKIND_ENUM = enum
            elif type_kind == comtypes.typeinfo.TKIND_ENUM:
                # Just return enum name; values are rarely needed inline
                ref_ti.ReleaseTypeAttr(ref_attr)
                return f"enum {udt_name}"

            # TKIND_INTERFACE or TKIND_DISPATCH = interface pointer
            elif type_kind in (comtypes.typeinfo.TKIND_INTERFACE,
                               comtypes.typeinfo.TKIND_DISPATCH):
                ref_ti.ReleaseTypeAttr(ref_attr)
                return f"{udt_name}*"

            # TKIND_ALIAS = typedef
            elif type_kind == comtypes.typeinfo.TKIND_ALIAS:
                # Resolve the aliased type - must recurse BEFORE releasing ref_attr
                # because tdescAlias points into the ref_attr buffer
                result = resolve_type_deep(ref_ti, ref_attr.tdescAlias, history_copy, depth + 1)
                ref_ti.ReleaseTypeAttr(ref_attr)
                return result

            # Other kinds - just return the name
            ref_ti.ReleaseTypeAttr(ref_attr)
            suffix = "*" if is_byref else ""
            return f"{udt_name}{suffix}"

        except comtypes.COMError:
            return f"UDT_hreftype_{tdesc.hreftype}"

    # Basic type lookup
    name = VT_MAP.get(base_vt, f"VT_0x{base_vt:X}")
    if is_byref and not name.endswith("*"):
        name = f"{name}*"
    return name


def format_guid_for_cpp(guid_str: Optional[str]) -> str:
    """Format GUID string as C++ initializer."""
    ZERO_GUID = "{0x00000000,0x0000,0x0000,{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}}"
    if not guid_str or guid_str.lower().startswith("unknown"):
        return ZERO_GUID
    try:
        g = comtypes.GUID(guid_str)
        d4 = [g.Data4[i] & 0xFF for i in range(8)]
        return (f"{{0x{g.Data1:08X},0x{g.Data2:04X},0x{g.Data3:04X},"
                f"{{0x{d4[0]:02X},0x{d4[1]:02X},0x{d4[2]:02X},0x{d4[3]:02X},"
                f"0x{d4[4]:02X},0x{d4[5]:02X},0x{d4[6]:02X},0x{d4[7]:02X}}}}}")
    except (ValueError, Exception):
        return ZERO_GUID


def parse_pe_mitigations(dll_characteristics: int) -> Dict[str, bool]:
    """Parse PE DllCharacteristics bitmask into security mitigation flags."""
    return {
        "aslr": bool(dll_characteristics & 0x0040),
        "high_entropy_aslr": bool(dll_characteristics & 0x0020),
        "dep": bool(dll_characteristics & 0x0100),
        "cfg": bool(dll_characteristics & 0x4000),
        "guard_rf": bool(dll_characteristics & 0x00020000),
    }


def decode_sddl(sd_bytes: bytes) -> Optional[str]:
    """Convert binary security descriptor to SDDL string."""
    try:
        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32
        sddl_ptr = ctypes.c_wchar_p()
        sddl_len = ctypes.c_ulong()
        # OWNER | GROUP | DACL
        if advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                ctypes.c_char_p(sd_bytes), 1, 0x7, ctypes.byref(sddl_ptr), ctypes.byref(sddl_len)):
            result = sddl_ptr.value
            kernel32.LocalFree(sddl_ptr)
            return result
    except Exception:
        pass
    return None


# SDDL analysis constants
_ACE_PATTERN = re.compile(r'\(([AD]);([^;]*);([^;]*);([^;]*);([^;]*);([^)]+)\)')

DANGEROUS_TRUSTEES_COM = {
    "WD": "Everyone",
    "AU": "Authenticated Users",
    "BU": "Built-in Users",
    "AN": "Anonymous",
    "WR": "Write Restricted",
    "AC": "All Application Packages",
    "S-1-1-0": "Everyone (SID)",
    "S-1-5-7": "Anonymous (SID)",
    "S-1-5-11": "Authenticated Users (SID)",
    "S-1-5-32-545": "Users (SID)",
    "S-1-15-2-1": "All App Packages (SID)",
}

DANGEROUS_TRUSTEES_SERVICE = {
    "WD": "Everyone",
    "AU": "Authenticated Users",
    "BU": "Built-in Users",
    "IU": "Interactive Users",
    "NU": "Network Users",
    "AN": "Anonymous",
}

DANGEROUS_RIGHTS_COM = {
    "GA": "Generic All",
    "GW": "Generic Write",
    "GX": "Generic Execute",
    "WD": "Write DAC",
    "WO": "Write Owner",
    "CC": "Create Child",
    "DC": "Delete Child",
    "LC": "List Children",
    "SW": "Self Write",
    "RP": "Read Property",
    "WP": "Write Property",
    "DT": "Delete Tree",
    "LO": "List Object",
    "CR": "Control Access",
    "FA": "File All Access",
    "FW": "File Write",
    "FX": "File Execute",
}

DANGEROUS_RIGHTS_SERVICE = {
    "DC": "SERVICE_CHANGE_CONFIG",
    "RP": "SERVICE_START",
    "WP": "SERVICE_STOP",
    "SD": "DELETE",
    "WD": "WRITE_DAC",
    "WO": "WRITE_OWNER",
    "GA": "GENERIC_ALL",
    "GW": "GENERIC_WRITE",
}

SERVICE_HEX_MASKS = {
    0x0002: "SERVICE_CHANGE_CONFIG",
    0x0010: "SERVICE_START",
    0x0020: "SERVICE_STOP",
    0x00040000: "WRITE_DAC",
    0x00080000: "WRITE_OWNER",
    0x10000000: "GENERIC_ALL",
}


def analyze_sddl_permissions(sddl: str, trustees: Dict[str, str],
                              rights: Dict[str, str],
                              hex_masks: Optional[Dict[int, str]] = None) -> Tuple[bool, List[str]]:
    """
    Analyze SDDL string for dangerous ACEs against given trustees and rights.
    Returns (is_dangerous, list of warning messages).
    """
    if not sddl:
        return False, []

    warnings = []
    for match in _ACE_PATTERN.finditer(sddl):
        ace_type, ace_flags, ace_rights, obj_guid, inherit_guid, trustee = match.groups()
        if ace_type != 'A':
            continue

        trustee_upper = trustee.upper()
        if trustee_upper not in trustees:
            continue

        trustee_name = trustees[trustee_upper]
        granted = []
        rights_upper = ace_rights.upper()
        for code, desc in rights.items():
            if code in rights_upper:
                granted.append(desc)

        if hex_masks and "0x" in ace_rights.lower():
            try:
                hex_val = int(ace_rights, 16)
                for mask, desc in hex_masks.items():
                    if hex_val & mask:
                        granted.append(desc)
            except ValueError:
                pass

        if granted:
            warnings.append(
                f"{trustee_name} has: {', '.join(set(granted))}")

    return len(warnings) > 0, warnings


def analyze_sddl_dangers(sddl: str) -> Tuple[bool, List[str]]:
    """Analyze SDDL string for dangerous COM ACEs."""
    return analyze_sddl_permissions(sddl, DANGEROUS_TRUSTEES_COM, DANGEROUS_RIGHTS_COM)


def verify_pe_signature(file_path: str) -> Tuple[bool, bool, Optional[str], Optional[str]]:
    """
    Verify Authenticode signature of a PE file using WinVerifyTrust.
    Returns (is_signed, is_valid, signer_name, error_message).

    Note: This function uses ctypes to call WinVerifyTrust directly.
    The signature verification is disabled by default due to stability issues
    on some systems. Set COMRADE_ENABLE_SIG_CHECK=1 to enable.
    """
    # Skip signature verification by default due to intermittent heap corruption
    # on some Windows/Python configurations (ARM64 specifically)
    import os
    if not os.environ.get('COMRADE_ENABLE_SIG_CHECK'):
        # Just check if file is signed using simpler method
        signer = get_signer_name(file_path)
        if signer:
            return True, True, signer, None
        return False, False, None, "Signature check skipped"

    try:
        from ctypes import wintypes

        # WinTrust structures - using proper alignment and packing
        class WINTRUST_FILE_INFO(ctypes.Structure):
            _pack_ = 8  # Ensure proper alignment on 64-bit
            _fields_ = [
                ("cbStruct", wintypes.DWORD),
                ("pcwszFilePath", wintypes.LPCWSTR),
                ("hFile", wintypes.HANDLE),
                ("pgKnownSubject", ctypes.c_void_p),  # GUID*
            ]

        class WINTRUST_DATA(ctypes.Structure):
            _pack_ = 8  # Ensure proper alignment on 64-bit
            _fields_ = [
                ("cbStruct", wintypes.DWORD),
                ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p),
                ("dwUIChoice", wintypes.DWORD),
                ("fdwRevocationChecks", wintypes.DWORD),
                ("dwUnionChoice", wintypes.DWORD),
                ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
                ("dwStateAction", wintypes.DWORD),
                ("hWVTStateData", wintypes.HANDLE),
                ("pwszURLReference", wintypes.LPCWSTR),
                ("dwProvFlags", wintypes.DWORD),
                ("dwUIContext", wintypes.DWORD),
                ("pSignatureSettings", ctypes.c_void_p),
            ]

        wintrust = ctypes.windll.wintrust
        # Set proper function signature
        wintrust.WinVerifyTrust.argtypes = [
            wintypes.HWND, ctypes.c_void_p, ctypes.c_void_p]
        wintrust.WinVerifyTrust.restype = wintypes.LONG

        # WINTRUST_ACTION_GENERIC_VERIFY_V2 - define GUID using pure ctypes
        class GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", wintypes.BYTE * 8),
            ]
        action_guid = GUID()
        action_guid.Data1 = 0x00AAC56B
        action_guid.Data2 = 0xCD44
        action_guid.Data3 = 0x11d0
        action_guid.Data4 = (ctypes.c_ubyte * 8)(0x8C, 0xC2,
                                                 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE)

        file_info = WINTRUST_FILE_INFO()
        file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
        file_info.pcwszFilePath = file_path
        file_info.hFile = None
        file_info.pgKnownSubject = None

        trust_data = WINTRUST_DATA()
        trust_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        trust_data.dwUIChoice = 2  # WTD_UI_NONE
        trust_data.fdwRevocationChecks = 0  # WTD_REVOKE_NONE
        trust_data.dwUnionChoice = 1  # WTD_CHOICE_FILE
        trust_data.pFile = ctypes.pointer(file_info)
        trust_data.dwStateAction = 1  # WTD_STATEACTION_VERIFY
        trust_data.dwProvFlags = 0x10  # WTD_CACHE_ONLY_URL_RETRIEVAL

        result = wintrust.WinVerifyTrust(
            None,
            ctypes.byref(action_guid),
            ctypes.byref(trust_data)
        )

        # Clean up state
        trust_data.dwStateAction = 2  # WTD_STATEACTION_CLOSE
        wintrust.WinVerifyTrust(None, ctypes.byref(
            action_guid), ctypes.byref(trust_data))

        # Result codes
        if result == 0:
            # Get signer info
            signer = get_signer_name(file_path)
            return True, True, signer, None
        elif result == 0x800B0100:  # TRUST_E_NOSIGNATURE
            return False, False, None, "No signature present"
        elif result == 0x800B0101:  # TRUST_E_EXPLICIT_DISTRUST
            return True, False, None, "Signature explicitly distrusted"
        elif result == 0x800B0109:  # CERT_E_UNTRUSTEDROOT
            signer = get_signer_name(file_path)
            return True, False, signer, "Untrusted root certificate"
        elif result == 0x800B010C:  # CERT_E_REVOKED
            return True, False, None, "Certificate revoked"
        elif result == 0x80096010:  # TRUST_E_BAD_DIGEST
            return True, False, None, "Signature hash mismatch (tampered)"
        else:
            return False, False, None, f"WinVerifyTrust error: 0x{result:08X}"

    except Exception as e:
        return False, False, None, str(e)


def get_signer_name(file_path: str) -> Optional[str]:
    """Extract signer name purely via ctypes (No PowerShell - OpSec safe)."""
    try:
        crypt32 = ctypes.windll.crypt32

        # Constants
        CERT_QUERY_OBJECT_FILE = 1
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 0x400
        CERT_QUERY_FORMAT_FLAG_BINARY = 2
        CERT_NAME_SIMPLE_DISPLAY_TYPE = 4

        # Query the object to get both store and message handles
        store_handle = ctypes.c_void_p()
        msg_handle = ctypes.c_void_p()

        if not crypt32.CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            ctypes.c_wchar_p(file_path),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0, None, None, None,
            ctypes.byref(store_handle),
            ctypes.byref(msg_handle),
            None
        ):
            return None

        # Get the first certificate from the store (the signer)
        p_cert_context = crypt32.CertEnumCertificatesInStore(
            store_handle, None)

        if not p_cert_context:
            crypt32.CertCloseStore(store_handle, 0)
            crypt32.CryptMsgClose(msg_handle)
            return None

        # Get the simple display name
        cb_name = crypt32.CertGetNameStringW(
            p_cert_context, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None, 0
        )

        result_name = None
        if cb_name > 0:
            name_buf = ctypes.create_unicode_buffer(cb_name)
            crypt32.CertGetNameStringW(
                p_cert_context, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, name_buf, cb_name
            )
            result_name = name_buf.value

        # Cleanup
        crypt32.CertFreeCertificateContext(p_cert_context)
        crypt32.CertCloseStore(store_handle, 0)
        crypt32.CryptMsgClose(msg_handle)

        return result_name

    except Exception:
        return None


def analyze_proxy_dll_security(dll_path: str, main_signer: Optional[str] = None) -> ProxyDllSecurityInfo:
    """
    Perform mini PE security analysis on a Proxy/Stub DLL.
    Checks for CFG, ASLR, DEP, signature, and signer match with main executable.
    """
    result = ProxyDllSecurityInfo(dll_path=dll_path)

    # Expand environment variables
    expanded_path = os.path.expandvars(dll_path)

    if not os.path.exists(expanded_path):
        result.exists = False
        result.analysis_error = "DLL file not found"
        return result

    result.exists = True

    # Check PE security mitigations
    if pefile:
        try:
            pe = pefile.PE(expanded_path, fast_load=True)

            if hasattr(pe, 'OPTIONAL_HEADER'):
                m = parse_pe_mitigations(pe.OPTIONAL_HEADER.DllCharacteristics)
                result.aslr = m["aslr"]
                result.high_entropy_aslr = m["high_entropy_aslr"]
                result.dep = m["dep"]
                result.cfg = m["cfg"]

            pe.close()
        except Exception as e:
            result.analysis_error = f"PE parse error: {e}"

    # Check digital signature
    result.is_signed, result.signature_valid, result.signer_name, sig_error = \
        verify_pe_signature(expanded_path)

    if sig_error and not result.analysis_error:
        result.analysis_error = sig_error

    # Check if signer matches main executable
    if main_signer and result.signer_name:
        # Normalize for comparison (case-insensitive, trim)
        result.same_signer_as_main = (
            main_signer.strip().lower() == result.signer_name.strip().lower()
        )

    return result


# =============================================================================
# Main Analyzer Class
# =============================================================================

class ComInterfaceAnalyzer:
    def __init__(self, executable_path: str = None, verbose: bool = False,
                 target_method_names: List[str] = None,
                 expected_decrypt_params: int = 3, expected_encrypt_params: int = 4,
                 log_file: str = None):
        self.executable_path = executable_path
        self.verbose = verbose
        self.type_lib = None
        self.results: List[AbeCandidate] = []
        self.discovered_clsid: Optional[str] = None
        self.browser_key: Optional[str] = None
        self.target_methods = target_method_names or [
            "DecryptData", "EncryptData"]
        self.expected_params = {"DecryptData": expected_decrypt_params,
                                "EncryptData": expected_encrypt_params}

        # Statistics
        self.start_time = None
        self.interfaces_scanned = 0
        self.interfaces_abe_capable = 0

        # Caches
        self.coclasses: List[CoclassInfo] = []
        self.proxy_stub_cache: Dict[str, ProxyStubInfo] = {}
        self.security_cache: Dict[str, ComSecurityInfo] = {}
        self._iface_cache: Dict[str, InterfaceInfo] = {}  # IID -> parsed InterfaceInfo
        # Default to empty object to prevent None access
        self.pe_info: PeTypelibInfo = PeTypelibInfo()
        self.service_security: Optional[ServiceSecurityInfo] = None

        # Setup logging
        self.logger = None
        if log_file:
            self.logger = logging.getLogger('ComradeABE')
            self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)
            handler = logging.FileHandler(log_file, encoding='utf-8')
            handler.setFormatter(logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'))
            self.logger.addHandler(handler)

    def _log(self, msg: str, indent: int = 0, verbose_only: bool = False, emoji: str = None):
        """Print and optionally log a message."""
        if verbose_only and not self.verbose:
            return
        prefix = f"{EMOJI.get(emoji, '')} " if emoji else ""
        print(f"{'  ' * indent}{prefix}{msg}")
        if self.logger:
            self.logger.log(
                logging.DEBUG if verbose_only else logging.INFO, msg)

    # -------------------------------------------------------------------------
    # Registry-based Discovery
    # -------------------------------------------------------------------------

    def find_service_details(self, browser_key: str) -> bool:
        """Find elevation service details from registry."""
        self.browser_key = browser_key.lower()
        self._log(
            f"Scanning registry for service details of '{self.browser_key}'...", emoji="search")

        # Find the actual service name
        candidates = BROWSER_SERVICES.get(self.browser_key, [browser_key])
        service_name = None
        for candidate in candidates:
            if reg_read_value(winreg.HKEY_LOCAL_MACHINE,
                              rf"SYSTEM\CurrentControlSet\Services\{candidate}", "ImagePath"):
                service_name = candidate
                self._log(f"Found service: {candidate}",
                          indent=1, verbose_only=True, emoji="info")
                break

        if not service_name:
            service_name = candidates[0] if candidates else browser_key
            self._log(
                f"No installed service found, trying: {service_name}", indent=1, verbose_only=True, emoji="warning")

        # Get executable path
        image_path = reg_read_value(winreg.HKEY_LOCAL_MACHINE,
                                    rf"SYSTEM\CurrentControlSet\Services\{service_name}", "ImagePath")
        if image_path:
            self.executable_path = os.path.normpath(
                os.path.expandvars(clean_executable_path(image_path)))
            self._log(
                f"Service ImagePath: {self.executable_path}", indent=1, emoji="info")

        # Find CLSID via AppID LocalService
        self._find_clsid_for_service(service_name)

        if not self.executable_path:
            self._log(
                f"Failed to determine executable path for '{browser_key}'", indent=1, emoji="failure")
            return False
        return True

    def _find_clsid_for_service(self, service_name: str):
        """Find CLSID linked to a service via AppID."""
        self._log(
            f"Searching for CLSIDs linked to '{service_name}'...", indent=1, verbose_only=True, emoji="search")

        # Search AppID paths for LocalService match
        search_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Classes\AppID"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Classes\AppID"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Classes\AppID"),
        ]

        for hkey, path in search_paths:
            for appid in reg_enum_subkeys(hkey, path):
                if not appid.startswith("{"):
                    continue
                local_svc = reg_read_value(
                    hkey, rf"{path}\{appid}", "LocalService")
                if local_svc and local_svc.lower() == service_name.lower():
                    self.discovered_clsid = appid
                    self._log(
                        f"Discovered CLSID: {self.discovered_clsid}", indent=1, emoji="success")
                    return

        # Fallback: search CLSID LocalServer32 for matching executable
        if self.executable_path:
            self._log("Fallback: searching CLSID LocalServer32...",
                      indent=2, verbose_only=True)
            clsid_paths = [
                (winreg.HKEY_CLASSES_ROOT, "CLSID"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Classes\CLSID"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Classes\CLSID"),
            ]
            for hkey, path in clsid_paths:
                for clsid in reg_enum_subkeys(hkey, path):
                    if not clsid.startswith("{"):
                        continue
                    server_path = reg_read_value(
                        hkey, rf"{path}\{clsid}\LocalServer32", None)
                    if server_path:
                        exe = clean_executable_path(server_path)
                        if exe.lower() == self.executable_path.lower():
                            self.discovered_clsid = clsid
                            self._log(
                                f"Discovered CLSID via LocalServer32: {clsid}", indent=1, emoji="success")
                            return

    def discover_elevation_services(self) -> List[ElevationServiceInfo]:
        """Auto-discover all elevation services on the system."""
        self._log("Discovering all elevation services...",
                  indent=1, emoji="search")
        services = []

        for svc_name in reg_enum_subkeys(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services"):
            if "elevationservice" not in svc_name.lower():
                continue

            svc_path = rf"SYSTEM\CurrentControlSet\Services\{svc_name}"
            info = ElevationServiceInfo(service_name=svc_name)

            # Infer browser vendor
            name_lower = svc_name.lower()
            if "googlechrome" in name_lower:
                info.browser_vendor = "Chrome"
            elif "microsoftedge" in name_lower:
                info.browser_vendor = "Edge"
            elif "brave" in name_lower:
                info.browser_vendor = "Brave"
            elif "avastsecure" in name_lower or "avast" in name_lower:
                info.browser_vendor = "Avast"
            elif "vivaldi" in name_lower:
                info.browser_vendor = "Vivaldi"
            elif "opera" in name_lower:
                info.browser_vendor = "Opera"
            else:
                info.browser_vendor = "Unknown"

            # Read service properties
            image_path = reg_read_value(
                winreg.HKEY_LOCAL_MACHINE, svc_path, "ImagePath")
            if image_path:
                info.executable_path = os.path.normpath(
                    os.path.expandvars(clean_executable_path(image_path)))
            info.display_name = reg_read_value(
                winreg.HKEY_LOCAL_MACHINE, svc_path, "DisplayName")
            info.description = reg_read_value(
                winreg.HKEY_LOCAL_MACHINE, svc_path, "Description")
            start_val = reg_read_value(
                winreg.HKEY_LOCAL_MACHINE, svc_path, "Start")
            if start_val is not None:
                info.start_type = START_TYPE_MAP.get(
                    start_val, f"Unknown({start_val})")

            # Get runtime status
            runtime = self.get_service_runtime_status(svc_name)
            info.status = runtime.status
            info.pid = runtime.pid

            services.append(info)
            self._log(
                f"Found: {svc_name} ({info.browser_vendor})", indent=2, emoji="success")

        self._log(
            f"Discovered {len(services)} elevation service(s)", indent=1, emoji="info")
        return services

    def get_service_runtime_status(self, service_name: str) -> ServiceRuntimeInfo:
        """Query service runtime status via SCM."""
        result = ServiceRuntimeInfo(service_name=service_name)
        try:
            advapi32 = ctypes.windll.advapi32
            SC_MANAGER_CONNECT = 0x0001
            SERVICE_QUERY_STATUS = 0x0004

            scm = advapi32.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
            if not scm:
                result.error = f"OpenSCManager failed: {ctypes.GetLastError()}"
                return result

            try:
                svc = advapi32.OpenServiceW(
                    scm, service_name, SERVICE_QUERY_STATUS)
                if not svc:
                    result.error = f"OpenService failed: {ctypes.GetLastError()}"
                    return result

                try:
                    class SERVICE_STATUS_PROCESS(ctypes.Structure):
                        _fields_ = [
                            ("dwServiceType", ctypes.c_ulong),
                            ("dwCurrentState", ctypes.c_ulong),
                            ("dwControlsAccepted", ctypes.c_ulong),
                            ("dwWin32ExitCode", ctypes.c_ulong),
                            ("dwServiceSpecificExitCode", ctypes.c_ulong),
                            ("dwCheckPoint", ctypes.c_ulong),
                            ("dwWaitHint", ctypes.c_ulong),
                            ("dwProcessId", ctypes.c_ulong),
                            ("dwServiceFlags", ctypes.c_ulong),
                        ]

                    status = SERVICE_STATUS_PROCESS()
                    needed = ctypes.c_ulong()
                    if advapi32.QueryServiceStatusEx(svc, 0, ctypes.byref(status),
                                                     ctypes.sizeof(status), ctypes.byref(needed)):
                        state_map = {1: "stopped", 2: "start_pending", 3: "stop_pending",
                                     4: "running", 5: "continue_pending", 6: "pause_pending", 7: "paused"}
                        result.status = state_map.get(
                            status.dwCurrentState, "unknown")
                        result.pid = status.dwProcessId if status.dwProcessId else None
                        result.can_stop = bool(status.dwControlsAccepted & 0x1)
                        result.can_pause = bool(
                            status.dwControlsAccepted & 0x2)
                finally:
                    advapi32.CloseServiceHandle(svc)
            finally:
                advapi32.CloseServiceHandle(scm)
        except Exception as e:
            result.error = str(e)

        # Get start type from registry
        start_val = reg_read_value(winreg.HKEY_LOCAL_MACHINE,
                                   rf"SYSTEM\CurrentControlSet\Services\{service_name}", "Start")
        if start_val is not None:
            result.start_type = START_TYPE_MAP.get(
                start_val, f"unknown({start_val})").lower()

        # Get dependencies
        deps = reg_read_value(winreg.HKEY_LOCAL_MACHINE,
                              rf"SYSTEM\CurrentControlSet\Services\{service_name}", "DependOnService")
        if deps:
            result.dependencies = list(deps) if isinstance(
                deps, (list, tuple)) else [deps]

        return result

    def analyze_service_security(self, service_name: str) -> ServiceSecurityInfo:
        """Analyze Windows Service security descriptor (DACL)."""
        result = ServiceSecurityInfo(service_name=service_name)

        try:
            from ctypes import wintypes
            advapi32 = ctypes.windll.advapi32
            kernel32 = ctypes.windll.kernel32

            # Set proper function signatures for 64-bit compatibility
            advapi32.OpenSCManagerW.argtypes = [
                wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
            advapi32.OpenSCManagerW.restype = wintypes.HANDLE
            advapi32.OpenServiceW.argtypes = [
                wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
            advapi32.OpenServiceW.restype = wintypes.HANDLE
            advapi32.CloseServiceHandle.argtypes = [wintypes.HANDLE]
            advapi32.CloseServiceHandle.restype = wintypes.BOOL
            advapi32.QueryServiceObjectSecurity.argtypes = [
                wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(
                    wintypes.DWORD)
            ]
            advapi32.QueryServiceObjectSecurity.restype = wintypes.BOOL

            # Open SCM and service with READ_CONTROL
            SC_MANAGER_CONNECT = 0x0001
            READ_CONTROL = 0x00020000

            scm = advapi32.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
            if not scm:
                result.query_error = f"OpenSCManager failed: {ctypes.GetLastError()}"
                self.service_security = result
                return result

            try:
                svc = advapi32.OpenServiceW(scm, service_name, READ_CONTROL)
                if not svc:
                    error = ctypes.GetLastError()
                    error_msgs = {
                        5: "Access denied", 1060: "Service not found", 1072: "Service marked for delete"}
                    result.query_error = f"OpenService failed: {error_msgs.get(error, error)}"
                    self.service_security = result
                    return result

                try:
                    # Query security descriptor size
                    # DACL_SECURITY_INFORMATION = 4, OWNER_SECURITY_INFORMATION = 1
                    sec_info = 4 | 1
                    needed = wintypes.DWORD()
                    advapi32.QueryServiceObjectSecurity(
                        svc, sec_info, None, 0, ctypes.byref(needed))

                    if needed.value > 0:
                        sd_buffer = ctypes.create_string_buffer(needed.value)
                        if advapi32.QueryServiceObjectSecurity(svc, sec_info, sd_buffer, needed.value,
                                                               ctypes.byref(needed)):
                            # Convert to SDDL
                            sddl_ptr = ctypes.c_wchar_p()
                            sddl_len = ctypes.c_ulong()
                            if advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                                    sd_buffer, 1, sec_info, ctypes.byref(sddl_ptr), ctypes.byref(sddl_len)):
                                result.dacl_sddl = sddl_ptr.value
                                kernel32.LocalFree(sddl_ptr)

                                # Analyze for dangerous permissions
                                result.has_weak_permissions, result.weak_permission_details = \
                                    self._analyze_service_dacl(
                                        result.dacl_sddl)
                        else:
                            result.query_error = f"QueryServiceObjectSecurity failed: {ctypes.GetLastError()}"
                    else:
                        result.query_error = "No security descriptor available"

                finally:
                    advapi32.CloseServiceHandle(svc)
            finally:
                advapi32.CloseServiceHandle(scm)

        except Exception as e:
            result.query_error = str(e)

        self.service_security = result
        return result

    def _analyze_service_dacl(self, sddl: str) -> Tuple[bool, List[str]]:
        """Analyze service DACL for weak permissions."""
        return analyze_sddl_permissions(
            sddl, DANGEROUS_TRUSTEES_SERVICE, DANGEROUS_RIGHTS_SERVICE,
            hex_masks=SERVICE_HEX_MASKS)

    # -------------------------------------------------------------------------
    # TypeLib Search
    # -------------------------------------------------------------------------

    def search_typelibs_by_pattern(self, pattern: str) -> List[TypeLibRegistryInfo]:
        """Search for TypeLibs in registry matching a pattern."""
        self._log(
            f"Searching TypeLibs matching '{pattern}'...", indent=1, emoji="search")
        results = []
        pattern_lower = pattern.lower()

        for tl_id in reg_enum_subkeys(winreg.HKEY_CLASSES_ROOT, "TypeLib"):
            if not tl_id.startswith("{"):
                continue

            for version in reg_enum_subkeys(winreg.HKEY_CLASSES_ROOT, rf"TypeLib\{tl_id}"):
                name = reg_read_value(
                    winreg.HKEY_CLASSES_ROOT, rf"TypeLib\{tl_id}\{version}", None)
                if not name or pattern_lower not in name.lower():
                    continue

                info = TypeLibRegistryInfo(
                    typelib_id=tl_id, name=name, version=version)
                info.helpdir = reg_read_value(winreg.HKEY_CLASSES_ROOT,
                                              rf"TypeLib\{tl_id}\{version}", "HELPDIR")

                # Find paths
                for lcid in reg_enum_subkeys(winreg.HKEY_CLASSES_ROOT, rf"TypeLib\{tl_id}\{version}"):
                    if not lcid.isdigit():
                        continue
                    info.lcid = lcid
                    info.win32_path = reg_read_value(winreg.HKEY_CLASSES_ROOT,
                                                     rf"TypeLib\{tl_id}\{version}\{lcid}\win32", None)
                    info.win64_path = reg_read_value(winreg.HKEY_CLASSES_ROOT,
                                                     rf"TypeLib\{tl_id}\{version}\{lcid}\win64", None)
                    break

                results.append(info)
                self._log(f"Found: {name} ({tl_id} v{version})",
                          indent=2, verbose_only=True, emoji="success")

        self._log(f"Found {len(results)} matching TypeLib(s)",
                  indent=1, emoji="info")
        return results

    # -------------------------------------------------------------------------
    # COM Analysis
    # -------------------------------------------------------------------------

    def analyze_com_security(self, clsid: str) -> ComSecurityInfo:
        """Analyze COM security settings for a CLSID."""
        if clsid in self.security_cache:
            return self.security_cache[clsid]

        result = ComSecurityInfo(clsid=clsid)
        result.appid = reg_read_value(
            winreg.HKEY_CLASSES_ROOT, rf"CLSID\{clsid}", "AppID")

        if result.appid:
            appid_path = rf"AppID\{result.appid}"
            result.runas = reg_read_value(
                winreg.HKEY_CLASSES_ROOT, appid_path, "RunAs")
            result.dll_surrogate = reg_read_value(
                winreg.HKEY_CLASSES_ROOT, appid_path, "DllSurrogate")
            result.local_service = reg_read_value(
                winreg.HKEY_CLASSES_ROOT, appid_path, "LocalService")

            # Read security descriptors
            try:
                access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
                with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, appid_path, 0, access) as key:
                    try:
                        perm = winreg.QueryValueEx(key, "LaunchPermission")[0]
                        result.has_launch_permission = True
                        result.launch_permission_size = len(perm)
                        result.launch_permission_sddl = decode_sddl(perm)
                    except FileNotFoundError:
                        pass
                    try:
                        perm = winreg.QueryValueEx(key, "AccessPermission")[0]
                        result.has_access_permission = True
                        result.access_permission_size = len(perm)
                        result.access_permission_sddl = decode_sddl(perm)
                    except FileNotFoundError:
                        pass
            except (FileNotFoundError, OSError):
                pass

        self.security_cache[clsid] = result
        return result

    def analyze_proxy_stub(self, iid: str) -> ProxyStubInfo:
        """Analyze proxy/stub registration for an interface."""
        if iid in self.proxy_stub_cache:
            return self.proxy_stub_cache[iid]

        result = ProxyStubInfo(iid=iid)
        iface_path = rf"Interface\{iid}"

        result.name = reg_read_value(
            winreg.HKEY_CLASSES_ROOT, iface_path, None)
        result.proxy_stub_clsid = reg_read_value(winreg.HKEY_CLASSES_ROOT,
                                                 rf"{iface_path}\ProxyStubClsid32", None)

        if result.proxy_stub_clsid:
            result.marshaling_type = "custom"
            ps_path = rf"CLSID\{result.proxy_stub_clsid}\InprocServer32"
            result.proxy_stub_dll = reg_read_value(
                winreg.HKEY_CLASSES_ROOT, ps_path, None)
            if result.proxy_stub_dll and "oleaut32" in result.proxy_stub_dll.lower():
                result.marshaling_type = "oleautomation"
                # For oleautomation, check if TypeLib GUID is properly registered
                result.typelib_id = reg_read_value(
                    winreg.HKEY_CLASSES_ROOT, rf"{iface_path}\TypeLib", None)
                result.typelib_version = reg_read_value(winreg.HKEY_CLASSES_ROOT,
                                                        rf"{iface_path}\TypeLib", "Version")
                # Validate TypeLib GUID is not empty and exists in registry
                if not result.typelib_id or not result.typelib_id.strip():
                    result.marshaling_type = "oleautomation (broken - no TypeLib GUID)"
                elif not reg_read_value(winreg.HKEY_CLASSES_ROOT, rf"TypeLib\{result.typelib_id}", None):
                    # TypeLib GUID specified but not registered in TypeLib registry
                    # This can still work if the interface itself is the TypeLib ID
                    pass
            elif result.proxy_stub_dll:
                # Analyze proxy DLL security (CFG, signature, etc.)
                main_signer = self.pe_info.signer_name if self.pe_info else None
                result.dll_security = analyze_proxy_dll_security(
                    result.proxy_stub_dll, main_signer)
        else:
            # Check for TypeLib marshaling
            result.typelib_id = reg_read_value(
                winreg.HKEY_CLASSES_ROOT, rf"{iface_path}\TypeLib", None)
            if result.typelib_id:
                result.marshaling_type = "oleautomation"
                result.typelib_version = reg_read_value(winreg.HKEY_CLASSES_ROOT,
                                                        rf"{iface_path}\TypeLib", "Version")
            else:
                result.registered = False
                result.marshaling_type = "not registered"

        self.proxy_stub_cache[iid] = result
        return result

    def analyze_pe_typelib(self) -> PeTypelibInfo:
        """Analyze PE file for TypeLib resources."""
        result = PeTypelibInfo()
        if not pefile or not self.executable_path:
            return result

        try:
            pe = pefile.PE(self.executable_path, fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'],
                                                   pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])

            # Machine type
            machine_map = {0x8664: ("AMD64", "x64"), 0x14c: ("I386", "x86"),
                           0xaa64: ("ARM64", "ARM64"), 0x1c0: ("ARM", "ARM")}
            if pe.FILE_HEADER.Machine in machine_map:
                result.machine, result.machine_name = machine_map[pe.FILE_HEADER.Machine]
            else:
                result.machine = f"0x{pe.FILE_HEADER.Machine:04X}"
                result.machine_name = "Unknown"

            # Timestamp (wrap in try/except for malformed/zero timestamps)
            ts = pe.FILE_HEADER.TimeDateStamp
            if ts:
                try:
                    result.timestamp = datetime.fromtimestamp(ts).isoformat()
                except (ValueError, OSError):
                    result.timestamp = f"invalid ({ts})"
            else:
                result.timestamp = None

            # Security mitigations from DllCharacteristics
            if hasattr(pe, 'OPTIONAL_HEADER'):
                m = parse_pe_mitigations(pe.OPTIONAL_HEADER.DllCharacteristics)
                result.aslr = m["aslr"]
                result.high_entropy_aslr = m["high_entropy_aslr"]
                result.dep = m["dep"]
                result.cfg = m["cfg"]
                result.guard_rf = m["guard_rf"]

            # Check for TypeLib resource (RT_TYPELIB = 16)
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if entry.id == 16:
                        result.has_embedded_typelib = True
                        if hasattr(entry, 'directory'):
                            result.typelib_count = len(entry.directory.entries)
                        break

            # Check imports and detect hardening APIs
            # These APIs indicate how the service validates callers (path validation, signature checks)
            HARDENING_APIS = {
                "wintrust.dll": {
                    "WinVerifyTrust": "Code signature verification",
                    "WinVerifyTrustEx": "Extended signature verification",
                },
                "crypt32.dll": {
                    "CertGetCertificateChain": "Certificate chain validation",
                    "CertVerifyCertificateChainPolicy": "Certificate policy verification",
                    "CryptQueryObject": "Cryptographic object query",
                },
                "kernel32.dll": {
                    "GetModuleFileNameW": "Path retrieval (self)",
                    "GetModuleFileNameA": "Path retrieval (self)",
                    "K32GetModuleFileNameExW": "Path retrieval (external process)",
                    "K32GetModuleFileNameExA": "Path retrieval (external process)",
                    "GetProcessImageFileNameW": "Process image path",
                    "QueryFullProcessImageNameW": "Full process image path",
                    "QueryFullProcessImageNameA": "Full process image path",
                },
                "psapi.dll": {
                    "GetModuleFileNameExW": "Module path (external process)",
                    "GetModuleFileNameExA": "Module path (external process)",
                    "GetProcessImageFileNameW": "Process image path",
                    "GetProcessImageFileNameA": "Process image path",
                },
                "ntdll.dll": {
                    "NtQueryInformationProcess": "Process information query",
                    "ZwQueryInformationProcess": "Process information query (Zw)",
                },
                "advapi32.dll": {
                    "GetTokenInformation": "Token/privilege inspection",
                    "OpenProcessToken": "Process token access",
                    "CheckTokenMembership": "Token group membership check",
                },
            }

            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode('utf-8', errors='ignore').lower()
                    result.imports.append(dll)
                    if 'rpcrt4' in dll:
                        result.uses_rpc = True
                    if 'ole32' in dll or 'oleaut32' in dll:
                        result.uses_ole = True

                    # Check for hardening APIs
                    if dll in HARDENING_APIS:
                        for imp in entry.imports:
                            if not imp.name:
                                continue
                            func_name = imp.name.decode(
                                'utf-8', errors='ignore')
                            if func_name in HARDENING_APIS[dll]:
                                desc = HARDENING_APIS[dll][func_name]
                                result.hardening_apis.append(
                                    f"{dll}!{func_name} ({desc})")

            pe.close()

            # Verify digital signature
            result.is_signed, result.signature_valid, result.signer_name, result.signature_error = \
                verify_pe_signature(self.executable_path)

        except Exception as e:
            result.pe_error = str(e)

        self.pe_info = result
        return result

    def analyze_coclasses(self) -> List[CoclassInfo]:
        """Enumerate TKIND_COCLASS entries from TypeLib."""
        if not self.type_lib:
            return []

        self._log("Analyzing TKIND_COCLASS entries...", indent=1, emoji="gear")
        self.coclasses = []

        for i in range(self.type_lib.GetTypeInfoCount()):
            try:
                ti = self.type_lib.GetTypeInfo(i)
                attr = ti.GetTypeAttr()

                if attr.typekind != comtypes.typeinfo.TKIND_COCLASS:
                    ti.ReleaseTypeAttr(attr)
                    continue

                name, _, _, _ = ti.GetDocumentation(-1)
                clsid = str(attr.guid)

                coclass = CoclassInfo(name=name, clsid=clsid)

                # Get server info from registry
                for subkey in ["LocalServer32", "InprocServer32"]:
                    server_path = reg_read_value(
                        winreg.HKEY_CLASSES_ROOT, rf"CLSID\{clsid}\{subkey}", None)
                    if server_path:
                        coclass.server_type = subkey
                        coclass.server_path = clean_executable_path(
                            server_path)
                        coclass.threading_model = reg_read_value(
                            winreg.HKEY_CLASSES_ROOT, rf"CLSID\{clsid}\{subkey}", "ThreadingModel")
                        break

                # Enumerate implemented interfaces
                for j in range(attr.cImplTypes):
                    try:
                        impl_flags = ti.GetImplTypeFlags(j)
                        ref_type = ti.GetRefTypeOfImplType(j)
                        impl_ti = ti.GetRefTypeInfo(ref_type)
                        impl_name, _, _, _ = impl_ti.GetDocumentation(-1)
                        impl_attr = impl_ti.GetTypeAttr()

                        coclass.implemented_interfaces.append({
                            "name": impl_name,
                            "iid": str(impl_attr.guid),
                            "is_default": bool(impl_flags & 0x1),
                            "is_source": bool(impl_flags & 0x2),
                        })
                        impl_ti.ReleaseTypeAttr(impl_attr)
                    except comtypes.COMError:
                        pass

                self.coclasses.append(coclass)
                ti.ReleaseTypeAttr(attr)

            except comtypes.COMError:
                pass

        self._log(f"Found {len(self.coclasses)} coclass(es)",
                  indent=1, emoji="info")
        return self.coclasses

    # -------------------------------------------------------------------------
    # TypeLib Loading and Interface Analysis
    # -------------------------------------------------------------------------

    def load_type_library(self) -> bool:
        """Load type library from executable."""
        if not self.executable_path:
            self._log("No executable path specified", emoji="failure")
            return False

        self._log(
            f"Attempting to load type library from: {self.executable_path}", emoji="search")
        try:
            self.type_lib = comtypes.typeinfo.LoadTypeLibEx(
                self.executable_path)
            name, _, _, _ = self.type_lib.GetDocumentation(-1)
            self._log(
                f"Successfully loaded type library: '{name}'", emoji="success")
            return True
        except comtypes.COMError as e:
            error_str = str(e)
            self._log(f"Failed to load type library: {e}", emoji="failure")
            # Check for architecture mismatch
            if "TYPE_E_CANTLOADLIBRARY" in error_str or "0x80029C4A" in error_str:
                import struct
                python_bits = struct.calcsize("P") * 8
                pe_arch = self.pe_info.machine_name if self.pe_info else "unknown"
                self._log(
                    f"Hint: Python is {python_bits}-bit, target PE is {pe_arch}.", indent=1, emoji="warning")
                self._log(
                    f"Try running with matching Python architecture.", indent=1, emoji="info")
            return False
        except OSError as e:
            self._log(f"OS error loading type library: {e}", emoji="failure")
            return False

    def get_inheritance_chain(self, ti: comtypes.typeinfo.ITypeInfo) -> List[InterfaceInfo]:
        """Build inheritance chain for an interface, using cache to minimize COM calls."""
        chain = []
        visited = set()

        def trace(type_info):
            attr = None
            try:
                attr = type_info.GetTypeAttr()
                iid = str(attr.guid)

                if iid in visited:
                    return
                visited.add(iid)

                # Skip corrupted type entries (garbage cFuncs/cImplTypes)
                if attr.cFuncs > 30 or attr.cImplTypes > 5:
                    return

                # Check cache first - reuse previously parsed data
                if iid in self._iface_cache:
                    cached = self._iface_cache[iid]
                    # Still need to recurse into base for the chain ordering
                    num_impl = attr.cImplTypes
                    type_info.ReleaseTypeAttr(attr)
                    attr = None
                    if num_impl > 0:
                        try:
                            ref = type_info.GetRefTypeOfImplType(0)
                            base_ti = type_info.GetRefTypeInfo(ref)
                            trace(base_ti)
                        except Exception:
                            pass
                    chain.append(cached)
                    return

                name, _, _, _ = type_info.GetDocumentation(-1)
                num_funcs = attr.cFuncs
                num_impl = attr.cImplTypes

                # Release attr early - we have all we need from it
                type_info.ReleaseTypeAttr(attr)
                attr = None

                # Get base interface
                base_name = "IUnknown"
                if num_impl > 0:
                    try:
                        ref = type_info.GetRefTypeOfImplType(0)
                        base_ti = type_info.GetRefTypeInfo(ref)
                        base_name, _, _, _ = base_ti.GetDocumentation(-1)
                        trace(base_ti)
                    except Exception:
                        pass

                # Parse methods
                methods = []
                for i in range(num_funcs):
                    fd = None
                    try:
                        fd = type_info.GetFuncDesc(i)
                        names = type_info.GetNames(fd.memid, fd.cParams + 1)
                        method_name = names[0] if names else f"Method{i}"

                        # Build parameter list with direction flags and deep type resolution
                        params = []
                        for p in range(fd.cParams):
                            pname = names[p +
                                          1] if len(names) > p + 1 else f"p{p}"
                            tdesc = fd.lprgelemdescParam[p].tdesc
                            pflags = fd.lprgelemdescParam[p]._.paramdesc.wParamFlags
                            # Use deep type resolution to expand structs/enums
                            ptype = resolve_type_deep(type_info, tdesc)
                            flags_str = get_param_flags_string(pflags)
                            if flags_str:
                                params.append(f"[{flags_str}] {ptype} {pname}")
                            else:
                                params.append(f"{ptype} {pname}")

                        ret_tdesc = fd.elemdescFunc.tdesc
                        ret_type = resolve_type_deep(type_info, ret_tdesc)

                        methods.append(MethodDetail(
                            name=method_name, ret_type=ret_type, params=params,
                            ovft=fd.oVft, memid=fd.memid, index_in_interface=i
                        ))
                    except Exception:
                        pass
                    finally:
                        if fd is not None:
                            try:
                                type_info.ReleaseFuncDesc(fd)
                            except Exception:
                                pass

                info = InterfaceInfo(
                    name=name, iid=iid, num_funcs=num_funcs,
                    methods_defined=methods, base_interface_name=base_name
                )
                self._iface_cache[iid] = info
                chain.append(info)

            except Exception:
                pass
            finally:
                if attr is not None:
                    try:
                        type_info.ReleaseTypeAttr(attr)
                    except Exception:
                        pass

        trace(ti)
        return chain

    def check_method_signature(self, method_name: str, fd, ti) -> bool:
        """Check if a method matches expected ABE signature."""
        expected = self.expected_params.get(method_name)
        if expected is None:
            return True

        if fd.cParams != expected:
            return False
        if fd.elemdescFunc.tdesc.vt != comtypes.automation.VT_HRESULT:
            return False

        if method_name == "DecryptData" and fd.cParams == 3:
            # BSTR in, BSTR* out, ULONG* out
            p0 = fd.lprgelemdescParam[0]
            if p0.tdesc.vt != comtypes.automation.VT_BSTR:
                return False
            if not (p0._.paramdesc.wParamFlags & comtypes.typeinfo.PARAMFLAG_FIN):
                return False
        elif method_name == "EncryptData" and fd.cParams == 4:
            # First param should be in
            p0 = fd.lprgelemdescParam[0]
            if not (p0._.paramdesc.wParamFlags & comtypes.typeinfo.PARAMFLAG_FIN):
                return False

        return True

    def analyze_interfaces(self):
        """Analyze all interfaces in the TypeLib for ABE capability."""
        if not self.type_lib:
            return

        self._log("Analyzing all TKIND_INTERFACE entries from TypeLib...",
                  indent=1, emoji="gear")
        count = self.type_lib.GetTypeInfoCount()
        self._log(f"Found {count} type definitions to scan",
                  indent=1, emoji="info")

        # Pre-filter: identify valid interface indices in a clean pass
        # This avoids COM heap corruption from TYPEATTR leaks affecting later entries
        valid_indices = []
        for i in range(count):
            try:
                ti = self.type_lib.GetTypeInfo(i)
                attr = ti.GetTypeAttr()
                is_valid = (attr.typekind == comtypes.typeinfo.TKIND_INTERFACE
                            and attr.cFuncs <= 30 and attr.cImplTypes <= 5)
                ti.ReleaseTypeAttr(attr)
                if is_valid:
                    valid_indices.append(i)
            except Exception:
                pass

        for i in valid_indices:
            attr = None
            try:
                ti = self.type_lib.GetTypeInfo(i)
                attr = ti.GetTypeAttr()

                self.interfaces_scanned += 1
                name, _, _, _ = ti.GetDocumentation(-1)
                iid = str(attr.guid)

                # Release attr early - get_inheritance_chain will do its own GetTypeAttr
                ti.ReleaseTypeAttr(attr)
                attr = None

                self._log(
                    f"Scanning Interface: '{name}' (IID: {iid})", indent=2, verbose_only=True)

                # Get inheritance chain and check for target methods
                chain = self.get_inheritance_chain(ti)
                found_methods = {}

                for iface in chain:
                    for method in iface.methods_defined:
                        if method.name in self.target_methods:
                            # Verify signature using already-parsed method data
                            expected = self.expected_params.get(method.name)
                            param_count = len(method.params)
                            if expected is not None and param_count != expected:
                                continue
                            if method.ret_type != "HRESULT":
                                continue
                            found_methods[method.name] = AnalyzedMethod(
                                name=method.name, ovft=method.ovft, memid=method.memid,
                                defining_interface_name=iface.name,
                                defining_interface_iid=iface.iid
                            )
                            self._log(f"'{method.name}' matched in '{iface.name}'",
                                      indent=4, verbose_only=True, emoji="lightbulb")

                # Check if all target methods found
                if all(m in found_methods for m in self.target_methods):
                    self.interfaces_abe_capable += 1
                    self.results.append(AbeCandidate(
                        clsid=self.discovered_clsid or "Unknown",
                        interface_name=name, interface_iid=iid,
                        methods=found_methods, inheritance_chain_info=chain
                    ))
                    self._log(
                        f"Found ABE-capable: '{name}' (IID: {iid})", indent=2, emoji="info")

            except Exception as e:
                if not isinstance(e, comtypes.COMError):
                    self._log(f"Skipping type definition {i}: {type(e).__name__}: {e}",
                              indent=2, verbose_only=True, emoji="warning")
            finally:
                if attr is not None:
                    try:
                        ti.ReleaseTypeAttr(attr)
                    except Exception:
                        pass

    # -------------------------------------------------------------------------
    # Main Analysis Entry Point
    # -------------------------------------------------------------------------

    def _step_discover(self, scan_mode: bool, browser_key: str, user_clsid: str) -> bool:
        """Discovery step: find service details and CLSID."""
        if scan_mode and browser_key:
            self._log(f"Scan mode enabled for: {browser_key}", emoji="gear")
            if not self.find_service_details(browser_key):
                return False
        if user_clsid:
            self.discovered_clsid = user_clsid
        return True

    def _step_pe_analysis(self):
        """PE analysis step: extract PE structure info."""
        if self.executable_path and pefile:
            self._log("Analyzing PE structure...", indent=1, emoji="gear")
            pe_info = self.analyze_pe_typelib()
            if pe_info.machine_name:
                self._log(f"PE Architecture: {pe_info.machine_name}",
                          indent=2, verbose_only=True, emoji="info")

    def _step_security_analysis(self):
        """Security analysis step: COM security + service DACL."""
        if not self.discovered_clsid:
            return
        self._log("Analyzing COM security settings...", indent=1, emoji="gear")
        sec = self.analyze_com_security(self.discovered_clsid)
        if sec.local_service:
            self._log(f"LocalService: {sec.local_service}",
                      indent=2, verbose_only=True, emoji="info")
            self._log("Analyzing service DACL...", indent=1, emoji="gear")
            svc_sec = self.analyze_service_security(sec.local_service)
            if svc_sec.has_weak_permissions:
                self._log("WEAK SERVICE PERMISSIONS DETECTED!",
                          indent=2, emoji="warning")

    def _log_proxy_dll_security(self, ps: ProxyStubInfo):
        """Log verbose proxy DLL security analysis."""
        if not ps.dll_security or not self.verbose:
            return
        sec = ps.dll_security
        if sec.exists:
            mitigations = [name for flag, name in [
                (sec.aslr, "ASLR"), (sec.high_entropy_aslr, "HiASLR"),
                (sec.dep, "DEP"), (sec.cfg, "CFG")] if flag]
            self._log(f"  Proxy DLL: {ps.proxy_stub_dll}", indent=2, verbose_only=True)
            self._log(f"  Mitigations: {', '.join(mitigations) if mitigations else 'NONE'}",
                      indent=2, verbose_only=True)
            if sec.is_signed:
                sig_status = "VALID" if sec.signature_valid else "INVALID"
                self._log(f"  Signature: {sig_status} ({sec.signer_name})",
                          indent=2, verbose_only=True)
                if not sec.same_signer_as_main:
                    self._log(f"  {EMOJI['warning']} DIFFERENT SIGNER than main executable!",
                              indent=2, verbose_only=True)
            else:
                self._log(f"  Signature: NOT SIGNED", indent=2,
                          verbose_only=True, emoji="warning")
            if not sec.cfg:
                self._log(f"  {EMOJI['warning']} Proxy DLL missing CFG - potential hijack target",
                          indent=2, verbose_only=True)
        elif sec.analysis_error:
            self._log(f"  Proxy DLL analysis error: {sec.analysis_error}",
                      indent=2, verbose_only=True)

    def _step_proxy_stub_analysis(self):
        """Proxy/stub analysis step: check marshaling and find alternatives."""
        if not self.results:
            return
        self._log("Analyzing proxy/stub registration...", indent=1, emoji="gear")
        alternatives_to_add = []
        for r in self.results:
            ps = self.analyze_proxy_stub(r.interface_iid)
            self._log(f"{r.interface_name}: {ps.marshaling_type}",
                      indent=2, verbose_only=True, emoji="info")

            # If marshaling is broken, look for working alternatives
            if "broken" in ps.marshaling_type.lower():
                self._log(f"{EMOJI['warning']} Interface has broken TypeLib registration!",
                          indent=2, emoji="warning")
                if self.type_lib:
                    for i in range(self.type_lib.GetTypeInfoCount()):
                        try:
                            ti = self.type_lib.GetTypeInfo(i)
                            attr = ti.GetTypeAttr()
                            if attr.typekind == comtypes.typeinfo.TKIND_INTERFACE:
                                alt_name, _, _, _ = ti.GetDocumentation(-1)
                                alt_iid = str(attr.guid)
                                if alt_iid != r.interface_iid:
                                    alt_ps = self.analyze_proxy_stub(alt_iid)
                                    if alt_ps.registered and "broken" not in alt_ps.marshaling_type.lower():
                                        if attr.cImplTypes > 0:
                                            try:
                                                ref = ti.GetRefTypeOfImplType(0)
                                                base_ti = ti.GetRefTypeInfo(ref)
                                                base_attr = base_ti.GetTypeAttr()
                                                base_iid = str(base_attr.guid)
                                                base_ti.ReleaseTypeAttr(base_attr)
                                                if base_iid == r.interface_iid:
                                                    self._log(f"{EMOJI['lightbulb']} Alternative: Use {alt_name} (IID: {alt_iid}) - has valid marshaling",
                                                              indent=2, emoji="lightbulb")
                                                    alt_chain = self.get_inheritance_chain(ti)
                                                    alt_candidate = AbeCandidate(
                                                        clsid=self.discovered_clsid or "Unknown",
                                                        interface_name=alt_name,
                                                        interface_iid=alt_iid,
                                                        methods=r.methods,
                                                        inheritance_chain_info=alt_chain
                                                    )
                                                    alternatives_to_add.append(alt_candidate)
                                            except Exception:
                                                pass
                            ti.ReleaseTypeAttr(attr)
                        except Exception:
                            pass

            self._log_proxy_dll_security(ps)

        # Add working alternatives to results
        for alt in alternatives_to_add:
            if not any(r.interface_iid == alt.interface_iid for r in self.results):
                self.results.append(alt)
                self.interfaces_abe_capable += 1

    def analyze(self, scan_mode: bool = False, browser_key: str = None, user_clsid: str = None):
        """Main analysis entry point."""
        comtypes.CoInitialize()
        self.start_time = time.time()

        try:
            if not self._step_discover(scan_mode, browser_key, user_clsid):
                return
            self._step_pe_analysis()
            if not self.load_type_library():
                return
            self.analyze_coclasses()
            self.analyze_interfaces()
            self._step_security_analysis()
            self._step_proxy_stub_analysis()
        finally:
            comtypes.CoUninitialize()

    # -------------------------------------------------------------------------
    # Output Methods
    # -------------------------------------------------------------------------

    def calculate_vtable_layout(self, chain: List[InterfaceInfo]) -> List[VtableSlotInfo]:
        """Calculate vtable layout from inheritance chain."""
        slots = []
        current_slot = 0

        for iface in reversed(chain):
            for method in iface.methods_defined:
                slots.append(VtableSlotInfo(
                    method_name=method.name, slot_index=current_slot,
                    offset_x64=current_slot * 8, offset_x86=current_slot * 4,
                    defining_interface=iface.name, memid=method.memid
                ))
                current_slot += 1

        return slots

    def export_to_json(self, output_file: str) -> bool:
        """Export analysis results to JSON."""
        if not self.results:
            self._log("No results to export", emoji="failure")
            return False

        try:
            data = {
                "metadata": {
                    "tool": "COMrade ABE Analyzer",
                    "version": VERSION,
                    "timestamp": datetime.now().isoformat(),
                    "duration_seconds": time.time() - self.start_time if self.start_time else 0,
                    "browser": self.browser_key or "unknown",
                    "executable": self.executable_path or "unknown"
                },
                "statistics": {
                    "interfaces_scanned": self.interfaces_scanned,
                    "abe_capable_found": self.interfaces_abe_capable,
                    "coclasses_found": len(self.coclasses),
                    "target_methods": self.target_methods
                },
                "discovered_clsid": self.discovered_clsid or "Unknown",
            }

            # PE info
            if self.pe_info:
                data["pe_info"] = {
                    "machine": self.pe_info.machine,
                    "machine_name": self.pe_info.machine_name,
                    "timestamp": self.pe_info.timestamp,
                    "has_typelib": self.pe_info.has_embedded_typelib,
                    "uses_rpc": self.pe_info.uses_rpc,
                    "uses_ole": self.pe_info.uses_ole,
                    "hardening_apis": self.pe_info.hardening_apis,
                    "security_mitigations": {
                        "aslr": self.pe_info.aslr,
                        "high_entropy_aslr": self.pe_info.high_entropy_aslr,
                        "dep": self.pe_info.dep,
                        "cfg": self.pe_info.cfg,
                    },
                    "signature": {
                        "is_signed": self.pe_info.is_signed,
                        "is_valid": self.pe_info.signature_valid,
                        "signer": self.pe_info.signer_name,
                        "error": self.pe_info.signature_error,
                    },
                }

            # Security info
            if self.discovered_clsid:
                sec = self.analyze_com_security(self.discovered_clsid)
                data["security_info"] = {
                    "appid": sec.appid,
                    "local_service": sec.local_service,
                    "runas": sec.runas,
                    "launch_permission_sddl": sec.launch_permission_sddl,
                    "access_permission_sddl": sec.access_permission_sddl,
                }

                if sec.local_service:
                    rt = self.get_service_runtime_status(sec.local_service)
                    data["service_runtime"] = {
                        "status": rt.status, "pid": rt.pid,
                        "start_type": rt.start_type, "dependencies": rt.dependencies,
                    }

            # Service DACL security
            if self.service_security:
                data["service_security"] = {
                    "service_name": self.service_security.service_name,
                    "dacl_sddl": self.service_security.dacl_sddl,
                    "has_weak_permissions": self.service_security.has_weak_permissions,
                    "weak_permission_details": self.service_security.weak_permission_details,
                    "query_error": self.service_security.query_error,
                }

            # Results
            data["results"] = []
            for r in self.results:
                vtable = self.calculate_vtable_layout(r.inheritance_chain_info)
                ps = self.analyze_proxy_stub(r.interface_iid)

                data["results"].append({
                    "interface_name": r.interface_name,
                    "interface_iid": r.interface_iid,
                    "clsid": r.clsid,
                    "methods": {name: {"vtable_offset": m.ovft, "memid": m.memid,
                                       "defining_interface": m.defining_interface_name}
                                for name, m in r.methods.items()},
                    "inheritance_chain": [{"name": i.name, "iid": i.iid,
                                           "base": i.base_interface_name,
                                           "methods": [{"name": md.name,
                                                        "return_type": md.ret_type,
                                                        "params": md.params,
                                                        "vtable_offset": md.ovft,
                                                        "memid": md.memid}
                                                       for md in i.methods_defined]}
                                          for i in r.inheritance_chain_info],
                    "proxy_stub": {
                        "type": ps.marshaling_type,
                        "registered": ps.registered,
                        "dll_path": ps.proxy_stub_dll,
                        "dll_security": {
                            "exists": ps.dll_security.exists,
                            "aslr": ps.dll_security.aslr,
                            "dep": ps.dll_security.dep,
                            "cfg": ps.dll_security.cfg,
                            "high_entropy_aslr": ps.dll_security.high_entropy_aslr,
                            "is_signed": ps.dll_security.is_signed,
                            "signature_valid": ps.dll_security.signature_valid,
                            "signer_name": ps.dll_security.signer_name,
                            "same_signer_as_main": ps.dll_security.same_signer_as_main,
                        } if ps.dll_security else None,
                    },
                    "vtable_slots": len(vtable),
                })

            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            self._log(f"Exported to: {output_file}", emoji="file")
            return True

        except Exception as e:
            self._log(f"Export failed: {e}", emoji="failure")
            return False

    def generate_cpp_stubs(self, chain: List[InterfaceInfo], main_iid: str) -> str:
        """Generate C++ interface stubs."""
        output = ""
        processed = set()

        for iface in reversed(chain):
            if iface.iid in processed:
                continue
            processed.add(iface.iid)

            output += f'MIDL_INTERFACE("{iface.iid}") // {format_guid_for_cpp(iface.iid)}\n'
            output += f"{iface.name} : public {iface.base_interface_name}\n{{\npublic:\n"

            if not iface.methods_defined:
                if iface.name == "IUnknown":
                    output += "    // Standard IUnknown methods\n"
                else:
                    output += "    // No methods defined\n"
            else:
                for m in iface.methods_defined:
                    params = ", ".join(m.params) if m.params else "void"
                    output += f"    virtual {m.ret_type} STDMETHODCALLTYPE {m.name}({params}) = 0;\n"

            output += "};\n\n"

        return output

    def _get_primary_candidate(self) -> 'AbeCandidate':
        """Find the primary candidate based on known IIDs."""
        known_iids = [iid.lower() for iid in KNOWN_PRIMARY_IIDS.get(self.browser_key, [])]
        for r in self.results:
            if r.interface_iid.lower() in known_iids:
                return r
        return self.results[0]

    def _print_summary_header(self):
        browser = (self.browser_key or "unknown").capitalize()
        exe = self.executable_path or "N/A"
        clsid = self.results[0].clsid
        print(f"\n--- {EMOJI['lightbulb']} Analysis Summary ---")
        print(f"  Browser Target    : {browser}")
        print(f"  Service Executable: {exe}")
        print(f"  Discovered CLSID  : {clsid}")
        print(f"      (C++ Style)   : {format_guid_for_cpp(clsid)}")

    def _print_statistics(self):
        if not self.start_time:
            return
        duration = time.time() - self.start_time
        print(f"\n  {EMOJI['gear']} Statistics:")
        print(f"    Analysis Duration : {duration:.2f} seconds")
        print(f"    Interfaces Scanned: {self.interfaces_scanned}")
        print(f"    ABE-Capable Found : {self.interfaces_abe_capable}")
        print(f"    Coclasses Found   : {len(self.coclasses)}")
        if self.interfaces_scanned > 0:
            print(f"    Success Rate      : {(self.interfaces_abe_capable / self.interfaces_scanned) * 100:.1f}%")

    def _print_pe_info(self):
        if not self.pe_info or self.pe_info.pe_error:
            return
        print(f"\n  {EMOJI['file']} PE Information:")
        print(f"    Architecture      : {self.pe_info.machine_name}")
        print(f"    Build Timestamp   : {self.pe_info.timestamp}")
        print(f"    Embedded TypeLib  : {'Yes' if self.pe_info.has_embedded_typelib else 'No'}")
        print(f"    Uses RPC Runtime  : {'Yes' if self.pe_info.uses_rpc else 'No'}")
        print(f"    Uses OLE/OleAut   : {'Yes' if self.pe_info.uses_ole else 'No'}")

    def _print_security_mitigations(self):
        if not self.pe_info or self.pe_info.pe_error:
            return
        print(f"\n  {EMOJI['gear']} Security Mitigations:")
        aslr_status = f"{EMOJI['success']} Enabled" if self.pe_info.aslr else f"{EMOJI['failure']} Disabled"
        dep_status = f"{EMOJI['success']} Enabled" if self.pe_info.dep else f"{EMOJI['failure']} Disabled"
        cfg_status = f"{EMOJI['success']} Enabled" if self.pe_info.cfg else f"{EMOJI['warning']} Disabled"
        high_ent = " (High Entropy)" if self.pe_info.high_entropy_aslr else ""
        print(f"    ASLR              : {aslr_status}{high_ent}")
        print(f"    DEP (NX)          : {dep_status}")
        print(f"    Control Flow Guard: {cfg_status}")

    def _print_digital_signature(self):
        if not self.pe_info or self.pe_info.pe_error:
            return
        print(f"\n  {EMOJI['gear']} Digital Signature:")
        if self.pe_info.is_signed:
            if self.pe_info.signature_valid:
                print(f"    Status            : {EMOJI['success']} Valid signature")
            else:
                print(f"    Status            : {EMOJI['warning']} Invalid - {self.pe_info.signature_error}")
            if self.pe_info.signer_name:
                print(f"    Signer            : {self.pe_info.signer_name}")
        else:
            print(f"    Status            : {EMOJI['failure']} Not signed - {self.pe_info.signature_error or 'No signature'}")

    def _print_hardening_apis(self):
        if not self.pe_info or self.pe_info.pe_error or not self.pe_info.hardening_apis:
            return
        print(f"\n  {EMOJI['warning']} Hardening APIs Detected ({len(self.pe_info.hardening_apis)}):")
        for api in self.pe_info.hardening_apis:
            print(f"    - {api}")

    def _print_com_security(self, show_sddl: bool, show_service_status: bool):
        if not self.discovered_clsid:
            return
        sec = self.analyze_com_security(self.discovered_clsid)
        if not (sec.appid or sec.local_service or sec.runas):
            return
        print(f"\n  {EMOJI['gear']} COM Security Settings:")
        if sec.appid:
            print(f"    AppID             : {sec.appid}")
        if sec.local_service:
            print(f"    LocalService      : {sec.local_service}")
            if show_service_status:
                rt = self.get_service_runtime_status(sec.local_service)
                status_emoji = EMOJI['success'] if rt.status == "running" else EMOJI['info']
                pid_str = f" (PID: {rt.pid})" if rt.pid else ""
                print(f"    Service Status    : {status_emoji} {rt.status}{pid_str}")
                print(f"    Service Start Type: {rt.start_type}")
        if sec.runas:
            print(f"    RunAs             : {sec.runas}")
        if sec.has_launch_permission:
            print(f"    LaunchPermission  : Set ({sec.launch_permission_size} bytes)")
            if show_sddl and sec.launch_permission_sddl:
                print(f"      SDDL: {sec.launch_permission_sddl}")
        if sec.has_access_permission:
            print(f"    AccessPermission  : Set ({sec.access_permission_size} bytes)")
            if show_sddl and sec.access_permission_sddl:
                print(f"      SDDL: {sec.access_permission_sddl}")

        if show_sddl:
            if sec.launch_permission_sddl:
                is_dangerous, warnings = analyze_sddl_dangers(sec.launch_permission_sddl)
                if is_dangerous:
                    print(f"    {EMOJI['warning']} Launch Permission Risks:")
                    for w in warnings:
                        print(f"      - {w}")
            if sec.access_permission_sddl:
                is_dangerous, warnings = analyze_sddl_dangers(sec.access_permission_sddl)
                if is_dangerous:
                    print(f"    {EMOJI['warning']} Access Permission Risks:")
                    for w in warnings:
                        print(f"      - {w}")

    def _print_service_dacl(self, show_sddl: bool):
        if not self.service_security:
            return
        svc_sec = self.service_security
        print(f"\n  {EMOJI['gear']} Service DACL Security:")
        if svc_sec.query_error:
            print(f"    {EMOJI['warning']} Query error: {svc_sec.query_error}")
        elif svc_sec.dacl_sddl:
            if svc_sec.has_weak_permissions:
                print(f"    {EMOJI['failure']} WEAK PERMISSIONS DETECTED:")
                for detail in svc_sec.weak_permission_details:
                    print(f"      - {detail}")
            else:
                print(f"    {EMOJI['success']} No dangerous permissions found")
            if show_sddl:
                print(f"    SDDL: {svc_sec.dacl_sddl}")
        else:
            print(f"    {EMOJI['info']} Unable to query (may require elevation)")

    def _print_coclasses(self):
        if not self.coclasses or not self.verbose:
            return
        print(f"\n  {EMOJI['gear']} Coclasses ({len(self.coclasses)}):")
        for cc in self.coclasses:
            print(f"    {cc.name}: {cc.clsid}")

    def _print_candidates(self):
        primary = self._get_primary_candidate()
        print(f"\n  Found {len(self.results)} ABE-Capable Interface(s):")
        for i, r in enumerate(self.results):
            is_primary = r.interface_iid.lower() == primary.interface_iid.lower()
            marker = f" {EMOJI['lightbulb']} (Likely primary for tool)" if is_primary else ""
            print(f"\n  Candidate {i + 1}:{marker}")
            print(f"    Interface Name: {r.interface_name}")
            print(f"    IID           : {r.interface_iid}")
            print(f"      (C++ Style) : {format_guid_for_cpp(r.interface_iid)}")

    def _print_verbose_details(self):
        if not self.verbose:
            return
        print(f"\n--- {EMOJI['info']} Verbose Candidate Details ---")
        for i, r in enumerate(self.results):
            print(f"\n  --- Candidate {i + 1}: '{r.interface_name}' ---")
            print(f"    Methods (ABE):")
            for name, m in r.methods.items():
                slot = m.ovft // 8
                print(f"      - {name}: VTable Offset {m.ovft} (Slot ~{slot}), in '{m.defining_interface_name}'")
            print(f"    Inheritance: {' -> '.join(iface.name for iface in reversed(r.inheritance_chain_info))}")
            for iface in reversed(r.inheritance_chain_info):
                print(f"      {iface.name} (IID: {iface.iid}) - {len(iface.methods_defined)} method(s)")
                for m in iface.methods_defined:
                    params = ', '.join(m.params) if m.params else 'void'
                    print(f"        - {m.ret_type} {m.name}({params}) (oVft: {m.ovft})")
        print("--- End Verbose Details ---")

    def _write_cpp_stubs(self, output_cpp_file: str):
        primary = self._get_primary_candidate()
        browser = (self.browser_key or "unknown").capitalize()
        self._log(f"\nGenerating C++ stubs for '{primary.interface_name}'...", emoji="gear")
        header = f"// COM Stubs for {browser}\n// Generated by COMrade ABE Analyzer\n"
        header += f"// CLSID: {format_guid_for_cpp(primary.clsid)}\n"
        header += f"// IID: {format_guid_for_cpp(primary.interface_iid)}\n\n"
        content = self.generate_cpp_stubs(primary.inheritance_chain_info, primary.interface_iid)
        try:
            with open(output_cpp_file, 'w', encoding='utf-8') as f:
                f.write(header + content)
            self._log(f"C++ stubs written to: {output_cpp_file}", emoji="success")
        except IOError as e:
            self._log(f"Error writing stubs: {e}", emoji="failure")

    def print_results(self, output_cpp_file: str = None, show_sddl: bool = False,
                      show_service_status: bool = False):
        """Print analysis results."""
        if not self.results:
            self._log("No ABE Interface candidates found.", emoji="failure")
            return

        self._print_summary_header()
        self._print_statistics()
        self._print_pe_info()
        self._print_security_mitigations()
        self._print_digital_signature()
        self._print_hardening_apis()
        self._print_com_security(show_sddl, show_service_status)
        self._print_service_dacl(show_sddl)
        self._print_coclasses()
        self._print_candidates()
        self._print_verbose_details()
        if output_cpp_file:
            self._write_cpp_stubs(output_cpp_file)

    def print_brief(self):
        """Print compact one-line-per-interface summary."""
        if not self.results:
            self._log("No ABE Interface candidates found.", emoji="failure")
            return

        browser = (self.browser_key or "unknown").upper()
        clsid = self.results[0].clsid

        for r in self.results:
            ps = self.analyze_proxy_stub(r.interface_iid)
            marshal_status = "OK" if ps.registered and "broken" not in ps.marshaling_type.lower() else "BROKEN"

            enc_offset = r.methods.get("EncryptData")
            dec_offset = r.methods.get("DecryptData")
            enc_str = f"Enc@{enc_offset.ovft}" if enc_offset else "Enc=?"
            dec_str = f"Dec@{dec_offset.ovft}" if dec_offset else "Dec=?"

            print(f"{browser:<8s}CLSID={clsid}  IID={r.interface_iid}  "
                  f"{r.interface_name:<32s}{enc_str}  {dec_str}  marshal={marshal_status}")

    def print_vtable_layout(self):
        """Print formatted vtable layout for each candidate."""
        if not self.results:
            return

        for r in self.results:
            vtable = self.calculate_vtable_layout(r.inheritance_chain_info)
            if not vtable:
                continue

            # Mark target methods
            target_names = set(self.target_methods)

            print(f"\n  Vtable for {r.interface_name} ({r.interface_iid}):")
            print(f"  {'Slot':>4s}  {'x64':>6s}  {'x86':>4s}  {'Interface':<24s}  Method")
            print(f"  {'----':>4s}  {'------':>6s}  {'----':>4s}  {'-' * 24}  {'------'}")

            for slot in vtable:
                marker = "  <--" if slot.method_name in target_names else ""
                print(f"  {slot.slot_index:4d}  0x{slot.offset_x64:04X}  0x{slot.offset_x86:02X}  "
                      f"{slot.defining_interface:<24s}  {slot.method_name}{marker}")

    def compare_interfaces(self, other_json: str) -> Dict[str, Any]:
        """Compare current results with a previous JSON export with comprehensive diffing."""
        try:
            with open(other_json, 'r', encoding='utf-8') as f:
                other = json.load(f)
        except Exception as e:
            return {"error": str(e)}

        diff = {
            "added_interfaces": [], "removed_interfaces": [],
            "vtable_offset_changes": [], "pe_changes": [],
            "security_changes": []
        }

        current = {r.interface_iid.lower(): r for r in self.results}
        other_results = {r["interface_iid"].lower(): r for r in other.get("results", [])}

        # Added/removed interfaces
        for iid, r in current.items():
            if iid not in other_results:
                diff["added_interfaces"].append(
                    {"name": r.interface_name, "iid": r.interface_iid})

        for iid, r in other_results.items():
            if iid not in current:
                diff["removed_interfaces"].append(
                    {"name": r["interface_name"], "iid": r["interface_iid"]})

        # Vtable offset changes for shared interfaces
        for iid in current:
            if iid not in other_results:
                continue
            cur_r = current[iid]
            old_r = other_results[iid]
            old_methods = old_r.get("methods", {})
            for method_name, cur_m in cur_r.methods.items():
                if method_name in old_methods:
                    old_offset = old_methods[method_name].get("vtable_offset")
                    if old_offset is not None and old_offset != cur_m.ovft:
                        diff["vtable_offset_changes"].append(
                            f"{cur_r.interface_name}.{method_name}: offset {old_offset} -> {cur_m.ovft}")

        # PE info changes
        old_pe = other.get("pe_info", {})
        if old_pe and self.pe_info:
            old_mits = old_pe.get("security_mitigations", {})
            for key, label in [("aslr", "ASLR"), ("dep", "DEP"), ("cfg", "CFG"),
                               ("high_entropy_aslr", "High Entropy ASLR")]:
                old_val = old_mits.get(key)
                new_val = getattr(self.pe_info, key, None)
                if old_val is not None and new_val is not None and old_val != new_val:
                    diff["pe_changes"].append(f"PE {label}: {old_val} -> {new_val}")

            old_sig = old_pe.get("signature", {})
            if old_sig.get("signer") != self.pe_info.signer_name:
                diff["pe_changes"].append(
                    f"PE signer: {old_sig.get('signer')} -> {self.pe_info.signer_name}")
            old_arch = old_pe.get("machine_name")
            if old_arch and old_arch != self.pe_info.machine_name:
                diff["pe_changes"].append(
                    f"PE architecture: {old_arch} -> {self.pe_info.machine_name}")

        # Security posture changes
        old_sec = other.get("security_info", {})
        if old_sec and self.discovered_clsid:
            cur_sec = self.analyze_com_security(self.discovered_clsid)
            if old_sec.get("local_service") != cur_sec.local_service:
                diff["security_changes"].append(
                    f"LocalService: {old_sec.get('local_service')} -> {cur_sec.local_service}")
            if old_sec.get("launch_permission_sddl") != cur_sec.launch_permission_sddl:
                diff["security_changes"].append("Launch permission SDDL changed")
            if old_sec.get("access_permission_sddl") != cur_sec.access_permission_sddl:
                diff["security_changes"].append("Access permission SDDL changed")

        return diff


# =============================================================================
# CLI Entry Point
# =============================================================================

def print_banner():
    print(r"""
-------------------------------------------------------------------------------------------

_________  ________      _____                    .___          _____ _____________________
\_   ___ \ \_____  \    /     \____________     __| _/____     /  _  \\______   \_   _____/
/    \  \/  /   |   \  /  \ /  \_  __ \__  \   / __ |/ __ \   /  /_\  \|    |  _/|    __)_
\     \____/    |    \/    Y    \  | \// __ \_/ /_/ \  ___/  /    |    \    |   \|        \
 \______  /\_______  /\____|__  /__|  (____  /\____ |\___  > \____|__  /______  /_______  /
        \/         \/         \/           \/      \/    \/          \/       \/        \/

                  by Alexander 'xaitax' Hagenah  |  v""" + VERSION + r"""
-------------------------------------------------------------------------------------------
    """)


def _parse_args():
    """Parse command-line arguments."""
    examples = """
Examples:
  %(prog)s chrome                    Analyze Chrome elevation service
  %(prog)s edge -d                   Analyze Edge with SDDL + service details
  %(prog)s brave -v -o out.json      Verbose analysis, export to JSON
  %(prog)s avast                     Analyze Avast Secure Browser elevation service
  %(prog)s all                       Scan all installed browsers
  %(prog)s all --brief               One-liner per browser
  %(prog)s discover                  List all elevation services
  %(prog)s search Google             Search TypeLibs by name
  %(prog)s chrome --vtable           Show full vtable layout
  %(prog)s chrome --compare old.json Compare with previous analysis
  %(prog)s "C:\\path\\to\\exe"         Analyze specific executable
"""

    parser = argparse.ArgumentParser(
        usage="%(prog)s <target> [options]",
        description="COMrade ABE: Discover and analyze COM ABE interfaces in Chromium browsers.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=examples
    )

    # Positional arguments
    parser.add_argument("target", metavar="TARGET",
                        help="chrome|edge|brave|avast|all, 'discover', 'search', or path to executable")
    parser.add_argument("pattern", nargs="?", default=None,
                        help="Search pattern (only used with 'search' command)")

    # Common options
    parser.add_argument("-d", "--details", action="store_true",
                        help="Show SDDL and service status details")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose output")
    parser.add_argument("-o", "--output", metavar="FILE_OR_DIR",
                        help="Export results to JSON (file or directory for 'all')")
    parser.add_argument("--cpp", metavar="FILE",
                        help="Generate C++ interface stubs")
    parser.add_argument("--compare", metavar="FILE",
                        help="Compare with previous JSON export")
    parser.add_argument("--clsid", metavar="CLSID",
                        help="Manually specify CLSID")
    parser.add_argument("--log", metavar="FILE",
                        help="Write logs to file")
    parser.add_argument("--brief", action="store_true",
                        help="Compact one-line-per-interface output")
    parser.add_argument("--vtable", action="store_true",
                        help="Show full vtable layout for each candidate")

    # Advanced options (hidden from main help)
    advanced = parser.add_argument_group("advanced options")
    advanced.add_argument("--methods", default="DecryptData,EncryptData",
                          help=argparse.SUPPRESS)
    advanced.add_argument("--decrypt-params", type=int, default=3,
                          help=argparse.SUPPRESS)
    advanced.add_argument("--encrypt-params", type=int, default=4,
                          help=argparse.SUPPRESS)

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    return parser.parse_args(), parser


def _check_platform():
    """Ensure we're running on Windows."""
    if sys.platform != "win32":
        print(f"{EMOJI['failure']} This script requires Windows.")
        sys.exit(1)


def _check_admin():
    """Warn if not running as admin."""
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if not is_admin:
            print(f"{EMOJI['warning']} Running as standard user. Service DACL checks may be incomplete.")
    except Exception:
        pass


def _create_analyzer(args) -> 'ComInterfaceAnalyzer':
    """Create analyzer instance from parsed args."""
    return ComInterfaceAnalyzer(
        verbose=args.verbose,
        target_method_names=[m.strip() for m in args.methods.split(',')],
        expected_decrypt_params=args.decrypt_params,
        expected_encrypt_params=args.encrypt_params,
        log_file=args.log
    )


def _cmd_discover(args):
    """Execute the 'discover' command."""
    analyzer = _create_analyzer(args)
    print(f"\n{EMOJI['search']} Discovering all elevation services...")
    comtypes.CoInitialize()
    try:
        services = analyzer.discover_elevation_services()
        if services:
            print(f"\n{EMOJI['success']} Found {len(services)} elevation service(s):\n")
            for svc in services:
                print(f"  {EMOJI['gear']} {svc.service_name}")
                print(f"      Browser Vendor : {svc.browser_vendor}")
                if svc.display_name:
                    print(f"      Display Name   : {svc.display_name}")
                if svc.executable_path:
                    print(f"      Executable     : {svc.executable_path}")
                if svc.start_type:
                    print(f"      Start Type     : {svc.start_type}")
                if svc.status:
                    emoji = EMOJI['success'] if svc.status == "running" else EMOJI['info']
                    pid = f" (PID: {svc.pid})" if svc.pid else ""
                    print(f"      Status         : {emoji} {svc.status}{pid}")
                print()
        else:
            print(f"{EMOJI['warning']} No elevation services found.")
    finally:
        comtypes.CoUninitialize()
    print(f"{EMOJI['success']} Discovery complete.")


def _cmd_search(args, parser):
    """Execute the 'search' command."""
    if not args.pattern:
        parser.error("'search' requires a pattern. Usage: comrade_abe.py search <pattern>")
    analyzer = _create_analyzer(args)
    print(f"\n{EMOJI['search']} Searching TypeLibs matching '{args.pattern}'...")
    comtypes.CoInitialize()
    try:
        typelibs = analyzer.search_typelibs_by_pattern(args.pattern)
        if typelibs:
            print(f"\n{EMOJI['success']} Found {len(typelibs)} matching TypeLib(s):\n")
            for tl in typelibs:
                print(f"  {EMOJI['file']} {tl.name}")
                print(f"      TypeLib ID : {tl.typelib_id}")
                print(f"      Version    : {tl.version}")
                if tl.win64_path:
                    print(f"      Win64 Path : {tl.win64_path}")
                elif tl.win32_path:
                    print(f"      Win32 Path : {tl.win32_path}")
                print()
        else:
            print(f"{EMOJI['warning']} No TypeLibs found matching '{args.pattern}'.")
    finally:
        comtypes.CoUninitialize()
    print(f"{EMOJI['success']} TypeLib search complete.")


def _cmd_analyze(args, parser):
    """Execute analysis for a single browser or executable path."""
    analyzer = _create_analyzer(args)
    target_lower = args.target.lower()
    browser_keys = list(BROWSER_SERVICES.keys())

    if target_lower in browser_keys:
        analyzer.analyze(scan_mode=True, browser_key=args.target, user_clsid=args.clsid)
    elif os.path.exists(args.target):
        analyzer.executable_path = args.target
        if args.clsid:
            analyzer.discovered_clsid = args.clsid
            analyzer.browser_key = "manual"
        else:
            path_lower = args.target.lower()
            if "google" in path_lower and "chrome" in path_lower:
                analyzer.browser_key = "chrome"
            elif "microsoft" in path_lower and "edge" in path_lower:
                analyzer.browser_key = "edge"
            elif "brave" in path_lower:
                analyzer.browser_key = "brave"
            elif "avast" in path_lower:
                analyzer.browser_key = "avast"
        analyzer.analyze(user_clsid=args.clsid)
    else:
        parser.error(
            f"Unknown target '{args.target}'. Use chrome|edge|brave|avast|all, 'discover', 'search', or a valid path.")

    _output_results(analyzer, args)


def _cmd_all(args):
    """Execute analysis for all installed browsers."""
    browser_keys = list(BROWSER_SERVICES.keys())

    # Determine output directory if -o points to a directory
    output_dir = None
    if args.output:
        if os.path.isdir(args.output) or args.output.endswith(os.sep) or args.output.endswith('/'):
            output_dir = args.output
            os.makedirs(output_dir, exist_ok=True)

    for browser_key in browser_keys:
        print(f"\n{'=' * 60}")
        print(f"  {EMOJI['gear']} Scanning: {browser_key.upper()}")
        print(f"{'=' * 60}")

        analyzer = _create_analyzer(args)
        analyzer.analyze(scan_mode=True, browser_key=browser_key, user_clsid=args.clsid)

        if args.brief:
            analyzer.print_brief()
        else:
            analyzer.print_results(
                output_cpp_file=args.cpp,
                show_sddl=args.details,
                show_service_status=args.details
            )

        # Export JSON per browser
        if analyzer.results:
            if output_dir:
                json_path = os.path.join(output_dir, f"{browser_key}_data.json")
                analyzer.export_to_json(json_path)
            elif args.output and not output_dir:
                # Single file output: only export first browser with results
                analyzer.export_to_json(args.output)
                args.output = None  # Prevent overwriting

    print(f"\n{EMOJI['success']} All-browser scan complete.")


def _output_results(analyzer: 'ComInterfaceAnalyzer', args):
    """Print results, export JSON, and run comparison."""
    if args.brief:
        analyzer.print_brief()
    else:
        analyzer.print_results(
            output_cpp_file=args.cpp,
            show_sddl=args.details,
            show_service_status=args.details
        )

    if args.vtable and analyzer.results:
        analyzer.print_vtable_layout()

    if args.output and analyzer.results:
        analyzer.export_to_json(args.output)

    if args.compare and analyzer.results:
        _cmd_compare(analyzer, args.compare)

    print(f"\n{EMOJI['success']} Analysis complete.")


def _cmd_compare(analyzer: 'ComInterfaceAnalyzer', compare_file: str):
    """Run comparison against previous JSON export."""
    print(f"\n{EMOJI['search']} Comparing with: {compare_file}")
    if not os.path.exists(compare_file):
        print(f"  {EMOJI['failure']} File not found: {compare_file}")
        return

    diff = analyzer.compare_interfaces(compare_file)
    if "error" in diff:
        print(f"  {EMOJI['failure']} Error: {diff['error']}")
    elif not any(diff.values()):
        print(f"  {EMOJI['success']} No changes detected.")
    else:
        print(f"\n  {EMOJI['warning']} Changes detected:")
        for iface in diff.get("added_interfaces", []):
            print(f"    + {iface['name']} ({iface['iid']})")
        for iface in diff.get("removed_interfaces", []):
            print(f"    - {iface['name']} ({iface['iid']})")
        for change in diff.get("vtable_offset_changes", []):
            print(f"    ~ {change}")
        for change in diff.get("pe_changes", []):
            print(f"    ~ {change}")
        for change in diff.get("security_changes", []):
            print(f"    ~ {change}")


def main():
    print_banner()
    args, parser = _parse_args()
    _check_platform()

    print(f"{EMOJI['gear']} COM ABE Interface Analyzer Initializing...")
    _check_admin()

    target = args.target.lower()
    if target == "discover":
        _cmd_discover(args)
    elif target == "search":
        _cmd_search(args, parser)
    elif target == "all":
        _cmd_all(args)
    else:
        _cmd_analyze(args, parser)


if __name__ == "__main__":
    main()
