import os
import re
import struct
import logging

import requests as http_requests

from ..config import UPLOAD_DIR, SYMBOL_CACHE

log = logging.getLogger(__name__)

PEFILE_AVAILABLE = False
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    pass

SYSTEM_DLLS = {
    "ntdll.dll", "kernel32.dll", "kernelbase.dll", "advapi32.dll",
    "user32.dll", "gdi32.dll", "ws2_32.dll", "msvcrt.dll", "ucrtbase.dll",
    "combase.dll", "ole32.dll", "oleaut32.dll", "rpcrt4.dll", "sechost.dll",
    "shell32.dll", "shlwapi.dll", "crypt32.dll", "bcrypt.dll", "ncrypt.dll",
    "setupapi.dll", "cfgmgr32.dll", "wintrust.dll", "mscoree.dll",
    "ntoskrnl.exe", "hal.dll", "fltmgr.sys", "ci.dll", "clfs.sys",
    "msvcp_win.dll", "win32u.dll", "imm32.dll", "comdlg32.dll",
    "version.dll", "winhttp.dll", "wininet.dll", "urlmon.dll",
    "psapi.dll", "dbghelp.dll", "iphlpapi.dll", "dnsapi.dll",
    "netapi32.dll", "wtsapi32.dll", "userenv.dll", "profapi.dll",
    "powrprof.dll", "sspicli.dll", "cryptbase.dll", "mswsock.dll",
    "nsi.dll", "wldap32.dll", "samlib.dll", "samcli.dll",
    "api-ms-win-crt-runtime-l1-1-0.dll", "api-ms-win-crt-heap-l1-1-0.dll",
    "api-ms-win-crt-stdio-l1-1-0.dll", "api-ms-win-crt-string-l1-1-0.dll",
    "api-ms-win-crt-math-l1-1-0.dll", "api-ms-win-crt-locale-l1-1-0.dll",
    "api-ms-win-crt-time-l1-1-0.dll", "api-ms-win-crt-convert-l1-1-0.dll",
    "api-ms-win-crt-environment-l1-1-0.dll",
    "api-ms-win-crt-filesystem-l1-1-0.dll",
    "api-ms-win-crt-utility-l1-1-0.dll",
    "api-ms-win-crt-multibyte-l1-1-0.dll",
    "api-ms-win-crt-process-l1-1-0.dll",
    "api-ms-win-core-synch-l1-1-0.dll",
    "api-ms-win-core-synch-l1-2-0.dll",
    "vcruntime140.dll", "vcruntime140d.dll",
    "msvcp140.dll", "msvcp140d.dll",
    "concrt140.dll", "vcomp140.dll",
}


def _is_system_dll(name):
    low = name.lower()
    if low in SYSTEM_DLLS:
        return True
    if low.startswith("api-ms-win-"):
        return True
    if low.startswith("ext-ms-"):
        return True
    return False


def get_pdb_info(binary_path):
    """Extract PDB GUID, age, and filename from a PE file."""
    if not PEFILE_AVAILABLE:
        return None, None, None
    try:
        pe = pefile.PE(binary_path, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]
        ])
        for entry in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
            if entry.struct.Type == 2:
                data = pe.get_data(entry.struct.AddressOfRawData,
                                   entry.struct.SizeOfData)
                if data[:4] == b"RSDS":
                    guid_raw = data[4:20]
                    age = struct.unpack("<I", data[20:24])[0]
                    pdb_name = data[24:].split(b"\x00")[0].decode("utf-8")
                    a, b, c = struct.unpack("<IHH", guid_raw[:8])
                    d = guid_raw[8:].hex().upper()
                    guid = f"{a:08X}{b:04X}{c:04X}{d}"
                    pe.close()
                    return pdb_name, guid, age
        pe.close()
    except Exception as e:
        log.warning("PDB info extraction failed: %s", e)
    return None, None, None


def download_symbols(binary_path):
    """Download PDB from Microsoft Symbol Server. Returns local path or None."""
    pdb_name, guid, age = get_pdb_info(binary_path)
    if not pdb_name or not guid:
        log.info("No PDB info found in %s", binary_path)
        return None

    pdb_local = os.path.join(SYMBOL_CACHE, pdb_name)
    if os.path.exists(pdb_local):
        log.info("PDB already cached: %s", pdb_local)
        return pdb_local

    urls = [
        f"https://msdl.microsoft.com/download/symbols/{pdb_name}/{guid}{age}/{pdb_name}",
        f"https://msdl.microsoft.com/download/symbols/{pdb_name}/{guid}{age}/{pdb_name[:-1]}_",
    ]

    for url in urls:
        try:
            log.info("Downloading PDB: %s", url)
            resp = http_requests.get(url, timeout=60,
                                     headers={"User-Agent": "Microsoft-Symbol-Server/10.0"})
            if resp.status_code == 200 and len(resp.content) > 100:
                with open(pdb_local, "wb") as fh:
                    fh.write(resp.content)
                log.info("PDB downloaded: %s (%d bytes)", pdb_local, len(resp.content))
                return pdb_local
        except Exception as e:
            log.warning("PDB download failed for %s: %s", url, e)

    log.info("Could not download PDB for %s", binary_path)
    return None


def _build_system_search_paths():
    """Build a list of directories where DLLs could reasonably live on this system."""
    dirs = set()

    windir = os.environ.get("WINDIR") or os.environ.get("SystemRoot") or r"C:\Windows"
    for sub in ("System32", "SysWOW64", "system", ""):
        candidate = os.path.join(windir, sub) if sub else windir
        if os.path.isdir(candidate):
            dirs.add(candidate)

    for p in os.environ.get("PATH", "").split(os.pathsep):
        p = p.strip().strip('"')
        if p and os.path.isdir(p):
            dirs.add(p)

    return dirs


def _dll_exists_on_system(name, search_dirs):
    """Check if a DLL can be found in any of the system search directories."""
    low = name.lower()
    for d in search_dirs:
        candidate = os.path.join(d, name)
        if os.path.isfile(candidate):
            return True
        candidate_low = os.path.join(d, low)
        if os.path.isfile(candidate_low):
            return True
    return False


def _find_dll_on_system(name, search_dirs):
    """Return the absolute path to a DLL found on the system, or None."""
    low = name.lower()
    for d in search_dirs:
        for candidate in (os.path.join(d, name), os.path.join(d, low)):
            if os.path.isfile(candidate):
                return candidate
    return None


def scan_pe_imports(binary_path):
    """Parse PE import table, return non-system DLLs not found anywhere on the system.
    Used by the standard upload flow."""
    if not PEFILE_AVAILABLE:
        return []
    try:
        pe = pefile.PE(binary_path, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
        ])
    except Exception as e:
        log.warning("PE import scan failed: %s", e)
        return []

    dll_names = set()
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll_names.add(entry.dll.decode("utf-8", errors="replace"))
    for entry in getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []):
        dll_names.add(entry.dll.decode("utf-8", errors="replace"))
    pe.close()

    binary_dir = os.path.dirname(binary_path)
    system_dirs = _build_system_search_paths()

    missing = []
    for name in sorted(dll_names):
        if _is_system_dll(name):
            continue
        if os.path.isfile(os.path.join(binary_dir, name)):
            continue
        if os.path.isfile(os.path.join(UPLOAD_DIR, name)):
            continue
        if _dll_exists_on_system(name, system_dirs):
            continue
        missing.append(name)

    log.info("PE import scan: %d DLLs imported, %d truly missing after system search", len(dll_names), len(missing))
    return missing


def scan_pe_imports_full(binary_path):
    """Return EVERY DLL the PE imports along with where it was found on this system.

    Used by Full Map Analysis mode where we want to analyze each linked DLL too.
    Each entry: {"name", "found_at" (abs path or None), "is_system" (bool — well-known
    Windows DLL), "size_bytes" (when found_at is set)}.
    """
    if not PEFILE_AVAILABLE:
        return []
    try:
        pe = pefile.PE(binary_path, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
        ])
    except Exception as e:
        log.warning("PE import scan failed: %s", e)
        return []

    dll_names = set()
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll_names.add(entry.dll.decode("utf-8", errors="replace"))
    for entry in getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []):
        dll_names.add(entry.dll.decode("utf-8", errors="replace"))
    pe.close()

    binary_dir = os.path.dirname(binary_path)
    system_dirs = _build_system_search_paths()
    search_order = [binary_dir] + list(system_dirs)

    results = []
    for name in sorted(dll_names):
        found_at = _find_dll_on_system(name, search_order)
        size = None
        if found_at:
            try:
                size = os.path.getsize(found_at)
            except OSError:
                size = None
        results.append({
            "name": name,
            "found_at": found_at,
            "is_system": _is_system_dll(name),
            "size_bytes": size,
        })

    found = sum(1 for r in results if r["found_at"])
    log.info("Full PE import scan: %d imports total, %d auto-resolvable from system paths",
             len(results), found)
    return results


def _get_pe_image_base(data):
    """Extract ImageBase from PE optional header."""
    try:
        if data[:2] != b"MZ":
            return 0
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        magic = struct.unpack_from("<H", data, pe_offset + 0x18)[0]
        if magic == 0x20B:  # PE32+
            return struct.unpack_from("<Q", data, pe_offset + 0x30)[0]
        elif magic == 0x10B:  # PE32
            return struct.unpack_from("<I", data, pe_offset + 0x34)[0]
    except Exception:
        pass
    return 0


def extract_strings_raw(binary_path, min_len=5):
    """Fallback raw binary string scan (ASCII + UTF-16LE)."""
    results = []
    try:
        with open(binary_path, "rb") as f:
            data = f.read()

        image_base = _get_pe_image_base(data)

        for m in re.finditer(rb"[\x20-\x7E]{%d,}" % min_len, data):
            results.append({"text": m.group().decode("ascii", errors="replace"),
                            "address_hex": hex(image_base + m.start()), "xref_count": 0})

        i = 0
        end_limit = len(data) - min_len * 2
        while i < end_limit:
            if 0x20 <= data[i] <= 0x7E and data[i + 1] == 0:
                end = i + 2
                while end < len(data) - 1 and 0x20 <= data[end] <= 0x7E and data[end + 1] == 0:
                    end += 2
                length = (end - i) // 2
                if length >= min_len:
                    try:
                        s = data[i:end].decode("utf-16-le")
                        if s not in {r["text"] for r in results[-20:]}:
                            results.append({"text": s, "address_hex": hex(image_base + i), "xref_count": 0})
                    except Exception:
                        pass
                i = end
            else:
                i += 1
    except Exception as e:
        log.warning("Raw string extraction failed: %s", e)
    return results
