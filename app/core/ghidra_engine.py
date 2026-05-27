import os
import shutil
import logging

from ..config import GHIDRA_INSTALL, PROJECT_DIR
from .pe_utils import extract_strings_raw

log = logging.getLogger(__name__)

GHIDRA_AVAILABLE = False

try:
    import pyghidra
    if not pyghidra.started():
        log.info("Starting pyghidra with Ghidra at %s ...", GHIDRA_INSTALL)
        pyghidra.start(install_dir=GHIDRA_INSTALL)
    GHIDRA_AVAILABLE = True
    log.info("pyghidra initialized successfully")
except Exception as e:
    log.warning("pyghidra initialization failed: %s", e)


def _clean_ghidra_locks(project_dir, project_name):
    nested = os.path.join(project_dir, project_name)
    if os.path.isdir(nested):
        for f in os.listdir(nested):
            if f.endswith(".lock") or f.endswith(".lock~"):
                try:
                    os.remove(os.path.join(nested, f))
                except OSError:
                    pass


def _open_ghidra_program(binary_path, project_name, analyze=False):
    if not GHIDRA_AVAILABLE:
        raise RuntimeError("pyghidra is not available")
    _clean_ghidra_locks(PROJECT_DIR, project_name)
    return pyghidra.open_program(
        binary_path,
        project_location=PROJECT_DIR,
        project_name=project_name,
        analyze=analyze,
    )


def _purge_ghidra_project(project_dir, project_name):
    """Remove an existing Ghidra project so the next open_program starts fresh."""
    nested = os.path.join(project_dir, project_name)
    if os.path.isdir(nested):
        log.info("Purging stale Ghidra project: %s", nested)
        shutil.rmtree(nested, ignore_errors=True)
    gpr = os.path.join(project_dir, project_name + ".gpr")
    if os.path.isfile(gpr):
        try:
            os.remove(gpr)
        except OSError:
            pass


def ghidra_full_analysis(binary_path, project_name, linked_libraries=None):
    """Run full Ghidra analysis and extract all metadata."""
    log.info("Running Ghidra analysis for %s (project: %s)", binary_path, project_name)
    _purge_ghidra_project(PROJECT_DIR, project_name)

    with _open_ghidra_program(binary_path, project_name, analyze=True) as flat_api:
        program = flat_api.getCurrentProgram()

        if linked_libraries:
            ext_mgr = program.getExternalManager()
            for lib_name, lib_path in linked_libraries.items():
                try:
                    abs_path = os.path.abspath(lib_path).replace("\\", "/")
                    if abs_path[1:3] == ":/":
                        abs_path = "/" + abs_path
                    ext_mgr.setExternalPath(lib_name, abs_path, True)
                    log.info("Linked external library: %s -> %s", lib_name, abs_path)
                except Exception as e:
                    log.warning("Failed to link library %s: %s", lib_name, e)

            from ghidra.util.task import ConsoleTaskMonitor as _CM
            try:
                from ghidra.app.plugin.core.analysis import AutoAnalysisManager
                mgr = AutoAnalysisManager.getAnalysisManager(program)
                mgr.reAnalyzeAll(program.getMemory().getLoadedAndInitializedAddressSet())
                mgr.startAnalysis(_CM())
                log.info("Re-analysis with linked libraries completed")
            except Exception as e:
                log.warning("Re-analysis after library linking failed: %s", e)

        from ghidra.app.decompiler import DecompInterface  # noqa: F811
        from ghidra.util.task import ConsoleTaskMonitor

        lang = program.getLanguage()
        arch = str(lang.getLanguageID())
        compiler_spec = str(program.getCompilerSpec().getCompilerSpecID())
        base_addr = str(program.getImageBase())
        entry_sym = program.getSymbolTable().getExternalEntryPointIterator()
        first_entry = str(next(iter(entry_sym), "unknown"))

        fm = program.getFunctionManager()
        rm = program.getReferenceManager()
        listing = program.getListing()
        monitor = ConsoleTaskMonitor()

        functions = []
        func_iter = fm.getFunctions(True)
        for func in func_iter:
            addr = func.getEntryPoint()
            name = func.getName()
            size = func.getBody().getNumAddresses() if func.getBody() else 0
            is_ext = func.isExternal()
            is_thunk = func.isThunk()
            functions.append({
                "name": name,
                "address_hex": str(addr),
                "size": int(size),
                "is_import": is_ext or is_thunk,
                "is_named": not name.startswith("FUN_") and not name.startswith("sub_"),
            })
        log.info("Extracted %d functions", len(functions))

        imports = []
        try:
            ext_iter = fm.getExternalFunctions()
            for efunc in ext_iter:
                loc = efunc.getExternalLocation()
                lib = str(loc.getLibraryName()) if loc else "unknown"
                imports.append({
                    "name": efunc.getName(),
                    "library": lib,
                    "address_hex": str(efunc.getEntryPoint()),
                })
        except Exception as e:
            log.warning("Import extraction failed: %s", e)
        log.info("Extracted %d imports", len(imports))

        exports = []
        try:
            ep_iter = program.getSymbolTable().getExternalEntryPointIterator()
            for addr in ep_iter:
                func = fm.getFunctionAt(addr)
                name = func.getName() if func else str(addr)
                exports.append({
                    "name": name,
                    "address_hex": str(addr),
                })
        except Exception as e:
            log.warning("Export extraction failed: %s", e)
        log.info("Extracted %d exports", len(exports))

        strings = []
        try:
            data_iter = listing.getDefinedData(
                program.getMemory().getLoadedAndInitializedAddressSet(), True
            )
            while data_iter.hasNext():
                data = data_iter.next()
                dt = data.getDataType()
                if dt is None:
                    continue
                type_name = dt.getName().lower()
                if "string" not in type_name and "unicode" not in type_name:
                    continue
                val = data.getValue()
                if val is None:
                    continue
                text = str(val)
                if len(text) >= 4:
                    strings.append({
                        "text": text,
                        "address_hex": str(data.getAddress()),
                        "xref_count": int(rm.getReferenceCountTo(data.getAddress())),
                    })
        except Exception as e:
            log.warning("Ghidra string extraction failed: %s", e)

        if len(strings) < 10:
            log.info("Ghidra found only %d strings, running fallback raw scan...", len(strings))
            raw_strings = extract_strings_raw(binary_path)
            seen_texts = {s["text"] for s in strings}
            for rs in raw_strings:
                if rs["text"] not in seen_texts:
                    strings.append(rs)
                    seen_texts.add(rs["text"])
        log.info("Extracted %d strings total", len(strings))

        result = {
            "arch": arch,
            "compiler": compiler_spec,
            "base_addr": base_addr,
            "entry_point": first_entry,
            "functions": functions,
            "imports": imports,
            "exports": exports,
            "strings": strings,
        }

    return result


def ghidra_decompile(binary_path, project_name, func_addr_str):
    """Decompile a single function using Ghidra."""
    with _open_ghidra_program(binary_path, project_name, analyze=False) as flat_api:
        program = flat_api.getCurrentProgram()
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor

        fm = program.getFunctionManager()
        addr = flat_api.toAddr(func_addr_str)
        func = fm.getFunctionAt(addr)
        if not func:
            func = fm.getFunctionContaining(addr)
        if not func:
            return "// Function not found at " + func_addr_str

        decomp = DecompInterface()
        decomp.openProgram(program)
        monitor = ConsoleTaskMonitor()

        results = decomp.decompileFunction(func, 120, monitor)
        decomp.dispose()

        if results and results.decompileCompleted():
            df = results.getDecompiledFunction()
            if df:
                return str(df.getC())
        error = results.getErrorMessage() if results else "unknown error"
        return f"// Decompilation failed: {error}"


def ghidra_batch_decompile(binary_path, project_name, addresses, timeout_seconds=60):
    """Decompile many functions in one Ghidra session.

    Opens the program once, reuses a single DecompInterface across all calls — much
    faster than calling ghidra_decompile() N times for the same project. Used by the
    grep tool when many uncached functions need to be decompiled to scan.

    Returns: {addr_str: pseudocode} for every successfully-decompiled address.
    """
    if not addresses:
        return {}
    results = {}
    with _open_ghidra_program(binary_path, project_name, analyze=False) as flat_api:
        program = flat_api.getCurrentProgram()
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor

        fm = program.getFunctionManager()
        decomp = DecompInterface()
        decomp.openProgram(program)
        monitor = ConsoleTaskMonitor()

        try:
            for addr_str in addresses:
                try:
                    addr = flat_api.toAddr(addr_str)
                    func = fm.getFunctionAt(addr) or fm.getFunctionContaining(addr)
                    if not func:
                        continue
                    res = decomp.decompileFunction(func, timeout_seconds, monitor)
                    if res and res.decompileCompleted():
                        df = res.getDecompiledFunction()
                        if df:
                            results[addr_str] = str(df.getC())
                except Exception:
                    log.exception("Batch decompile failed for %s", addr_str)
        finally:
            decomp.dispose()
    return results


def ghidra_get_function_variables(binary_path, project_name, func_addr_str):
    """Return {params, locals} for a function, INCLUDING decompiler-generated names.

    Listing-level params/locals only cover named/typed variables. The decompiler also
    introduces synthetic names like iVar1, plVar2, local_28, auStackY_88, hModule, etc.
    To capture all of these we decompile once and read HighFunction.getLocalSymbolMap()
    — that's the symbol set the user actually sees in the pseudocode view.
    """
    with _open_ghidra_program(binary_path, project_name, analyze=False) as flat_api:
        program = flat_api.getCurrentProgram()
        fm = program.getFunctionManager()
        addr = flat_api.toAddr(func_addr_str)
        func = fm.getFunctionAt(addr) or fm.getFunctionContaining(addr)
        if not func:
            return None

        params = []
        locals_ = []
        seen_names = set()

        # Pull every symbol the decompiler is rendering — superset of listing locals/params
        try:
            from ghidra.app.decompiler import DecompInterface
            from ghidra.util.task import ConsoleTaskMonitor

            decomp = DecompInterface()
            decomp.openProgram(program)
            try:
                res = decomp.decompileFunction(func, 60, ConsoleTaskMonitor())
                if res and res.decompileCompleted():
                    high_func = res.getHighFunction()
                    if high_func is not None:
                        sym_map = high_func.getLocalSymbolMap()
                        for sym in sym_map.getSymbols():
                            try:
                                name = str(sym.getName())
                                if not name or name in seen_names:
                                    continue
                                seen_names.add(name)
                                dt = sym.getDataType()
                                type_name = str(dt.getName()) if dt is not None else ""
                                entry = {"name": name, "type": type_name}
                                if sym.isParameter():
                                    entry["ordinal"] = int(sym.getCategoryIndex())
                                    params.append(entry)
                                else:
                                    locals_.append(entry)
                            except Exception:
                                pass
            finally:
                decomp.dispose()
        except Exception:
            log.exception("HighFunction symbol enumeration failed for %s", func_addr_str)

        # Fall back / supplement with listing-level params and locals (covers names that
        # were set at the function-signature level and may not always reach HighFunction)
        try:
            for p in func.getParameters():
                name = str(p.getName())
                if name and name not in seen_names:
                    seen_names.add(name)
                    params.append({
                        "name": name,
                        "type": str(p.getDataType().getName()) if p.getDataType() else "",
                        "ordinal": int(p.getOrdinal()),
                    })
            for v in func.getLocalVariables():
                name = str(v.getName())
                if name and name not in seen_names:
                    seen_names.add(name)
                    locals_.append({
                        "name": name,
                        "type": str(v.getDataType().getName()) if v.getDataType() else "",
                    })
        except Exception:
            pass

        return {"params": params, "locals": locals_}


def _save_program(program):
    """Persist program changes to the Ghidra project.

    NOTE: Do NOT call DomainFile.save() inside pyghidra's open_program() context —
    pyghidra holds its own wrapper transaction open across the whole `with` block,
    and an explicit save attempt deadlocks against it with
    'Unable to lock due to active transaction'.

    Pyghidra auto-saves the program when the context manager exits cleanly, so as
    long as our own transaction is properly ended via endTransaction(tx_id, True),
    setName changes ARE persisted on context exit. This function is now a no-op
    kept only for callers that still reference it.
    """
    _ = program
    return True


def ghidra_rename_function(binary_path, project_name, func_addr_str, new_name):
    """Rename a function in the Ghidra program and persist to the project.
    Returns (success: bool, error: str|None, old_name: str|None)."""
    from ghidra.program.model.symbol import SourceType
    with _open_ghidra_program(binary_path, project_name, analyze=False) as flat_api:
        program = flat_api.getCurrentProgram()
        fm = program.getFunctionManager()
        addr = flat_api.toAddr(func_addr_str)
        func = fm.getFunctionAt(addr) or fm.getFunctionContaining(addr)
        if not func:
            return False, f"Function not found at {func_addr_str}", None

        if func.isExternal():
            return False, "Cannot rename an external function", None
        if func.isThunk():
            return False, "Cannot rename a thunk function", None

        old_name = str(func.getName())
        if old_name == new_name:
            return True, None, old_name  # no-op

        try:
            tx_id = program.startTransaction(f"Rename {old_name} -> {new_name}")
            try:
                func.setName(new_name, SourceType.USER_DEFINED)
            finally:
                program.endTransaction(tx_id, True)
        except Exception as e:
            return False, f"Rename failed: {e}", old_name

        try:
            _save_program(program)
        except Exception as e:
            return False, f"Set name succeeded but save failed: {e}", old_name

        return True, None, old_name


def ghidra_rename_variable(binary_path, project_name, func_addr_str, old_var_name, new_var_name):
    """Rename a parameter, local variable, or decompiler-generated variable.

    Handles three cases in order:
      1) Listing-level Parameter -> setName.
      2) Listing-level LocalVariable -> setName.
      3) HighFunction symbol (covers iVar1, plVar2, local_28, auStackY_88,
         hModule, param_N, etc.) -> HighFunctionDBUtil.updateDBVariable, which
         persists the rename into the program database.

    Returns (success: bool, error: str|None, kind: 'param'|'local'|'high_local'|None).
    """
    from ghidra.program.model.symbol import SourceType
    with _open_ghidra_program(binary_path, project_name, analyze=False) as flat_api:
        program = flat_api.getCurrentProgram()
        fm = program.getFunctionManager()
        addr = flat_api.toAddr(func_addr_str)
        func = fm.getFunctionAt(addr) or fm.getFunctionContaining(addr)
        if not func:
            return False, f"Function not found at {func_addr_str}", None

        # --- 1) Listing-level parameter ---
        listing_target = None
        listing_kind = None
        try:
            for p in func.getParameters():
                if str(p.getName()) == old_var_name:
                    listing_target = p
                    listing_kind = "param"
                    break
            if listing_target is None:
                for v in func.getLocalVariables():
                    if str(v.getName()) == old_var_name:
                        listing_target = v
                        listing_kind = "local"
                        break
        except Exception:
            pass

        if listing_target is not None:
            try:
                tx_id = program.startTransaction(f"Rename var {old_var_name} -> {new_var_name}")
                try:
                    listing_target.setName(new_var_name, SourceType.USER_DEFINED)
                finally:
                    program.endTransaction(tx_id, True)
            except Exception as e:
                return False, f"Variable rename failed: {e}", listing_kind
            try:
                _save_program(program)
            except Exception as e:
                return False, f"Set name succeeded but save failed: {e}", listing_kind
            return True, None, listing_kind

        # --- 2) HighFunction symbol (decompiler-only variable) ---
        try:
            from ghidra.app.decompiler import DecompInterface
            from ghidra.util.task import ConsoleTaskMonitor
            from ghidra.program.model.pcode import HighFunctionDBUtil

            decomp = DecompInterface()
            decomp.openProgram(program)
            try:
                res = decomp.decompileFunction(func, 60, ConsoleTaskMonitor())
                if not (res and res.decompileCompleted()):
                    return False, f"Variable '{old_var_name}' not found (decompile failed)", None
                high_func = res.getHighFunction()
                if high_func is None:
                    return False, f"Variable '{old_var_name}' not found (no HighFunction)", None

                target_sym = None
                sym_map = high_func.getLocalSymbolMap()
                for sym in sym_map.getSymbols():
                    try:
                        if str(sym.getName()) == old_var_name:
                            target_sym = sym
                            break
                    except Exception:
                        continue
                if target_sym is None:
                    return False, f"Variable '{old_var_name}' not found in this function", None

                try:
                    tx_id = program.startTransaction(
                        f"Rename high var {old_var_name} -> {new_var_name}"
                    )
                    try:
                        HighFunctionDBUtil.updateDBVariable(
                            target_sym, new_var_name, None, SourceType.USER_DEFINED
                        )
                    finally:
                        program.endTransaction(tx_id, True)
                except Exception as e:
                    return False, f"Variable rename failed: {e}", "high_local"

                try:
                    _save_program(program)
                except Exception as e:
                    return False, f"Set name succeeded but save failed: {e}", "high_local"

                return True, None, "high_local"
            finally:
                decomp.dispose()
        except Exception as e:
            log.exception("HighFunction rename path failed")
            return False, f"Rename failed: {e}", None


def ghidra_get_symbol_info(binary_path, project_name, symbol_name, max_preview_bytes=64):
    """Return ground-truth metadata for a global symbol.

    Everything reported comes directly from Ghidra's symbol table, listing, and memory
    APIs — no inference. Where Ghidra hasn't defined a datatype at the address,
    `is_defined` is False and `datatype` is None (an honest "unknown", not a guess).

    Returns (info: dict, error: str|None). info shape:
      {
        "name", "address_hex",
        "kind": "data" | "function" | "label" | "other",
        "datatype": str | None,          # Ghidra-assigned type, or None if undefined
        "length": int,                   # bytes (0 if undefined)
        "is_defined": bool,              # True iff Listing has Data at this address
        "value": str | None,             # Data.getValue() rendered, or None
        "bytes_hex": str | None,         # space-separated hex of first N bytes
        "bytes_ascii": str | None,       # ASCII preview ('.' for non-printable)
        "section": str | None,           # memory block name (.text, .rdata, .bss, ...)
      }
    """
    with _open_ghidra_program(binary_path, project_name, analyze=False) as flat_api:
        program = flat_api.getCurrentProgram()
        st = program.getSymbolTable()

        try:
            syms = list(st.getGlobalSymbols(symbol_name))
        except Exception:
            syms = []
        if not syms:
            try:
                for s in st.getSymbolIterator(symbol_name, True):
                    syms.append(s)
                    if len(syms) >= 1:
                        break
            except Exception:
                pass
        if not syms:
            return None, f"Global symbol '{symbol_name}' not found"

        sym = syms[0]
        addr = sym.getAddress()
        addr_hex = str(addr) if addr is not None else None

        # Classify the symbol
        kind = "other"
        try:
            from ghidra.program.model.symbol import SymbolType
            t = sym.getSymbolType()
            if t == SymbolType.FUNCTION:
                kind = "function"
            elif t == SymbolType.LABEL:
                kind = "label"
        except Exception:
            pass

        block_name = None
        try:
            mem = program.getMemory()
            block = mem.getBlock(addr) if addr is not None else None
            if block is not None:
                block_name = str(block.getName())
        except Exception:
            pass

        info = {
            "name": str(sym.getName()),
            "address_hex": addr_hex,
            "kind": kind,
            "datatype": None,
            "length": 0,
            "is_defined": False,
            "value": None,
            "bytes_hex": None,
            "bytes_ascii": None,
            "section": block_name,
        }

        # Listing data — ground truth for type, size, value
        try:
            data = program.getListing().getDataAt(addr)
            if data is not None:
                info["is_defined"] = True
                dt = data.getDataType()
                if dt is not None:
                    info["datatype"] = str(dt.getName())
                info["length"] = int(data.getLength())
                if kind == "other":
                    info["kind"] = "data"
                    kind = "data"
                try:
                    val = data.getValue()
                    if val is not None:
                        info["value"] = str(val)
                except Exception:
                    pass
        except Exception:
            pass

        # No byte preview for functions
        if kind == "function":
            return info, None

        # Byte preview straight from memory. If a byte is uninitialized (BSS) the
        # read raises — we just stop early instead of guessing.
        try:
            length = info["length"] if info["length"] > 0 else max_preview_bytes
            length = min(length, max_preview_bytes)
            if length > 0:
                mem = program.getMemory()
                hex_parts = []
                ascii_parts = []
                for i in range(length):
                    try:
                        b = mem.getByte(addr.add(i)) & 0xFF
                    except Exception:
                        break
                    hex_parts.append(f"{b:02X}")
                    ascii_parts.append(chr(b) if 0x20 <= b < 0x7F else ".")
                if hex_parts:
                    info["bytes_hex"] = " ".join(hex_parts)
                    info["bytes_ascii"] = "".join(ascii_parts)
        except Exception:
            pass  # honest no-preview on uninitialized memory

        return info, None


def ghidra_get_symbol_xrefs(binary_path, project_name, symbol_name, max_results=100):
    """Find every reference to a GLOBAL symbol (DAT_xxx, named buffer, BSS var, etc.).

    For each reference, returns the containing function + the site address. References
    from outside any function (data-to-data) are skipped. Not deduplicated — multiple
    accesses from the same function show up as multiple entries.

    Returns (results: list, error: str|None). results is a list of dicts:
      {"function", "address_hex" (function entry), "from_address" (call site),
       "ref_type" (e.g. READ, WRITE, DATA)}
    Empty list means the symbol exists but has no references inside any function.
    """
    with _open_ghidra_program(binary_path, project_name, analyze=False) as flat_api:
        program = flat_api.getCurrentProgram()
        st = program.getSymbolTable()
        fm = program.getFunctionManager()
        rm = program.getReferenceManager()

        try:
            syms = list(st.getGlobalSymbols(symbol_name))
        except Exception:
            syms = []
        if not syms:
            try:
                for s in st.getSymbolIterator(symbol_name, True):
                    syms.append(s)
                    if len(syms) >= 1:
                        break
            except Exception:
                pass
        if not syms:
            return None, f"Global symbol '{symbol_name}' not found"

        sym = syms[0]
        addr = sym.getAddress()

        results = []
        try:
            for ref in rm.getReferencesTo(addr):
                from_func = fm.getFunctionContaining(ref.getFromAddress())
                if not from_func:
                    continue
                results.append({
                    "function": str(from_func.getName()),
                    "address_hex": str(from_func.getEntryPoint()),
                    "from_address": str(ref.getFromAddress()),
                    "ref_type": str(ref.getReferenceType()),
                })
                if len(results) >= max_results:
                    break
        except Exception as e:
            log.exception("Symbol xref enumeration failed")
            return None, f"Xref enumeration failed: {e}"

        return results, None


def ghidra_rename_global_symbol(binary_path, project_name, old_name, new_name):
    """Rename a global (program-level) symbol like DAT_xxx, PTR_xxx, s_xxx, OFF_xxx.

    Affects every function that references the symbol — call sites get the new
    name on the next decompile.

    Returns (success: bool, error: str|None, address_hex: str|None).
    """
    from ghidra.program.model.symbol import SourceType
    with _open_ghidra_program(binary_path, project_name, analyze=False) as flat_api:
        program = flat_api.getCurrentProgram()
        st = program.getSymbolTable()

        # getGlobalSymbols returns a List; pick the first match.
        try:
            syms = list(st.getGlobalSymbols(old_name))
        except Exception:
            syms = []
        if not syms:
            # Fall back to scanning the full symbol iterator — covers namespaced cases
            try:
                for s in st.getSymbolIterator(old_name, True):
                    syms.append(s)
                    if len(syms) >= 1:
                        break
            except Exception:
                pass
        if not syms:
            return False, f"Global symbol '{old_name}' not found", None

        sym = syms[0]
        try:
            addr_obj = sym.getAddress()
            addr_str = str(addr_obj) if addr_obj is not None else None
        except Exception:
            addr_str = None

        try:
            tx_id = program.startTransaction(f"Rename symbol {old_name} -> {new_name}")
            try:
                sym.setName(new_name, SourceType.USER_DEFINED)
            finally:
                program.endTransaction(tx_id, True)
        except Exception as e:
            return False, f"Symbol rename failed: {e}", addr_str

        try:
            _save_program(program)
        except Exception as e:
            return False, f"Set name succeeded but save failed: {e}", addr_str

        return True, None, addr_str


def ghidra_disassemble(binary_path, project_name, func_addr_str):
    """Disassemble a function using Ghidra."""
    with _open_ghidra_program(binary_path, project_name, analyze=False) as flat_api:
        program = flat_api.getCurrentProgram()
        fm = program.getFunctionManager()
        listing = program.getListing()

        addr = flat_api.toAddr(func_addr_str)
        func = fm.getFunctionAt(addr)
        if not func:
            func = fm.getFunctionContaining(addr)
        if not func:
            return []

        instructions = []
        insn_iter = listing.getInstructions(func.getBody(), True)
        for insn in insn_iter:
            mnemonic = str(insn.getMnemonicString())
            num_ops = insn.getNumOperands()
            op_str = ", ".join(
                str(insn.getDefaultOperandRepresentation(i))
                for i in range(num_ops)
            )
            raw_bytes = bytes(insn.getBytes()).hex()

            row_type = ""
            flow = str(insn.getFlowType())
            if "CALL" in flow:
                row_type = "call"
            elif "RETURN" in flow:
                row_type = "ret"
            elif "JUMP" in flow or "BRANCH" in flow:
                row_type = "jump"

            label = ""
            if row_type == "call":
                for ref in insn.getReferencesFrom():
                    target_func = fm.getFunctionAt(ref.getToAddress())
                    if target_func:
                        label = str(target_func.getName())
                        break

            instructions.append({
                "address": str(insn.getAddress()),
                "bytes": raw_bytes,
                "mnemonic": mnemonic,
                "op_str": op_str,
                "label": label,
                "type": row_type,
            })

        return instructions


def ghidra_get_xrefs(binary_path, project_name, func_addr_str):
    """Get cross-references TO a function (callers)."""
    with _open_ghidra_program(binary_path, project_name, analyze=False) as flat_api:
        program = flat_api.getCurrentProgram()
        fm = program.getFunctionManager()
        rm = program.getReferenceManager()

        addr = flat_api.toAddr(func_addr_str)
        func = fm.getFunctionAt(addr)
        if not func:
            func = fm.getFunctionContaining(addr)
        if not func:
            return []

        seen = set()
        callers = []
        refs = rm.getReferencesTo(func.getEntryPoint())
        for ref in refs:
            from_func = fm.getFunctionContaining(ref.getFromAddress())
            if from_func and str(from_func.getEntryPoint()) not in seen:
                seen.add(str(from_func.getEntryPoint()))
                callers.append({
                    "name": str(from_func.getName()),
                    "address_hex": str(from_func.getEntryPoint()),
                    "ref_type": str(ref.getReferenceType()),
                    "from_address": str(ref.getFromAddress()),
                })
        return callers


def ghidra_get_string_xrefs(binary_path, project_name, search_text):
    """Find references to strings matching search_text."""
    with _open_ghidra_program(binary_path, project_name, analyze=False) as flat_api:
        program = flat_api.getCurrentProgram()
        fm = program.getFunctionManager()
        rm = program.getReferenceManager()

        listing = program.getListing()
        data_iter = listing.getDefinedData(
            program.getMemory().getLoadedAndInitializedAddressSet(), True
        )

        results = []
        search_lower = search_text.lower()
        while data_iter.hasNext():
            data = data_iter.next()
            dt = data.getDataType()
            if dt is None:
                continue
            type_name = dt.getName().lower()
            if "string" not in type_name and "unicode" not in type_name:
                continue
            text = str(data.getValue())
            if search_lower in text.lower():
                refs_list = []
                refs = rm.getReferencesTo(data.getAddress())
                for ref in refs:
                    from_func = fm.getFunctionContaining(ref.getFromAddress())
                    if from_func:
                        refs_list.append({
                            "function": str(from_func.getName()),
                            "address_hex": str(from_func.getEntryPoint()),
                            "from_address": str(ref.getFromAddress()),
                        })
                results.append({
                    "text": text,
                    "address_hex": str(data.getAddress()),
                    "references": refs_list,
                })
                if len(results) >= 50:
                    break
        return results
