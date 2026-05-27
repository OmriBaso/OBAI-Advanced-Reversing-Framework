import logging

from flask import Blueprint, request

from .. import ok, err
from ..models.session import SESSIONS
from ..models.database import read_db, write_db
from ..core.helpers import (
    find_func_addr, find_function_entry, resolve_angr_func_addr,
    build_addr_to_name_map, cache_key, resolve_function_module_paths,
    grep_function_bodies, rename_function_in_db, rename_variable_in_db,
    rename_symbol_in_db,
)
from ..core.ghidra_engine import (
    ghidra_decompile, ghidra_disassemble, ghidra_get_xrefs, ghidra_get_string_xrefs,
    ghidra_rename_function, ghidra_rename_variable, ghidra_get_function_variables,
    ghidra_rename_global_symbol, ghidra_get_symbol_xrefs, ghidra_get_symbol_info,
)
from ..core.angr_engine import angr_get_cfg_data, angr_get_call_chain
from ..core.bindiff import diff_modules_summary, diff_function_disassembly


def _resolve_module_paths(sess, db, func_name, module):
    """Wrapper around resolve_function_module_paths that returns an err() on failure."""
    mod_name, bp, pn = resolve_function_module_paths(sess, db, func_name, module)
    if not mod_name:
        return None, None, None, err("Function not found", 404)
    if not bp or not pn:
        return mod_name, None, None, err("No live analysis session for this module", 503)
    return mod_name, bp, pn, None


def _module_arg():
    """Read the optional ?module= query param, normalized to None if blank."""
    m = (request.args.get("module") or "").strip()
    return m or None

log = logging.getLogger(__name__)

analysis_bp = Blueprint("analysis", __name__)


@analysis_bp.route("/api/analysis/<sid>/ping", methods=["GET"])
def ping(sid):
    """Lightweight heartbeat: bumps last_used so the reaper doesn't kill the session
    while the browser tab is still open."""
    sess = SESSIONS.get(sid)
    if not sess:
        return err("Invalid session", 404)
    sess.touch()
    return ok({"alive": True})


@analysis_bp.route("/api/analysis/<sid>/modules", methods=["GET"])
def list_modules(sid):
    """List every analyzed module (main binary + linked DLLs in Full Map mode)."""
    sess = SESSIONS.get(sid)
    if not sess:
        return err("Invalid session", 404)
    sess.touch()
    if sess.db_path:
        db = read_db(sess.db_path)
        modules = db.get("modules", [])
        if not modules:
            bi = db.get("binary_info", {})
            modules = [{
                "name": bi.get("filename", "main"),
                "is_main": True,
                "arch": bi.get("arch", ""),
                "symbols_loaded": bi.get("symbols_loaded", False),
            }]
        # Function count per module for UI badges
        counts = {}
        for f in db.get("functions", []):
            m = f.get("module") or bi.get("filename", "main")
            counts[m] = counts.get(m, 0) + 1
        for m in modules:
            m["n_functions"] = counts.get(m.get("name"), 0)
        return ok(modules)
    return ok([])


@analysis_bp.route("/api/analysis/<sid>/functions", methods=["GET"])
def list_functions(sid):
    sess = SESSIONS.get(sid)
    if not sess:
        return err("Invalid session", 404)
    sess.touch()
    if sess.db_path:
        return ok(read_db(sess.db_path).get("functions", []))
    return ok([])


@analysis_bp.route("/api/analysis/<sid>/imports", methods=["GET"])
def list_imports(sid):
    sess = SESSIONS.get(sid)
    if not sess:
        return err("Invalid session", 404)
    sess.touch()
    if sess.db_path:
        return ok(read_db(sess.db_path).get("imports", []))
    return ok([])


@analysis_bp.route("/api/analysis/<sid>/exports", methods=["GET"])
def list_exports(sid):
    sess = SESSIONS.get(sid)
    if not sess:
        return err("Invalid session", 404)
    sess.touch()
    if sess.db_path:
        return ok(read_db(sess.db_path).get("exports", []))
    return ok([])


@analysis_bp.route("/api/analysis/<sid>/strings", methods=["GET"])
def list_strings(sid):
    sess = SESSIONS.get(sid)
    if not sess:
        return err("Invalid session", 404)
    sess.touch()
    if sess.db_path:
        return ok(read_db(sess.db_path).get("strings", []))
    return ok([])


@analysis_bp.route("/api/analysis/<sid>/functions/<path:func_name>/pseudocode", methods=["GET"])
def function_pseudocode(sid, func_name):
    sess = SESSIONS.get(sid)
    if not sess:
        return err("Invalid session", 404)
    sess.touch()
    module = _module_arg()

    db = read_db(sess.db_path) if sess.db_path else {}
    cache = db.get("pseudocode_cache", {})

    mod_name, binary_path, project_name, error = _resolve_module_paths(sess, db, func_name, module)
    if error:
        return error

    # Permissive cache read: qualified key first, then legacy bare-name
    cached = cache.get(cache_key(mod_name, func_name)) or cache.get(func_name)
    if cached:
        return ok({"function": func_name, "module": mod_name, "pseudocode": cached})

    func_addr = find_func_addr(db, func_name, mod_name)
    if not func_addr:
        return err("Function not found", 404)

    with sess.lock:
        code = ghidra_decompile(binary_path, project_name, func_addr)

    if not code:
        code = "// Decompilation not available"

    if sess.db_path:
        db_live = read_db(sess.db_path)
        db_live.setdefault("pseudocode_cache", {})[cache_key(mod_name, func_name)] = code
        write_db(db_live, sess.db_path)

    return ok({"function": func_name, "module": mod_name, "pseudocode": code})


@analysis_bp.route("/api/analysis/<sid>/functions/<path:func_name>/disasm", methods=["GET"])
def function_disasm(sid, func_name):
    sess = SESSIONS.get(sid)
    if not sess:
        return err("Invalid session", 404)
    sess.touch()
    module = _module_arg()

    db = read_db(sess.db_path) if sess.db_path else {}
    cache = db.get("disasm_cache", {})

    mod_name, binary_path, project_name, error = _resolve_module_paths(sess, db, func_name, module)
    if error:
        return error

    cached = cache.get(cache_key(mod_name, func_name)) or cache.get(func_name)
    if cached:
        return ok({"function": func_name, "module": mod_name, "instructions": cached})

    func_addr = find_func_addr(db, func_name, mod_name)
    if not func_addr:
        return err("Function not found", 404)

    with sess.lock:
        instructions = ghidra_disassemble(binary_path, project_name, func_addr)

    if sess.db_path:
        db_live = read_db(sess.db_path)
        db_live.setdefault("disasm_cache", {})[cache_key(mod_name, func_name)] = instructions
        write_db(db_live, sess.db_path)

    return ok({"function": func_name, "module": mod_name, "instructions": instructions})


@analysis_bp.route("/api/analysis/<sid>/functions/<path:func_name>/cfg", methods=["GET"])
def function_cfg(sid, func_name):
    sess = SESSIONS.get(sid)
    if not sess:
        return err("Invalid session", 404)
    sess.touch()

    if not sess.angr_project or not sess.angr_cfg:
        return ok({"nodes": [], "edges": []})

    db = read_db(sess.db_path) if sess.db_path else {}
    func_addr = resolve_angr_func_addr(sess, db, func_name)
    if func_addr is None:
        return ok({"nodes": [], "edges": []})

    with sess.lock:
        data = angr_get_cfg_data(sess.angr_project, sess.angr_cfg, func_addr)
    return ok(data)


@analysis_bp.route("/api/analysis/<sid>/functions/<path:func_name>/xrefs", methods=["GET"])
def function_xrefs(sid, func_name):
    sess = SESSIONS.get(sid)
    if not sess:
        return err("Invalid session", 404)
    sess.touch()
    module = _module_arg()

    db = read_db(sess.db_path) if sess.db_path else {}
    cache = db.get("xrefs_cache", {})

    mod_name, binary_path, project_name, error = _resolve_module_paths(sess, db, func_name, module)
    if error:
        return error

    cached = cache.get(cache_key(mod_name, func_name)) or cache.get(func_name)
    if cached:
        return ok(cached)

    func_addr = find_func_addr(db, func_name, mod_name)
    if not func_addr:
        return err("Function not found", 404)

    with sess.lock:
        xrefs = ghidra_get_xrefs(binary_path, project_name, func_addr)

    if sess.db_path:
        db_live = read_db(sess.db_path)
        db_live.setdefault("xrefs_cache", {})[cache_key(mod_name, func_name)] = xrefs
        write_db(db_live, sess.db_path)

    return ok(xrefs)


@analysis_bp.route("/api/analysis/<sid>/strings/xrefs", methods=["POST"])
def string_xrefs(sid):
    sess = SESSIONS.get(sid)
    if not sess:
        return err("Invalid session", 404)
    sess.touch()

    body = request.get_json(force=True) or {}
    search = body.get("search", "")
    if not search:
        return err("No search text provided")

    if not sess.ghidra_project_name:
        return ok([])

    with sess.lock:
        results = ghidra_get_string_xrefs(sess.binary_path, sess.ghidra_project_name, search)
    return ok(results)


@analysis_bp.route("/api/analysis/<sid>/functions/<path:func_name>/callers", methods=["GET"])
def function_callers(sid, func_name):
    sess = SESSIONS.get(sid)
    if not sess:
        return err("Invalid session", 404)
    sess.touch()
    if not sess.angr_cfg:
        return ok([])
    db = read_db(sess.db_path) if sess.db_path else {}
    addr = resolve_angr_func_addr(sess, db, func_name)
    if addr is None:
        return ok([])
    name_map = build_addr_to_name_map(db)
    cg = sess.angr_cfg.kb.callgraph
    results = []
    for a in cg.predecessors(addr):
        f = sess.angr_cfg.kb.functions.get(a)
        if f:
            name = name_map.get(a) or f.name or f"sub_{a:x}"
            results.append({"name": name, "address_hex": hex(a),
                            "is_import": f.is_simprocedure or f.is_plt})
    return ok(results)


@analysis_bp.route("/api/analysis/<sid>/functions/<path:func_name>/callees", methods=["GET"])
def function_callees(sid, func_name):
    sess = SESSIONS.get(sid)
    if not sess:
        return err("Invalid session", 404)
    sess.touch()
    if not sess.angr_cfg:
        return ok([])
    db = read_db(sess.db_path) if sess.db_path else {}
    addr = resolve_angr_func_addr(sess, db, func_name)
    if addr is None:
        return ok([])
    name_map = build_addr_to_name_map(db)
    cg = sess.angr_cfg.kb.callgraph
    results = []
    for a in cg.successors(addr):
        f = sess.angr_cfg.kb.functions.get(a)
        if f:
            name = name_map.get(a) or f.name or f"sub_{a:x}"
            results.append({"name": name, "address_hex": hex(a),
                            "is_import": f.is_simprocedure or f.is_plt})
    return ok(results)


@analysis_bp.route("/api/analysis/<sid>/functions/<path:func_name>/call-chain", methods=["GET"])
def function_call_chain(sid, func_name):
    sess = SESSIONS.get(sid)
    if not sess:
        return err("Invalid session", 404)
    sess.touch()
    if not sess.angr_cfg:
        return err("angr CFG not available for this session", 503)

    direction = request.args.get("direction", "backward")
    if direction not in ("backward", "forward"):
        return err("direction must be 'backward' or 'forward'")
    try:
        max_depth = max(1, min(int(request.args.get("max_depth", 8)), 30))
        max_nodes = max(10, min(int(request.args.get("max_nodes", 300)), 2000))
    except (TypeError, ValueError):
        return err("max_depth and max_nodes must be integers")

    db = read_db(sess.db_path) if sess.db_path else {}
    data, error = angr_get_call_chain(sess, db, func_name, direction, max_depth, max_nodes)
    if error:
        return err(error, 404)
    return ok(data)


@analysis_bp.route("/api/analysis/<sid>/functions/<path:func_name>/variables", methods=["GET"])
def function_variables(sid, func_name):
    """List parameters + locals of a function — used by the in-decompile right-click UI
    to know which identifiers are rename-targetable variables."""
    sess = SESSIONS.get(sid)
    if not sess:
        return err("Invalid session", 404)
    sess.touch()
    module = _module_arg()

    db = read_db(sess.db_path) if sess.db_path else {}
    mod_name, binary_path, project_name, error = _resolve_module_paths(sess, db, func_name, module)
    if error:
        return error

    func_addr = find_func_addr(db, func_name, mod_name)
    if not func_addr:
        return err("Function not found", 404)

    with sess.lock:
        data = ghidra_get_function_variables(binary_path, project_name, func_addr)
    if data is None:
        return err("Function variables not available", 404)
    return ok({"function": func_name, "module": mod_name, **data})


@analysis_bp.route("/api/analysis/<sid>/functions/<path:func_name>/rename", methods=["POST"])
def rename_function_endpoint(sid, func_name):
    sess = SESSIONS.get(sid)
    if not sess:
        return err("Invalid session", 404)
    sess.touch()

    body = request.get_json(force=True) or {}
    new_name = (body.get("new_name") or "").strip()
    if not new_name:
        return err("new_name is required")
    if not new_name.replace("_", "").isalnum() or new_name[0].isdigit():
        return err("new_name must be a valid identifier (alnum + underscores, not starting with digit)")
    module = (body.get("module") or "").strip() or None

    db = read_db(sess.db_path) if sess.db_path else {}
    mod_name, binary_path, project_name, error = _resolve_module_paths(sess, db, func_name, module)
    if error:
        return error

    func_addr = find_func_addr(db, func_name, mod_name)
    if not func_addr:
        return err("Function not found", 404)

    with sess.lock:
        success, errmsg, old_name = ghidra_rename_function(binary_path, project_name, func_addr, new_name)
        if not success:
            return err(errmsg or "Rename failed", 500)

        # On Ghidra success: update DB + invalidate caches
        if sess.db_path:
            db_live = read_db(sess.db_path)
            rename_function_in_db(db_live, func_name, new_name, mod_name)
            write_db(db_live, sess.db_path)

    return ok({
        "old_name": old_name or func_name,
        "new_name": new_name,
        "module": mod_name,
        "address_hex": func_addr,
    })


@analysis_bp.route("/api/analysis/<sid>/functions/<path:func_name>/rename-variable", methods=["POST"])
def rename_variable_endpoint(sid, func_name):
    sess = SESSIONS.get(sid)
    if not sess:
        return err("Invalid session", 404)
    sess.touch()

    body = request.get_json(force=True) or {}
    old_var_name = (body.get("old_var_name") or "").strip()
    new_var_name = (body.get("new_var_name") or "").strip()
    if not old_var_name or not new_var_name:
        return err("old_var_name and new_var_name are required")
    if not new_var_name.replace("_", "").isalnum() or new_var_name[0].isdigit():
        return err("new_var_name must be a valid identifier")
    module = (body.get("module") or "").strip() or None

    db = read_db(sess.db_path) if sess.db_path else {}
    mod_name, binary_path, project_name, error = _resolve_module_paths(sess, db, func_name, module)
    if error:
        return error

    func_addr = find_func_addr(db, func_name, mod_name)
    if not func_addr:
        return err("Function not found", 404)

    with sess.lock:
        success, errmsg, kind = ghidra_rename_variable(
            binary_path, project_name, func_addr, old_var_name, new_var_name
        )
        if not success:
            return err(errmsg or "Variable rename failed", 500)

        if sess.db_path:
            db_live = read_db(sess.db_path)
            rename_variable_in_db(db_live, func_name, mod_name)
            write_db(db_live, sess.db_path)

    return ok({
        "function": func_name,
        "module": mod_name,
        "old_var_name": old_var_name,
        "new_var_name": new_var_name,
        "kind": kind,
    })


def _resolve_symbol_module_paths(sess, module):
    """Resolve (binary_path, project_name) for a symbol query — pick the named module
    or fall back to the main one."""
    if module:
        m = sess.get_module(module)
        if m and m.binary_path and m.ghidra_project_name:
            return m.binary_path, m.ghidra_project_name
    main = sess.main_module()
    if main and main.binary_path and main.ghidra_project_name:
        return main.binary_path, main.ghidra_project_name
    if sess.binary_path and sess.ghidra_project_name:
        return sess.binary_path, sess.ghidra_project_name
    return None, None


@analysis_bp.route("/api/analysis/<sid>/imports/<path:import_name>/xrefs", methods=["GET"])
def import_xrefs(sid, import_name):
    """List every function that references an imported API (kernel32!CreateFileW, etc.).
    Resolves the import to its IAT/thunk address, then reuses ghidra_get_xrefs."""
    sess = SESSIONS.get(sid)
    if not sess:
        return err("Invalid session", 404)
    sess.touch()
    module = _module_arg()

    db = read_db(sess.db_path) if sess.db_path else {}
    imports = db.get("imports", [])

    # Find the import by name (and optional module)
    entry = None
    for imp in imports:
        if imp.get("name") != import_name:
            continue
        if module is None or imp.get("module") == module:
            entry = imp
            break
    if not entry:
        return err("Import not found", 404)

    mod_name = entry.get("module")
    addr_hex = entry.get("address_hex")
    if not addr_hex:
        return err("Import has no address", 404)

    # Cached?
    cache = db.get("imports_xrefs_cache", {}) or {}
    cached = cache.get(cache_key(mod_name, import_name)) or cache.get(import_name)
    if cached:
        return ok(cached)

    # Resolve module's binary/project
    binary_path = None
    project_name = None
    if mod_name:
        m = sess.get_module(mod_name)
        if m and m.binary_path and m.ghidra_project_name:
            binary_path, project_name = m.binary_path, m.ghidra_project_name
    if not binary_path:
        if sess.binary_path and sess.ghidra_project_name:
            binary_path, project_name = sess.binary_path, sess.ghidra_project_name
    if not binary_path or not project_name:
        return err("No live Ghidra project for this module", 503)

    with sess.lock:
        xrefs = ghidra_get_xrefs(binary_path, project_name, addr_hex)

    if sess.db_path:
        db_live = read_db(sess.db_path)
        db_live.setdefault("imports_xrefs_cache", {})[cache_key(mod_name, import_name)] = xrefs
        write_db(db_live, sess.db_path)

    return ok(xrefs)


@analysis_bp.route("/api/analysis/<sid>/symbols/<path:symbol_name>/info", methods=["GET"])
def symbol_info(sid, symbol_name):
    """Inspect a global symbol — datatype, size, value, byte preview."""
    sess = SESSIONS.get(sid)
    if not sess:
        return err("Invalid session", 404)
    sess.touch()
    module = _module_arg()
    binary_path, project_name = _resolve_symbol_module_paths(sess, module)
    if not binary_path or not project_name:
        return err("No live Ghidra project for this module", 503)

    with sess.lock:
        info, error = ghidra_get_symbol_info(binary_path, project_name, symbol_name)
    if error:
        return err(error, 404)
    return ok(info)


@analysis_bp.route("/api/analysis/<sid>/symbols/<path:symbol_name>/xrefs", methods=["GET"])
def symbol_xrefs(sid, symbol_name):
    """List every reference to a global symbol (DAT_xxx, named buffer, BSS var)."""
    sess = SESSIONS.get(sid)
    if not sess:
        return err("Invalid session", 404)
    sess.touch()
    module = _module_arg()

    # Resolve binary / project: named module if given, else main
    binary_path = None
    project_name = None
    if module:
        m = sess.get_module(module)
        if m and m.binary_path and m.ghidra_project_name:
            binary_path, project_name = m.binary_path, m.ghidra_project_name
    if not binary_path:
        main = sess.main_module()
        if main and main.binary_path and main.ghidra_project_name:
            binary_path, project_name = main.binary_path, main.ghidra_project_name
        elif sess.binary_path and sess.ghidra_project_name:
            binary_path, project_name = sess.binary_path, sess.ghidra_project_name
    if not binary_path or not project_name:
        return err("No live Ghidra project for this module", 503)

    with sess.lock:
        results, error = ghidra_get_symbol_xrefs(binary_path, project_name, symbol_name)
    if error:
        return err(error, 404)
    return ok(results)


@analysis_bp.route("/api/analysis/<sid>/symbols/rename", methods=["POST"])
def rename_symbol_endpoint(sid):
    """Rename a GLOBAL symbol (DAT_xxx, PTR_xxx, s_xxx, OFF_xxx).
    Belongs to a specific module — pass `module` to target a non-main module."""
    sess = SESSIONS.get(sid)
    if not sess:
        return err("Invalid session", 404)
    sess.touch()

    body = request.get_json(force=True) or {}
    old_name = (body.get("old_name") or "").strip()
    new_name = (body.get("new_name") or "").strip()
    if not old_name or not new_name:
        return err("old_name and new_name are required")
    if not new_name.replace("_", "").isalnum() or new_name[0].isdigit():
        return err("new_name must be a valid identifier")
    module = (body.get("module") or "").strip() or None

    # Resolve binary / project: use the named module if given, else main.
    binary_path = None
    project_name = None
    if module:
        m = sess.get_module(module)
        if m and m.binary_path and m.ghidra_project_name:
            binary_path, project_name = m.binary_path, m.ghidra_project_name
    if not binary_path:
        main = sess.main_module()
        if main and main.binary_path and main.ghidra_project_name:
            binary_path, project_name = main.binary_path, main.ghidra_project_name
            module = module or main.name
        elif sess.binary_path and sess.ghidra_project_name:
            binary_path, project_name = sess.binary_path, sess.ghidra_project_name
    if not binary_path or not project_name:
        return err("No live Ghidra project for this module", 503)

    with sess.lock:
        success, errmsg, addr_str = ghidra_rename_global_symbol(
            binary_path, project_name, old_name, new_name
        )
        if not success:
            return err(errmsg or "Symbol rename failed", 500)
        if sess.db_path:
            db_live = read_db(sess.db_path)
            rename_symbol_in_db(db_live, module)
            write_db(db_live, sess.db_path)

    return ok({
        "old_name": old_name,
        "new_name": new_name,
        "module": module,
        "address_hex": addr_str,
    })


@analysis_bp.route("/api/analysis/<sid>/grep-functions", methods=["POST"])
def grep_functions(sid):
    """Regex-grep across function pseudocode. Auto-decompiles uncached functions
    up to the supplied budget and caches results."""
    sess = SESSIONS.get(sid)
    if not sess:
        return err("Invalid session", 404)
    sess.touch()
    body = request.get_json(force=True) or {}
    pattern = (body.get("pattern") or "").strip()
    if not pattern:
        return err("pattern is required")
    module = (body.get("module") or "").strip() or None
    case_sensitive = bool(body.get("case_sensitive"))
    try:
        max_results = max(1, min(int(body.get("max_results", 50)), 500))
        max_decompile_budget = max(0, min(int(body.get("max_decompile_budget", 1000)), 10000))
    except (TypeError, ValueError):
        return err("max_results and max_decompile_budget must be integers")

    db = read_db(sess.db_path) if sess.db_path else {}
    result = grep_function_bodies(
        sess, db, pattern,
        module=module,
        case_sensitive=case_sensitive,
        max_results=max_results,
        max_decompile_budget=max_decompile_budget,
    )
    if result.get("error"):
        return err(result["error"])
    return ok(result)


@analysis_bp.route("/api/analysis/<sid>/diff/<base_module>/<compare_module>", methods=["GET"])
def bindiff_summary(sid, base_module, compare_module):
    """Quick name-and-size based diff between two loaded modules."""
    sess = SESSIONS.get(sid)
    if not sess:
        return err("Invalid session", 404)
    sess.touch()
    if base_module == compare_module:
        return err("base_module and compare_module must be different")
    if not sess.get_module(base_module) or not sess.get_module(compare_module):
        return err("One or both modules not in this session", 404)
    db = read_db(sess.db_path) if sess.db_path else {}
    return ok(diff_modules_summary(db, base_module, compare_module))


@analysis_bp.route(
    "/api/analysis/<sid>/diff/<base_module>/<compare_module>/functions/<path:func_name>",
    methods=["GET"],
)
def bindiff_function(sid, base_module, compare_module, func_name):
    """Side-by-side disassembly diff for one function present in both modules."""
    sess = SESSIONS.get(sid)
    if not sess:
        return err("Invalid session", 404)
    sess.touch()
    if base_module == compare_module:
        return err("base_module and compare_module must be different")
    db = read_db(sess.db_path) if sess.db_path else {}
    result, error = diff_function_disassembly(sess, db, base_module, compare_module, func_name)
    if error:
        return err(error, 404)
    return ok(result)


@analysis_bp.route("/api/analysis/<sid>/vulnerabilities", methods=["GET"])
def list_vulnerabilities(sid):
    sess = SESSIONS.get(sid)
    if not sess:
        return err("Invalid session", 404)
    sess.touch()
    if sess.db_path:
        return ok(read_db(sess.db_path).get("vulnerabilities", []))
    return ok([])
