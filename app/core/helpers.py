"""Shared helpers for address resolution and DB lookups.

Multi-module aware: every function/import/export/string entry carries a 'module'
field (synthesized to the main module's name for legacy schema<6 DBs at load time).
Cache keys are 'module!func_name' for new entries; legacy bare-name keys still
resolve via permissive fallback.
"""


def addr_str_to_int(addr_str):
    """Convert a Ghidra address string (e.g. '00401000' or '0x140001000') to int."""
    if not addr_str:
        return None
    s = str(addr_str).strip()
    try:
        return int(s, 16)
    except (ValueError, TypeError):
        return None


def cache_key(module, func_name):
    """Build the standard cache key for a function. module=None drops the prefix."""
    if module:
        return f"{module}!{func_name}"
    return func_name


def _read_cache(cache, module, func_name):
    """Permissive read: try the qualified key, fall back to the bare name (legacy)."""
    if not cache:
        return None
    if module:
        v = cache.get(f"{module}!{func_name}")
        if v is not None:
            return v
    return cache.get(func_name)


def find_function_entry(db, func_name, module=None):
    """Return the full function dict, optionally restricted to a module.

    If module is None and several modules contain a function with the same name,
    returns the first match. Callers wanting strict disambiguation should pass module.
    """
    for f in db.get("functions", []):
        if f.get("name") != func_name:
            continue
        if module is None or f.get("module") == module:
            return f
    return None


def find_func_addr(db, func_name, module=None):
    """Find a function's address string by name (and optional module)."""
    entry = find_function_entry(db, func_name, module)
    return entry["address_hex"] if entry else None


def module_for_function(db, func_name, default=None):
    """Resolve which module a function belongs to. Returns `default` if not found.
    If the function name exists in multiple modules, returns the first match."""
    entry = find_function_entry(db, func_name)
    return entry.get("module") if entry else default


def build_addr_to_name_map(db, module=None):
    """Build an address->name lookup. If module is given, restrict to that module."""
    mapping = {}
    for f in db.get("functions", []):
        if module is not None and f.get("module") != module:
            continue
        addr = addr_str_to_int(f["address_hex"])
        if addr is not None:
            mapping[addr] = f["name"]
    return mapping


def resolve_angr_func_addr(sess, db, func_name, module=None):
    """Resolve a function name to an angr address. angr is only loaded for the main
    module, so this returns None for non-main modules (callers should fall back)."""
    addr_str = find_func_addr(db, func_name, module)
    addr_int = addr_str_to_int(addr_str)
    if addr_int is not None and sess.angr_cfg:
        if addr_int in sess.angr_cfg.kb.functions:
            return addr_int
        for a in sess.angr_cfg.kb.functions:
            if abs(a - addr_int) <= 16:
                return a
    return addr_int


def _module_paths(sess, db, func_name, module=None):
    """Return (binary_path, ghidra_project_name) for the module owning a function,
    or (None, None) if it can't be resolved."""
    mod_name, bp, pn = resolve_function_module_paths(sess, db, func_name, module)
    return bp, pn


def resolve_function_module_paths(sess, db, func_name, module=None):
    """Resolve which module owns a function and return its Ghidra project paths.

    Returns (module_name, binary_path, ghidra_project_name). Any element may be None
    if resolution failed."""
    entry = find_function_entry(db, func_name, module)
    if not entry:
        return None, None, None
    mod_name = entry.get("module")
    if sess and getattr(sess, "modules", None):
        m = sess.get_module(mod_name)
        if m and m.binary_path and m.ghidra_project_name:
            return mod_name, m.binary_path, m.ghidra_project_name
    # Legacy single-module session
    if sess and sess.binary_path and sess.ghidra_project_name:
        return mod_name, sess.binary_path, sess.ghidra_project_name
    return mod_name, None, None


def rename_function_in_db(db, old_name, new_name, module):
    """Update DB entries + invalidate caches after a successful Ghidra function rename.

    Renames db['functions'] entry. Drops every pseudocode/disasm/xref cache key
    for the affected module — many cached pseudocodes mention the old name in
    call sites, so dropping is simpler and correct than substring substitution.
    Other modules' caches are untouched.
    """
    renamed = False
    for f in db.get("functions", []):
        if f.get("name") == old_name and f.get("module") == module:
            f["name"] = new_name
            renamed = True
            break
    if not renamed:
        return False

    module_prefix = f"{module}!"
    for cache_field in ("pseudocode_cache", "disasm_cache", "xrefs_cache"):
        c = db.get(cache_field, {}) or {}
        for k in list(c.keys()):
            # Drop qualified keys for this module
            if k.startswith(module_prefix):
                c.pop(k, None)
            # Also drop legacy bare-name keys matching old_name (pre-multi-module)
            elif k == old_name:
                c.pop(k, None)
    return True


def rename_variable_in_db(db, func_name, module):
    """Invalidate the affected function's pseudocode cache after a variable rename."""
    cache = db.get("pseudocode_cache", {}) or {}
    cache.pop(cache_key(module, func_name), None)
    cache.pop(func_name, None)  # legacy
    return True


def rename_symbol_in_db(db, module):
    """Invalidate the module's pseudocode / disasm caches after a global symbol rename.
    Any function in the module may reference the symbol — drop them all so the next
    decompile picks up the new name."""
    if not module:
        return False
    module_prefix = f"{module}!"
    for cache_field in ("pseudocode_cache", "disasm_cache"):
        c = db.get(cache_field, {}) or {}
        for k in list(c.keys()):
            if k.startswith(module_prefix):
                c.pop(k, None)
    return True


def grep_function_bodies(
    sess,
    db,
    pattern,
    module=None,
    case_sensitive=False,
    max_results=50,
    max_decompile_budget=1000,
    context_lines=1,
):
    """Regex-grep across function pseudocode.

    Strategy:
      1) Scan the existing pseudocode_cache (fast).
      2) For uncached functions in scope, batch-decompile via Ghidra and cache
         the results, up to max_decompile_budget total decompiles across all
         modules in scope.
      3) Stop early when max_results is hit.

    Returns dict with: matches (list), scanned (int), total_in_scope (int),
    decompiled (int), budget_exhausted (bool), early_stop (bool), pattern (str).
    Each match: {module, function, address_hex, lines: [{line_no, text, is_match}]}
    """
    import re
    from .ghidra_engine import ghidra_batch_decompile
    from ..models.database import write_db

    flags = 0 if case_sensitive else re.IGNORECASE
    try:
        rx = re.compile(pattern, flags)
    except re.error as e:
        return {"error": f"Invalid regex: {e}", "matches": [], "scanned": 0,
                "total_in_scope": 0, "decompiled": 0,
                "budget_exhausted": False, "early_stop": False, "pattern": pattern}

    cache = db.setdefault("pseudocode_cache", {})

    funcs = db.get("functions", [])
    if module:
        in_scope = [f for f in funcs if f.get("module") == module]
    else:
        in_scope = list(funcs)
    # Skip imports / thunks — they have no body to grep
    in_scope = [f for f in in_scope if not f.get("is_import") and not f.get("is_thunk")]
    total_in_scope = len(in_scope)

    matches = []
    scanned = 0
    decompiled = 0
    early_stop = False
    budget_exhausted = False

    def grep_text(code, mod_name, func_name, address_hex):
        lines = code.splitlines()
        hits = []
        for i, line in enumerate(lines):
            if rx.search(line):
                lo = max(0, i - context_lines)
                hi = min(len(lines), i + context_lines + 1)
                window = [{"line_no": j + 1, "text": lines[j], "is_match": j == i}
                          for j in range(lo, hi)]
                hits.append(window)
                if len(hits) >= 3:  # cap per-function to keep output tight
                    break
        if hits:
            # Flatten + dedupe by line_no (overlapping context windows)
            seen_lines = {}
            for window in hits:
                for entry in window:
                    seen_lines[entry["line_no"]] = entry
            flat = [seen_lines[k] for k in sorted(seen_lines.keys())]
            matches.append({
                "module": mod_name,
                "function": func_name,
                "address_hex": address_hex,
                "lines": flat,
            })

    # ---- Pass 1: scan what's already cached ----
    uncached = []
    for f in in_scope:
        if len(matches) >= max_results:
            early_stop = True
            break
        scanned += 1
        mod_name = f.get("module") or ""
        key = cache_key(mod_name, f["name"])
        code = cache.get(key) or cache.get(f["name"])  # legacy fallback
        if code is None:
            uncached.append(f)
            continue
        grep_text(code, mod_name, f["name"], f.get("address_hex", ""))

    # ---- Pass 2: batch-decompile uncached functions per module ----
    if not early_stop and uncached:
        by_module = {}
        for f in uncached:
            by_module.setdefault(f.get("module") or "", []).append(f)

        for mod_name, mod_funcs in by_module.items():
            if early_stop or budget_exhausted:
                break
            m = sess.get_module(mod_name) if hasattr(sess, "get_module") else None
            if not m or not m.binary_path or not m.ghidra_project_name:
                # Legacy fallback
                if sess and sess.binary_path and sess.ghidra_project_name:
                    bp, pn = sess.binary_path, sess.ghidra_project_name
                else:
                    continue
            else:
                bp, pn = m.binary_path, m.ghidra_project_name

            # How many can we still decompile?
            remaining = max_decompile_budget - decompiled
            if remaining <= 0:
                budget_exhausted = True
                break
            batch = mod_funcs[:remaining]
            if len(mod_funcs) > remaining:
                budget_exhausted = True

            addrs = [f["address_hex"] for f in batch]
            with sess.lock:
                decoded = ghidra_batch_decompile(bp, pn, addrs)
            for f in batch:
                decompiled += 1
                code = decoded.get(f["address_hex"])
                if code is None:
                    continue
                cache[cache_key(mod_name, f["name"])] = code
                scanned += 1
                grep_text(code, mod_name, f["name"], f.get("address_hex", ""))
                if len(matches) >= max_results:
                    early_stop = True
                    break

    if decompiled > 0 and sess and sess.db_path:
        try:
            write_db(db, sess.db_path)
        except Exception:
            pass

    return {
        "matches": matches,
        "scanned": scanned,
        "total_in_scope": total_in_scope,
        "decompiled": decompiled,
        "budget_exhausted": budget_exhausted,
        "early_stop": early_stop,
        "pattern": pattern,
    }


def get_cached_pseudocode(sess, db, func_name, module=None):
    """Get pseudocode from cache, or decompile on demand and cache.

    With module specified, restricts function lookup and uses 'module!func_name' cache
    key. With module=None, picks the function's recorded module (first match)."""
    if not func_name:
        return ""

    cache = (db or {}).get("pseudocode_cache", {})
    cached = _read_cache(cache, module, func_name)
    if cached:
        return cached

    entry = find_function_entry(db, func_name, module)
    if not entry:
        return ""
    resolved_module = module or entry.get("module")
    binary_path, project_name = _module_paths(sess, db, func_name, resolved_module)
    if not binary_path or not project_name:
        return ""

    func_addr = entry["address_hex"]
    try:
        from .ghidra_engine import ghidra_decompile
        from ..models.database import read_db, write_db

        with sess.lock:
            code = ghidra_decompile(binary_path, project_name, func_addr)
        if code and sess.db_path:
            db_live = read_db(sess.db_path)
            db_live.setdefault("pseudocode_cache", {})[cache_key(resolved_module, func_name)] = code
            write_db(db_live, sess.db_path)
        return code or ""
    except Exception:
        return ""
