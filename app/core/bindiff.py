"""Bin Diff helpers — module-level summary and per-function disassembly diff."""

import re
import hashlib
import logging
from difflib import SequenceMatcher

from .ghidra_engine import ghidra_disassemble
from .helpers import find_function_entry, addr_str_to_int

log = logging.getLogger(__name__)

# Matches 6+ hex-digit literals (with optional 0x prefix) — these are very likely
# absolute addresses that will differ between rebuilds without the code actually changing.
_ABS_ADDR_RX = re.compile(r"\b(?:0x)?[0-9a-fA-F]{6,}\b")


def normalize_instruction(mnemonic: str, op_str: str) -> str:
    """Return a normalized 'mnemonic op_str' string with absolute addresses stripped.

    Keeps small constants (offsets, immediates) intact since those are signal — only
    long hex literals that look like absolute addresses get replaced with <addr>.
    """
    op = _ABS_ADDR_RX.sub("<addr>", op_str or "")
    return f"{(mnemonic or '').strip()} {op.strip()}".strip()


def function_signature(insns):
    """Hash a function's normalized instruction stream. Same code → same hash."""
    h = hashlib.sha1()
    for ins in insns:
        m = ins.get("mnemonic", "")
        o = ins.get("op_str", "")
        h.update(normalize_instruction(m, o).encode("utf-8", errors="replace"))
        h.update(b"\n")
    return h.hexdigest()


def _functions_for_module(db, module):
    """All functions belonging to a module — exclude imports/thunks; they have no body."""
    out = []
    for f in db.get("functions", []):
        if f.get("module") != module:
            continue
        if f.get("is_import") or f.get("is_thunk"):
            continue
        out.append(f)
    return out


def diff_modules_summary(db, base_module, compare_module):
    """Quick name-and-size based diff summary across two modules.

    Cheap: no disassembly is run here. Status values:
      - "removed":   exists only in base
      - "added":     exists only in compare
      - "size_diff": same name, different sizes (almost certainly changed)
      - "same_size": same name, same size (might be unchanged; user can deep-compare)

    The frontend can request a per-function deep diff to get the real verdict.
    """
    base = _functions_for_module(db, base_module)
    cmp_ = _functions_for_module(db, compare_module)
    by_name_base = {f["name"]: f for f in base}
    by_name_cmp = {f["name"]: f for f in cmp_}

    results = []
    seen = set()

    for name, b in by_name_base.items():
        seen.add(name)
        c = by_name_cmp.get(name)
        if c is None:
            results.append({
                "name": name,
                "status": "removed",
                "base_address": b.get("address_hex"),
                "base_size": int(b.get("size", 0)),
                "compare_address": None,
                "compare_size": None,
            })
            continue
        b_size = int(b.get("size", 0))
        c_size = int(c.get("size", 0))
        results.append({
            "name": name,
            "status": "size_diff" if b_size != c_size else "same_size",
            "base_address": b.get("address_hex"),
            "base_size": b_size,
            "compare_address": c.get("address_hex"),
            "compare_size": c_size,
        })

    for name, c in by_name_cmp.items():
        if name in seen:
            continue
        results.append({
            "name": name,
            "status": "added",
            "base_address": None,
            "base_size": None,
            "compare_address": c.get("address_hex"),
            "compare_size": int(c.get("size", 0)),
        })

    # Sort: changed first, then added/removed, then same_size last
    status_order = {"size_diff": 0, "removed": 1, "added": 2, "same_size": 3}
    results.sort(key=lambda r: (status_order.get(r["status"], 9), r["name"]))
    return {
        "base_module": base_module,
        "compare_module": compare_module,
        "total_base": len(base),
        "total_compare": len(cmp_),
        "diff": results,
    }


def diff_function_disassembly(sess, db, base_module, compare_module, func_name):
    """Side-by-side disassembly diff for a single function present in both modules.

    Returns (result_dict, error_str). Result shape:
      {
        function, base_module, compare_module,
        base_insns:    [{address, mnemonic, op_str, normalized}, ...],
        compare_insns: same shape,
        ops: [{tag: 'equal'|'replace'|'insert'|'delete',
               base_start, base_end, compare_start, compare_end}],
        identical: bool,   # True iff every line matched (normalized)
      }
    """
    base_entry = find_function_entry(db, func_name, base_module)
    cmp_entry = find_function_entry(db, func_name, compare_module)
    if not base_entry or not cmp_entry:
        return None, f"Function '{func_name}' not in both modules"

    base_mod_obj = sess.get_module(base_module)
    cmp_mod_obj = sess.get_module(compare_module)
    if not base_mod_obj or not cmp_mod_obj:
        return None, "Module(s) not found in session"

    try:
        with sess.lock:
            base_raw = ghidra_disassemble(
                base_mod_obj.binary_path,
                base_mod_obj.ghidra_project_name,
                base_entry["address_hex"],
            )
            cmp_raw = ghidra_disassemble(
                cmp_mod_obj.binary_path,
                cmp_mod_obj.ghidra_project_name,
                cmp_entry["address_hex"],
            )
    except Exception as e:
        return None, f"Disassembly failed: {e}"

    base_insns = [
        {
            "address": ins.get("address", ""),
            "mnemonic": ins.get("mnemonic", ""),
            "op_str": ins.get("op_str", ""),
            "normalized": normalize_instruction(ins.get("mnemonic", ""), ins.get("op_str", "")),
        }
        for ins in base_raw
    ]
    cmp_insns = [
        {
            "address": ins.get("address", ""),
            "mnemonic": ins.get("mnemonic", ""),
            "op_str": ins.get("op_str", ""),
            "normalized": normalize_instruction(ins.get("mnemonic", ""), ins.get("op_str", "")),
        }
        for ins in cmp_raw
    ]

    a = [i["normalized"] for i in base_insns]
    b = [i["normalized"] for i in cmp_insns]
    sm = SequenceMatcher(a=a, b=b, autojunk=False)
    ops = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        ops.append({
            "tag": tag,
            "base_start": i1,
            "base_end": i2,
            "compare_start": j1,
            "compare_end": j2,
        })

    identical = all(op["tag"] == "equal" for op in ops)

    return {
        "function": func_name,
        "base_module": base_module,
        "compare_module": compare_module,
        "base_insns": base_insns,
        "compare_insns": cmp_insns,
        "ops": ops,
        "identical": identical,
    }, None
