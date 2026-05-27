import os
import shutil
import logging

from flask import Blueprint, request
from werkzeug.utils import secure_filename

from .. import ok, err
from ..config import UPLOAD_DIR
from ..models.session import (
    SESSIONS, init_analysis, _place_pdb_alongside, _analyze_module,
)
from ..models.database import read_db, write_db
from ..core.pe_utils import scan_pe_imports, scan_pe_imports_full

log = logging.getLogger(__name__)

upload_bp = Blueprint("upload", __name__)


@upload_bp.route("/api/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    if not f:
        return err("No file uploaded")
    mode = (request.form.get("mode") or "basic").lower()
    # accept legacy "standard" as alias for "basic"
    if mode == "standard":
        mode = "basic"
    if mode not in ("basic", "basic_pdb", "full_map"):
        return err("mode must be 'basic', 'basic_pdb', or 'full_map'")

    filename = secure_filename(f.filename or "binary.bin")
    path = os.path.join(UPLOAD_DIR, filename)
    f.save(path)

    try:
        sess = SESSIONS.create(path)
        sess.analysis_mode = mode
        # basic_pdb + full_map share the rich dependency picker (full import list)
        if mode in ("basic_pdb", "full_map"):
            imports = scan_pe_imports_full(path)
            return ok({
                "analysis_id": sess.id,
                "filename": filename,
                "mode": mode,
                "imports": imports,
            })
        # basic — only surface truly-missing DLLs
        missing = scan_pe_imports(path)
        return ok({
            "analysis_id": sess.id,
            "filename": filename,
            "mode": "basic",
            "missing_dlls": missing,
        })
    except Exception as e:
        log.exception("Upload failed")
        return err(f"Upload failed: {e}", 500)


@upload_bp.route("/api/fill-from-path/<sid>", methods=["POST"])
def fill_from_path(sid):
    """Copy DLLs that were auto-discovered on the system into the session's pending
    libraries. Body: {"imports": [{"name", "found_at"}, ...]} — typically the entries
    from the upload response that have found_at != null. Pre-uploaded entries are
    preserved unless 'overwrite' is true."""
    sess = SESSIONS.get(sid)
    if not sess:
        return err("Session not found", 404)
    if sess.state != "pending_deps":
        return err(f"Session is in state '{sess.state}', not accepting libraries")

    body = request.get_json(force=True) or {}
    entries = body.get("imports") or []
    overwrite = bool(body.get("overwrite"))

    copied = []
    skipped = []
    errors = []
    for e in entries:
        name = (e.get("name") or "").strip()
        src = (e.get("found_at") or "").strip()
        if not name or not src:
            continue
        if not overwrite and name in sess.pending_libraries:
            skipped.append({"name": name, "reason": "already_set"})
            continue
        if not os.path.isfile(src):
            errors.append({"name": name, "reason": f"source missing: {src}"})
            continue
        safe = secure_filename(name) or "library.dll"
        dest = os.path.join(UPLOAD_DIR, safe)
        try:
            if os.path.abspath(src) != os.path.abspath(dest):
                shutil.copy2(src, dest)
            sess.pending_libraries[name] = dest
            copied.append({"name": name, "path": dest})
        except OSError as oe:
            errors.append({"name": name, "reason": str(oe)})

    log.info("fill-from-path %s: copied=%d skipped=%d errors=%d",
             sid, len(copied), len(skipped), len(errors))
    return ok({"copied": copied, "skipped": skipped, "errors": errors,
               "pending_libraries": list(sess.pending_libraries.keys())})


@upload_bp.route("/api/upload-library/<sid>", methods=["POST"])
def upload_library(sid):
    sess = SESSIONS.get(sid)
    if not sess:
        return err("Session not found", 404)
    if sess.state != "pending_deps":
        return err("Session is not awaiting dependencies")

    f = request.files.get("file")
    if not f:
        return err("No file uploaded")
    filename = secure_filename(f.filename or "library.dll")
    lib_path = os.path.join(UPLOAD_DIR, filename)
    f.save(lib_path)

    dll_name = request.form.get("dll_name", filename)
    sess.pending_libraries[dll_name] = lib_path
    log.info("Library uploaded for session %s: %s -> %s", sid, dll_name, lib_path)

    return ok({"dll_name": dll_name, "filename": filename})


@upload_bp.route("/api/analysis/<sid>/add-binary", methods=["POST"])
def add_binary(sid):
    """Append a new binary to an already-analyzed session as a new module.

    The original upload's analysis mode (basic / basic_pdb / full_map) controls how
    the MAIN binary's linked DLLs are handled. This endpoint only adds ONE more
    standalone binary as its own module — no recursive dep-picker flow here (yet).
    """
    sess = SESSIONS.get(sid)
    if not sess:
        return err("Invalid session", 404)
    if sess.state != "ready":
        return err(f"Session is in state '{sess.state}', can't add a binary right now")

    f = request.files.get("file")
    if not f:
        return err("No file uploaded")
    mode = (request.form.get("mode") or "basic").lower()
    if mode == "standard":
        mode = "basic"
    if mode not in ("basic", "basic_pdb", "full_map"):
        return err("mode must be 'basic', 'basic_pdb', or 'full_map'")

    filename = secure_filename(f.filename or "binary.bin")
    if not filename:
        return err("Invalid filename")

    # Name collision with an already-loaded module — reject.
    if any(m.name == filename for m in sess.modules):
        return err(f"A module named '{filename}' is already loaded in this session", 409)

    path = os.path.join(UPLOAD_DIR, filename)
    f.save(path)

    try:
        # PDB best effort (regardless of mode — never hurts).
        try:
            pdb_loaded = _place_pdb_alongside(path)
        except Exception:
            log.exception("PDB download for added binary failed")
            pdb_loaded = False

        with sess.lock:
            module, raw_data = _analyze_module(path, linked_libraries=None)
            # Preserve the original filename as the module name (case, etc.)
            module.name = filename
            module.symbols_loaded = bool(pdb_loaded)
            sess.modules.append(module)

            db_live = read_db(sess.db_path) if sess.db_path else {}
            db_live.setdefault("modules", []).append(module.to_dict())
            db_live.setdefault("functions", []).extend(
                {**f, "module": filename} for f in raw_data["functions"]
            )
            db_live.setdefault("imports", []).extend(
                {**i, "module": filename} for i in raw_data["imports"]
            )
            db_live.setdefault("exports", []).extend(
                {**e, "module": filename} for e in raw_data["exports"]
            )
            db_live.setdefault("strings", []).extend(
                {**s, "module": filename} for s in raw_data["strings"]
            )
            write_db(db_live, sess.db_path)

        return ok({
            "module": module.to_dict(),
            "mode": mode,
            "n_functions": len(raw_data["functions"]),
            "n_imports": len(raw_data["imports"]),
            "n_exports": len(raw_data["exports"]),
            "n_strings": len(raw_data["strings"]),
        })
    except Exception as e:
        log.exception("Add-binary failed")
        return err(f"Add-binary failed: {e}", 500)


@upload_bp.route("/api/start-analysis/<sid>", methods=["POST"])
def start_analysis(sid):
    sess = SESSIONS.get(sid)
    if not sess:
        return err("Session not found", 404)
    if sess.state not in ("pending_deps",):
        return err(f"Session is in state '{sess.state}', cannot start analysis")

    try:
        db = init_analysis(sess)
        return ok({
            "analysis_id": sess.id,
            "filename": os.path.basename(sess.binary_path),
            "n_functions": len(db.get("functions", [])),
            "n_imports": len(db.get("imports", [])),
            "n_exports": len(db.get("exports", [])),
            "n_strings": len(db.get("strings", [])),
            "arch": db["binary_info"]["arch"],
            "symbols_loaded": db["binary_info"]["symbols_loaded"],
            "linked_libraries": list(sess.pending_libraries.keys()),
        })
    except Exception as e:
        log.exception("Analysis failed")
        return err(f"Analysis failed: {e}", 500)
