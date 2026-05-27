import os
import json
import logging

from flask import Blueprint, request
from werkzeug.utils import secure_filename

from .. import ok, err
from ..config import DB_DIR
from ..models.session import SESSIONS
from ..models.database import read_db

log = logging.getLogger(__name__)

databases_bp = Blueprint("databases", __name__)


@databases_bp.route("/api/databases", methods=["GET"])
def list_databases():
    dbs = []
    for fname in sorted(os.listdir(DB_DIR)):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(DB_DIR, fname)
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f)
            bi = data.get("binary_info", {})
            dbs.append({
                "filename": fname,
                "path": fpath,
                "binary_name": bi.get("filename", "unknown"),
                "arch": bi.get("arch", "unknown"),
                "symbols_loaded": bi.get("symbols_loaded", False),
                "n_functions": len(data.get("functions", [])),
                "n_vulnerabilities": len(data.get("vulnerabilities", [])),
                "created_at": data.get("created_at", ""),
                "schema": data.get("schema", 0),
            })
        except Exception:
            continue
    return ok(dbs)


@databases_bp.route("/api/load-db", methods=["POST"])
def load_database():
    body = request.get_json(force=True) or {}
    db_filename = body.get("filename")

    if not db_filename:
        return err("No database filename provided")

    db_file_path = os.path.join(DB_DIR, secure_filename(db_filename))
    if not os.path.isfile(db_file_path):
        return err("Database file not found", 404)

    try:
        db_json = read_db(db_file_path)
    except Exception as e:
        return err(f"Failed to read database: {e}", 500)

    try:
        sess = SESSIONS.create_from_db(db_json, db_file_path)
    except Exception as e:
        log.exception("Failed to create session from DB")
        return err(f"Failed to load session: {e}", 500)

    bi = db_json.get("binary_info", {})
    return ok({
        "analysis_id": sess.id,
        "filename": bi.get("filename", "unknown"),
        "n_functions": len(db_json.get("functions", [])),
        "n_imports": len(db_json.get("imports", [])),
        "n_exports": len(db_json.get("exports", [])),
        "n_strings": len(db_json.get("strings", [])),
        "n_vulnerabilities": len(db_json.get("vulnerabilities", [])),
        "arch": bi.get("arch", "unknown"),
        "symbols_loaded": bi.get("symbols_loaded", False),
        "from_db": True,
    })
