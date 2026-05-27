import os
import json
import hashlib
import logging

from ..config import DB_DIR

log = logging.getLogger(__name__)


def sha256_file(path, chunk=1024 * 1024):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def db_path_for(binary_path, sid=None):
    h = sha256_file(binary_path)[:12]
    base = os.path.splitext(os.path.basename(binary_path))[0]
    tag = sid or "standalone"
    return os.path.join(DB_DIR, f"{base}_{h}_{tag}.json")


def write_db(db, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2)


def read_db(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
