import os
import uuid
import time
import shutil
import logging
import threading
from dataclasses import dataclass, field

from ..config import now_iso
from .database import sha256_file, db_path_for, write_db, read_db
from ..core.pe_utils import download_symbols
from ..core.ghidra_engine import ghidra_full_analysis
from ..core.angr_engine import angr_create_project, angr_run_cfg

log = logging.getLogger(__name__)

TEAM_NAMES = ("recon", "code_analysis", "security")

DB_SCHEMA_VERSION = 6


@dataclass
class ModuleInfo:
    """One analyzed binary (main or linked DLL)."""
    name: str               # logical name = filename (e.g. "smsexec.exe", "hman.dll")
    binary_path: str
    is_main: bool = False
    ghidra_project_name: str = ""
    arch: str = ""
    compiler: str = ""
    base_addr: str = ""
    entry_point: str = ""
    symbols_loaded: bool = False

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "binary_path": self.binary_path,
            "is_main": self.is_main,
            "ghidra_project_name": self.ghidra_project_name,
            "arch": self.arch,
            "compiler": self.compiler,
            "base_addr": self.base_addr,
            "entry_point": self.entry_point,
            "symbols_loaded": self.symbols_loaded,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ModuleInfo":
        return cls(
            name=d.get("name", "main"),
            binary_path=d.get("binary_path", ""),
            is_main=d.get("is_main", False),
            ghidra_project_name=d.get("ghidra_project_name", ""),
            arch=d.get("arch", ""),
            compiler=d.get("compiler", ""),
            base_addr=d.get("base_addr", ""),
            entry_point=d.get("entry_point", ""),
            symbols_loaded=d.get("symbols_loaded", False),
        )


@dataclass
class TeamBriefing:
    summary: str = ""
    findings: dict[str, str] = field(default_factory=dict)
    areas_covered: list[str] = field(default_factory=list)
    open_questions: list[str] = field(default_factory=list)
    last_updated: str = ""

    def to_dict(self) -> dict:
        return {
            "summary": self.summary,
            "findings": dict(self.findings),
            "areas_covered": list(self.areas_covered),
            "open_questions": list(self.open_questions),
            "last_updated": self.last_updated,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "TeamBriefing":
        return cls(
            summary=d.get("summary", ""),
            findings=d.get("findings", {}),
            areas_covered=d.get("areas_covered", []),
            open_questions=d.get("open_questions", []),
            last_updated=d.get("last_updated", ""),
        )

    def render_compact(self, team_name: str) -> str:
        """Render a compact briefing string for the orchestrator's system prompt."""
        if not self.summary and not self.findings:
            return f"**{team_name}** — No activity yet."
        parts = [f"**{team_name}**"]
        if self.last_updated:
            parts[0] += f" (updated {self.last_updated})"
        if self.summary:
            parts.append(self.summary)
        parts.append(f"Findings: {len(self.findings)}")
        if self.open_questions:
            q_preview = "; ".join(self.open_questions[:3])
            parts.append(f"Open questions: {q_preview}")
        return " | ".join(parts)


def _empty_team_briefings() -> dict[str, TeamBriefing]:
    return {name: TeamBriefing() for name in TEAM_NAMES}


class AnalysisSession:
    def __init__(self, binary_path, db_only=False, preloaded_db=None):
        self.id = str(uuid.uuid4())
        self.binary_path = binary_path
        self.db_path = None
        self.db_only = db_only
        self.preloaded_db = preloaded_db
        self.ghidra_project_name = None
        self.angr_project = None
        self.angr_cfg = None
        self.pdb_path = None
        self.pending_libraries = {}
        # "basic" | "basic_pdb" | "full_map"
        # basic       — main binary only; only truly-missing DLLs are surfaced for upload
        # basic_pdb   — all imports surfaced; user can Fill-from-Path; PDBs downloaded;
        #               linked libs feed setExternalPath only (no per-DLL Ghidra pass)
        # full_map    — basic_pdb + run full Ghidra analysis on every linked DLL
        self.analysis_mode = "basic"
        self.state = "pending_deps"
        self.created_at = time.time()
        self.last_used = time.time()
        self.lock = threading.RLock()
        self.working_memory: dict[str, str] = {}
        self.team_briefings: dict[str, TeamBriefing] = _empty_team_briefings()
        self.modules: list[ModuleInfo] = []

    def touch(self):
        self.last_used = time.time()

    @property
    def full_map_mode(self) -> bool:
        """Backward-compat shim for code that still reads sess.full_map_mode."""
        return self.analysis_mode == "full_map"

    @full_map_mode.setter
    def full_map_mode(self, value: bool):
        self.analysis_mode = "full_map" if value else "basic"

    def main_module(self) -> "ModuleInfo | None":
        for m in self.modules:
            if m.is_main:
                return m
        return self.modules[0] if self.modules else None

    def get_module(self, name: str | None) -> "ModuleInfo | None":
        if not name:
            return self.main_module()
        for m in self.modules:
            if m.name == name:
                return m
        return None


class SessionManager:
    def __init__(self, ttl_seconds=3600, reap_every=120):
        self.ttl = ttl_seconds
        self.sessions = {}
        self.lock = threading.RLock()
        t = threading.Thread(target=self._reap_loop, args=(reap_every,), daemon=True)
        t.start()

    def _reap_loop(self, interval):
        while True:
            time.sleep(interval)
            now = time.time()
            with self.lock:
                for sid in list(self.sessions):
                    if now - self.sessions[sid].last_used > self.ttl:
                        self.sessions.pop(sid, None)

    def create(self, binary_path):
        sess = AnalysisSession(binary_path)
        with self.lock:
            self.sessions[sess.id] = sess
        return sess

    def create_from_db(self, db_json, db_file_path):
        sess = AnalysisSession(
            db_json.get("binary_path", "<db-loaded>"),
            db_only=True,
            preloaded_db=db_json,
        )
        sess.db_path = db_file_path
        sess.state = "ready"
        # Restore mode (schema 6+) or derive from legacy full_map_mode flag
        mode = db_json.get("analysis_mode")
        if not mode:
            mode = "full_map" if db_json.get("full_map_mode") else "basic"
        sess.analysis_mode = mode
        sess.working_memory = db_json.get("working_memory", {})
        raw_briefings = db_json.get("team_briefings", {})
        for tname in TEAM_NAMES:
            if tname in raw_briefings:
                sess.team_briefings[tname] = TeamBriefing.from_dict(raw_briefings[tname])

        # Restore modules. Old (schema<6) DBs have none — synthesize a single main module.
        raw_modules = db_json.get("modules") or []
        if raw_modules:
            sess.modules = [ModuleInfo.from_dict(m) for m in raw_modules]
        else:
            bi = db_json.get("binary_info", {})
            binary_path_legacy = db_json.get("binary_path", "")
            main_name = bi.get("filename") or (os.path.basename(binary_path_legacy) if binary_path_legacy else "main")
            sess.modules = [ModuleInfo(
                name=main_name,
                binary_path=binary_path_legacy,
                is_main=True,
                arch=bi.get("arch", ""),
                compiler=bi.get("compiler", ""),
                base_addr=bi.get("base_addr", ""),
                entry_point=bi.get("entry_point", ""),
                symbols_loaded=bi.get("symbols_loaded", False),
            )]

        binary_path = db_json.get("binary_path", "")
        if binary_path and os.path.isfile(binary_path):
            binary_base = os.path.splitext(os.path.basename(binary_path))[0]
            sess.ghidra_project_name = f"{binary_base}_{sha256_file(binary_path)[:8]}"
            # Ensure the main module records the same project name we'll use for decompilation
            main = sess.main_module()
            if main and not main.ghidra_project_name:
                main.ghidra_project_name = sess.ghidra_project_name
            log.info("Loading angr for CFG on %s...", binary_path)
            angr_proj = angr_create_project(binary_path)
            angr_cfg = angr_run_cfg(angr_proj) if angr_proj else None
            sess.angr_project = angr_proj
            sess.angr_cfg = angr_cfg
            sess.db_only = False
            if angr_cfg:
                log.info("angr CFG loaded — %d functions", len(angr_cfg.kb.functions))
        with self.lock:
            self.sessions[sess.id] = sess
        return sess

    def get(self, sid):
        with self.lock:
            return self.sessions.get(sid)


SESSIONS = SessionManager()


def _place_pdb_alongside(binary_path):
    """Download PDB (best effort) and copy it next to the binary so Ghidra picks it up."""
    pdb = download_symbols(binary_path)
    if not pdb:
        return False
    dest = os.path.join(os.path.dirname(binary_path), os.path.basename(pdb))
    if not os.path.exists(dest):
        shutil.copy2(pdb, dest)
    return True


def _analyze_module(binary_path, linked_libraries=None):
    """Run a single Ghidra full-analysis pass and return (ModuleInfo, raw_data)."""
    name = os.path.basename(binary_path)
    binary_base = os.path.splitext(name)[0]
    project_name = f"{binary_base}_{sha256_file(binary_path)[:8]}"
    log.info("Ghidra analysis for module %s (project %s)", name, project_name)
    data = ghidra_full_analysis(binary_path, project_name, linked_libraries=linked_libraries)
    module = ModuleInfo(
        name=name,
        binary_path=binary_path,
        ghidra_project_name=project_name,
        arch=data["arch"],
        compiler=data["compiler"],
        base_addr=data["base_addr"],
        entry_point=data["entry_point"],
    )
    return module, data


def init_analysis(sess):
    """Run full Ghidra (+ angr on main) analysis pipeline.

    Standard mode: analyze only the main binary; linked libraries (if any) are passed
    to Ghidra as external paths for symbol resolution.

    Full Map mode: additionally run a full Ghidra pass on every linked library so the
    user / AI can decompile and navigate them. Each pass produces its own Ghidra project.
    """
    sess.state = "analyzing"
    log.info(
        "Starting analysis for %s (mode=%s, %d linked libs)",
        sess.binary_path, sess.analysis_mode, len(sess.pending_libraries),
    )

    # PDBs (main + every linked lib) — best effort
    main_pdb = _place_pdb_alongside(sess.binary_path)
    sess.pdb_path = main_pdb  # truthy flag for backward compat
    lib_pdb_loaded = {}
    for lib_name, lib_path in sess.pending_libraries.items():
        try:
            lib_pdb_loaded[lib_name] = _place_pdb_alongside(lib_path)
        except Exception:
            log.exception("PDB download failed for %s", lib_name)
            lib_pdb_loaded[lib_name] = False

    # Main module — pass linked libs so Ghidra can resolve external symbols by name
    linked = sess.pending_libraries if sess.pending_libraries else None
    main_module, main_data = _analyze_module(sess.binary_path, linked_libraries=linked)
    main_module.is_main = True
    main_module.symbols_loaded = bool(main_pdb)
    sess.ghidra_project_name = main_module.ghidra_project_name

    modules = [main_module]
    main_name = main_module.name

    all_functions = [{**f, "module": main_name} for f in main_data["functions"]]
    all_imports = [{**i, "module": main_name} for i in main_data["imports"]]
    all_exports = [{**e, "module": main_name} for e in main_data["exports"]]
    all_strings = [{**s, "module": main_name} for s in main_data["strings"]]

    # Full Map: analyze each linked DLL as its own module
    if sess.analysis_mode == "full_map" and sess.pending_libraries:
        for lib_name, lib_path in sess.pending_libraries.items():
            if not os.path.isfile(lib_path):
                log.warning("Linked lib path missing, skipping: %s -> %s", lib_name, lib_path)
                continue
            try:
                lib_module, lib_data = _analyze_module(lib_path, linked_libraries=None)
                lib_module.name = lib_name  # preserve original DLL name (case, etc.)
                lib_module.symbols_loaded = bool(lib_pdb_loaded.get(lib_name))
                modules.append(lib_module)
                all_functions.extend({**f, "module": lib_name} for f in lib_data["functions"])
                all_imports.extend({**i, "module": lib_name} for i in lib_data["imports"])
                all_exports.extend({**e, "module": lib_name} for e in lib_data["exports"])
                all_strings.extend({**s, "module": lib_name} for s in lib_data["strings"])
                log.info(
                    "Module %s: %d functions, %d strings",
                    lib_name, len(lib_data["functions"]), len(lib_data["strings"]),
                )
            except Exception:
                log.exception("Full Map analysis failed for module %s", lib_name)

    sess.modules = modules

    # angr CFG — main module only (cross-module CFG is intentionally not done here)
    log.info("Running angr CFGFast on main module...")
    angr_proj = angr_create_project(sess.binary_path)
    angr_cfg = angr_run_cfg(angr_proj) if angr_proj else None
    sess.angr_project = angr_proj
    sess.angr_cfg = angr_cfg
    if angr_cfg:
        log.info("angr CFG done — %d functions", len(angr_cfg.kb.functions))

    db = {
        "schema": DB_SCHEMA_VERSION,
        "created_at": now_iso(),
        "binary_path": sess.binary_path,
        "analysis_id": sess.id,
        "analysis_mode": sess.analysis_mode,
        "full_map_mode": sess.analysis_mode == "full_map",  # kept for compat
        "main_module": main_name,
        "binary_info": {
            "arch": main_module.arch,
            "compiler": main_module.compiler,
            "base_addr": main_module.base_addr,
            "entry_point": main_module.entry_point,
            "symbols_loaded": main_module.symbols_loaded,
            "filename": main_name,
        },
        "modules": [m.to_dict() for m in modules],
        "functions": all_functions,
        "imports": all_imports,
        "exports": all_exports,
        "strings": all_strings,
        "pseudocode_cache": {},
        "disasm_cache": {},
        "xrefs_cache": {},
        "string_xrefs_cache": {},
        "vulnerabilities": [],
        "chat_sessions": {},
        "working_memory": {},
        "team_briefings": {name: TeamBriefing().to_dict() for name in TEAM_NAMES},
    }

    path = db_path_for(sess.binary_path, sess.id)
    write_db(db, path)
    sess.db_path = path
    sess.state = "ready"
    return db
