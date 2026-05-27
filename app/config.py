import os
import json
import logging
from datetime import datetime

log = logging.getLogger(__name__)

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

CONFIG_PATH = os.path.abspath(os.path.join(BASE_DIR, "re_config.json"))
DB_DIR = os.path.abspath(os.path.join(BASE_DIR, "analysis_db"))
UPLOAD_DIR = os.environ.get("RB_UPLOAD_DIR", os.path.abspath(os.path.join(BASE_DIR, "uploads")))
SYMBOL_CACHE = os.path.abspath(os.path.join(BASE_DIR, "symbol_cache"))
PROJECT_DIR = os.path.abspath(os.path.join(BASE_DIR, "ghidra_projects"))
# Honor GHIDRA_HOME if set; otherwise fall back to a bundled ghidra_12.0_PUBLIC/
# in the repo root. The bundle is gitignored (too large for GitHub), so clones
# without it must set GHIDRA_HOME or unzip Ghidra into the default location.
GHIDRA_INSTALL = os.path.abspath(os.environ.get("GHIDRA_HOME") or os.path.join(BASE_DIR, "ghidra_12.0_PUBLIC"))

for d in (DB_DIR, UPLOAD_DIR, SYMBOL_CACHE, PROJECT_DIR):
    os.makedirs(d, exist_ok=True)

DEFAULT_CONFIG = {
    "active_provider": "anthropic",
    "providers": {
        "anthropic": {"api_key": "", "model": "claude-sonnet-4-6-20250514"},
        "openai": {"api_key": "", "model": "gpt-4o"},
        "ollama": {"base_url": "http://localhost:11434", "model": "llama3"},
    },
}


def now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def load_config():
    if not os.path.exists(CONFIG_PATH):
        return dict(DEFAULT_CONFIG)
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except (json.JSONDecodeError, OSError):
        return dict(DEFAULT_CONFIG)

    if "providers" not in raw:
        provider = raw.get("provider", "anthropic")
        model = raw.get("model", "")
        api_key = raw.get("api_key", "")
        return {
            "active_provider": provider,
            "providers": {
                "anthropic": {
                    "api_key": api_key if provider == "anthropic" else "",
                    "model": model if provider == "anthropic" else "claude-sonnet-4-6-20250514",
                },
                "openai": {
                    "api_key": api_key if provider == "openai" else "",
                    "model": model if provider == "openai" else "gpt-4o",
                },
                "ollama": {"base_url": "http://localhost:11434", "model": "llama3"},
            },
        }
    return raw


def save_config(cfg):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


def get_active_provider_config(cfg=None):
    """Return (provider_name, provider_dict) for the currently active provider."""
    cfg = cfg or load_config()
    name = cfg.get("active_provider", "anthropic")
    providers = cfg.get("providers", {})
    return name, providers.get(name, {})
