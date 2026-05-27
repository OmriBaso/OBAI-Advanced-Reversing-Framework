import logging

from flask import Blueprint, request, send_file

from .. import ok, err
from ..config import load_config, save_config
from ..models.session import SESSIONS
from ..core.export import export_to_c_files

log = logging.getLogger(__name__)

config_bp = Blueprint("config", __name__)


@config_bp.route("/api/config", methods=["GET"])
def get_config():
    cfg = load_config()
    masked = dict(cfg)
    providers = masked.get("providers", {})
    for name, pcfg in providers.items():
        if pcfg.get("api_key"):
            pcfg["api_key"] = "\u2022" * 8
    return ok(masked)


@config_bp.route("/api/config", methods=["POST"])
def set_config():
    body = request.get_json(force=True) or {}

    cfg = load_config()

    if "active_provider" in body:
        provider = body["active_provider"].lower().strip()
        if provider not in ("anthropic", "openai", "ollama"):
            return err("Provider must be 'anthropic', 'openai', or 'ollama'")
        cfg["active_provider"] = provider

    if "providers" in body:
        for name, pcfg in body["providers"].items():
            if name not in cfg.get("providers", {}):
                continue
            existing = cfg["providers"][name]
            if "model" in pcfg:
                existing["model"] = pcfg["model"]
            if "api_key" in pcfg and pcfg["api_key"] and "\u2022" not in pcfg["api_key"]:
                existing["api_key"] = pcfg["api_key"]
            if "base_url" in pcfg:
                existing["base_url"] = pcfg["base_url"]
            if "thinking_budget" in pcfg:
                try:
                    existing["thinking_budget"] = int(pcfg["thinking_budget"])
                except (ValueError, TypeError):
                    pass

    save_config(cfg)
    return ok({"saved": True, "active_provider": cfg.get("active_provider")})


@config_bp.route("/api/analysis/<sid>/export", methods=["POST"])
def export_analysis(sid):
    sess = SESSIONS.get(sid)
    if not sess:
        return err("Invalid session", 404)
    sess.touch()

    body = request.get_json(silent=True) or {}
    selected = body.get("functions")

    try:
        buf, filename = export_to_c_files(sess, selected_functions=selected if selected else None)
        return send_file(buf, mimetype="application/zip", as_attachment=True, download_name=filename)
    except Exception as e:
        log.exception("Export failed")
        return err(f"Export failed: {e}", 500)
