"""Chat route with SSE streaming and multi-agent orchestration."""

import os
import uuid
import logging

from flask import Blueprint, request

from .. import ok, err
from ..config import load_config, get_active_provider_config, now_iso
from ..models.session import SESSIONS
from ..models.database import read_db, write_db
from ..core.helpers import get_cached_pseudocode
from ..agents.providers import create_provider
from ..agents.orchestrator import OrchestratorAgent
from ..agents.teams.security import SecurityLeader
from ..agents.providers.base import AgentEvent, EventType
from ..streaming.sse import SSEResponse, sse_event

log = logging.getLogger(__name__)

chat_bp = Blueprint("chat", __name__)


def _build_chat_context(sess, db, current_function, chat_data):
    """Build the context dict for the orchestrator agent."""
    binary_info = db.get("binary_info", {})
    all_funcs = [f["name"] for f in db.get("functions", [])]
    current_code = get_cached_pseudocode(sess, db, current_function) if current_function else ""

    imp_list = db.get("imports", [])
    imp_summary = (
        f"{len(imp_list)} imports from {len(set(i.get('library','') for i in imp_list))} libraries"
        if imp_list else ""
    )

    modules = db.get("modules", []) or []
    return {
        "binary_name": binary_info.get("filename", os.path.basename(sess.binary_path)),
        "arch": binary_info.get("arch", "unknown"),
        "current_function": current_function or "",
        "current_code": current_code,
        "context_functions": chat_data.get("context_functions", {}),
        "available_functions": all_funcs,
        "imports_summary": imp_summary,
        "string_count": len(db.get("strings", [])),
        "export_count": len(db.get("exports", [])),
        "full_map_mode": bool(db.get("full_map_mode")),
        "modules": [m.get("name", "") for m in modules],
    }


def _save_chat(sess, db, chat_id, chat_data):
    if not sess.db_path:
        return
    db_live = read_db(sess.db_path)
    chats = db_live.get("chat_sessions", {})
    serializable = dict(chat_data)
    ctx = serializable.get("context_functions", {})
    serializable["context_function_names"] = list(ctx.keys())
    chats[chat_id] = serializable
    db_live["chat_sessions"] = chats
    write_db(db_live, sess.db_path)


def _create_provider():
    """Create the active LLM provider from config."""
    cfg = load_config()
    name, provider_cfg = get_active_provider_config(cfg)
    if name != "ollama" and not provider_cfg.get("api_key"):
        raise RuntimeError("API key not configured — open Settings to set it")
    return create_provider(name, provider_cfg)


@chat_bp.route("/api/analysis/<sid>/chat", methods=["POST"])
def chat(sid):
    sess = SESSIONS.get(sid)
    if not sess:
        return err("Invalid session", 404)
    sess.touch()

    body = request.get_json(force=True) or {}
    action = body.get("action", "message")
    chat_id = body.get("chat_id") or str(uuid.uuid4())
    current_function = body.get("current_function")
    user_message = body.get("message", "")
    stream_mode = body.get("stream", True)

    db = read_db(sess.db_path) if sess.db_path else {}

    chats = db.get("chat_sessions", {})
    chat_data = chats.get(chat_id)
    if not chat_data:
        chat_data = {
            "created_at": now_iso(),
            "messages": [],
            "context_functions": {},
            "current_function": current_function,
        }

    if not isinstance(chat_data.get("context_functions"), dict):
        restored = {}
        for name in chat_data.get("context_function_names", []):
            code = db.get("pseudocode_cache", {}).get(name, "")
            if code:
                restored[name] = code
        chat_data["context_functions"] = restored

    if current_function and current_function != chat_data.get("current_function"):
        chat_data["current_function"] = current_function

    try:
        provider = _create_provider()
    except RuntimeError as e:
        return err(str(e), 400)

    context = _build_chat_context(sess, db, current_function, chat_data)

    if action == "message":
        if not user_message.strip():
            return err("Empty message")

        chat_data["messages"].append({"role": "user", "content": user_message, "timestamp": now_iso()})
        _save_chat(sess, db, chat_id, chat_data)

        orchestrator = OrchestratorAgent(provider, sess, db)
        messages_for_llm = [
            {"role": m["role"], "content": m["content"]}
            for m in chat_data["messages"]
            if m.get("role") in ("user", "assistant", "system")
        ]

        if stream_mode:
            def streaming_gen():
                collected_text = ""
                vulns = []
                asst_index = None

                def persist_partial():
                    nonlocal asst_index
                    msg = {
                        "role": "assistant",
                        "content": collected_text,
                        "timestamp": now_iso(),
                    }
                    if asst_index is None:
                        chat_data["messages"].append(msg)
                        asst_index = len(chat_data["messages"]) - 1
                    else:
                        chat_data["messages"][asst_index] = msg
                    _save_chat(sess, db, chat_id, chat_data)

                try:
                    for event in orchestrator.run_streaming(messages_for_llm, context):
                        if event.type == EventType.TEXT_DELTA:
                            collected_text += event.data.get("content", "")
                        elif event.type == EventType.VULNERABILITY:
                            vulns.append(event.data)
                        elif event.type == EventType.TOOL_RESULT and collected_text:
                            persist_partial()
                        yield event
                finally:
                    if collected_text or asst_index is not None:
                        persist_partial()

                    if vulns and sess.db_path:
                        db_live = read_db(sess.db_path)
                        existing = db_live.setdefault("vulnerabilities", [])
                        for v in vulns:
                            v["id"] = str(uuid.uuid4())
                            v["discovered_at"] = now_iso()
                            v["exploit_code"] = None
                            existing.append(v)
                        write_db(db_live, sess.db_path)

            return SSEResponse(streaming_gen(), chat_id=chat_id)

        else:
            try:
                response = orchestrator.run(messages_for_llm, context)
            except Exception as e:
                return err(f"AI error: {e}", 502)

            chat_data["messages"].append({
                "role": "assistant",
                "content": response.text,
                "timestamp": now_iso(),
            })

            vulns = response.usage.get("vulnerabilities", [])
            if vulns and sess.db_path:
                db_live = read_db(sess.db_path)
                existing = db_live.setdefault("vulnerabilities", [])
                for v in vulns:
                    v["id"] = str(uuid.uuid4())
                    v["discovered_at"] = now_iso()
                    v["exploit_code"] = None
                    existing.append(v)
                write_db(db_live, sess.db_path)

            _save_chat(sess, db, chat_id, chat_data)

            return ok({
                "chat_id": chat_id,
                "response": response.text,
                "context_functions": list(chat_data.get("context_functions", {}).keys()),
            })

    elif action == "free_roam":
        start_fn = current_function or body.get("start_function")
        max_depth = min(int(body.get("max_depth", 5)), 10)
        if not start_fn:
            return err("Select a function to start free-roam from")

        sec_leader = SecurityLeader(provider, sess, db)
        task = (
            f"Systematically scan functions starting from {start_fn}, following callees up to depth {max_depth}. "
            f"Use read_pseudocode to examine each function, then use get_callees to find more functions to scan. "
            f"Report any vulnerabilities found using report_vulnerability. "
            f"Update your briefing with findings before finishing."
        )
        scan_context = dict(context)
        scan_context["task"] = task

        if stream_mode:
            def scan_gen():
                for event in sec_leader.run_streaming(
                    [{"role": "user", "content": task}], scan_context
                ):
                    yield event

            return SSEResponse(scan_gen(), chat_id=chat_id)

        else:
            response = sec_leader.run([{"role": "user", "content": task}], scan_context)
            vulns = response.usage.get("vulnerabilities", [])

            if vulns and sess.db_path:
                db_live = read_db(sess.db_path)
                existing = db_live.setdefault("vulnerabilities", [])
                for v in vulns:
                    v["id"] = str(uuid.uuid4())
                    v["discovered_at"] = now_iso()
                    v["exploit_code"] = None
                    existing.append(v)
                write_db(db_live, sess.db_path)

            return ok({
                "chat_id": chat_id,
                "response": response.text,
                "vulnerabilities": vulns,
            })

    elif action == "generate_exploit":
        vuln_id = body.get("vuln_id")
        if not vuln_id:
            return err("No vulnerability ID provided")

        vulns = db.get("vulnerabilities", [])
        vuln = next((v for v in vulns if v.get("id") == vuln_id), None)
        if not vuln:
            return err("Vulnerability not found", 404)

        sec_leader = SecurityLeader(provider, sess, db)
        exploit_context = dict(context)
        exploit_context["vulnerability"] = vuln
        exploit_context["task"] = f"Generate a PoC exploit for: {vuln['name']}"

        task_msg = (
            f"Generate a complete, compilable C/C++ proof-of-concept exploit for: {vuln['name']}. "
            f"Vulnerability details: {vuln.get('description', '')}. Function: {vuln.get('function', '')}. "
            f"Classification: {vuln.get('classification', '')}. "
            f"Use read_pseudocode to examine the vulnerable function, then submit_exploit with the PoC."
        )

        if stream_mode:
            def exploit_gen():
                for event in sec_leader.run_streaming(
                    [{"role": "user", "content": task_msg}], exploit_context
                ):
                    yield event

            return SSEResponse(exploit_gen(), chat_id=chat_id)

        else:
            response = sec_leader.run([{"role": "user", "content": task_msg}], exploit_context)
            exploits = response.usage.get("exploits", [])
            exploit_code = exploits[0]["code"] if exploits else response.text

            if sess.db_path:
                db_live = read_db(sess.db_path)
                for v in db_live.get("vulnerabilities", []):
                    if v.get("id") == vuln_id:
                        v["exploit_code"] = exploit_code
                        break
                write_db(db_live, sess.db_path)

            return ok({"vuln_id": vuln_id, "exploit_code": exploit_code})

    return err("Unknown action", 400)


@chat_bp.route("/api/analysis/<sid>/chat/answer", methods=["POST"])
def chat_answer(sid):
    """Provide an answer to a pending ask_user question."""
    sess = SESSIONS.get(sid)
    if not sess:
        return err("Invalid session", 404)

    body = request.get_json(force=True) or {}
    question_id = body.get("question_id", "")
    answer = body.get("answer", "")

    if not question_id or not answer:
        return err("question_id and answer are required")

    from ..agents.tools import answer_question
    if answer_question(question_id, answer):
        return ok({"status": "answered"})
    return err("Unknown or expired question_id", 404)


@chat_bp.route("/api/analysis/<sid>/chat/reset", methods=["POST"])
def chat_reset(sid):
    sess = SESSIONS.get(sid)
    if not sess:
        return err("Invalid session", 404)
    body = request.get_json(force=True) or {}
    chat_id = body.get("chat_id")
    if chat_id and sess.db_path:
        db = read_db(sess.db_path)
        db.get("chat_sessions", {}).pop(chat_id, None)
        write_db(db, sess.db_path)
    return ok({"reset": True})


def _chat_summary(chat_id, chat_data):
    msgs = chat_data.get("messages", [])
    preview = ""
    for m in msgs:
        if m.get("role") == "user" and m.get("content"):
            preview = m["content"].strip().replace("\n", " ")[:120]
            break
    last_updated = chat_data.get("created_at", "")
    for m in reversed(msgs):
        if m.get("timestamp"):
            last_updated = m["timestamp"]
            break
    return {
        "chat_id": chat_id,
        "created_at": chat_data.get("created_at", ""),
        "last_updated": last_updated,
        "message_count": len(msgs),
        "preview": preview or "(empty chat)",
    }


@chat_bp.route("/api/analysis/<sid>/chats", methods=["GET"])
def list_chats(sid):
    sess = SESSIONS.get(sid)
    if not sess:
        return err("Invalid session", 404)
    sess.touch()
    if not sess.db_path:
        return ok([])
    db = read_db(sess.db_path)
    chats = db.get("chat_sessions", {}) or {}
    summaries = [_chat_summary(cid, cdata) for cid, cdata in chats.items()]
    summaries.sort(key=lambda s: s["last_updated"] or s["created_at"], reverse=True)
    return ok(summaries)


@chat_bp.route("/api/analysis/<sid>/chats/<chat_id>", methods=["GET"])
def get_chat(sid, chat_id):
    sess = SESSIONS.get(sid)
    if not sess:
        return err("Invalid session", 404)
    sess.touch()
    if not sess.db_path:
        return err("No database for this session", 404)
    db = read_db(sess.db_path)
    chat = db.get("chat_sessions", {}).get(chat_id)
    if not chat:
        return err("Chat not found", 404)
    return ok({
        "chat_id": chat_id,
        "messages": chat.get("messages", []),
        "current_function": chat.get("current_function", ""),
        "context_function_names": chat.get("context_function_names", []),
        "created_at": chat.get("created_at", ""),
    })
