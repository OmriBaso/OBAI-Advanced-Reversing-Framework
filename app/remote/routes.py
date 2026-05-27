"""Flask blueprint for remote agent HTTP endpoints."""

import logging
from flask import Blueprint, request, jsonify

from .. import ok, err
from . import agent_manager as mgr

log = logging.getLogger(__name__)

remote_bp = Blueprint("remote", __name__)


@remote_bp.route("/api/remote/register", methods=["POST"])
def register():
    body = request.get_json(force=True) or {}
    if not body.get("hostname"):
        return err("hostname is required")

    agent = mgr.register_agent(body)
    return ok({
        "agent_id": agent.agent_id,
        "status": "connected",
    })


@remote_bp.route("/api/remote/<agent_id>/poll", methods=["GET"])
def poll(agent_id):
    agent = mgr.get_agent(agent_id)
    if not agent:
        return err("Unknown agent", 404)

    timeout = min(float(request.args.get("timeout", 30)), 60)
    task = mgr.poll_task(agent_id, timeout=timeout)

    if task:
        return ok({"has_task": True, "task": task})
    return ok({"has_task": False, "task": None})


@remote_bp.route("/api/remote/<agent_id>/result", methods=["POST"])
def result(agent_id):
    agent = mgr.get_agent(agent_id)
    if not agent:
        return err("Unknown agent", 404)

    body = request.get_json(force=True) or {}
    task_id = body.get("task_id")
    if not task_id:
        return err("task_id is required")

    mgr.deliver_result(task_id, body)
    return ok({"received": True})


@remote_bp.route("/api/remote/<agent_id>/heartbeat", methods=["POST"])
def heartbeat(agent_id):
    if mgr.heartbeat(agent_id):
        return ok({"alive": True})
    return err("Unknown agent", 404)


@remote_bp.route("/api/remote/agents", methods=["GET"])
def list_agents():
    agents = mgr.list_agents()
    return ok({"agents": agents, "count": len(agents)})


@remote_bp.route("/api/remote/<agent_id>", methods=["DELETE"])
def disconnect(agent_id):
    mgr.unregister_agent(agent_id)
    return ok({"disconnected": True})
