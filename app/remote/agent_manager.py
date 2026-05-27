"""In-memory agent registry, task queues, and result delivery."""

import time
import uuid
import logging
import threading
from dataclasses import dataclass, field, asdict
from queue import Queue, Empty

log = logging.getLogger(__name__)

HEARTBEAT_TIMEOUT = 120  # seconds before an agent is considered dead


@dataclass
class AgentInfo:
    agent_id: str
    hostname: str = ""
    domain: str = ""
    username: str = ""
    os_version: str = ""
    ip_addresses: list = field(default_factory=list)
    is_elevated: bool = False
    dotnet_version: str = ""
    agent_version: str = ""
    connected_at: float = field(default_factory=time.time)
    last_heartbeat: float = field(default_factory=time.time)

    def to_dict(self):
        d = asdict(self)
        d["alive"] = (time.time() - self.last_heartbeat) < HEARTBEAT_TIMEOUT
        d["connected_seconds"] = int(time.time() - self.connected_at)
        return d


@dataclass
class PendingResult:
    event: threading.Event = field(default_factory=threading.Event)
    result: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Global registries
# ---------------------------------------------------------------------------

AGENTS: dict[str, AgentInfo] = {}
TASK_QUEUES: dict[str, Queue] = {}
PENDING_RESULTS: dict[str, PendingResult] = {}

_lock = threading.RLock()


def register_agent(info: dict) -> AgentInfo:
    agent_id = str(uuid.uuid4())[:12]
    agent = AgentInfo(
        agent_id=agent_id,
        hostname=info.get("hostname", ""),
        domain=info.get("domain", ""),
        username=info.get("username", ""),
        os_version=info.get("os_version", ""),
        ip_addresses=info.get("ip_addresses", []),
        is_elevated=info.get("is_elevated", False),
        dotnet_version=info.get("dotnet_version", ""),
        agent_version=info.get("agent_version", ""),
    )

    with _lock:
        AGENTS[agent_id] = agent
        TASK_QUEUES[agent_id] = Queue()

    log.info("Agent registered: %s (%s\\%s @ %s)",
             agent_id, agent.domain, agent.username, agent.hostname)
    return agent


def unregister_agent(agent_id: str):
    with _lock:
        AGENTS.pop(agent_id, None)
        TASK_QUEUES.pop(agent_id, None)
    log.info("Agent unregistered: %s", agent_id)


def heartbeat(agent_id: str) -> bool:
    with _lock:
        agent = AGENTS.get(agent_id)
        if not agent:
            return False
        agent.last_heartbeat = time.time()
        return True


def get_agent(agent_id: str) -> AgentInfo | None:
    return AGENTS.get(agent_id)


def list_agents() -> list[dict]:
    with _lock:
        return [a.to_dict() for a in AGENTS.values()]


def list_alive_agents() -> list[dict]:
    now = time.time()
    with _lock:
        return [
            a.to_dict() for a in AGENTS.values()
            if (now - a.last_heartbeat) < HEARTBEAT_TIMEOUT
        ]


def submit_task(agent_id: str, task_type: str, command: str = "",
                timeout: int = 120, parameters: dict | None = None) -> str:
    """Queue a task for an agent. Returns task_id."""
    with _lock:
        q = TASK_QUEUES.get(agent_id)
        if q is None:
            raise ValueError(f"Agent {agent_id} not connected")

    task_id = str(uuid.uuid4())[:16]
    task = {
        "task_id": task_id,
        "type": task_type,
        "command": command,
        "timeout": timeout,
        "parameters": parameters or {},
    }

    pending = PendingResult()
    with _lock:
        PENDING_RESULTS[task_id] = pending

    q.put(task)
    log.info("Task %s queued for agent %s (type=%s)", task_id, agent_id, task_type)
    return task_id


def poll_task(agent_id: str, timeout: float = 30.0) -> dict | None:
    """Block until a task is available or timeout. Called by the agent."""
    with _lock:
        q = TASK_QUEUES.get(agent_id)
        agent = AGENTS.get(agent_id)
        if q is None:
            return None
        if agent:
            agent.last_heartbeat = time.time()

    try:
        return q.get(timeout=timeout)
    except Empty:
        return None


def deliver_result(task_id: str, result: dict):
    """Called by the agent to deliver a task result."""
    with _lock:
        pending = PENDING_RESULTS.get(task_id)
        if not pending:
            log.warning("Result for unknown task %s", task_id)
            return
        pending.result = result
        pending.event.set()

    log.info("Result delivered for task %s", task_id)


def wait_for_result(task_id: str, timeout: float = 180.0) -> dict | None:
    """Block until result is available. Called by AI tool executor."""
    with _lock:
        pending = PENDING_RESULTS.get(task_id)
        if not pending:
            return None

    if pending.event.wait(timeout=timeout):
        with _lock:
            PENDING_RESULTS.pop(task_id, None)
        return pending.result

    with _lock:
        PENDING_RESULTS.pop(task_id, None)
    return None


# ---------------------------------------------------------------------------
# Background reaper for dead agents
# ---------------------------------------------------------------------------

def _reap_dead_agents():
    while True:
        time.sleep(60)
        now = time.time()
        dead = []
        with _lock:
            for aid, agent in AGENTS.items():
                if (now - agent.last_heartbeat) > HEARTBEAT_TIMEOUT * 2:
                    dead.append(aid)
            for aid in dead:
                AGENTS.pop(aid, None)
                TASK_QUEUES.pop(aid, None)

        if dead:
            log.info("Reaped %d dead agent(s): %s", len(dead), dead)


_reaper = threading.Thread(target=_reap_dead_agents, daemon=True)
_reaper.start()
