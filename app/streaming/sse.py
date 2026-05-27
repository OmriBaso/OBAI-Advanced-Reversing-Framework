"""Server-Sent Events helpers for Flask streaming responses."""

import json
from flask import Response
from typing import Generator

from ..agents.providers.base import AgentEvent


def sse_event(event_type: str, data: dict) -> str:
    """Format a single SSE event string."""
    payload = json.dumps(data, ensure_ascii=False)
    return f"event: {event_type}\ndata: {payload}\n\n"


def agent_event_to_sse(event: AgentEvent) -> str:
    """Convert an AgentEvent to an SSE string."""
    return sse_event(event.type.value, event.data)


def sse_stream(generator: Generator[AgentEvent, None, None]) -> Generator[str, None, None]:
    """Convert a generator of AgentEvents into a generator of SSE strings."""
    for event in generator:
        yield agent_event_to_sse(event)


def SSEResponse(generator: Generator[AgentEvent, None, None], chat_id: str = "") -> Response:
    """Create a Flask Response for SSE streaming from an agent event generator."""
    def generate():
        emitted_done = False
        try:
            for event in generator:
                if event.type.value == "done":
                    emitted_done = True
                    event.data["chat_id"] = chat_id
                yield agent_event_to_sse(event)
        except Exception as e:
            yield sse_event("error", {"message": str(e)})
        finally:
            if not emitted_done and chat_id:
                yield sse_event("done", {"chat_id": chat_id})

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
