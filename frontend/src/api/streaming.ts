import type { SSEEventType, AgentActivity } from "./types";

export interface SSECallbacks {
  onTextDelta: (content: string) => void;
  onThinking?: (content: string) => void;
  onToolUse: (data: { tool: string; phase: string; arguments?: Record<string, unknown> }) => void;
  onToolResult: (data: { tool: string; summary: string; is_error: boolean }) => void;
  onAgentStart: (data: { agent: string; task: string }) => void;
  onAgentDone: (data: { agent: string }) => void;
  onVulnerability: (data: Record<string, unknown>) => void;
  onAskUser?: (data: { question: string; question_id: string }) => void;
  onDone: (data: { chat_id?: string }) => void;
  onError: (message: string) => void;
}

export function streamChat(
  sid: string,
  body: Record<string, unknown>,
  callbacks: SSECallbacks
): AbortController {
  const controller = new AbortController();

  fetch(`/api/analysis/${sid}/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ...body, stream: true }),
    signal: controller.signal,
  })
    .then(async (resp) => {
      if (!resp.ok) {
        const json = await resp.json().catch(() => ({ error: "Request failed" }));
        callbacks.onError(json.error || `HTTP ${resp.status}`);
        return;
      }

      const reader = resp.body?.getReader();
      if (!reader) {
        callbacks.onError("No response body");
        return;
      }

      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";

        let currentEvent = "";
        for (const line of lines) {
          if (line.startsWith("event: ")) {
            currentEvent = line.slice(7).trim();
          } else if (line.startsWith("data: ") && currentEvent) {
            try {
              const data = JSON.parse(line.slice(6));
              handleSSEEvent(currentEvent as SSEEventType, data, callbacks);
            } catch {
              // skip malformed JSON
            }
            currentEvent = "";
          }
        }
      }
    })
    .catch((err) => {
      if (err.name !== "AbortError") {
        callbacks.onError(err.message);
      }
    });

  return controller;
}

function handleSSEEvent(
  type: SSEEventType,
  data: Record<string, unknown>,
  callbacks: SSECallbacks
) {
  switch (type) {
    case "text_delta":
      callbacks.onTextDelta((data.content as string) || "");
      break;
    case "thinking":
      callbacks.onThinking?.((data.content as string) || "");
      break;
    case "tool_use":
      callbacks.onToolUse(data as { tool: string; phase: string; arguments?: Record<string, unknown> });
      break;
    case "tool_result":
      callbacks.onToolResult(data as { tool: string; summary: string; is_error: boolean });
      break;
    case "agent_start":
      callbacks.onAgentStart(data as { agent: string; task: string });
      break;
    case "agent_done":
      callbacks.onAgentDone(data as { agent: string });
      break;
    case "vulnerability":
      callbacks.onVulnerability(data);
      break;
    case "ask_user":
      callbacks.onAskUser?.(data as { question: string; question_id: string });
      break;
    case "done":
      callbacks.onDone(data as { chat_id?: string });
      break;
    case "error":
      callbacks.onError((data.message as string) || "Unknown error");
      break;
  }
}
