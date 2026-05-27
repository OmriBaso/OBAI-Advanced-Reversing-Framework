import { create } from "zustand";
import { streamChat } from "../api/streaming";
import { apiClient } from "../api/client";
import type { ChatMessage, AgentActivity, ChatSummary } from "../api/types";

interface ChatState {
  chatId: string;
  messages: ChatMessage[];
  streamingText: string;
  streamingThinking: string;
  agentActivities: AgentActivity[];
  isStreaming: boolean;
  abortController: AbortController | null;
  pendingQuestion: string | null;
  pendingQuestionId: string | null;
  chats: ChatSummary[];

  sendMessage: (sid: string, message: string, currentFunction: string) => void;
  answerQuestion: (sid: string, answer: string) => void;
  startFreeRoam: (sid: string, startFunction: string, maxDepth: number) => void;
  generateExploit: (sid: string, vulnId: string) => void;
  resetChat: (sid: string) => void;
  cancelStream: () => void;
  refreshChats: (sid: string) => Promise<void>;
  loadChat: (sid: string, chatId: string) => Promise<void>;
  newChat: () => void;
}

function generateId() {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === "x" ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

function buildStreamCallbacks(set: Function, get: () => ChatState, sid: string) {
  return {
    onTextDelta: (content: string) => {
      set((s: ChatState) => ({ streamingText: s.streamingText + content }));
    },
    onThinking: (content: string) => {
      set((s: ChatState) => ({
        streamingThinking: s.streamingThinking + content,
      }));
    },
    onToolUse: (data: {
      tool: string;
      phase: string;
      arguments?: Record<string, unknown>;
    }) => {
      if (data.phase === "start") {
        set((s: ChatState) => ({
          agentActivities: [
            ...s.agentActivities,
            { type: "tool_start" as const, tool: data.tool },
          ],
        }));
      } else if (data.phase === "executing") {
        set((s: ChatState) => ({
          agentActivities: [
            ...s.agentActivities,
            { type: "tool_executing" as const, tool: data.tool },
          ],
        }));
      }
    },
    onToolResult: (data: {
      tool: string;
      summary: string;
      is_error: boolean;
    }) => {
      set((s: ChatState) => ({
        agentActivities: [
          ...s.agentActivities,
          {
            type: "tool_result" as const,
            tool: data.tool,
            summary: data.summary,
            is_error: data.is_error,
          },
        ],
      }));
    },
    onAgentStart: (data: { agent: string; task: string }) => {
      set((s: ChatState) => ({
        agentActivities: [
          ...s.agentActivities,
          { type: "agent_start" as const, agent: data.agent, task: data.task },
        ],
      }));
    },
    onAgentDone: (data: { agent: string }) => {
      set((s: ChatState) => ({
        agentActivities: [
          ...s.agentActivities,
          { type: "agent_done" as const, agent: data.agent },
        ],
      }));
    },
    onAskUser: (data: { question: string; question_id: string }) => {
      set({
        pendingQuestion: data.question,
        pendingQuestionId: data.question_id,
      });
    },
    onVulnerability: () => {},
    onDone: (data: { chat_id?: string }) => {
      const state = get();
      const finalText = state.streamingText;
      const finalThinking = state.streamingThinking;
      set((s: ChatState) => ({
        messages: [
          ...s.messages,
          {
            role: "assistant" as const,
            content: finalText,
            thinkingText: finalThinking || undefined,
            agentActivities: [...s.agentActivities],
          },
        ],
        streamingText: "",
        streamingThinking: "",
        agentActivities: [],
        isStreaming: false,
        abortController: null,
        chatId: data.chat_id || s.chatId,
      }));
      get().refreshChats(sid).catch(() => {});
    },
    onError: (message: string) => {
      set((s: ChatState) => ({
        messages: [
          ...s.messages,
          { role: "assistant" as const, content: `Error: ${message}` },
        ],
        streamingText: "",
        streamingThinking: "",
        isStreaming: false,
        abortController: null,
      }));
    },
  };
}

export const useChatStore = create<ChatState>((set, get) => ({
  chatId: generateId(),
  messages: [],
  streamingText: "",
  streamingThinking: "",
  agentActivities: [],
  isStreaming: false,
  abortController: null,
  pendingQuestion: null,
  pendingQuestionId: null,
  chats: [],

  sendMessage: (sid, message, currentFunction) => {
    const { chatId } = get();

    set((s) => ({
      messages: [
        ...s.messages,
        { role: "user" as const, content: message },
      ],
      streamingText: "",
      streamingThinking: "",
      agentActivities: [],
      isStreaming: true,
    }));

    const controller = streamChat(
      sid,
      {
        action: "message",
        message,
        current_function: currentFunction,
        chat_id: chatId,
      },
      buildStreamCallbacks(set, get, sid)
    );

    set({ abortController: controller });
  },

  answerQuestion: async (sid, answer) => {
    const { pendingQuestionId } = get();
    if (!pendingQuestionId) return;

    set({ pendingQuestion: null, pendingQuestionId: null });

    try {
      await fetch(`/api/analysis/${sid}/chat/answer`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          question_id: pendingQuestionId,
          answer,
        }),
      });
    } catch (err) {
      console.error("Failed to answer question:", err);
    }
  },

  startFreeRoam: (sid, startFunction, maxDepth) => {
    const { chatId } = get();

    set({
      streamingText: "",
      streamingThinking: "",
      agentActivities: [],
      isStreaming: true,
    });

    const controller = streamChat(
      sid,
      {
        action: "free_roam",
        start_function: startFunction,
        max_depth: maxDepth,
        chat_id: chatId,
      },
      buildStreamCallbacks(set, get, sid)
    );

    set({ abortController: controller });
  },

  generateExploit: (sid, vulnId) => {
    const { chatId } = get();

    set({
      streamingText: "",
      streamingThinking: "",
      agentActivities: [],
      isStreaming: true,
    });

    const controller = streamChat(
      sid,
      { action: "generate_exploit", vuln_id: vulnId, chat_id: chatId },
      buildStreamCallbacks(set, get, sid)
    );

    set({ abortController: controller });
  },

  resetChat: async (sid) => {
    const { chatId, abortController } = get();
    abortController?.abort();
    try {
      await fetch(`/api/analysis/${sid}/chat/reset`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ chat_id: chatId }),
      });
    } catch {}
    set({
      chatId: generateId(),
      messages: [],
      streamingText: "",
      streamingThinking: "",
      agentActivities: [],
      isStreaming: false,
      abortController: null,
      pendingQuestion: null,
      pendingQuestionId: null,
    });
  },

  cancelStream: () => {
    const { abortController, streamingText, streamingThinking, agentActivities } = get();
    abortController?.abort();

    if (streamingText || agentActivities.length > 0) {
      set((s) => ({
        messages: [
          ...s.messages,
          {
            role: "assistant" as const,
            content: streamingText || "(Stopped by user)",
            thinkingText: streamingThinking || undefined,
            agentActivities: [...agentActivities],
          },
        ],
        streamingText: "",
        streamingThinking: "",
        agentActivities: [],
        isStreaming: false,
        abortController: null,
      }));
    } else {
      set({ isStreaming: false, abortController: null });
    }
  },

  refreshChats: async (sid) => {
    if (!sid) return;
    try {
      const chats = await apiClient.listChats(sid);
      set({ chats });
    } catch {
      set({ chats: [] });
    }
  },

  loadChat: async (sid, chatId) => {
    const { abortController } = get();
    abortController?.abort();
    const data = await apiClient.getChat(sid, chatId);
    set({
      chatId: data.chat_id,
      messages: data.messages.map((m) => ({
        role: m.role,
        content: m.content,
        timestamp: m.timestamp,
      })),
      streamingText: "",
      streamingThinking: "",
      agentActivities: [],
      isStreaming: false,
      abortController: null,
      pendingQuestion: null,
      pendingQuestionId: null,
    });
  },

  newChat: () => {
    const { abortController } = get();
    abortController?.abort();
    set({
      chatId: generateId(),
      messages: [],
      streamingText: "",
      streamingThinking: "",
      agentActivities: [],
      isStreaming: false,
      abortController: null,
      pendingQuestion: null,
      pendingQuestionId: null,
    });
  },
}));
