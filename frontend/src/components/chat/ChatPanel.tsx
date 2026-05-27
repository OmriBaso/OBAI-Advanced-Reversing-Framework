import { useRef, useEffect, useState } from "react";
import { useAnalysisStore } from "../../stores/analysisStore";
import { useChatStore } from "../../stores/chatStore";
import { MessageBubble } from "./MessageBubble";
import { AgentActivity } from "./AgentActivity";
import { ChatInput } from "./ChatInput";
import { RotateCcw, Radar, StopCircle, HelpCircle, Send, Plus, ChevronDown } from "lucide-react";

export function ChatPanel() {
  const { sid, selectedFunction } = useAnalysisStore();
  const {
    chatId,
    chats,
    messages,
    streamingText,
    streamingThinking,
    agentActivities,
    isStreaming,
    pendingQuestion,
    sendMessage,
    answerQuestion,
    startFreeRoam,
    resetChat,
    cancelStream,
    newChat,
    loadChat,
  } = useChatStore();

  const scrollRef = useRef<HTMLDivElement>(null);
  const [questionAnswer, setQuestionAnswer] = useState("");
  const [pickerOpen, setPickerOpen] = useState(false);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, streamingText, streamingThinking, agentActivities, pendingQuestion]);

  const handleSend = (text: string) => {
    sendMessage(sid, text, selectedFunction);
  };

  const handleAnswer = () => {
    if (!questionAnswer.trim()) return;
    answerQuestion(sid, questionAnswer.trim());
    setQuestionAnswer("");
  };

  const currentChat = chats.find((c) => c.chat_id === chatId);
  const currentLabel = currentChat?.preview || (messages.length === 0 ? "New chat" : "Current chat");

  return (
    <div className="h-full flex flex-col bg-[var(--color-bg-secondary)]">
      <div className="flex items-center justify-between px-4 py-2 border-b border-[var(--color-border)] gap-2">
        <div className="flex items-center gap-2 min-w-0 flex-1">
          <span className="text-xs font-semibold text-[var(--color-text-primary)] flex-shrink-0">Chat</span>
          <div className="relative min-w-0 flex-1">
            <button
              onClick={() => setPickerOpen((o) => !o)}
              disabled={isStreaming}
              className="flex items-center gap-1 px-2 py-1 text-[10px] rounded bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] disabled:opacity-50 transition-colors max-w-full"
            >
              <span className="truncate max-w-[200px]">{currentLabel}</span>
              <ChevronDown size={10} className="flex-shrink-0" />
            </button>
            {pickerOpen && (
              <>
                <div className="fixed inset-0 z-10" onClick={() => setPickerOpen(false)} />
                <div className="absolute top-full left-0 mt-1 w-72 max-h-80 overflow-auto z-20 rounded-md border border-[var(--color-border)] bg-[var(--color-bg-secondary)] shadow-lg">
                  {chats.length === 0 && (
                    <div className="px-3 py-2 text-[10px] text-[var(--color-text-muted)]">
                      No saved chats yet.
                    </div>
                  )}
                  {chats.map((c) => (
                    <button
                      key={c.chat_id}
                      onClick={() => {
                        setPickerOpen(false);
                        if (c.chat_id !== chatId) loadChat(sid, c.chat_id);
                      }}
                      className={`w-full text-left px-3 py-2 hover:bg-[var(--color-bg-tertiary)] transition-colors ${
                        c.chat_id === chatId ? "bg-[var(--color-bg-tertiary)]" : ""
                      }`}
                    >
                      <div className="text-[11px] text-[var(--color-text-primary)] truncate">
                        {c.preview}
                      </div>
                      <div className="text-[9px] text-[var(--color-text-muted)] mt-0.5">
                        {c.message_count} msg{c.message_count === 1 ? "" : "s"}
                        {c.last_updated && ` · ${c.last_updated}`}
                      </div>
                    </button>
                  ))}
                </div>
              </>
            )}
          </div>
          <button
            onClick={() => {
              setPickerOpen(false);
              newChat();
            }}
            disabled={isStreaming}
            className="flex items-center gap-1 px-2 py-1 text-[10px] rounded bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] disabled:opacity-50 transition-colors flex-shrink-0"
            title="Start a new chat"
          >
            <Plus size={10} /> New
          </button>
          {isStreaming && (
            <div className="flex items-center gap-1.5 text-[10px] text-[var(--color-accent)] flex-shrink-0">
              <div className="w-1.5 h-1.5 rounded-full bg-[var(--color-accent)] animate-pulse" />
              thinking...
            </div>
          )}
        </div>
        <div className="flex items-center gap-1">
          {selectedFunction && (
            <button
              onClick={() => startFreeRoam(sid, selectedFunction, 5)}
              disabled={isStreaming}
              className="flex items-center gap-1 px-2 py-1 text-[10px] rounded bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] disabled:opacity-50 transition-colors"
            >
              <Radar size={10} /> Free Roam
            </button>
          )}
          {isStreaming && (
            <button
              onClick={cancelStream}
              className="flex items-center gap-1 px-2 py-1 text-[10px] rounded bg-[var(--color-red)] text-white transition-colors"
            >
              <StopCircle size={10} /> Stop
            </button>
          )}
          <button
            onClick={() => resetChat(sid)}
            className="flex items-center gap-1 px-2 py-1 text-[10px] rounded bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors"
          >
            <RotateCcw size={10} /> Reset
          </button>
        </div>
      </div>

      <div ref={scrollRef} className="flex-1 overflow-y-auto px-4 py-3 space-y-3">
        {messages.map((msg, i) => (
          <MessageBubble key={i} message={msg} />
        ))}

        {isStreaming && agentActivities.length > 0 && (
          <AgentActivity activities={agentActivities} />
        )}

        {isStreaming && (streamingText || streamingThinking) && (
          <MessageBubble
            message={{ role: "assistant", content: streamingText }}
            thinkingText={streamingThinking}
            isStreaming
          />
        )}

        {pendingQuestion && (
          <div className="rounded-lg border border-[var(--color-yellow)]/40 bg-[var(--color-yellow)]/5 p-3 space-y-2">
            <div className="flex items-start gap-2">
              <HelpCircle size={14} className="text-[var(--color-yellow)] flex-shrink-0 mt-0.5" />
              <p className="text-xs text-[var(--color-text-primary)] leading-relaxed">
                {pendingQuestion}
              </p>
            </div>
            <div className="flex gap-2">
              <input
                type="text"
                value={questionAnswer}
                onChange={(e) => setQuestionAnswer(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleAnswer()}
                placeholder="Type your answer..."
                className="flex-1 bg-[var(--color-bg-primary)] border border-[var(--color-border)] rounded px-2 py-1.5 text-xs text-[var(--color-text-primary)] placeholder:text-[var(--color-text-muted)] focus:outline-none focus:border-[var(--color-yellow)]"
                autoFocus
              />
              <button
                onClick={handleAnswer}
                disabled={!questionAnswer.trim()}
                className="flex items-center gap-1 px-3 py-1.5 text-[10px] rounded bg-[var(--color-yellow)] text-black font-medium disabled:opacity-50 transition-colors"
              >
                <Send size={10} /> Answer
              </button>
            </div>
          </div>
        )}
      </div>

      <ChatInput onSend={handleSend} disabled={isStreaming && !pendingQuestion} />
    </div>
  );
}
