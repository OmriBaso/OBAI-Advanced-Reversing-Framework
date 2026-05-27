import { useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import rehypeHighlight from "rehype-highlight";
import type { ChatMessage } from "../../api/types";
import { AgentActivity } from "./AgentActivity";
import { User, Bot, Brain, ChevronDown, ChevronRight } from "lucide-react";

interface Props {
  message: ChatMessage;
  isStreaming?: boolean;
  thinkingText?: string;
}

function ThinkingBlock({ text, isStreaming }: { text: string; isStreaming?: boolean }) {
  const [open, setOpen] = useState(false);

  if (!text) return null;

  return (
    <div className="mb-2">
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-1.5 text-[10px] text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)] transition-colors"
      >
        <Brain size={11} className="text-[var(--color-purple)]" />
        {open ? <ChevronDown size={10} /> : <ChevronRight size={10} />}
        <span className="font-medium">
          {isStreaming ? "Thinking..." : "Thought process"}
        </span>
        {isStreaming && (
          <div className="w-1.5 h-1.5 rounded-full bg-[var(--color-purple)] animate-pulse" />
        )}
      </button>
      {open && (
        <div className="mt-1 ml-4 pl-2 border-l-2 border-[var(--color-purple)]/30 text-[10px] text-[var(--color-text-muted)] leading-relaxed whitespace-pre-wrap max-h-60 overflow-y-auto">
          {text}
          {isStreaming && (
            <span className="inline-block w-1 h-3 bg-[var(--color-purple)] animate-pulse ml-0.5" />
          )}
        </div>
      )}
    </div>
  );
}

export function MessageBubble({ message, isStreaming, thinkingText }: Props) {
  const isUser = message.role === "user";
  const thinking = thinkingText || message.thinkingText;

  return (
    <div className={`flex gap-3 ${isUser ? "flex-row-reverse" : ""}`}>
      <div
        className={`w-7 h-7 rounded-full flex items-center justify-center flex-shrink-0 ${
          isUser ? "bg-[var(--color-accent)]" : "bg-[var(--color-bg-tertiary)] border border-[var(--color-border)]"
        }`}
      >
        {isUser ? <User size={14} className="text-white" /> : <Bot size={14} className="text-[var(--color-accent)]" />}
      </div>

      <div className={`flex-1 min-w-0 ${isUser ? "text-right" : ""}`}>
        {message.agentActivities && message.agentActivities.length > 0 && (
          <div className="mb-2">
            <AgentActivity activities={message.agentActivities} collapsed />
          </div>
        )}

        {!isUser && thinking && (
          <ThinkingBlock text={thinking} isStreaming={isStreaming} />
        )}

        <div
          className={`inline-block text-left rounded-lg px-3 py-2 text-xs leading-relaxed max-w-full ${
            isUser
              ? "bg-[var(--color-accent)] text-white"
              : "bg-[var(--color-bg-tertiary)] text-[var(--color-text-primary)]"
          }`}
        >
          {isUser ? (
            <p className="whitespace-pre-wrap">{message.content}</p>
          ) : (
            <div className="prose prose-invert prose-xs max-w-none [&_pre]:bg-[var(--color-bg-primary)] [&_pre]:rounded [&_pre]:p-2 [&_pre]:text-[11px] [&_code]:text-[11px] [&_code]:font-mono [&_p]:my-1 [&_ul]:my-1 [&_ol]:my-1 [&_h1]:text-sm [&_h2]:text-xs [&_h3]:text-xs [&_h1]:font-semibold [&_h2]:font-semibold [&_a]:text-[var(--color-accent)]">
              <ReactMarkdown remarkPlugins={[remarkGfm]} rehypePlugins={[rehypeHighlight]}>
                {message.content}
              </ReactMarkdown>
            </div>
          )}
          {isStreaming && (
            <span className="inline-block w-1.5 h-4 bg-[var(--color-accent)] animate-pulse ml-0.5" />
          )}
        </div>
      </div>
    </div>
  );
}
