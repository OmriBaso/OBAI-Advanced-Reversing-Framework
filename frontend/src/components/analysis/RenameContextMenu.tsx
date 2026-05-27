import { useEffect, useRef, useState } from "react";

interface Props {
  kind: "func" | "var" | "symbol";
  name: string;
  x: number;
  y: number;
  canJump?: boolean;
  onJump?: () => void;
  onCommit: (newName: string) => Promise<void> | void;
  onClose: () => void;
}

const KIND_LABEL: Record<Props["kind"], string> = {
  func: "function",
  var: "variable",
  symbol: "symbol",
};

export function RenameContextMenu({ kind, name, x, y, canJump, onJump, onCommit, onClose }: Props) {
  const [editing, setEditing] = useState(false);
  const [value, setValue] = useState(name);
  const [busy, setBusy] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const rootRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const onMouseDown = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) onClose();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("mousedown", onMouseDown);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("mousedown", onMouseDown);
      window.removeEventListener("keydown", onKey);
    };
  }, [onClose]);

  useEffect(() => {
    if (editing && inputRef.current) {
      inputRef.current.focus();
      inputRef.current.select();
    }
  }, [editing]);

  const startRename = () => {
    setEditing(true);
    setValue(name);
  };

  const commit = async () => {
    const trimmed = value.trim();
    if (!trimmed || trimmed === name) {
      onClose();
      return;
    }
    setBusy(true);
    try {
      await onCommit(trimmed);
    } finally {
      setBusy(false);
      onClose();
    }
  };

  // Clamp to viewport
  const maxX = typeof window !== "undefined" ? window.innerWidth - 260 : x;
  const maxY = typeof window !== "undefined" ? window.innerHeight - 120 : y;

  return (
    <div
      ref={rootRef}
      style={{
        position: "fixed",
        left: Math.min(x, Math.max(0, maxX)),
        top: Math.min(y, Math.max(0, maxY)),
        zIndex: 80,
      }}
      className="min-w-[220px] bg-[var(--color-bg-secondary)] border border-[var(--color-border)] rounded-md shadow-2xl overflow-hidden text-xs"
    >
      <div className="px-3 py-1.5 border-b border-[var(--color-border)] text-[10px] text-[var(--color-text-muted)] font-mono truncate">
        {KIND_LABEL[kind]} · {name}
      </div>

      {editing ? (
        <div className="p-2 flex gap-1">
          <input
            ref={inputRef}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                commit();
              } else if (e.key === "Escape") {
                e.preventDefault();
                onClose();
              }
            }}
            disabled={busy}
            className="flex-1 px-2 py-1 text-xs font-mono rounded bg-[var(--color-bg-primary)] border border-[var(--color-accent)] text-[var(--color-text-primary)] focus:outline-none disabled:opacity-50"
          />
          <button
            onClick={commit}
            disabled={busy}
            className="px-2 py-1 text-[10px] rounded bg-[var(--color-accent)] text-white disabled:opacity-50"
          >
            {busy ? "…" : "OK"}
          </button>
        </div>
      ) : (
        <div className="py-1">
          <button
            onClick={startRename}
            className="w-full text-left px-3 py-1.5 hover:bg-[var(--color-bg-tertiary)] text-[var(--color-text-primary)]"
          >
            Rename {KIND_LABEL[kind]}…
          </button>
          {kind === "func" && canJump && onJump && (
            <button
              onClick={() => {
                onJump();
                onClose();
              }}
              className="w-full text-left px-3 py-1.5 hover:bg-[var(--color-bg-tertiary)] text-[var(--color-text-primary)]"
            >
              Jump to function
            </button>
          )}
        </div>
      )}
    </div>
  );
}
