import { useState, useRef, useEffect } from "react";
import { useAnalysisStore } from "../../stores/analysisStore";
import { useUIStore } from "../../stores/uiStore";
import { UploadZone } from "../upload/UploadZone";
import { Search, Layers, FilePlus } from "lucide-react";

export function Sidebar() {
  const {
    sid,
    functions,
    modules,
    moduleFilter,
    selectedFunction,
    selectedFunctionModule,
    setSelectedFunction,
    setModuleFilter,
    renameFunction,
  } = useAnalysisStore();
  const { funcSearch, setFuncSearch, funcFilter, setFuncFilter, openModal } = useUIStore();

  // Inline rename state — keyed by function "<module>::<name>"
  const [editing, setEditing] = useState<string | null>(null);
  const [editValue, setEditValue] = useState("");
  const editInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (editing && editInputRef.current) {
      editInputRef.current.focus();
      editInputRef.current.select();
    }
  }, [editing]);

  const startEdit = (module: string | undefined, name: string) => {
    setEditing(`${module || ""}::${name}`);
    setEditValue(name);
  };
  const cancelEdit = () => {
    setEditing(null);
    setEditValue("");
  };
  const commitEdit = async (module: string | undefined, oldName: string) => {
    const newName = editValue.trim();
    setEditing(null);
    if (!newName || newName === oldName) return;
    try {
      await renameFunction(oldName, newName, module);
    } catch (e) {
      console.error("Rename failed:", e);
    }
  };

  const filtered = functions.filter((f) => {
    if (funcFilter === "named" && !f.is_named) return false;
    if (funcFilter === "imports" && !f.is_import) return false;
    if (moduleFilter && f.module !== moduleFilter) return false;
    if (funcSearch && !f.name.toLowerCase().includes(funcSearch.toLowerCase())) return false;
    return true;
  });

  const mainModuleName = modules.find((m) => m.is_main)?.name ?? "";
  const hasMultipleModules = modules.length > 1;

  return (
    <div className="h-full flex flex-col bg-[var(--color-bg-secondary)]">
      {!sid ? (
        <div className="flex-1 flex items-center justify-center p-4">
          <UploadZone />
        </div>
      ) : (
        <>
          <div className="p-2 border-b border-[var(--color-border)] space-y-2">
            <div className="relative">
              <Search size={14} className="absolute left-2.5 top-2 text-[var(--color-text-muted)]" />
              <input
                type="text"
                placeholder="Search functions..."
                value={funcSearch}
                onChange={(e) => setFuncSearch(e.target.value)}
                className="w-full pl-8 pr-3 py-1.5 text-xs rounded bg-[var(--color-bg-primary)] border border-[var(--color-border)] text-[var(--color-text-primary)] placeholder:text-[var(--color-text-muted)] focus:outline-none focus:border-[var(--color-accent)]"
              />
            </div>

            <div className="flex gap-1">
              {(["all", "named", "imports"] as const).map((f) => (
                <button
                  key={f}
                  onClick={() => setFuncFilter(f)}
                  className={`flex-1 text-xs py-1 rounded transition-colors ${
                    funcFilter === f
                      ? "bg-[var(--color-accent)] text-white"
                      : "bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
                  }`}
                >
                  {f === "all" ? `All (${functions.length})` : f === "named" ? "Named" : "Imports"}
                </button>
              ))}
            </div>

            <div className="flex items-center gap-1.5">
              <Layers size={12} className="text-[var(--color-text-muted)] flex-shrink-0" />
              <select
                value={moduleFilter}
                onChange={(e) => setModuleFilter(e.target.value)}
                className="flex-1 px-2 py-1 text-[10px] rounded bg-[var(--color-bg-primary)] border border-[var(--color-border)] text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
              >
                <option value="">
                  {hasMultipleModules ? `All modules (${modules.length})` : "All modules"}
                </option>
                {modules.map((m) => (
                  <option key={m.name} value={m.name}>
                    {m.name}
                    {m.is_main ? " (main)" : ""}
                    {typeof m.n_functions === "number" ? `  ·  ${m.n_functions}` : ""}
                  </option>
                ))}
              </select>
              <button
                onClick={() => openModal("addBinary")}
                className="flex items-center gap-1 px-2 py-1 text-[10px] rounded bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] flex-shrink-0"
                title="Add another binary to this session"
              >
                <FilePlus size={11} />
              </button>
            </div>
          </div>

          <div className="flex-1 overflow-y-auto">
            {filtered.map((func) => {
              const isSelected =
                selectedFunction === func.name &&
                (!selectedFunctionModule || selectedFunctionModule === func.module);
              const showModuleBadge =
                hasMultipleModules && func.module && func.module !== mainModuleName;
              const editKey = `${func.module || ""}::${func.name}`;
              const isEditing = editing === editKey;
              return (
                <div
                  key={(func.module || "") + func.name + func.address_hex}
                  onClick={() => !isEditing && setSelectedFunction(func.name, func.module)}
                  onDoubleClick={(e) => {
                    if (func.is_import) return;
                    e.preventDefault();
                    e.stopPropagation();
                    startEdit(func.module, func.name);
                  }}
                  className={`w-full text-left px-3 py-1.5 text-xs flex items-center gap-2 border-b border-[var(--color-border-light)] transition-colors cursor-pointer ${
                    isSelected
                      ? "bg-[var(--color-bg-tertiary)] text-[var(--color-accent)] border-l-2 border-l-[var(--color-accent)]"
                      : "text-[var(--color-text-secondary)] hover:bg-[var(--color-bg-tertiary)] hover:text-[var(--color-text-primary)]"
                  }`}
                  title={func.is_import ? "" : "Double-click to rename"}
                >
                  {isEditing ? (
                    <input
                      ref={editInputRef}
                      value={editValue}
                      onChange={(e) => setEditValue(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") {
                          e.preventDefault();
                          commitEdit(func.module, func.name);
                        } else if (e.key === "Escape") {
                          e.preventDefault();
                          cancelEdit();
                        }
                      }}
                      onBlur={() => commitEdit(func.module, func.name)}
                      onClick={(e) => e.stopPropagation()}
                      className="flex-1 px-1 py-0 text-xs font-mono rounded bg-[var(--color-bg-primary)] border border-[var(--color-accent)] text-[var(--color-text-primary)] focus:outline-none"
                    />
                  ) : (
                    <span className="truncate flex-1 font-mono">{func.name}</span>
                  )}
                  {showModuleBadge && (
                    <span
                      className="text-[9px] px-1 rounded bg-[var(--color-bg-primary)] text-[var(--color-text-muted)] font-mono flex-shrink-0 truncate max-w-[80px]"
                      title={func.module}
                    >
                      {func.module}
                    </span>
                  )}
                  <span className="text-[10px] text-[var(--color-text-muted)] font-mono flex-shrink-0">
                    {func.address_hex}
                  </span>
                  {func.is_import && (
                    <span className="text-[9px] px-1 rounded bg-[var(--color-purple)] text-white flex-shrink-0">
                      IMP
                    </span>
                  )}
                </div>
              );
            })}
          </div>

          <div className="p-2 text-[10px] text-[var(--color-text-muted)] border-t border-[var(--color-border)]">
            {filtered.length} / {functions.length} functions
            {moduleFilter && ` · filtered to ${moduleFilter}`}
          </div>
        </>
      )}
    </div>
  );
}
