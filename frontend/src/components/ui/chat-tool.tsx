import { CheckCircle2, CircleStop, Play, ShieldAlert, TerminalSquare } from "lucide-react";
import type { ReactNode } from "react";
import { Button } from "./button";

export type ChatToolState = "approval-requested" | "running" | "completed" | "failed" | "canceled" | "recovery-required";

interface ChatToolProps {
  title: string;
  target: string;
  command: string;
  explanation: string;
  state: ChatToolState;
  destructive: boolean;
  output?: string;
  exit?: number | null;
  editing?: boolean;
  editCommand?: string;
  destructiveAck?: boolean;
  busy?: boolean;
  onEditCommand?: (value: string) => void;
  onStartEdit?: () => void;
  onSaveEdit?: () => void;
  onCancelEdit?: () => void;
  onAckChange?: (checked: boolean) => void;
  onRun?: () => void;
  onCancel?: () => void;
  onSummarize?: () => void;
  extraActions?: ReactNode;
}

const stateCopy: Record<ChatToolState, string> = {
  "approval-requested": "Needs your approval",
  running: "Running",
  completed: "Completed",
  failed: "Failed",
  canceled: "Canceled",
  "recovery-required": "Needs recovery",
};

export function ChatTool({
  title, target, command, explanation, state, destructive, output, exit,
  editing, editCommand, destructiveAck, busy, onEditCommand, onStartEdit,
  onSaveEdit, onCancelEdit, onAckChange, onRun, onCancel, onSummarize, extraActions,
}: ChatToolProps) {
  return <section className={`chat-tool is-${state}`} aria-label={`${title}: ${stateCopy[state]}`}>
    <header className="chat-tool-header">
      <span className="chat-tool-icon"><TerminalSquare /></span>
      <div><strong>{title}</strong><span>{target}</span></div>
      <span className="chat-tool-state">{state === "running" ? <span className="chat-tool-spinner" /> : state === "completed" ? <CheckCircle2 /> : state === "canceled" ? <CircleStop /> : state === "recovery-required" || destructive ? <ShieldAlert /> : <span className="chat-tool-dot" />}{stateCopy[state]}</span>
    </header>

    <div className="chat-tool-body">
      <p>{explanation}</p>
      {editing ? <textarea className="chat-tool-editor" aria-label="Edited command" value={editCommand} onChange={(event) => onEditCommand?.(event.target.value)} /> : <pre className="chat-tool-command"><code>{command}</code></pre>}

      {destructive && state === "approval-requested" && <label className="chat-tool-warning"><input type="checkbox" checked={destructiveAck} onChange={(event) => onAckChange?.(event.target.checked)} /><span><strong>This command can change or remove server data.</strong> I reviewed the destructive warning, exact command, and target.</span></label>}

      {state === "approval-requested" && <div className="chat-tool-actions">
        {editing ? <><Button size="sm" variant="outline" onClick={onSaveEdit} disabled={busy || !editCommand?.trim()}>Save command</Button><Button size="sm" variant="ghost" onClick={onCancelEdit}>Cancel edit</Button></> : <><Button size="sm" onClick={onRun} disabled={busy || (destructive && !destructiveAck)}><Play />Run exact command</Button><Button size="sm" variant="outline" onClick={onStartEdit}>Edit</Button><Button size="sm" variant="ghost" onClick={onCancel}>Decline</Button>{extraActions}</>}
      </div>}

      {(state === "running" || output !== undefined) && <div className="chat-tool-output">
        <div><span>Command output</span>{state === "running" ? <span>Live</span> : <span>Exit {exit ?? "unknown"}</span>}</div>
        <pre><code>{output || (state === "running" ? "Waiting for output…" : "No output was retained.")}</code></pre>
      </div>}

      {state === "completed" && onSummarize && <div className="chat-tool-actions"><Button size="sm" variant="outline" onClick={onSummarize} disabled={busy}>Explain this output</Button>{extraActions}</div>}
    </div>
  </section>;
}
