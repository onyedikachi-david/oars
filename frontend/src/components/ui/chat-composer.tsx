import { ArrowUp, CircleStop } from "lucide-react";
import type { KeyboardEvent } from "react";
import { Button } from "./button";

interface ChatComposerProps {
  value: string;
  disabled?: boolean;
  busy?: boolean;
  blocker?: string | null;
  contextSummary: string;
  onChange: (value: string) => void;
  onSend: () => void;
  onStop?: () => void;
  onOpenContext: () => void;
}

export function ChatComposer({ value, disabled, busy, blocker, contextSummary, onChange, onSend, onStop, onOpenContext }: ChatComposerProps) {
  const onKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key !== "Enter" || event.shiftKey || event.nativeEvent.isComposing) return;
    event.preventDefault();
    if (!disabled && !busy) onSend();
  };

  return <div className="chat-composer-wrap">
    <div className="chat-composer">
      <textarea aria-label="AI terminal request" placeholder="Ask about this server…" value={value} onChange={(event) => onChange(event.target.value)} onKeyDown={onKeyDown} />
      <div className="chat-composer-footer">
        <button className="chat-context-receipt" type="button" title={contextSummary || "No context selected"} onClick={onOpenContext}><strong>Context</strong><span>{contextSummary || "None"}</span></button>
        <div><span>{blocker ?? "Enter to send · Shift+Enter for a new line"}</span>{busy && onStop ? <Button size="icon" variant="outline" aria-label="Stop response" onClick={onStop}><CircleStop /></Button> : <Button size="icon" aria-label="Ask" disabled={disabled} onClick={onSend}><ArrowUp /></Button>}</div>
      </div>
    </div>
  </div>;
}
