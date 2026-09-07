import { useEffect, useRef, type HTMLAttributes, type UIEvent } from "react";
import { cn } from "@/lib/utils";

interface MessageScrollerProps extends HTMLAttributes<HTMLDivElement> {
  follow?: boolean;
}

/** Bottom-anchored transcript scroller adapted for Oars from the MIT shadcn
 * chatbot template. Native state remains the source of every message. */
export function MessageScroller({ className, follow = true, children, ...props }: MessageScrollerProps) {
  const viewportRef = useRef<HTMLDivElement>(null);
  const pinnedToBottom = useRef(true);

  useEffect(() => {
    if (!follow || !pinnedToBottom.current) return;
    const viewport = viewportRef.current;
    if (!viewport) return;
    viewport.scrollTo({ top: viewport.scrollHeight, behavior: "smooth" });
  }, [children, follow]);

  const onScroll = (event: UIEvent<HTMLDivElement>) => {
    const viewport = event.currentTarget;
    pinnedToBottom.current = viewport.scrollHeight - viewport.scrollTop - viewport.clientHeight < 80;
    props.onScroll?.(event);
  };

  return <div ref={viewportRef} className={cn("chat-scroller", className)} {...props} onScroll={onScroll}>{children}</div>;
}

export function MessageScrollerContent({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("chat-scroller-content", className)} {...props} />;
}
