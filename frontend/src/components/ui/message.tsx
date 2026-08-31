import type { HTMLAttributes } from "react";
import { cn } from "@/lib/utils";

export function Message({ className, ...props }: HTMLAttributes<HTMLElement>) {
  return <article className={cn("chat-message", className)} {...props} />;
}

export function MessageAvatar({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("chat-message-avatar", className)} aria-hidden="true" {...props} />;
}

export function MessageContent({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("chat-message-content", className)} {...props} />;
}
