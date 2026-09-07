import type { HTMLAttributes } from "react";
import { cn } from "@/lib/utils";

interface BubbleProps extends HTMLAttributes<HTMLDivElement> {
  role: "user" | "assistant" | "system";
}

export function Bubble({ role, className, ...props }: BubbleProps) {
  return <div className={cn("chat-bubble", `is-${role}`, className)} data-role={role} {...props} />;
}
