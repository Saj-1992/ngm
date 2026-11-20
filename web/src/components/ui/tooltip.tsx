import * as TooltipPrimitive from "@radix-ui/react-tooltip";
import { HelpCircle } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "./primitives";

export function AppTooltipProvider({ children }: { children: ReactNode }) {
  return <TooltipPrimitive.Provider delayDuration={250} skipDelayDuration={100}>{children}</TooltipPrimitive.Provider>;
}

export function Tip({
  content,
  side = "top",
  children,
}: {
  content?: ReactNode;
  side?: "top" | "bottom" | "left" | "right";
  children: ReactNode;
}) {
  if (!content) return <>{children}</>;
  return (
    <TooltipPrimitive.Root>
      <TooltipPrimitive.Trigger asChild>{children}</TooltipPrimitive.Trigger>
      <TooltipPrimitive.Portal>
        <TooltipPrimitive.Content
          side={side}
          sideOffset={6}
          className={cn(
            "z-50 max-w-xs rounded-lg border border-border bg-fg px-2.5 py-1.5 text-xs leading-relaxed text-bg shadow-lg",
            "animate-in fade-in-0 zoom-in-95",
          )}
        >
          {content}
          <TooltipPrimitive.Arrow className="fill-fg" />
        </TooltipPrimitive.Content>
      </TooltipPrimitive.Portal>
    </TooltipPrimitive.Root>
  );
}

export function HelpTip({ text, className }: { text: string; className?: string }) {
  return (
    <Tip content={text}>
      <button
        type="button"
        aria-label={text}
        className={cn(
          "inline-flex size-4 shrink-0 items-center justify-center rounded-full text-fg-muted transition hover:text-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
          className,
        )}
      >
        <HelpCircle className="size-3.5" aria-hidden />
      </button>
    </Tip>
  );
}
