import { CircleCheck, CircleHelp, CircleMinus, CircleX, TriangleAlert } from "lucide-react";
import type { HealthStatus } from "@/lib/api";
import { useI18n } from "@/i18n/i18n";
import { cn } from "./ui/primitives";

const styles: Record<HealthStatus, { cls: string; Icon: typeof CircleCheck }> = {
  healthy: { cls: "bg-ok-soft text-ok", Icon: CircleCheck },
  degraded: { cls: "bg-warn-soft text-warn", Icon: TriangleAlert },
  down: { cls: "bg-bad-soft text-bad", Icon: CircleX },
  unknown: { cls: "bg-unknown-soft text-unknown", Icon: CircleHelp },
  disabled: { cls: "bg-unknown-soft text-unknown", Icon: CircleMinus },
};

/** Status is conveyed by icon + text, not colour alone (WCAG 1.4.1). */
export function StatusBadge({ status, size = "sm" }: { status: HealthStatus; size?: "sm" | "lg" }) {
  const { t } = useI18n();
  const s = styles[status] ?? styles.unknown;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full font-medium",
        size === "lg" ? "px-3 py-1 text-sm" : "px-2 py-0.5 text-xs",
        s.cls,
      )}
    >
      <s.Icon aria-hidden className={size === "lg" ? "size-4" : "size-3.5"} />
      {t(`status.${status}` as const)}
    </span>
  );
}
