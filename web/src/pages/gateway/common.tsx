import { MoreHorizontal } from "lucide-react";
import * as Dropdown from "@radix-ui/react-dropdown-menu";
import type { ReactNode } from "react";
import { Info } from "lucide-react";
import { Button, cn } from "@/components/ui/primitives";
import { useI18n } from "@/i18n/i18n";
import { ApiError } from "@/lib/api";

export const errText = (e: unknown) => {
  if (e instanceof ApiError) {
    const issues = (e.details?.issues as { message: string }[] | undefined)?.map((i) => i.message).join(" · ");
    return issues ? `${e.message}: ${issues}` : e.message;
  }
  return String(e);
};

const menuItem = "flex cursor-pointer select-none items-center gap-2 rounded-md px-2 py-1.5 text-sm text-fg outline-none data-[highlighted]:bg-surface-2";

/** Row action menu (edit/delete). */
export function RowMenu({ label, items }: { label: string; items: { label: ReactNode; onSelect: () => void; danger?: boolean }[] }) {
  return (
    <Dropdown.Root>
      <Dropdown.Trigger asChild>
        <Button variant="ghost" size="icon" aria-label={label}>
          <MoreHorizontal className="size-4" aria-hidden />
        </Button>
      </Dropdown.Trigger>
      <Dropdown.Portal>
        <Dropdown.Content align="end" sideOffset={4} className="z-50 min-w-40 rounded-xl border border-border bg-surface p-1 shadow-card">
          {items.map((it, i) => (
            <Dropdown.Item key={i} className={cn(menuItem, it.danger && "text-bad")} onSelect={it.onSelect}>
              {it.label}
            </Dropdown.Item>
          ))}
        </Dropdown.Content>
      </Dropdown.Portal>
    </Dropdown.Root>
  );
}

/** Reminder that edits are desired state until applied. */
export function DesiredNote() {
  const { t } = useI18n();
  return (
    <p className="mb-4 flex items-start gap-2 rounded-xl bg-accent-soft px-4 py-2.5 text-sm text-accent">
      <Info className="mt-0.5 size-4 shrink-0" aria-hidden />
      {t("common.desiredNote")}
    </p>
  );
}

export function Pill({ children, tone = "muted" }: { children: ReactNode; tone?: "muted" | "ok" | "warn" | "bad" | "accent" }) {
  const cls = { muted: "bg-surface-2 text-fg-muted", ok: "bg-ok-soft text-ok", warn: "bg-warn-soft text-warn", bad: "bg-bad-soft text-bad", accent: "bg-accent-soft text-accent" }[tone];
  return <span className={cn("inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium", cls)}>{children}</span>;
}

export const tableCls = "w-full text-sm";
export const thCls = "px-4 py-3 text-start text-xs font-medium text-fg-muted";
export const tdCls = "px-4 py-3 align-top";

/** Splits a textarea into trimmed non-empty lines. */
export const lines = (s: string) => s.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);

/** Idempotency key for one user action. */
export const actionKey = () => {
  const b = new Uint8Array(12);
  crypto.getRandomValues(b);
  return "ui-" + Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
};

/** Formats addr:port, bracketing IPv6. */
export const bind = (l: { address: string; port: number }) => (l.address.includes(":") ? `[${l.address}]:${l.port}` : `${l.address}:${l.port}`);
