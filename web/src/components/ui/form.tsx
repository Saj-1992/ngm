import { en, type MessageKey } from "@/i18n/messages";
import * as Dialog from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import React, { forwardRef, useId, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes } from "react";
import { useI18n } from "@/i18n/i18n";
import { Button, cn } from "./primitives";

const fieldCls =
  "h-10 w-full rounded-lg border border-border bg-surface px-3 text-sm text-fg placeholder:text-fg-muted/70 focus-visible:outline-2 focus-visible:outline-ring disabled:opacity-60";

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(({ className, ...p }, ref) => (
  <input ref={ref} className={cn(fieldCls, className)} {...p} />
));
Input.displayName = "Input";

export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(({ className, ...p }, ref) => (
  <select ref={ref} className={cn(fieldCls, "pe-8", className)} {...p} />
));
Select.displayName = "Select";

/** Label + control + optional hint/error, wired for screen readers. */
export function Field({
  label,
  hint,
  error,
  children,
}: {
  label: ReactNode;
  hint?: ReactNode;
  error?: ReactNode;
  children: (ids: { id: string; describedBy?: string; invalid: boolean }) => ReactNode;
}) {
  const id = useId();
  const hintId = hint ? id + "-hint" : undefined;
  const errId = error ? id + "-err" : undefined;
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={id} className="text-sm font-medium text-fg">
        {label}
      </label>
      {children({ id, describedBy: [hintId, errId].filter(Boolean).join(" ") || undefined, invalid: !!error })}
      {hint && (
        <p id={hintId} className="text-xs text-fg-muted">
          {hint}
        </p>
      )}
      {error && (
        <p id={errId} role="alert" className="text-xs font-medium text-bad">
          {error}
        </p>
      )}
    </div>
  );
}

export function FormError({ children }: { children?: ReactNode }) {
  if (!children) return null;
  return (
    <div role="alert" className="rounded-lg border border-bad/30 bg-bad-soft px-3 py-2 text-sm text-bad">
      {children}
    </div>
  );
}

/** Accessible modal built on Radix Dialog (focus trap, Esc, aria). */
export function Modal({
  open,
  onOpenChange,
  title,
  description,
  children,
  footer,
  wide,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  title: ReactNode;
  description?: ReactNode;
  children?: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
}) {
  const { t, dir } = useI18n();
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/45" />
        <Dialog.Content
          dir={dir}
          className={cn(
            "fixed start-1/2 top-1/2 z-50 flex max-h-[90dvh] w-[calc(100vw-2rem)] -translate-y-1/2 flex-col rounded-2xl border border-border bg-surface shadow-card ltr:-translate-x-1/2 rtl:translate-x-1/2",
            wide ? "max-w-2xl" : "max-w-md",
          )}
        >
          <div className="flex items-start justify-between gap-4 border-b border-border px-5 py-4">
            <div>
              <Dialog.Title className="text-base font-semibold text-fg">{title}</Dialog.Title>
              {description ? (
                <Dialog.Description className="mt-1 text-sm text-fg-muted">{description}</Dialog.Description>
              ) : (
                <Dialog.Description className="sr-only">{title}</Dialog.Description>
              )}
            </div>
            <Dialog.Close asChild>
              <Button variant="ghost" size="icon" aria-label={t("common.close")}>
                <X className="size-4" aria-hidden />
              </Button>
            </Dialog.Close>
          </div>
          <div className="overflow-y-auto px-5 py-4">{children}</div>
          {footer && <div className="flex justify-end gap-2 border-t border-border px-5 py-3">{footer}</div>}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

/** Numeric one-time-code input (6 digits), LTR even in RTL layouts. */
export const OtpInput = forwardRef<HTMLInputElement, Omit<InputHTMLAttributes<HTMLInputElement>, "onChange"> & { value: string; onChange: (v: string) => void }>(
  ({ value, onChange, className, ...p }, ref) => (
    <Input
      ref={ref}
      dir="ltr"
      inputMode="numeric"
      autoComplete="one-time-code"
      pattern="[0-9]{6}"
      maxLength={6}
      value={value}
      onChange={(e) => onChange(e.target.value.replace(/[^0-9۰-۹]/g, "").replace(/[۰-۹]/g, (d) => String("۰۱۲۳۴۵۶۷۸۹".indexOf(d))).slice(0, 6))}
      className={cn("text-center font-mono text-xl tracking-[0.5em]", className)}
      {...p}
    />
  ),
);
OtpInput.displayName = "OtpInput";

export const Textarea = forwardRef<HTMLTextAreaElement, React.TextareaHTMLAttributes<HTMLTextAreaElement>>(({ className, ...p }, ref) => (
  <textarea ref={ref} className={cn("min-h-24 w-full rounded-lg border border-border bg-surface px-3 py-2 text-sm text-fg focus-visible:outline-2 focus-visible:outline-ring", className)} {...p} />
));
Textarea.displayName = "Textarea";

/** Labelled checkbox with optional hint. */
export function Check({ checked, onChange, label, hint, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: ReactNode; hint?: ReactNode; disabled?: boolean }) {
  const id = useId();
  return (
    <div className="flex items-start gap-2.5">
      <input id={id} type="checkbox" className="mt-0.5 size-4 shrink-0 accent-[var(--accent)]" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      <label htmlFor={id} className="text-sm text-fg">
        {label}
        {hint && <span className="mt-0.5 block text-xs text-fg-muted">{hint}</span>}
      </label>
    </div>
  );
}

/** Simple segmented tabs. */
export function Tabs<T extends string>({ value, onChange, items }: { value: T; onChange: (v: T) => void; items: { value: T; label: ReactNode }[] }) {
  return (
    <div role="tablist" className="inline-flex rounded-lg bg-surface-2 p-1">
      {items.map((it) => (
        <button
          key={it.value}
          role="tab"
          aria-selected={value === it.value}
          onClick={() => onChange(it.value)}
          className={cn("rounded-md px-3 py-1.5 text-sm transition-colors", value === it.value ? "bg-surface font-medium text-fg shadow-card" : "text-fg-muted hover:text-fg")}
        >
          {it.label}
        </button>
      ))}
    </div>
  );
}

/** Lists validation issues. */
export function IssueList({ issues }: { issues: { severity: string; code: string; message: string }[] }) {
  if (!issues.length) return null;
  return (
    <ul className="flex flex-col gap-1.5">
      {issues.map((i, n) => (
        <li key={n} className={cn("rounded-lg px-3 py-2 text-sm", i.severity === "error" ? "bg-bad-soft text-bad" : "bg-warn-soft text-warn")}>
          <bdi dir="ltr" className="me-2 font-mono text-[11px] opacity-80">{i.code}</bdi>
          <IssueText code={i.code} message={i.message} />
        </li>
      ))}
    </ul>
  );
}

/** Persian headline by issue code; the server's exact text stays visible as an LTR detail. */
function IssueText({ code, message }: { code: string; message: string }) {
  const { t, locale } = useI18n();
  const k = `issue.${code}` as MessageKey;
  if (locale !== "fa" || !(k in en)) return <span dir="auto">{message}</span>;
  return (
    <span className="inline-flex min-w-0 flex-col">
      <span>{t(k)}</span>
      <bdi dir="ltr" className="text-xs opacity-90">{message}</bdi>
    </span>
  );
}
