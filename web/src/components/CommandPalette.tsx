import * as Dialog from "@radix-ui/react-dialog";
import { Search } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useI18n } from "@/i18n/i18n";
import { useSession } from "@/lib/session";
import { navGroups } from "@/nav";

/**
 * Global command palette (Ctrl/⌘+K): navigation only. Risky actions are
 * deliberately absent; they stay behind their preview/confirmation flows.
 */
export function CommandPalette() {
  const { t, dir } = useI18n();
  const { can } = useSession();
  const nav = useNavigate();
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const [i, setI] = useState(0);
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, []);
  const items = useMemo(() => navGroups.flatMap((g) => g.items.filter((x) => !x.phase && (!x.perm || can(x.perm))).map((x) => ({ path: x.path, label: t(x.label), group: t(g.label) })))
    .filter((x) => !q || (x.label + " " + x.group + " " + x.path).toLowerCase().includes(q.toLowerCase())), [q, t, can]);
  const go = (p: string) => { setOpen(false); setQ(""); nav(p); };
  return (
    <Dialog.Root open={open} onOpenChange={setOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/40" />
        <Dialog.Content dir={dir} className="fixed start-1/2 top-24 z-50 w-[calc(100vw-2rem)] max-w-lg rounded-2xl border border-border bg-surface shadow-card ltr:-translate-x-1/2 rtl:translate-x-1/2">
          <Dialog.Title className="sr-only">{t("cmd.title")}</Dialog.Title>
          <Dialog.Description className="sr-only">{t("cmd.hint")}</Dialog.Description>
          <div className="flex items-center gap-2 border-b border-border px-4">
            <Search className="size-4 text-fg-muted" aria-hidden />
            <input autoFocus aria-label={t("cmd.title")} placeholder={t("cmd.placeholder")} className="h-12 flex-1 bg-transparent text-sm outline-none" value={q}
              onChange={(e) => { setQ(e.target.value); setI(0); }}
              onKeyDown={(e) => {
                if (e.key === "ArrowDown") { e.preventDefault(); setI((x) => Math.min(items.length - 1, x + 1)); }
                if (e.key === "ArrowUp") { e.preventDefault(); setI((x) => Math.max(0, x - 1)); }
                if (e.key === "Enter" && items[i]) go(items[i].path);
              }} />
          </div>
          <ul role="listbox" className="max-h-80 overflow-y-auto p-2">
            {items.map((x, k) => (
              <li key={x.path} role="option" aria-selected={k === i}>
                <button type="button" onClick={() => go(x.path)} onMouseEnter={() => setI(k)} className={`flex w-full justify-between rounded-lg px-3 py-2 text-start text-sm ${k === i ? "bg-accent-soft text-accent" : ""}`}>
                  <span>{x.label}</span><span className="text-xs text-fg-muted">{x.group}</span>
                </button>
              </li>
            ))}
            {items.length === 0 && <li className="px-3 py-2 text-sm text-fg-muted">{t("cmd.none")}</li>}
          </ul>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
