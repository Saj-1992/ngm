import * as Dialog from "@radix-ui/react-dialog";
import * as Dropdown from "@radix-ui/react-dropdown-menu";
import { Check, Languages, LogOut, Menu, Monitor, Moon, Sun, UserRound, X } from "lucide-react";
import { useState, type ReactNode } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { useI18n, type Locale } from "@/i18n/i18n";
import type { LiveStatus } from "@/lib/hooks";
import { useTheme, type ThemePref } from "@/lib/theme";
import { api } from "@/lib/api";
import { useSession } from "@/lib/session";
import { navGroups } from "@/nav";
import { Button, cn } from "./ui/primitives";

function Brand() {
  const { t } = useI18n();
  return (
    <div className="flex items-center gap-2.5 px-3">
      <div className="flex size-8 items-center justify-center rounded-lg bg-accent text-sm font-bold text-accent-fg" aria-hidden>
        N
      </div>
      <div className="min-w-0 leading-tight">
        <div className="text-sm font-semibold text-fg">{t("app.name")}</div>
        <div className="truncate text-xs text-fg-muted">{t("app.title")}</div>
      </div>
    </div>
  );
}

function NavTree({ onNavigate }: { onNavigate?: () => void }) {
  const { t } = useI18n();
  const { can } = useSession();
  return (
    <nav aria-label={t("app.title")} className="flex flex-col gap-5 px-3 py-4">
      {navGroups.map((g) => (
        <div key={g.label}>
          <div className="mb-1.5 px-2 text-[11px] font-semibold uppercase tracking-wider text-fg-muted">{t(g.label)}</div>
          <ul className="flex flex-col gap-0.5">
            {g.items.filter((it) => !it.perm || can(it.perm)).map((it) => (
              <li key={it.path}>
                <NavLink
                  to={it.path}
                  end={it.path === "/"}
                  onClick={onNavigate}
                  className={({ isActive }) =>
                    cn(
                      "flex items-center gap-2.5 rounded-lg px-2 py-1.5 text-sm transition-colors",
                      isActive ? "bg-accent-soft font-medium text-accent" : "text-fg-muted hover:bg-surface-2 hover:text-fg",
                    )
                  }
                >
                  <it.icon aria-hidden className="size-4 shrink-0" />
                  <span className="truncate">{t(it.label)}</span>
                  {it.phase && (
                    <span className="ms-auto rounded bg-surface-2 px-1.5 text-[10px] font-medium text-fg-muted" title={t("planned.phase", { phase: it.phase })}>
                      P{it.phase}
                    </span>
                  )}
                </NavLink>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </nav>
  );
}

function LiveIndicator({ status }: { status: LiveStatus }) {
  const { t } = useI18n();
  const map = {
    connected: { dot: "bg-ok", label: t("live.connected") },
    connecting: { dot: "bg-warn", label: t("live.connecting") },
    resync: { dot: "bg-warn", label: t("live.resync") },
    offline: { dot: "bg-bad", label: t("live.offline") },
  }[status];
  return (
    <span className="inline-flex items-center gap-2 rounded-full border border-border px-2.5 py-1 text-xs text-fg-muted" role="status" aria-live="polite">
      <span className={cn("size-2 rounded-full", map.dot)} aria-hidden />
      <span className="sr-only sm:not-sr-only">{map.label}</span>
    </span>
  );
}

const menuItem =
  "flex cursor-pointer select-none items-center gap-2 rounded-md px-2 py-1.5 text-sm text-fg outline-none data-[highlighted]:bg-surface-2";
const menuContent = "z-50 min-w-40 rounded-xl border border-border bg-surface p-1 shadow-card";

function UserMenu() {
  const { t } = useI18n();
  const { state, refresh } = useSession();
  const user = state.status === "ready" ? state.session?.user : undefined;
  if (!user) return null;
  return (
    <Dropdown.Root>
      <Dropdown.Trigger asChild>
        <Button variant="ghost" size="sm" aria-label={user.username}>
          <UserRound className="size-4" aria-hidden />
          <span dir="ltr" className="hidden sm:inline">{user.username}</span>
        </Button>
      </Dropdown.Trigger>
      <Dropdown.Portal>
        <Dropdown.Content align="end" sideOffset={6} className={menuContent}>
          <Dropdown.Item
            className={menuItem}
            onSelect={async () => {
              await api.logout().catch(() => {});
              await refresh();
            }}
          >
            <LogOut className="size-4 rtl:rotate-180" aria-hidden />
            {t("auth.signOut")}
          </Dropdown.Item>
        </Dropdown.Content>
      </Dropdown.Portal>
    </Dropdown.Root>
  );
}

function LanguageMenu() {
  const { t, locale, setLocale } = useI18n();
  const opts: { v: Locale; label: string }[] = [
    { v: "fa", label: "فارسی" },
    { v: "en", label: "English" },
  ];
  return (
    <Dropdown.Root>
      <Dropdown.Trigger asChild>
        <Button variant="ghost" size="icon" aria-label={t("topbar.language")}>
          <Languages className="size-4" aria-hidden />
        </Button>
      </Dropdown.Trigger>
      <Dropdown.Portal>
        <Dropdown.Content align="end" sideOffset={6} className={menuContent}>
          {opts.map((o) => (
            <Dropdown.Item key={o.v} className={menuItem} onSelect={() => setLocale(o.v)} lang={o.v}>
              <Check className={cn("size-4", locale === o.v ? "opacity-100" : "opacity-0")} aria-hidden />
              {o.label}
            </Dropdown.Item>
          ))}
        </Dropdown.Content>
      </Dropdown.Portal>
    </Dropdown.Root>
  );
}

function ThemeMenu() {
  const { t } = useI18n();
  const { pref, setPref } = useTheme();
  const opts: { v: ThemePref; Icon: typeof Sun }[] = [
    { v: "light", Icon: Sun },
    { v: "dark", Icon: Moon },
    { v: "system", Icon: Monitor },
  ];
  const Current = opts.find((o) => o.v === pref)?.Icon ?? Monitor;
  return (
    <Dropdown.Root>
      <Dropdown.Trigger asChild>
        <Button variant="ghost" size="icon" aria-label={t("topbar.theme")}>
          <Current className="size-4" aria-hidden />
        </Button>
      </Dropdown.Trigger>
      <Dropdown.Portal>
        <Dropdown.Content align="end" sideOffset={6} className={menuContent}>
          {opts.map((o) => (
            <Dropdown.Item key={o.v} className={menuItem} onSelect={() => setPref(o.v)}>
              <o.Icon className="size-4" aria-hidden />
              {t(`theme.${o.v}` as const)}
              {pref === o.v && <Check className="ms-auto size-4" aria-hidden />}
            </Dropdown.Item>
          ))}
        </Dropdown.Content>
      </Dropdown.Portal>
    </Dropdown.Root>
  );
}

export function Layout({ children, live }: { children: ReactNode; live: LiveStatus }) {
  const { t, dir } = useI18n();
  const [open, setOpen] = useState(false);
  const loc = useLocation();
  return (
    <div className="min-h-dvh bg-bg">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:start-3 focus:top-3 focus:z-50 focus:rounded-lg focus:bg-surface focus:px-3 focus:py-2">
        {t("skip.toContent")}
      </a>

      {/* Desktop sidebar */}
      <aside className="fixed inset-y-0 start-0 hidden w-64 flex-col border-e border-border bg-surface lg:flex">
        <div className="flex h-16 items-center border-b border-border">
          <Brand />
        </div>
        <div className="flex-1 overflow-y-auto">
          <NavTree />
        </div>
      </aside>

      {/* Mobile drawer */}
      <Dialog.Root open={open} onOpenChange={setOpen}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-40 bg-black/40 lg:hidden" />
          <Dialog.Content
            dir={dir}
            className="fixed inset-y-0 start-0 z-50 flex w-72 max-w-[85vw] flex-col border-e border-border bg-surface lg:hidden"
          >
            <Dialog.Title className="sr-only">{t("app.title")}</Dialog.Title>
            <Dialog.Description className="sr-only">{t("nav.openMenu")}</Dialog.Description>
            <div className="flex h-16 items-center justify-between border-b border-border pe-2">
              <Brand />
              <Dialog.Close asChild>
                <Button variant="ghost" size="icon" aria-label={t("nav.closeMenu")}>
                  <X className="size-4" aria-hidden />
                </Button>
              </Dialog.Close>
            </div>
            <div className="flex-1 overflow-y-auto">
              <NavTree onNavigate={() => setOpen(false)} />
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>

      <div className="lg:ps-64">
        <header className="sticky top-0 z-30 flex h-16 items-center gap-3 border-b border-border bg-surface/85 px-4 backdrop-blur sm:px-6">
          <Button variant="ghost" size="icon" className="lg:hidden" aria-label={t("nav.openMenu")} onClick={() => setOpen(true)}>
            <Menu className="size-5" aria-hidden />
          </Button>
          <span className="min-w-0 truncate rounded-full bg-warn-soft px-2.5 py-1 text-xs font-medium text-warn" title={t("app.devBuild")}>{t("app.devBuild")}</span>
          <div className="ms-auto flex shrink-0 items-center gap-1.5">
            <LiveIndicator status={live} />
            <LanguageMenu />
            <ThemeMenu />
            <UserMenu />
          </div>
        </header>
        <main id="main" key={loc.pathname} className="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:py-8">
          {children}
        </main>
      </div>
    </div>
  );
}
