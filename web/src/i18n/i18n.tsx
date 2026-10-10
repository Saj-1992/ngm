import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { en, fa, type MessageKey } from "./messages";

export type Locale = "en" | "fa";
const catalogs: Record<Locale, Record<MessageKey, string>> = { en, fa };

type I18n = {
  locale: Locale;
  dir: "ltr" | "rtl";
  setLocale: (l: Locale) => void;
  t: (key: MessageKey, vars?: Record<string, string | number>) => string;
  formatDateTime: (d: string | Date) => string;
  formatNumber: (n: number) => string;
};

const Ctx = createContext<I18n | null>(null);
const STORAGE_KEY = "ngm.locale";

function initialLocale(): Locale {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v === "en" || v === "fa") return v;
  } catch {
    /* storage unavailable */
  }
  return navigator.language?.toLowerCase().startsWith("fa") ? "fa" : "en";
}

export function translate(locale: Locale, key: MessageKey, vars?: Record<string, string | number>): string {
  let s = catalogs[locale][key] ?? en[key] ?? key;
  if (vars) for (const [k, v] of Object.entries(vars)) s = s.replaceAll(`{${k}}`, String(v));
  return s;
}

export function I18nProvider({ children, initial }: { children: ReactNode; initial?: Locale }) {
  const [locale, setLocaleState] = useState<Locale>(() => initial ?? initialLocale());
  const dir = locale === "fa" ? "rtl" : "ltr";

  useEffect(() => {
    document.documentElement.lang = locale;
    document.documentElement.dir = dir;
  }, [locale, dir]);

  const setLocale = useCallback((l: Locale) => {
    setLocaleState(l);
    try {
      localStorage.setItem(STORAGE_KEY, l);
    } catch {
      /* ignore */
    }
  }, []);

  const value = useMemo<I18n>(() => {
    const tag = locale === "fa" ? "fa-IR" : "en-GB";
    const dtf = new Intl.DateTimeFormat(tag, { dateStyle: "medium", timeStyle: "medium" });
    const nf = new Intl.NumberFormat(tag);
    return {
      locale,
      dir,
      setLocale,
      t: (k, v) => translate(locale, k, v),
      formatDateTime: (d) => dtf.format(typeof d === "string" ? new Date(d) : d),
      formatNumber: (n) => nf.format(n),
    };
  }, [locale, dir, setLocale]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useI18n(): I18n {
  const v = useContext(Ctx);
  if (!v) throw new Error("useI18n outside I18nProvider");
  return v;
}
