import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/primitives";
import { FormError, Modal, OtpInput } from "@/components/ui/form";
import { useI18n } from "@/i18n/i18n";
import { api, ApiError, setAuthListener, setStepUpHandler, type Session, type SetupStatus } from "./api";

type SessionState =
  | { status: "loading" }
  | { status: "error"; error: unknown }
  | { status: "ready"; setup: SetupStatus; session: Session | null };

type Ctx = {
  state: SessionState;
  refresh: () => Promise<void>;
  can: (perm: string) => boolean;
};

const SessionCtx = createContext<Ctx | null>(null);

export function SessionProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<SessionState>({ status: "loading" });
  const { setLocale, locale } = useI18n();
  const localeRef = useRef(locale);
  localeRef.current = locale;

  const refresh = useCallback(async () => {
    try {
      const setup = await api.setupStatus();
      let session: Session | null = null;
      try {
        session = await api.session();
      } catch (e) {
        if (!(e instanceof ApiError && e.status === 401)) throw e;
      }
      if (session && (session.user.locale === "fa" || session.user.locale === "en") && session.stage === "active") {
        // Respect an explicit per-browser choice; otherwise adopt the account locale.
        let stored: string | null = null;
        try {
          stored = localStorage.getItem("ngm.locale");
        } catch {
          /* ignore */
        }
        if (!stored && session.user.locale !== localeRef.current) setLocale(session.user.locale as "fa" | "en");
      }
      setState({ status: "ready", setup, session });
    } catch (error) {
      setState({ status: "error", error });
    }
  }, [setLocale]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    setAuthListener(() => void refresh());
    return () => setAuthListener(null);
  }, [refresh]);

  const can = useCallback(
    (perm: string) => state.status === "ready" && !!state.session && state.session.stage === "active" && state.session.permissions.includes(perm),
    [state],
  );

  return (
    <SessionCtx.Provider value={{ state, refresh, can }}>
      <StepUpProvider>{children}</StepUpProvider>
    </SessionCtx.Provider>
  );
}

export function useSession(): Ctx {
  const v = useContext(SessionCtx);
  if (!v) throw new Error("useSession outside SessionProvider");
  return v;
}

/** Prompts for a fresh TOTP code when the API answers step_up_required. */
function StepUpProvider({ children }: { children: ReactNode }) {
  const { t } = useI18n();
  const [open, setOpen] = useState(false);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const resolver = useRef<((ok: boolean) => void) | null>(null);

  useEffect(() => {
    setStepUpHandler(
      () =>
        new Promise<boolean>((resolve) => {
          resolver.current = resolve;
          setCode("");
          setError(null);
          setOpen(true);
        }),
    );
    return () => setStepUpHandler(null);
  }, []);

  const finish = (ok: boolean) => {
    resolver.current?.(ok);
    resolver.current = null;
    setOpen(false);
  };

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.stepUp(code);
      finish(true);
    } catch (e) {
      setError(e instanceof ApiError && e.code === "rate_limited" ? t("auth.locked", { seconds: Number(e.details?.retry_after_seconds ?? 60) }) : t("mfa.invalid"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      {children}
      <Modal
        open={open}
        onOpenChange={(o) => !o && finish(false)}
        title={
          <span className="inline-flex items-center gap-2">
            <ShieldCheck className="size-4 text-accent" aria-hidden />
            {t("stepup.title")}
          </span>
        }
        description={t("stepup.body")}
        footer={
          <>
            <Button variant="ghost" onClick={() => finish(false)}>
              {t("common.cancel")}
            </Button>
            <Button variant="primary" disabled={code.length !== 6 || busy} onClick={submit}>
              {t("mfa.verify")}
            </Button>
          </>
        }
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (code.length === 6) void submit();
          }}
          className="flex flex-col gap-3"
        >
          <OtpInput autoFocus aria-label={t("mfa.code")} value={code} onChange={setCode} />
          <FormError>{error}</FormError>
        </form>
      </Modal>
    </>
  );
}
