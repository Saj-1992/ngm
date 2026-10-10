import { Copy, KeyRound, Languages, Loader2 } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { QRCode } from "@/components/QRCode";
import { Field, FormError, Input, OtpInput } from "@/components/ui/form";
import { Button, Card, Ltr } from "@/components/ui/primitives";
import { useI18n } from "@/i18n/i18n";
import { api, ApiError } from "@/lib/api";
import { useSession } from "@/lib/session";

export function AuthShell({ children, wide }: { children: ReactNode; wide?: boolean }) {
  const { t, locale, setLocale } = useI18n();
  return (
    <div className="flex min-h-dvh flex-col items-center justify-center bg-bg px-4 py-10">
      <div className={wide ? "w-full max-w-4xl" : "w-full max-w-md"}>
        <div className="mb-6 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="flex size-9 items-center justify-center rounded-xl bg-accent text-sm font-bold text-accent-fg" aria-hidden>
              N
            </div>
            <div className="leading-tight">
              <div className="font-semibold text-fg">{t("app.name")}</div>
              <div className="text-xs text-fg-muted">{t("app.title")}</div>
            </div>
          </div>
          <Button variant="ghost" size="sm" onClick={() => setLocale(locale === "fa" ? "en" : "fa")} aria-label={t("topbar.language")}>
            <Languages className="size-4" aria-hidden />
            <span lang={locale === "fa" ? "en" : "fa"}>{locale === "fa" ? "English" : "فارسی"}</span>
          </Button>
        </div>
        {children}
      </div>
    </div>
  );
}

function errorText(e: unknown, t: ReturnType<typeof useI18n>["t"]): string {
  if (e instanceof ApiError) {
    if (e.code === "rate_limited") return t("auth.locked", { seconds: Number(e.details?.retry_after_seconds ?? 60) });
    if (e.code === "invalid_credentials") return t("auth.invalid");
    if (e.code === "invalid_code") return t("mfa.invalid");
    return e.message;
  }
  return t("common.error");
}

export function LoginPage() {
  const { t } = useI18n();
  const { refresh } = useSession();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.login(username, password);
      setPassword("");
      await refresh();
    } catch (err) {
      setError(errorText(err, t));
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthShell>
      <Card className="p-6">
        <h1 className="mb-1 text-xl font-semibold text-fg">{t("auth.signInTitle")}</h1>
        <p className="mb-5 text-sm text-fg-muted">{t("auth.localOnlyHint")}</p>
        <form onSubmit={submit} className="flex flex-col gap-4" noValidate>
          <Field label={t("auth.username")}>
            {({ id }) => <Input id={id} dir="ltr" autoComplete="username" autoCapitalize="none" spellCheck={false} value={username} onChange={(e) => setUsername(e.target.value)} required autoFocus />}
          </Field>
          <Field label={t("auth.password")}>
            {({ id }) => <Input id={id} dir="ltr" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />}
          </Field>
          <FormError>{error}</FormError>
          <Button variant="primary" type="submit" disabled={busy || !username || !password}>
            {busy && <Loader2 className="size-4 animate-spin" aria-hidden />}
            {busy ? t("auth.signingIn") : t("auth.signIn")}
          </Button>
        </form>
      </Card>
    </AuthShell>
  );
}

export function MfaVerifyPage() {
  const { t } = useI18n();
  const { refresh } = useSession();
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.mfaVerify(code);
      await refresh();
    } catch (err) {
      setError(errorText(err, t));
      setCode("");
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthShell>
      <Card className="p-6">
        <div className="mb-4 flex size-11 items-center justify-center rounded-xl bg-accent-soft text-accent">
          <KeyRound className="size-5" aria-hidden />
        </div>
        <h1 className="mb-1 text-xl font-semibold text-fg">{t("mfa.verifyTitle")}</h1>
        <p className="mb-5 text-sm text-fg-muted">{t("mfa.verifyBody")}</p>
        <form onSubmit={submit} className="flex flex-col gap-4">
          <Field label={t("mfa.code")}>{({ id }) => <OtpInput id={id} autoFocus value={code} onChange={setCode} />}</Field>
          <FormError>{error}</FormError>
          <Button variant="primary" type="submit" disabled={busy || code.length !== 6}>
            {t("mfa.verify")}
          </Button>
          <Button variant="ghost" type="button" onClick={async () => { await api.logout().catch(() => {}); await refresh(); }}>
            {t("auth.signOut")}
          </Button>
        </form>
      </Card>
    </AuthShell>
  );
}

/** TOTP enrolment: shows the QR once, then confirms the first code. */
export function MfaEnroll({ onDone }: { onDone: () => Promise<void> | void }) {
  const { t } = useI18n();
  const [enr, setEnr] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let alive = true;
    api.mfaEnroll().then(
      (r) => alive && setEnr(r),
      (e) => alive && setLoadErr(errorText(e, t)),
    );
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.mfaConfirm(code);
      await onDone();
    } catch (err) {
      setError(errorText(err, t));
      setCode("");
    } finally {
      setBusy(false);
    }
  };

  if (loadErr) return <FormError>{loadErr}</FormError>;
  if (!enr)
    return (
      <div role="status" className="flex items-center gap-2 py-8 text-sm text-fg-muted">
        <Loader2 className="size-4 animate-spin" aria-hidden />
        {t("common.loading")}
      </div>
    );
  const grouped = enr.secret.match(/.{1,4}/g)?.join(" ") ?? enr.secret;
  return (
    <div className="flex flex-col gap-5">
      <p className="text-sm text-fg-muted">{t("mfa.enrollBody")}</p>
      <div className="flex flex-col items-center gap-4 sm:flex-row sm:items-start">
        <div className="rounded-xl border border-border bg-white p-2">
          <QRCode value={enr.otpauth_uri} size={176} label={t("mfa.enrollTitle")} />
        </div>
        <div className="min-w-0 flex-1 text-sm">
          <p className="mb-2 text-fg-muted">{t("mfa.manualKey")}</p>
          <div className="flex items-center gap-2">
            <Ltr className="break-all rounded-lg bg-surface-2 px-3 py-2 text-fg">{grouped}</Ltr>
            <Button
              variant="ghost"
              size="icon"
              aria-label={t("common.copy")}
              onClick={() => navigator.clipboard?.writeText(enr.secret).then(() => setCopied(true), () => {})}
            >
              <Copy className="size-4" aria-hidden />
            </Button>
          </div>
          {copied && <p className="mt-1 text-xs text-ok">{t("common.copied")}</p>}
          <p className="mt-3 text-xs text-warn">{t("mfa.secretOnce")}</p>
        </div>
      </div>
      <form onSubmit={submit} className="flex flex-col gap-3">
        <Field label={t("mfa.code")}>{({ id }) => <OtpInput id={id} value={code} onChange={setCode} />}</Field>
        <FormError>{error}</FormError>
        <Button variant="primary" type="submit" disabled={busy || code.length !== 6}>
          {t("mfa.confirm")}
        </Button>
      </form>
    </div>
  );
}

export function MfaEnrollPage() {
  const { t } = useI18n();
  const { refresh } = useSession();
  return (
    <AuthShell>
      <Card className="p-6">
        <h1 className="mb-3 text-xl font-semibold text-fg">{t("mfa.enrollTitle")}</h1>
        <MfaEnroll onDone={refresh} />
      </Card>
    </AuthShell>
  );
}
