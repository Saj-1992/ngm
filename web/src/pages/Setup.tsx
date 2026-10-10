import { CheckCircle2, Circle, CircleDashed, Info, TriangleAlert, XCircle } from "lucide-react";
import { useState } from "react";
import { Field, FormError, Input, Select } from "@/components/ui/form";
import { Button, Card, CardHeader, Ltr, cn } from "@/components/ui/primitives";
import { useI18n } from "@/i18n/i18n";
import type { MessageKey } from "@/i18n/messages";
import { api, ApiError, type PreflightCheck, type SetupStatus } from "@/lib/api";
import { useSession } from "@/lib/session";
import { AuthShell, MfaEnroll } from "./AuthPages";

const checkIcon: Record<PreflightCheck["status"], { Icon: typeof Info; cls: string }> = {
  pass: { Icon: CheckCircle2, cls: "text-ok" },
  warn: { Icon: TriangleAlert, cls: "text-warn" },
  fail: { Icon: XCircle, cls: "text-bad" },
  info: { Icon: Info, cls: "text-fg-muted" },
};

function Stepper({ setup, current }: { setup: SetupStatus; current: string }) {
  const { t } = useI18n();
  return (
    <ol className="flex flex-col gap-1">
      {setup.steps.map((s, i) => {
        const Icon = s.status === "complete" ? CheckCircle2 : s.status === "planned" ? CircleDashed : Circle;
        const active = s.id === current;
        return (
          <li
            key={s.id}
            aria-current={active ? "step" : undefined}
            className={cn("flex items-center gap-3 rounded-lg px-3 py-2 text-sm", active ? "bg-accent-soft text-accent" : "text-fg-muted")}
          >
            <Icon className={cn("size-4 shrink-0", s.status === "complete" && "text-ok")} aria-hidden />
            <span className="flex-1">
              <span className="me-1 tabular-nums">{i + 1}.</span>
              {t(`setup.step.${s.id}` as MessageKey)}
            </span>
            <span className="text-xs">
              {s.status === "planned" ? t("setup.status.planned", { phase: s.phase ?? "?" }) : t(`setup.status.${s.status}` as MessageKey)}
            </span>
          </li>
        );
      })}
    </ol>
  );
}

function OwnerForm({ onCreated }: { onCreated: () => void }) {
  const { t, locale } = useI18n();
  const [f, setF] = useState({ token: "", username: "", display: "", pw: "", pw2: "", loc: locale as string });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const mismatch = f.pw2 !== "" && f.pw !== f.pw2;
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setF({ ...f, [k]: e.target.value });

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (f.pw !== f.pw2) return;
    setBusy(true);
    setError(null);
    try {
      await api.setupOwner({ bootstrap_token: f.token.trim(), username: f.username.trim().toLowerCase(), display_name: f.display, password: f.pw, locale: f.loc });
      onCreated();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t("common.error"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit} className="grid gap-4 sm:grid-cols-2" noValidate>
      <div className="sm:col-span-2">
        <Field label={t("setup.bootstrapToken")} hint={t("setup.bootstrapHint")}>
          {({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} dir="ltr" autoComplete="off" spellCheck={false} value={f.token} onChange={set("token")} required autoFocus />}
        </Field>
      </div>
      <Field label={t("auth.username")}>
        {({ id }) => <Input id={id} dir="ltr" autoComplete="username" autoCapitalize="none" value={f.username} onChange={set("username")} required />}
      </Field>
      <Field label={t("setup.displayName")}>{({ id }) => <Input id={id} value={f.display} onChange={set("display")} />}</Field>
      <Field label={t("auth.password")} hint={t("setup.passwordRules")}>
        {({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} dir="ltr" type="password" autoComplete="new-password" value={f.pw} onChange={set("pw")} required />}
      </Field>
      <Field label={t("setup.confirmPassword")} error={mismatch ? t("setup.mismatch") : undefined}>
        {({ id, describedBy, invalid }) => (
          <Input id={id} aria-describedby={describedBy} aria-invalid={invalid} dir="ltr" type="password" autoComplete="new-password" value={f.pw2} onChange={set("pw2")} required />
        )}
      </Field>
      <Field label={t("setup.language")}>
        {({ id }) => (
          <Select id={id} value={f.loc} onChange={set("loc")}>
            <option value="fa">فارسی</option>
            <option value="en">English</option>
          </Select>
        )}
      </Field>
      <div className="sm:col-span-2">
        <FormError>{error}</FormError>
      </div>
      <div className="sm:col-span-2">
        <Button variant="primary" type="submit" disabled={busy || !f.token || !f.username || !f.pw || mismatch}>
          {t("setup.continue")}
        </Button>
      </div>
    </form>
  );
}

/** First-run wizard (MASTER_SPEC §11). Steps 3–7 depend on later phases. */
export function SetupPage() {
  const { t } = useI18n();
  const { state, refresh } = useSession();
  const [enrolling, setEnrolling] = useState(false);
  if (state.status !== "ready") return null;
  const { setup, session } = state;
  const ownerCreated = setup.initialized;
  const current = !setup.owner_ready ? "owner" : "management_origin";

  return (
    <AuthShell wide>
      <div className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight text-fg">{t("setup.title")}</h1>
        <p className="mt-1 text-sm text-fg-muted">{t("setup.subtitle")}</p>
      </div>
      <div className="grid gap-5 lg:grid-cols-[18rem_1fr]">
        <Card className="h-fit p-2">
          <Stepper setup={setup} current={current} />
        </Card>
        <div className="flex flex-col gap-5">
          <Card>
            <CardHeader title={t("setup.preflightTitle")} />
            {setup.preflight ? (
              <ul className="divide-y divide-border">
                {setup.preflight.checks.map((c) => {
                  const s = checkIcon[c.status];
                  return (
                    <li key={c.id} className="flex items-start gap-3 px-5 py-2.5 text-sm">
                      <s.Icon className={cn("mt-0.5 size-4 shrink-0", s.cls)} aria-label={c.status} />
                      <Ltr className="w-28 shrink-0 text-fg-muted">{c.id}</Ltr>
                      <span className="min-w-0 break-words text-fg" dir="auto">
                        {c.detail}
                      </span>
                    </li>
                  );
                })}
              </ul>
            ) : (
              <p className="px-5 py-4 text-sm text-fg-muted">{setup.preflight_recorded ? t("setup.preflightHidden") : t("setup.noPreflight")}</p>
            )}
          </Card>

          <Card className="p-5">
            <h2 className="mb-4 text-base font-semibold text-fg">{t("setup.ownerTitle")}</h2>
            {!ownerCreated ? (
              setup.local_bootstrap ? (
                <OwnerForm onCreated={() => { setEnrolling(true); void refresh(); }} />
              ) : (
                <FormError>{t("setup.notLocal")}</FormError>
              )
            ) : session?.stage === "mfa_enroll" || enrolling ? (
              session?.stage === "mfa_enroll" ? <MfaEnroll onDone={refresh} /> : null
            ) : (
              <div className="flex flex-col gap-3">
                <p className="flex items-center gap-2 text-sm text-ok">
                  <CheckCircle2 className="size-4" aria-hidden />
                  {t("setup.status.complete")}
                </p>
                <p className="text-sm text-fg-muted">{t("setup.remainingNote")}</p>
                <div>
                  <Button asChild variant="primary">
                    <a href="/">{t("setup.toDashboard")}</a>
                  </Button>
                </div>
              </div>
            )}
          </Card>
        </div>
      </div>
    </AuthShell>
  );
}
