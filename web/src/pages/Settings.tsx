import { UpdatesCard } from "./ops6/Updates";
import { NotificationsCard } from "./ops6/Notifications";
import { Copy, KeyRound, Plus } from "lucide-react";
import { useState } from "react";
import { EmptyState, ErrorState, LoadingState } from "@/components/States";
import { Field, FormError, Input, Modal } from "@/components/ui/form";
import { Button, Card, CardHeader, Ltr, PageHeader, cn } from "@/components/ui/primitives";
import { useI18n } from "@/i18n/i18n";
import { api, ApiError } from "@/lib/api";
import { useAsync } from "@/lib/hooks";
import { useSession } from "@/lib/session";

function PasswordCard() {
  const { t } = useI18n();
  const [cur, setCur] = useState("");
  const [next, setNext] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setMsg(null);
    try {
      await api.changePassword(cur, next);
      setCur("");
      setNext("");
      setMsg({ ok: true, text: t("settings.passwordChanged") });
    } catch (err) {
      setMsg({ ok: false, text: err instanceof ApiError && err.code === "invalid_credentials" ? t("auth.invalid") : err instanceof ApiError ? err.message : String(err) });
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card>
      <CardHeader title={t("settings.password")} />
      <form onSubmit={submit} className="flex flex-col gap-4 p-5">
        <Field label={t("settings.currentPassword")}>{({ id }) => <Input id={id} dir="ltr" type="password" autoComplete="current-password" value={cur} onChange={(e) => setCur(e.target.value)} />}</Field>
        <Field label={t("settings.newPassword")} hint={t("setup.passwordRules")}>
          {({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} dir="ltr" type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} />}
        </Field>
        {msg && (msg.ok ? <p role="status" className="text-sm text-ok">{msg.text}</p> : <FormError>{msg.text}</FormError>)}
        <div>
          <Button variant="primary" type="submit" disabled={busy || !cur || !next}>{t("common.save")}</Button>
        </div>
      </form>
    </Card>
  );
}

function TokensCard() {
  const { t, formatDateTime } = useI18n();
  const { state, can } = useSession();
  const tokens = useAsync(api.tokens);
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [days, setDays] = useState(90);
  const [scopes, setScopes] = useState<Set<string>>(new Set());
  const [created, setCreated] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const perms = state.status === "ready" ? state.session?.permissions ?? [] : [];
  // Only non-step-up permissions the caller holds can become token scopes.
  const STEP_UP = new Set(["users.write", "roles.write", "tokens.write", "secrets.write", "firewall.write", "backups.restore", "updates.install", "settings.write", "owner.transfer", "system.purge"]);
  const scopable = perms.filter((p) => !STEP_UP.has(p));

  const create = async () => {
    setError(null);
    try {
      const r = await api.createToken({ name, scopes: [...scopes], expires_in_days: days });
      setCreated(r.token);
      setName("");
      setScopes(new Set());
      tokens.reload();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    }
  };

  return (
    <Card>
      <CardHeader
        title={
          <span className="inline-flex items-center gap-2">
            <KeyRound className="size-4 text-fg-muted" aria-hidden />
            {t("tokens.title")}
          </span>
        }
        action={can("tokens.write") && (
          <Button size="sm" variant="outline" onClick={() => { setCreated(null); setOpen(true); }}>
            <Plus className="size-4" aria-hidden />
            {t("tokens.new")}
          </Button>
        )}
      />
      <p className="px-5 pt-3 text-xs text-fg-muted">{t("tokens.subtitle")}</p>
      {tokens.status === "error" && !tokens.data ? (
        <ErrorState error={tokens.error} onRetry={tokens.reload} />
      ) : !tokens.data ? (
        <LoadingState />
      ) : tokens.data.items.length === 0 ? (
        <EmptyState title={t("tokens.empty")} />
      ) : (
        <ul className="divide-y divide-border">
          {tokens.data.items.map((k) => (
            <li key={k.id} className={cn("flex flex-wrap items-center gap-x-4 gap-y-1 px-5 py-3 text-sm")}>
              <span className="font-medium text-fg">{k.name}</span>
              <Ltr className="text-fg-muted">{k.prefix}…</Ltr>
              <span className="flex flex-wrap gap-1">{k.scopes.map((s) => <span key={s} className="rounded bg-surface-2 px-1.5 text-[11px]"><Ltr>{s}</Ltr></span>)}</span>
              <span className="ms-auto text-xs text-fg-muted">
                {t("tokens.expires")}: {k.expires_at ? formatDateTime(k.expires_at) : t("common.never")}
                {" · "}
                {t("tokens.lastUsed")}: {k.last_used_at ? formatDateTime(k.last_used_at) : t("common.never")}
              </span>
              {k.revoked_at ? (
                <span className="text-xs text-bad">{t("tokens.revoked")}</span>
              ) : (
                can("tokens.write") && (
                  <Button size="sm" variant="ghost" className="text-bad" onClick={async () => { await api.revokeToken(k.id).catch(() => {}); tokens.reload(); }}>
                    {t("tokens.revoke")}
                  </Button>
                )
              )}
            </li>
          ))}
        </ul>
      )}
      <Modal
        open={open}
        onOpenChange={setOpen}
        title={t("tokens.new")}
        wide
        footer={
          created ? (
            <Button variant="primary" onClick={() => setOpen(false)}>{t("common.close")}</Button>
          ) : (
            <>
              <Button variant="ghost" onClick={() => setOpen(false)}>{t("common.cancel")}</Button>
              <Button variant="primary" disabled={!name || scopes.size === 0} onClick={create}>{t("common.create")}</Button>
            </>
          )
        }
      >
        {created ? (
          <div className="flex flex-col gap-3">
            <p className="text-sm text-warn">{t("tokens.showOnce")}</p>
            <div className="flex items-center gap-2">
              <Ltr className="break-all rounded-lg bg-surface-2 px-3 py-2 text-fg">{created}</Ltr>
              <Button variant="ghost" size="icon" aria-label={t("common.copy")} onClick={() => navigator.clipboard?.writeText(created)}>
                <Copy className="size-4" aria-hidden />
              </Button>
            </div>
          </div>
        ) : (
          <div className="flex flex-col gap-4">
            <Field label={t("tokens.name")}>{({ id }) => <Input id={id} maxLength={64} value={name} onChange={(e) => setName(e.target.value)} />}</Field>
            <Field label={t("tokens.expiresDays")}>
              {({ id }) => <Input id={id} dir="ltr" type="number" min={0} max={366} value={days} onChange={(e) => setDays(Math.max(0, Math.min(366, Number(e.target.value) || 0)))} />}
            </Field>
            <fieldset>
              <legend className="mb-2 text-sm font-medium text-fg">{t("tokens.scopes")}</legend>
              <div className="grid gap-1 sm:grid-cols-2">
                {scopable.map((p) => (
                  <label key={p} className="flex items-center gap-2 text-sm">
                    <input type="checkbox" className="size-4" checked={scopes.has(p)} onChange={(e) => { const n = new Set(scopes); if (e.target.checked) n.add(p); else n.delete(p); setScopes(n); }} />
                    <Ltr>{p}</Ltr>
                  </label>
                ))}
              </div>
            </fieldset>
            <FormError>{error}</FormError>
          </div>
        )}
      </Modal>
    </Card>
  );
}

export function SettingsPage() {
  const { t } = useI18n();
  return (
    <>
      <PageHeader title={t("settings.title")} />
      <div className="grid gap-5 lg:grid-cols-2">
        <PasswordCard />
        <TokensCard />
        <div className="lg:col-span-2"><NotificationsCard /></div>
        <div className="lg:col-span-2"><UpdatesCard /></div>
      </div>
    </>
  );
}
