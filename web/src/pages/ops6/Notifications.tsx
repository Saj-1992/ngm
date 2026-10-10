import type { MessageKey } from "@/i18n/messages";
import { Plus, Send, Trash2 } from "lucide-react";
import { useState } from "react";
import { confirmDialog } from "@/components/Confirm";
import { EmptyState, LoadingState } from "@/components/States";
import { Check, Field, FormError, Input, Modal, Select } from "@/components/ui/form";
import { Button, Card, CardHeader, Ltr } from "@/components/ui/primitives";
import { useI18n } from "@/i18n/i18n";
import { opsx } from "@/lib/api";
import { useAsync } from "@/lib/hooks";
import { useSession } from "@/lib/session";
import { Pill, errText } from "../gateway/common";

/** Notification targets (Settings section). */
export function NotificationsCard() {
  const { t, formatDateTime } = useI18n();
  const { can } = useSession();
  const ts = useAsync(opsx.targets);
  const ds = useAsync(opsx.deliveries);
  const [add, setAdd] = useState(false);
  const [f, setF] = useState({ name: "", kind: "telegram", chat_id: "", url: "", secret: "", min_severity: "warning", enabled: true });
  const [err, setErr] = useState<string | null>(null);
  const writable = can("settings.write");
  const save = async () => {
    setErr(null);
    try { await opsx.createTarget(f); setAdd(false); setF({ ...f, name: "", secret: "", chat_id: "", url: "" }); ts.reload(); } catch (e) { setErr(errText(e)); }
  };
  return (
    <Card>
      <CardHeader title={t("ntf.title")} action={writable && <Button size="sm" variant="outline" onClick={() => setAdd(true)}><Plus className="size-4" aria-hidden />{t("ntf.add")}</Button>} />
      <p className="px-5 pb-3 text-xs text-fg-muted">{t("ntf.note")}</p>
      {!ts.data ? <LoadingState /> : ts.data.items.length === 0 ? <EmptyState title={t("ntf.empty")} /> : (
        <ul className="divide-y divide-border">
          {ts.data.items.map((x) => (
            <li key={x.id} className="flex flex-wrap items-center gap-3 px-5 py-3 text-sm">
              <span className="font-medium">{x.name}</span><Pill>{x.kind}</Pill><Ltr className="text-xs text-fg-muted">{x.chat_id ?? x.url}</Ltr>
              <span className="text-xs text-fg-muted">≥ {x.min_severity}</span>
              {writable && <>
                <Check checked={x.enabled} onChange={async (v) => { await opsx.setTarget(x.id, v); ts.reload(); }} label={t("common.enabled")} />
                <Button size="sm" variant="ghost" onClick={async () => { await opsx.testTarget(x.id); setTimeout(ds.reload, 12000); }}><Send className="size-4" aria-hidden />{t("ntf.test")}</Button>
                <Button size="icon" variant="ghost" aria-label={t("common.delete")} onClick={async () => { if (await confirmDialog(t("common.confirmDelete", { name: x.name }))) { await opsx.deleteTarget(x.id); ts.reload(); } }}><Trash2 className="size-4" aria-hidden /></Button>
              </>}
            </li>
          ))}
        </ul>
      )}
      {ds.data && ds.data.items.length > 0 && (
        <details className="border-t border-border px-5 py-3 text-xs">
          <summary className="cursor-pointer text-fg-muted">{t("ntf.deliveries")}</summary>
          <ul className="mt-2 flex flex-col gap-1">{ds.data.items.slice(0, 30).map((d) => (
            <li key={d.id} className="flex flex-wrap gap-2"><Pill tone={d.status === "sent" ? "ok" : d.status === "pending" ? "muted" : "bad"}>{d.status}</Pill><span>{d.event}</span><span className="text-fg-muted">{formatDateTime(d.created_at)} · {d.attempts}×</span>{d.last_error && <Ltr className="text-bad">{d.last_error}</Ltr>}</li>
          ))}</ul>
        </details>
      )}
      {add && (
        <Modal open onOpenChange={(o) => !o && setAdd(false)} title={t("ntf.add")}
          footer={<><Button variant="ghost" onClick={() => setAdd(false)}>{t("common.cancel")}</Button><Button variant="primary" disabled={!f.name} onClick={save}>{t("common.save")}</Button></>}>
          <div className="flex flex-col gap-3">
            <Field label={t("common.name")}>{({ id }) => <Input id={id} value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} />}</Field>
            <Field label={t("ntf.kind")}>{({ id }) => <Select id={id} value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })}><option value="telegram">Telegram</option><option value="webhook">Webhook (HTTPS)</option></Select>}</Field>
            {f.kind === "telegram" ? <>
              <Field label={t("ntf.botToken")}>{({ id }) => <Input id={id} type="password" autoComplete="off" dir="ltr" value={f.secret} onChange={(e) => setF({ ...f, secret: e.target.value })} />}</Field>
              <Field label={t("ntf.chatId")}>{({ id }) => <Input id={id} dir="ltr" value={f.chat_id} onChange={(e) => setF({ ...f, chat_id: e.target.value })} />}</Field>
            </> : <>
              <Field label="URL">{({ id }) => <Input id={id} dir="ltr" placeholder="https://" value={f.url} onChange={(e) => setF({ ...f, url: e.target.value })} />}</Field>
              <Field label={t("ntf.signing")} hint={t("ntf.signingHint")}>{({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} type="password" autoComplete="off" dir="ltr" value={f.secret} onChange={(e) => setF({ ...f, secret: e.target.value })} />}</Field>
            </>}
            <Field label={t("ntf.minSev")}>{({ id }) => <Select id={id} value={f.min_severity} onChange={(e) => setF({ ...f, min_severity: e.target.value })}>{["info", "warning", "critical"].map((s) => <option key={s} value={s}>{t(`mon.sev.${s}` as MessageKey)}</option>)}</Select>}</Field>
            <FormError>{err}</FormError>
          </div>
        </Modal>
      )}
    </Card>
  );
}
