import { Archive, Download, KeyRound, ShieldCheck, TriangleAlert } from "lucide-react";
import { useState } from "react";
import { confirmDialog } from "@/components/Confirm";
import { EmptyState, ErrorState, LoadingState } from "@/components/States";
import { Check, Field, FormError, Input, Modal } from "@/components/ui/form";
import { Button, Card, CardHeader, Ltr, PageHeader } from "@/components/ui/primitives";
import { useI18n } from "@/i18n/i18n";
import { ops, type Backup, type BackupSchedule } from "@/lib/api";
import { useAsync } from "@/lib/hooks";
import { useSession } from "@/lib/session";
import { JobProgress } from "../gateway/Deployments";
import { Pill, RowMenu, actionKey, errText, tableCls, tdCls, thCls } from "../gateway/common";

const size = (n: number) => (n < 1024 * 1024 ? `${(n / 1024).toFixed(1)} KiB` : `${(n / 1024 / 1024).toFixed(1)} MiB`);

function PassphraseForm({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const { t } = useI18n();
  const [p, setP] = useState("");
  const [p2, setP2] = useState("");
  const [ack, setAck] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const save = async () => {
    setErr(null);
    try {
      await ops.backups.setPassphrase(p);
      setP("");
      setP2("");
      onDone();
      onClose();
    } catch (e) {
      setErr(errText(e));
    }
  };
  const ok = [...p].length >= 16 && p === p2 && ack;
  return (
    <Modal open onOpenChange={(o) => !o && onClose()} title={t("bk.passphrase")} description={t("bk.passphraseNote")}
      footer={<><Button variant="ghost" onClick={onClose}>{t("common.cancel")}</Button><Button variant="primary" disabled={!ok} onClick={save}>{t("common.save")}</Button></>}>
      <form className="flex flex-col gap-4" onSubmit={(e) => { e.preventDefault(); if (ok) void save(); }}>
        <Field label={t("bk.passphrase")} hint={t("bk.passphraseHint")}>{({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} type="password" autoComplete="new-password" value={p} onChange={(e) => setP(e.target.value)} />}</Field>
        <Field label={t("bk.passphraseRepeat")}>{({ id }) => <Input id={id} type="password" autoComplete="new-password" value={p2} onChange={(e) => setP2(e.target.value)} />}</Field>
        <Check checked={ack} onChange={setAck} label={t("bk.passphraseAck")} />
        <FormError>{err}</FormError>
      </form>
    </Modal>
  );
}

function ScheduleCard({ initial, writable, onSaved }: { initial: BackupSchedule; writable: boolean; onSaved: () => void }) {
  const { t } = useI18n();
  const [s, setS] = useState(initial);
  const [err, setErr] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const save = async () => {
    setErr(null);
    setSaved(false);
    try {
      await ops.backups.setSchedule({ ...s, interval_hours: Number(s.interval_hours), retain: Number(s.retain) });
      setSaved(true);
      onSaved();
    } catch (e) {
      setErr(errText(e));
    }
  };
  return (
    <Card>
      <CardHeader title={t("bk.schedule")} />
      <div className="flex flex-col gap-4 px-5 pb-5">
        <Check checked={s.enabled} disabled={!writable} onChange={(v) => setS({ ...s, enabled: v })} label={t("bk.scheduleEnabled")} />
        <div className="grid grid-cols-2 gap-3">
          <Field label={t("bk.interval")}>{({ id }) => <Input id={id} dir="ltr" type="number" min={1} max={720} disabled={!writable} value={s.interval_hours} onChange={(e) => setS({ ...s, interval_hours: Number(e.target.value) })} />}</Field>
          <Field label={t("bk.retain")}>{({ id }) => <Input id={id} dir="ltr" type="number" min={1} max={365} disabled={!writable} value={s.retain} onChange={(e) => setS({ ...s, retain: Number(e.target.value) })} />}</Field>
        </div>
        {writable && <div className="flex items-center gap-3"><Button variant="outline" onClick={save}>{t("common.save")}</Button>{saved && <span className="text-sm text-ok">{t("bk.saved")}</span>}</div>}
        <FormError>{err}</FormError>
      </div>
    </Card>
  );
}

export function BackupsPage() {
  const { t, formatDateTime } = useI18n();
  const { can } = useSession();
  const list = useAsync(ops.backups.list);
  const settings = useAsync(ops.backups.settings);
  const [pp, setPP] = useState(false);
  const [job, setJob] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [verified, setVerified] = useState<Record<string, "ok" | "bad" | "busy">>({});
  const canCreate = can("backups.create");
  const canSettings = can("settings.write");
  const configured = settings.data?.passphrase_configured;

  const create = async () => {
    setErr(null);
    try {
      const r = await ops.backups.create(actionKey());
      setJob(r.job_id);
    } catch (e) {
      setErr(errText(e));
    }
  };
  const verify = async (b: Backup) => {
    setVerified((v) => ({ ...v, [b.id]: "busy" }));
    try {
      await ops.backups.verify(b.id);
      setVerified((v) => ({ ...v, [b.id]: "ok" }));
    } catch (e) {
      setVerified((v) => ({ ...v, [b.id]: "bad" }));
      setErr(errText(e));
    }
  };
  const remove = async (b: Backup) => {
    if (!(await confirmDialog(t("common.confirmDelete", { name: b.file_name })))) return;
    try { await ops.backups.remove(b.id); list.reload(); } catch (e) { setErr(errText(e)); }
  };

  return (
    <>
      <PageHeader title={t("bk.title")} subtitle={t("bk.subtitle")}
        actions={<>
          {canSettings && <Button variant="outline" onClick={() => setPP(true)}><KeyRound className="size-4" aria-hidden />{configured ? t("bk.changePassphrase") : t("bk.setPassphrase")}</Button>}
          {canCreate && <Button variant="primary" disabled={!configured} onClick={create}><Archive className="size-4" aria-hidden />{t("bk.create")}</Button>}
        </>} />
      <p className="mb-4 flex items-start gap-2 rounded-xl bg-warn-soft px-4 py-2.5 text-sm text-warn">
        <TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden />{t("bk.localWarning")}
      </p>
      {settings.data && !configured && (
        <p className="mb-4 rounded-xl bg-accent-soft px-4 py-2.5 text-sm text-accent">{t("bk.needPassphrase")}</p>
      )}
      <FormError>{err}</FormError>
      <div className="flex flex-col gap-4">
        {job && <Card className="p-5"><JobProgress id={job} onDone={list.reload} /></Card>}
        <Card>
          {list.status === "error" && !list.data ? <ErrorState error={list.error} onRetry={list.reload} /> : !list.data ? <LoadingState /> : list.data.items.length === 0 ? <EmptyState title={t("bk.empty")} /> : (
            <div className="relative overflow-x-auto">
              <table className={tableCls}>
                <thead><tr className="border-b border-border">
                  <th className={thCls}>{t("bk.created")}</th><th className={thCls}>{t("bk.trigger")}</th><th className={thCls}>{t("bk.size")}</th>
                  <th className={thCls}>{t("bk.contents")}</th><th className={thCls}><span className="sr-only">{t("common.actions")}</span></th>
                </tr></thead>
                <tbody className="divide-y divide-border">
                  {list.data.items.map((b) => (
                    <tr key={b.id}>
                      <td className={tdCls}>
                        <div className="font-medium">{formatDateTime(b.created_at)}</div>
                        <Ltr className="text-[11px] text-fg-muted">{b.file_name}</Ltr>
                      </td>
                      <td className={tdCls}><Pill tone={b.trigger.startsWith("pre_") ? "warn" : "muted"}>{t(b.trigger === "scheduled" ? "bk.scheduled" : b.trigger === "manual" ? "bk.manual" : "bk.safety")}</Pill></td>
                      <td className={`${tdCls} text-xs`}><Ltr>{size(b.size_bytes)}</Ltr></td>
                      <td className={`${tdCls} text-xs text-fg-muted`}>
                        <Ltr>NGM {b.manifest.ngm_version} · schema v{b.manifest.schema_version}</Ltr>
                        {verified[b.id] === "ok" && <span className="ms-2 inline-flex items-center gap-1 text-ok"><ShieldCheck className="size-3.5" aria-hidden />{t("bk.verifiedOk")}</span>}
                        {verified[b.id] === "bad" && <span className="ms-2 text-bad">{t("bk.verifiedBad")}</span>}
                      </td>
                      <td className={`${tdCls} text-end`}>
                        <div className="flex items-center justify-end gap-1">
                          {canCreate && <Button asChild variant="ghost" size="icon" aria-label={`${t("bk.download")} ${b.file_name}`}><a href={ops.backups.downloadUrl(b.id)} download={b.file_name}><Download className="size-4" aria-hidden /></a></Button>}
                          <RowMenu label={`${t("common.actions")} ${b.file_name}`} items={[
                            { label: verified[b.id] === "busy" ? t("common.loading") : t("bk.verify"), onSelect: () => void verify(b) },
                            ...(canCreate ? [{ label: t("common.delete"), danger: true, onSelect: () => void remove(b) }] : []),
                          ]} />
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
        {settings.data && <ScheduleCard key={JSON.stringify(settings.data.schedule)} initial={settings.data.schedule} writable={canSettings} onSaved={settings.reload} />}
        <Card className="p-5 text-sm">
          <h2 className="font-semibold text-fg">{t("bk.restoreTitle")}</h2>
          <p className="mt-1 text-fg-muted">{t("bk.restoreBody")}</p>
          <pre className="mt-3 overflow-x-auto rounded-lg bg-surface-2 p-3 text-xs" dir="ltr">{"sudo ngm restore --preview /path/to/archive.ngmbak\nsudo ngm restore /path/to/archive.ngmbak"}</pre>
        </Card>
      </div>
      {pp && <PassphraseForm onClose={() => setPP(false)} onDone={settings.reload} />}
    </>
  );
}
