import { Plus, ShieldAlert, ShieldCheck, Wand2 } from "lucide-react";
import { useEffect, useState } from "react";
import { confirmDialog } from "@/components/Confirm";
import { EmptyState, ErrorState, LoadingState } from "@/components/States";
import { Check, Field, FormError, Input, Modal, Select } from "@/components/ui/form";
import { Button, Card, CardHeader, Ltr, PageHeader } from "@/components/ui/primitives";
import { useI18n } from "@/i18n/i18n";
import { gw, ops, type FWRule } from "@/lib/api";
import { useAsync } from "@/lib/hooks";
import { useSession } from "@/lib/session";
import { JobProgress } from "../gateway/Deployments";
import { Pill, RowMenu, actionKey, errText, tableCls, tdCls, thCls } from "../gateway/common";

const TERMINAL = ["Succeeded", "Blocked", "Failed", "RolledBack", "RecoveryRequired", "Cancelled"];

/** Dead-man confirmation: shown while a risky change waits for proof of access. */
function ConfirmPanel({ jobId }: { jobId: string }) {
  const { t } = useI18n();
  const [deadline, setDeadline] = useState<number | null>(null);
  const [now, setNow] = useState(Date.now());
  const [state, setState] = useState<"waiting" | "sent" | "done">("waiting");
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const [j, s] = await Promise.all([gw.job(jobId), gw.jobSteps(jobId)]);
        if (!alive) return;
        if (TERMINAL.includes(j.state)) {
          setState("done");
          return;
        }
        const v = s.items.find((x) => x.to_state === "Verifying");
        const ev = v?.evidence as { confirm_required?: boolean; confirm_deadline?: string } | undefined;
        if (ev?.confirm_required && ev.confirm_deadline) setDeadline(Date.parse(ev.confirm_deadline));
      } catch {
        /* retry */
      }
      if (alive) setTimeout(tick, 1000);
    };
    void tick();
    const iv = setInterval(() => setNow(Date.now()), 500);
    return () => {
      alive = false;
      clearInterval(iv);
    };
  }, [jobId]);
  if (state === "done" || deadline === null) return null;
  const left = Math.max(0, Math.ceil((deadline - now) / 1000));
  const confirm = async () => {
    setErr(null);
    try {
      await ops.firewall.confirm(jobId);
      setState("sent");
    } catch (e) {
      setErr(errText(e));
    }
  };
  return (
    <div role="alert" className="mt-4 rounded-xl border border-warn bg-warn-soft p-4 text-sm text-fg">
      <div className="flex items-center gap-2 font-semibold text-warn"><ShieldAlert className="size-4" aria-hidden />{t("fw.confirmTitle")}</div>
      <p className="mt-1">{t("fw.confirmBody", { s: left })}</p>
      <div className="mt-3 flex items-center gap-3">
        <Button variant="primary" disabled={state === "sent" || left === 0} onClick={confirm}>{state === "sent" ? t("fw.confirmed") : t("fw.confirmBtn")}</Button>
        <span className="font-mono text-lg tabular-nums" aria-label={t("fw.secondsLeft")}>{left}s</span>
      </div>
      <FormError>{err}</FormError>
    </div>
  );
}

function RuleForm({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const { t } = useI18n();
  const [f, setF] = useState({ key: "", action: "allow", proto: "tcp", port: 443, source: "any" });
  const [err, setErr] = useState<string | null>(null);
  const save = async () => {
    setErr(null);
    try {
      await ops.firewall.create({ ...f, key: f.key.trim(), source: f.source.trim() || "any", port: Number(f.port) });
      onDone();
      onClose();
    } catch (e) {
      setErr(errText(e));
    }
  };
  return (
    <Modal open onOpenChange={(o) => !o && onClose()} title={t("fw.newRule")}
      footer={<><Button variant="ghost" onClick={onClose}>{t("common.cancel")}</Button><Button variant="primary" disabled={!f.key} onClick={save}>{t("common.save")}</Button></>}>
      <form className="flex flex-col gap-4" onSubmit={(e) => { e.preventDefault(); void save(); }}>
        <Field label={t("fw.key")} hint={t("fw.keyHint")}>{({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} dir="ltr" value={f.key} onChange={(e) => setF({ ...f, key: e.target.value.toLowerCase() })} />}</Field>
        <div className="grid grid-cols-3 gap-3">
          <Field label={t("fw.action")}>{({ id }) => <Select id={id} value={f.action} onChange={(e) => setF({ ...f, action: e.target.value })}><option value="allow">allow</option><option value="limit">limit</option><option value="deny">deny</option></Select>}</Field>
          <Field label={t("fw.proto")}>{({ id }) => <Select id={id} value={f.proto} onChange={(e) => setF({ ...f, proto: e.target.value })}><option value="tcp">tcp</option><option value="udp">udp</option><option value="any">any</option></Select>}</Field>
          <Field label={t("gw.port")}>{({ id }) => <Input id={id} dir="ltr" type="number" min={1} max={65535} value={f.port} onChange={(e) => setF({ ...f, port: Number(e.target.value) })} />}</Field>
        </div>
        <Field label={t("fw.source")} hint={t("fw.sourceHint")}>{({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} dir="ltr" value={f.source} onChange={(e) => setF({ ...f, source: e.target.value })} />}</Field>
        <FormError>{err}</FormError>
      </form>
    </Modal>
  );
}

export function FirewallPage() {
  const { t, formatDateTime } = useI18n();
  const { can } = useSession();
  const fw = useAsync(ops.firewall.get);
  const [adding, setAdding] = useState(false);
  const [applyOpen, setApplyOpen] = useState(false);
  const [enable, setEnable] = useState(false);
  const [job, setJob] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const writable = can("firewall.write");
  const obs = fw.data?.observed;

  const apply = async () => {
    setErr(null);
    try {
      const r = await ops.firewall.apply(enable, actionKey());
      setApplyOpen(false);
      setJob(r.job_id);
    } catch (e) {
      setErr(errText(e));
    }
  };
  const fromListeners = async () => {
    setErr(null);
    try { await ops.firewall.fromListeners(); fw.reload(); } catch (e) { setErr(errText(e)); }
  };
  const remove = async (r: FWRule) => {
    if (!(await confirmDialog(t("fw.removeConfirm", { name: r.key })))) return;
    try { await ops.firewall.remove(r); fw.reload(); } catch (e) { setErr(errText(e)); }
  };

  return (
    <>
      <PageHeader title={t("fw.title")} subtitle={t("fw.subtitle")}
        actions={writable && (
          <>
            <Button variant="outline" onClick={fromListeners}><Wand2 className="size-4" aria-hidden />{t("fw.fromListeners")}</Button>
            <Button variant="outline" onClick={() => setAdding(true)}><Plus className="size-4" aria-hidden />{t("fw.newRule")}</Button>
            <Button variant="primary" onClick={() => { setEnable(false); setApplyOpen(true); }}>{t("fw.apply")}</Button>
          </>
        )} />
      <FormError>{err && !applyOpen ? err : null}</FormError>
      {fw.status === "error" && !fw.data ? <ErrorState error={fw.error} onRetry={fw.reload} /> : !fw.data ? <LoadingState /> : (
        <div className="flex flex-col gap-4">
          <Card>
            <CardHeader title={t("fw.observed")} action={fw.data.observed_at && <span className="text-xs text-fg-muted">{formatDateTime(fw.data.observed_at)}</span>} />
            {!obs ? <p className="px-5 pb-5 text-sm text-fg-muted">{t("fw.noEvidence")}</p> : (
              <dl className="grid grid-cols-2 gap-x-6 gap-y-3 px-5 pb-5 text-sm sm:grid-cols-4">
                <div><dt className="text-xs text-fg-muted">UFW</dt><dd className="mt-1">{!obs.installed ? <Pill tone="bad">{t("fw.notInstalled")}</Pill> : obs.active ? <Pill tone="ok">{t("fw.active")}</Pill> : <Pill tone="warn">{t("fw.inactive")}</Pill>}</dd></div>
                <div><dt className="text-xs text-fg-muted">{t("fw.defaults")}</dt><dd className="mt-1"><Ltr className="text-xs">{obs.defaults || "—"}</Ltr></dd></div>
                <div><dt className="text-xs text-fg-muted">{t("fw.ssh")}</dt><dd className="mt-1 flex items-center gap-1">{obs.ssh_open ? <ShieldCheck className="size-4 text-ok" aria-hidden /> : <ShieldAlert className="size-4 text-warn" aria-hidden />}<Ltr>{(obs.ssh_ports ?? []).join(", ") || "—"}</Ltr></dd></div>
                <div><dt className="text-xs text-fg-muted">{t("fw.foreign")}</dt><dd className="mt-1">{(obs.foreign ?? []).length}</dd></div>
              </dl>
            )}
            {obs && (obs.foreign ?? []).length > 0 && (
              <details className="border-t border-border px-5 py-3 text-sm">
                <summary className="cursor-pointer text-fg-muted">{t("fw.foreignNote")}</summary>
                <ul className="mt-2 flex flex-col gap-1">{obs.foreign.map((x) => <li key={x}><Ltr className="text-xs">{x}</Ltr></li>)}</ul>
              </details>
            )}
          </Card>
          <Card>
            <CardHeader title={t("fw.rules")} />
            {fw.data.rules.length === 0 ? <EmptyState title={t("fw.empty")} body={t("fw.emptyBody")} /> : (
              <div className="relative overflow-x-auto">
                <table className={tableCls}>
                  <thead><tr className="border-b border-border">
                    <th className={thCls}>{t("fw.key")}</th><th className={thCls}>{t("fw.action")}</th><th className={thCls}>{t("gw.port")}</th>
                    <th className={thCls}>{t("fw.source")}</th><th className={thCls}>{t("fw.state")}</th><th className={thCls}><span className="sr-only">{t("common.actions")}</span></th>
                  </tr></thead>
                  <tbody className="divide-y divide-border">
                    {fw.data.rules.map((r) => (
                      <tr key={r.id}>
                        <td className={tdCls}><Ltr className="font-medium">ngm:{r.key}</Ltr></td>
                        <td className={tdCls}><Pill tone={r.action === "allow" ? "ok" : r.action === "deny" ? "bad" : "warn"}>{r.action}</Pill></td>
                        <td className={tdCls}><Ltr>{r.port}/{r.proto}</Ltr></td>
                        <td className={tdCls}><Ltr>{r.source}</Ltr></td>
                        <td className={tdCls}><Pill tone={r.active_state === "present" ? "ok" : "muted"}>{t(r.active_state === "present" ? "fw.present" : r.active_state === "absent" ? "fw.pending" : "fw.unknown")}</Pill></td>
                        <td className={`${tdCls} text-end`}>{writable && <RowMenu label={`${t("common.delete")} ${r.key}`} items={[{ label: t("common.delete"), danger: true, onSelect: () => void remove(r) }]} />}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
          {job && (
            <Card className="p-5">
              <JobProgress id={job} onDone={fw.reload} />
              <ConfirmPanel jobId={job} />
            </Card>
          )}
        </div>
      )}
      {adding && <RuleForm onClose={() => setAdding(false)} onDone={fw.reload} />}
      <Modal open={applyOpen} onOpenChange={setApplyOpen} title={t("fw.apply")} description={t("fw.applyNote")}
        footer={<><Button variant="ghost" onClick={() => setApplyOpen(false)}>{t("common.cancel")}</Button><Button variant="primary" onClick={apply}>{t("fw.apply")}</Button></>}>
        <div className="flex flex-col gap-3 text-sm">
          {obs && !obs.active && <Check checked={enable} onChange={setEnable} label={t("fw.enable")} hint={t("fw.enableHint")} />}
          <FormError>{err}</FormError>
        </div>
      </Modal>
    </>
  );
}
