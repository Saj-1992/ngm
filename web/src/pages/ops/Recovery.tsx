import { CheckCircle2, LifeBuoy } from "lucide-react";
import { useState } from "react";
import { EmptyState, ErrorState, LoadingState } from "@/components/States";
import { Field, FormError, Modal, Select, Textarea } from "@/components/ui/form";
import { Button, Card, Ltr, PageHeader } from "@/components/ui/primitives";
import { useI18n } from "@/i18n/i18n";
import type { MessageKey } from "@/i18n/messages";
import { ops, type Incident } from "@/lib/api";
import { useAsync } from "@/lib/hooks";
import { useSession } from "@/lib/session";
import { JobStateBadge } from "../Jobs";
import { JobProgress } from "../gateway/Deployments";
import { Pill, errText } from "../gateway/common";

function Detail({ inc, writable, onClose, onDone }: { inc: Incident; writable: boolean; onClose: () => void; onDone: () => void }) {
  const { t, formatDateTime } = useI18n();
  const d = useAsync(() => ops.recovery.get(inc.id), [inc.id]);
  const [outcome, setOutcome] = useState<"rolled_back" | "failed" | "succeeded">("rolled_back");
  const [note, setNote] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [job, setJob] = useState<string | null>(null);
  const open = inc.status !== "resolved";
  const drift = d.data?.drift;
  const reconcile = async (mode: "adopt" | "restore") => {
    setErr(null);
    try {
      const r = await ops.recovery.reconcile(inc.id, mode);
      setJob(r.job_id);
    } catch (e) {
      setErr(errText(e));
    }
  };
  const resolve = async () => {
    setErr(null);
    try {
      await ops.recovery.resolve(inc.id, outcome, note.trim());
      onDone();
      onClose();
    } catch (e) {
      setErr(errText(e));
    }
  };
  return (
    <Modal open wide onOpenChange={(o) => !o && onClose()} title={t("rc.incident")} description={inc.summary}
      footer={<><Button variant="ghost" onClick={onClose}>{t("common.close")}</Button>
        {open && writable && !drift && <Button variant="primary" disabled={[...note.trim()].length < 10} onClick={resolve}>{t("rc.resolve")}</Button>}</>}>
      <div className="flex flex-col gap-4 text-sm">
        <section>
          <h3 className="mb-2 font-semibold text-fg">{t("rc.actions")}</h3>
          <ol className="flex list-decimal flex-col gap-2 ps-5">
            {inc.actions.map((a) => (
              <li key={a.code}>
                <span>{t(`rc.action.${a.code}` as MessageKey)}</span>
                {a.command && <pre className="mt-1 overflow-x-auto rounded-lg bg-surface-2 p-2 text-xs" dir="ltr">{a.command}</pre>}
              </li>
            ))}
          </ol>
        </section>
        <section>
          <h3 className="mb-2 font-semibold text-fg">{t("rc.evidence")}</h3>
          <pre className="max-h-40 overflow-auto rounded-lg bg-surface-2 p-2 text-xs" dir="ltr">{JSON.stringify(inc.evidence, null, 2)}</pre>
        </section>
        {d.status === "error" ? <ErrorState error={d.error} onRetry={d.reload} /> : !d.data ? <LoadingState /> : d.data.steps && (
          <section>
            <h3 className="mb-2 font-semibold text-fg">{t("rc.journal")}</h3>
            <ol className="flex flex-col gap-1">
              {d.data.steps.map((s) => (
                <li key={s.id} className="flex flex-wrap items-center gap-2 text-xs">
                  <span className="text-fg-muted tabular-nums">{s.seq}.</span><Ltr className="font-sans font-medium">{s.name}</Ltr>
                  {s.to_state && <span className="text-fg-muted">→ {s.to_state}</span>}<span className="text-fg-muted">{formatDateTime(s.started_at)}</span>
                </li>
              ))}
            </ol>
          </section>
        )}
        {open && drift && (
          <section role="alert" className="flex flex-col gap-3 rounded-xl border border-warn bg-warn-soft p-4">
            <h3 className="font-semibold text-warn">{t("rc.drift")}</h3>
            <p>{t("rc.driftBody")}</p>
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs">
              <dt className="text-fg-muted">{t("rc.serving")}</dt><dd><Ltr>{drift.serving}</Ltr></dd>
              <dt className="text-fg-muted">{t("rc.recorded")}</dt><dd><Ltr>{drift.recorded}</Ltr></dd>
            </dl>
            {writable && !job && (
              <div className="flex flex-wrap gap-2">
                <Button variant="primary" onClick={() => reconcile("adopt")}>{t("rc.adopt")}</Button>
                <Button variant="outline" onClick={() => reconcile("restore")}>{t("rc.restore")}</Button>
              </div>
            )}
            {job && <JobProgress id={job} onDone={() => { d.reload(); onDone(); }} />}
            <p className="text-xs text-fg-muted">{t("rc.reconcileNote")}</p>
          </section>
        )}
        {open && writable && !drift && (
          <section className="flex flex-col gap-3 border-t border-border pt-4">
            <p className="text-fg-muted">{t("rc.resolveNote")}</p>
            <Field label={t("rc.outcome")}>{({ id }) => (
              <Select id={id} value={outcome} onChange={(e) => setOutcome(e.target.value as typeof outcome)}>
                <option value="rolled_back">{t("rc.outcome.rolled_back")}</option><option value="failed">{t("rc.outcome.failed")}</option><option value="succeeded">{t("rc.outcome.succeeded")}</option>
              </Select>
            )}</Field>
            <Field label={t("rc.note")} hint={t("rc.noteHint")}>{({ id, describedBy }) => <Textarea id={id} aria-describedby={describedBy} rows={3} value={note} onChange={(e) => setNote(e.target.value)} />}</Field>
            <FormError>{err}</FormError>
          </section>
        )}
      </div>
    </Modal>
  );
}

export function RecoveryPage() {
  const { t, formatDateTime } = useI18n();
  const { can } = useSession();
  const list = useAsync(() => ops.recovery.list());
  const drift = useAsync(ops.recovery.drift);
  const [sel, setSel] = useState<Incident | null>(null);
  const [djob, setDjob] = useState<string | null>(null);
  const [derr, setDerr] = useState<string | null>(null);
  const openIncidents = list.data?.items.some((i) => i.status !== "resolved");
  const reconcileDrift = async (mode: "adopt" | "restore") => {
    setDerr(null);
    try { setDjob((await ops.recovery.reconcileDrift(mode)).job_id); } catch (e) { setDerr(errText(e)); }
  };
  const openCount = list.data?.items.filter((i) => i.status !== "resolved").length ?? 0;
  return (
    <>
      <PageHeader title={t("rc.title")} subtitle={t("rc.subtitle")} />
      {drift.data?.drift && !openIncidents && (
        <Card className="mb-4 border-warn p-4 text-sm">
          <h2 className="font-semibold text-warn">{t("rc.drift")}</h2>
          <p className="mt-1">{t("rc.driftBody")}</p>
          <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs">
            <dt className="text-fg-muted">{t("rc.serving")}</dt><dd><Ltr>{drift.data.drift.serving}</Ltr></dd>
            <dt className="text-fg-muted">{t("rc.recorded")}</dt><dd><Ltr>{drift.data.drift.recorded}</Ltr></dd>
          </dl>
          {can("recovery.write") && !djob && (
            <div className="mt-3 flex flex-wrap gap-2">
              <Button variant="primary" onClick={() => reconcileDrift("adopt")}>{t("rc.adopt")}</Button>
              <Button variant="outline" onClick={() => reconcileDrift("restore")}>{t("rc.restore")}</Button>
            </div>
          )}
          {djob && <div className="mt-3"><JobProgress id={djob} onDone={drift.reload} /></div>}
          <FormError>{derr}</FormError>
        </Card>
      )}
      {list.data && (openCount === 0
        ? <p className="mb-4 flex items-center gap-2 rounded-xl bg-ok-soft px-4 py-2.5 text-sm text-ok"><CheckCircle2 className="size-4" aria-hidden />{t("rc.allClear")}</p>
        : <p role="status" className="mb-4 flex items-center gap-2 rounded-xl bg-bad-soft px-4 py-2.5 text-sm text-bad"><LifeBuoy className="size-4" aria-hidden />{t("rc.openCount", { n: openCount })}</p>)}
      <Card>
        {list.status === "error" && !list.data ? <ErrorState error={list.error} onRetry={list.reload} /> : !list.data ? <LoadingState /> : list.data.items.length === 0 ? <EmptyState title={t("rc.empty")} /> : (
          <ul className="divide-y divide-border">
            {list.data.items.map((i) => (
              <li key={i.id}>
                <button type="button" className="flex w-full flex-wrap items-center gap-3 px-5 py-3 text-start hover:bg-surface-2" onClick={() => setSel(i)}>
                  <Pill tone={i.status === "resolved" ? "muted" : "bad"}>{t(i.status === "resolved" ? "rc.resolved" : "rc.open")}</Pill>
                  <span className="min-w-0 flex-1 truncate text-sm font-medium text-fg" dir="auto">{i.summary}</span>
                  {i.job_kind && <Ltr className="text-xs text-fg-muted">{i.job_kind}</Ltr>}
                  {i.job_state && <JobStateBadge state={i.job_state as never} />}
                  <span className="text-xs text-fg-muted">{formatDateTime(i.opened_at)}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </Card>
      {sel && <Detail inc={sel} writable={can("recovery.write")} onClose={() => setSel(null)} onDone={list.reload} />}
    </>
  );
}
