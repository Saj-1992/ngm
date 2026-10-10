import { confirmDialog } from "@/components/Confirm";
import { CheckCircle2, CircleDashed, FileCode2, Loader2, Rocket, RotateCcw, XCircle } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { ErrorState, LoadingState } from "@/components/States";
import { Check, FormError, IssueList, Modal } from "@/components/ui/form";
import { Button, Card, CardHeader, Ltr, PageHeader, cn } from "@/components/ui/primitives";
import { useI18n } from "@/i18n/i18n";
import type { MessageKey } from "@/i18n/messages";
import { gw, type Generation, type Job, type JobDetail, type JobStep, type Page } from "@/lib/api";
import { useAsync, type AsyncState } from "@/lib/hooks";
import { useSession } from "@/lib/session";
import { JobStateBadge, Jobs } from "../Jobs";
import { Pill, actionKey, errText } from "./common";

const TERMINAL = ["Succeeded", "Blocked", "Failed", "RolledBack", "RecoveryRequired", "Cancelled"];
const genTone: Record<string, "ok" | "muted" | "bad" | "warn" | "accent"> = { active: "ok", superseded: "muted", failed: "bad", rolled_back: "warn", staged: "accent" };

/** Live view of one deployment job (polls; SSE triggers list refresh elsewhere). */
export function JobProgress({ id, onDone }: { id: string; onDone: () => void }) {
  const [job, setJob] = useState<JobDetail | null>(null);
  const [steps, setSteps] = useState<JobStep[]>([]);
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const [j, s] = await Promise.all([gw.job(id), gw.jobSteps(id)]);
        if (!alive) return;
        setJob(j);
        setSteps(s.items);
        if (TERMINAL.includes(j.state)) {
          onDone();
          return;
        }
      } catch {
        /* retry */
      }
      if (alive) setTimeout(tick, 800);
    };
    void tick();
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);
  if (!job) return <LoadingState />;
  const running = !TERMINAL.includes(job.state);
  return (
    <div className="flex flex-col gap-3" aria-live="polite">
      <div className="flex items-center gap-2">
        {running ? <Loader2 className="size-4 animate-spin text-accent" aria-hidden /> : job.state === "Succeeded" ? <CheckCircle2 className="size-4 text-ok" aria-hidden /> : <XCircle className="size-4 text-bad" aria-hidden />}
        <JobStateBadge state={job.state} />
        <Ltr className="text-xs text-fg-muted">{job.id}</Ltr>
      </div>
      <ol className="flex flex-col gap-1.5">
        {steps.map((s) => (
          <li key={s.id} className="flex items-center gap-2 text-sm">
            {s.status === "started" ? <CircleDashed className="size-3.5 animate-spin text-accent" aria-hidden /> : s.status === "failed" ? <XCircle className="size-3.5 text-bad" aria-hidden /> : <CheckCircle2 className="size-3.5 text-ok" aria-hidden />}
            <Ltr className="font-sans">{s.name}</Ltr>
            {s.to_state && <span className="text-xs text-fg-muted">→ {s.to_state}</span>}
          </li>
        ))}
      </ol>
      {job.error && (
        <div className="rounded-lg bg-bad-soft px-3 py-2 text-sm text-bad">
          <Ltr className="me-2 text-xs">{job.error.code}</Ltr>
          <span dir="auto">{job.error.message}</span>
          {Array.isArray(job.error.details) && <IssueList issues={job.error.details as never} />}
          {typeof job.error.details === "string" && <pre className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap text-xs" dir="ltr">{job.error.details}</pre>}
        </div>
      )}
    </div>
  );
}

export function DeploymentsPage({ jobs }: { jobs: AsyncState<Page<Job>> & { reload: () => void } }) {
  const { t, formatDateTime } = useI18n();
  const { can } = useSession();
  const val = useAsync(() => gw.validate(true));
  const gens = useAsync(gw.deployments);
  const [showPreview, setShowPreview] = useState(false);
  const [applyOpen, setApplyOpen] = useState(false);
  const [opts, setOpts] = useState({ disable_distro_default_site: false, force: false });
  const [running, setRunning] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const canDeploy = can("deploy.apply");
  const refresh = useCallback(() => {
    gens.reload();
    jobs.reload();
    val.reload();
  }, [gens.reload, jobs.reload, val.reload]);

  const apply = async () => {
    setErr(null);
    try {
      const r = await gw.apply(opts, actionKey());
      setRunning(r.job_id);
      setApplyOpen(false);
    } catch (e) {
      setErr(errText(e));
    }
  };
  const rollback = async (g: Generation) => {
    if (!(await confirmDialog(t("dep.rollbackConfirm", { n: g.number })))) return;
    setErr(null);
    try {
      const r = await gw.rollback(g.id, actionKey());
      setRunning(r.job_id);
    } catch (e) {
      setErr(errText(e));
    }
  };

  const errors = val.data?.issues.filter((i) => i.severity === "error") ?? [];
  return (
    <>
      <PageHeader title={t("dep.title")} subtitle={t("dep.subtitle")}
        actions={canDeploy && <Button variant="primary" disabled={!val.data?.valid} onClick={() => setApplyOpen(true)}><Rocket className="size-4" aria-hidden />{t("dep.apply")}</Button>} />
      <FormError>{err}</FormError>
      <div className="grid gap-5 lg:grid-cols-2">
        <Card>
          <CardHeader title={t("dep.desired")} action={val.data && <Pill tone={val.data.valid ? "ok" : "bad"}>{val.data.valid ? t("dep.valid") : t("dep.invalid")}</Pill>} />
          <div className="flex flex-col gap-3 p-5">
            {val.status === "error" && !val.data ? <ErrorState error={val.error} onRetry={val.reload} /> : !val.data ? <LoadingState /> : (
              <>
                {val.data.issues.length ? <IssueList issues={val.data.issues} /> : <p className="text-sm text-ok">{t("dep.noIssues")}</p>}
                {val.data.preview && (
                  <Button variant="outline" size="sm" className="self-start" onClick={() => setShowPreview(!showPreview)}><FileCode2 className="size-4" aria-hidden />{t("dep.showPreview")}</Button>
                )}
              </>
            )}
            {errors.length > 0 && <span className="sr-only">{errors.length}</span>}
          </div>
        </Card>
        <Card>
          <CardHeader title={t("dep.progress")} />
          <div className="p-5">{running ? <JobProgress id={running} onDone={refresh} /> : <p className="text-sm text-fg-muted">{t("common.none")}</p>}</div>
        </Card>
      </div>

      {showPreview && val.data?.preview && (
        <Card className="mt-5">
          <CardHeader title={t("dep.preview")} />
          <div className="flex flex-col gap-4 p-5">
            {Object.entries(val.data.preview.files).map(([name, body]) => (
              <div key={name}>
                <Ltr className="mb-1 block text-xs text-fg-muted">{name}</Ltr>
                <pre dir="ltr" className="max-h-96 overflow-auto rounded-lg bg-surface-2 p-3 font-mono text-xs leading-relaxed text-fg">{body}</pre>
              </div>
            ))}
          </div>
        </Card>
      )}

      <Card className="mt-5">
        <CardHeader title={t("dep.history")} />
        {gens.status === "error" && !gens.data ? <ErrorState error={gens.error} onRetry={gens.reload} /> : !gens.data ? <LoadingState /> : gens.data.items.length === 0 ? (
          <p className="px-5 py-8 text-center text-sm text-fg-muted">{t("dep.noGenerations")}</p>
        ) : (
          <ul className="divide-y divide-border">
            {gens.data.items.map((g) => (
              <li key={g.id} className="flex flex-wrap items-center gap-3 px-5 py-3 text-sm">
                <span className="w-10 font-semibold tabular-nums">#{g.number}</span>
                <Pill tone={genTone[g.status]}>{t(`dep.status.${g.status}` as MessageKey)}</Pill>
                <Ltr className="text-xs text-fg-muted">{g.id.slice(-8)}</Ltr>
                <span className="text-xs text-fg-muted">{formatDateTime(g.activated_at ?? g.created_at)}</span>
                {g.summary.diff && g.summary.diff.length > 0 && (
                  <span className="text-xs text-fg-muted">
                    {g.summary.diff.map((d) => <Ltr key={d.file} className="me-2">{d.file} <span className="text-ok">+{d.lines_added}</span>/<span className="text-bad">−{d.lines_removed}</span></Ltr>)}
                  </span>
                )}
                {g.status === "superseded" && canDeploy && (
                  <Button size="sm" variant="outline" className="ms-auto" onClick={() => rollback(g)}><RotateCcw className="size-4" aria-hidden />{t("dep.rollback")}</Button>
                )}
              </li>
            ))}
          </ul>
        )}
      </Card>

      <div className="mt-5"><Jobs jobs={jobs} embedded /></div>

      <Modal open={applyOpen} onOpenChange={setApplyOpen} title={t("dep.applyTitle")} description={t("dep.applyBody")}
        footer={<><Button variant="ghost" onClick={() => setApplyOpen(false)}>{t("common.cancel")}</Button><Button variant="primary" onClick={apply}><Rocket className="size-4" aria-hidden />{t("dep.apply").replace("…", "")}</Button></>}>
        <div className={cn("flex flex-col gap-3")}>
          {val.data && val.data.issues.length > 0 && <IssueList issues={val.data.issues} />}
          <Check checked={opts.disable_distro_default_site} onChange={(v) => setOpts({ ...opts, disable_distro_default_site: v })} label={t("dep.disableDefaultSite")} />
          <Check checked={opts.force} onChange={(v) => setOpts({ ...opts, force: v })} label={t("dep.force")} />
        </div>
      </Modal>
    </>
  );
}
