import type { MessageKey } from "@/i18n/messages";
import { BellOff, Cpu, HardDrive, MemoryStick } from "lucide-react";
import { useCallback, useEffect } from "react";
import { EmptyState, ErrorState, LoadingState } from "@/components/States";
import { Button, Card, CardHeader, Ltr, PageHeader } from "@/components/ui/primitives";
import { useI18n } from "@/i18n/i18n";
import { opsx, type MetricPoint } from "@/lib/api";
import { useAsync } from "@/lib/hooks";
import { useSession } from "@/lib/session";
import { Pill } from "../gateway/common";
import { AlertText } from "./AlertText";

const gib = (n: number) => (n / (1 << 30)).toFixed(1);
export const sevTone = { critical: "bad", warning: "warn", info: "accent" } as const;

/** Minimal accessible sparkline (no chart library). */
function Spark({ pts, value, label }: { pts: number[]; value: string; label: string }) {
  const max = Math.max(1, ...pts);
  const d = pts.map((p, i) => `${(i / Math.max(1, pts.length - 1)) * 100},${30 - (p / max) * 28}`).join(" ");
  return (
    <figure className="flex flex-col gap-1">
      <figcaption className="text-xs text-fg-muted">{label}</figcaption>
      <p className="text-2xl font-semibold tabular-nums">{value}</p>
      <svg viewBox="0 0 100 30" preserveAspectRatio="none" className="h-10 w-full text-accent" role="img" aria-label={label}>
        {pts.length > 1 && <polyline points={d} fill="none" stroke="currentColor" strokeWidth="1.5" vectorEffect="non-scaling-stroke" />}
      </svg>
    </figure>
  );
}

export function MonitoringPage() {
  const { t, formatDateTime } = useI18n();
  const { can } = useSession();
  const sys = useAsync(() => opsx.system(24));
  const al = useAsync(() => opsx.alerts(false));
  const reload = useCallback(() => { sys.reload(); al.reload(); }, [sys.reload, al.reload]);
  useEffect(() => {
    const iv = setInterval(reload, 30000);
    return () => clearInterval(iv);
  }, [reload]);
  const h: MetricPoint[] = sys.data?.history ?? [];
  const cur = sys.data?.current;
  return (
    <>
      <PageHeader title={t("mon.title")} subtitle={t("mon.subtitle")} />
      <Card className="mb-4 p-5">
        {sys.status === "error" && !sys.data ? <ErrorState error={sys.error} onRetry={sys.reload} /> : !sys.data ? <LoadingState /> : !cur ? <EmptyState title={t("mon.noMetrics")} /> : (
          <>
            {sys.data.stale && <p className="mb-3 rounded-lg bg-warn-soft px-3 py-2 text-sm text-warn">{t("mon.stale")}</p>}
            <div className="grid gap-6 sm:grid-cols-3">
              <div className="flex gap-3"><Cpu className="mt-1 size-5 text-fg-muted" aria-hidden /><Spark label={t("mon.cpu", { n: cur.cpus })} value={`${cur.cpu_pct.toFixed(0)}%`} pts={h.map((p) => p.cpu_pct)} /></div>
              <div className="flex gap-3"><MemoryStick className="mt-1 size-5 text-fg-muted" aria-hidden /><Spark label={t("mon.memory")} value={`${gib(cur.mem_used)} / ${gib(cur.mem_total)} GiB`} pts={h.map((p) => p.mem_used)} /></div>
              <div className="flex gap-3"><HardDrive className="mt-1 size-5 text-fg-muted" aria-hidden /><Spark label={t("mon.disk")} value={`${gib(cur.disk_used)} / ${gib(cur.disk_total)} GiB`} pts={h.map((p) => p.disk_used)} /></div>
            </div>
            <p className="mt-3 text-xs text-fg-muted">{t("mon.observed", { at: formatDateTime(sys.data.observed_at!) })} · load {cur.load1.toFixed(2)}</p>
          </>
        )}
      </Card>
      <Card>
        <CardHeader title={t("mon.alerts")} />
        {al.status === "error" && !al.data ? <ErrorState error={al.error} onRetry={al.reload} /> : !al.data ? <LoadingState /> : al.data.items.length === 0 ? <EmptyState title={t("mon.noAlerts")} /> : (
          <ul className="divide-y divide-border">
            {al.data.items.map((a) => (
              <li key={a.id} className="flex flex-wrap items-center gap-3 px-5 py-3 text-sm">
                <Pill tone={a.state === "resolved" ? "muted" : sevTone[a.severity]}>{t(`mon.sev.${a.severity}` as MessageKey)}</Pill>
                <span className="min-w-0 flex-1"><AlertText rule={a.rule} subject={a.subject} message={a.message} /></span>
                <Ltr className="text-xs text-fg-muted">{a.rule}</Ltr>
                <span className="text-xs text-fg-muted">{t(`mon.state.${a.state}` as MessageKey)} · {formatDateTime(a.last_at)}</span>
                {a.state === "firing" && can("alerts.write") && <Button size="sm" variant="ghost" onClick={async () => { await opsx.ack(a.id); al.reload(); }}><BellOff className="size-4" aria-hidden />{t("mon.ack")}</Button>}
              </li>
            ))}
          </ul>
        )}
      </Card>
    </>
  );
}
