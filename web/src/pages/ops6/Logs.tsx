import type { MessageKey } from "@/i18n/messages";
import { Download, Pause, Play, Search } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { EmptyState, ErrorState, LoadingState } from "@/components/States";
import { Field, Input, Select } from "@/components/ui/form";
import { Button, Card, Ltr, PageHeader } from "@/components/ui/primitives";
import { useI18n } from "@/i18n/i18n";
import { opsx, type LogEntry, type LogQuery } from "@/lib/api";
import { useAsync } from "@/lib/hooks";
import { Pill, tableCls, tdCls, thCls } from "../gateway/common";

const CATS = ["", "http", "stream", "error", "api", "ops", "monitor", "security", "audit", "health"];
const sevTone = (s: string) => (s === "error" ? "bad" : s === "warn" ? "warn" : "muted");

export function LogsPage() {
  const { t, formatDateTime } = useI18n();
  const [f, setF] = useState<LogQuery>({ category: "http", q: "", status: "", host: "" });
  const [applied, setApplied] = useState<LogQuery>(f);
  const list = useAsync(() => opsx.logs({ ...applied, limit: 200 }), [JSON.stringify(applied)]);
  const status = useAsync(opsx.logStatus);
  const [live, setLive] = useState(false);
  const [tail, setTail] = useState<LogEntry[]>([]);
  const esRef = useRef<EventSource | null>(null);
  useEffect(() => {
    if (!live) return;
    const es = new EventSource(opsx.logTailUrl(applied));
    esRef.current = es;
    es.addEventListener("log", (ev) => {
      try {
        const e = JSON.parse((ev as MessageEvent).data) as LogEntry;
        setTail((xs) => [e, ...xs].slice(0, 500));
      } catch { /* ignore */ }
    });
    return () => es.close();
  }, [live, applied]);
  const rows = live ? tail : list.data?.items ?? [];
  const st = status.data?.status;
  return (
    <>
      <PageHeader title={t("logs.title")} subtitle={t("logs.subtitle")}
        actions={<>
          <Button variant={live ? "primary" : "outline"} onClick={() => { setTail([]); setLive(!live); }}>{live ? <Pause className="size-4" aria-hidden /> : <Play className="size-4" aria-hidden />}{t(live ? "logs.stopTail" : "logs.tail")}</Button>
          {["csv", "jsonl", "txt"].map((fm) => <Button key={fm} asChild variant="ghost"><a href={opsx.logExportUrl(applied, fm)} download><Download className="size-4" aria-hidden />{fm.toUpperCase()}</a></Button>)}
        </>} />
      {st && (st.paused || st.sources.some((s) => s.error || s.lag_bytes > 1 << 20)) && (
        <p className="mb-3 rounded-lg bg-warn-soft px-3 py-2 text-sm text-warn" dir="auto">{st.paused ? st.reason : t("logs.lagging")}</p>
      )}
      {!st && status.data && <p className="mb-3 rounded-lg bg-warn-soft px-3 py-2 text-sm text-warn">{t("logs.noIndexer")}</p>}
      <form className="mb-4 grid grid-cols-2 gap-3 [&>*]:min-w-0 sm:grid-cols-[10rem_1fr_8rem_12rem_auto] sm:items-end" onSubmit={(e) => { e.preventDefault(); setApplied(f); setTail([]); }}>
        <Field label={t("logs.category")}>{({ id }) => <Select id={id} value={f.category} onChange={(e) => setF({ ...f, category: e.target.value })}>{CATS.map((c) => <option key={c} value={c}>{c ? t(`logs.cat.${c}` as MessageKey) : t("logs.all")}</option>)}</Select>}</Field>
        <Field label={t("logs.search")}>{({ id }) => <Input id={id} value={f.q} onChange={(e) => setF({ ...f, q: e.target.value })} />}</Field>
        <Field label={t("logs.status")}>{({ id }) => <Input id={id} dir="ltr" placeholder="5xx" value={f.status} onChange={(e) => setF({ ...f, status: e.target.value })} />}</Field>
        <Field label={t("logs.host")}>{({ id }) => <Input id={id} dir="ltr" value={f.host} onChange={(e) => setF({ ...f, host: e.target.value })} />}</Field>
        <Button type="submit" variant="outline"><Search className="size-4" aria-hidden />{t("logs.apply")}</Button>
      </form>
      <Card>
        {!live && list.status === "error" && !list.data ? <ErrorState error={list.error} onRetry={list.reload} /> : !live && !list.data ? <LoadingState /> : rows.length === 0 ? <EmptyState title={t(live ? "logs.waiting" : "logs.empty")} /> : (
          <div className="relative overflow-x-auto">
            <table className={tableCls}>
              <thead><tr className="border-b border-border"><th className={thCls}>{t("logs.time")}</th><th className={thCls}>{t("logs.category")}</th><th className={thCls}>{t("logs.message")}</th><th className={thCls}>{t("logs.host")}</th><th className={thCls}>IP</th></tr></thead>
              <tbody className="divide-y divide-border">
                {rows.map((e) => (
                  <tr key={e.id}>
                    <td className={`${tdCls} whitespace-nowrap text-xs`}>{formatDateTime(new Date(e.ts).toISOString())}</td>
                    <td className={tdCls}><Pill tone={sevTone(e.severity)}>{e.category}</Pill></td>
                    <td className={tdCls}><Ltr className="text-xs">{e.message}</Ltr></td>
                    <td className={tdCls}><Ltr className="text-xs">{e.host}</Ltr></td>
                    <td className={tdCls}><Ltr className="text-xs text-fg-muted">{e.ip}</Ltr></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      {status.data && <p className="mt-3 text-xs text-fg-muted">{t("logs.retention")}: <Ltr>{Object.entries(status.data.retention_days).map(([k, v]) => `${k} ${v}d`).join(" · ")}</Ltr></p>}
    </>
  );
}
