import { ShieldCheck, ShieldX } from "lucide-react";
import { useState } from "react";
import { EmptyState, ErrorState, LoadingState } from "@/components/States";
import { Select } from "@/components/ui/form";
import { Button, Card, Ltr, PageHeader, cn } from "@/components/ui/primitives";
import { useI18n } from "@/i18n/i18n";
import { api, type AuditEvent } from "@/lib/api";
import { useAsync } from "@/lib/hooks";

const resultCls = { success: "bg-ok-soft text-ok", failure: "bg-bad-soft text-bad", denied: "bg-warn-soft text-warn" } as const;

export function AuditPage() {
  const { t, formatDateTime } = useI18n();
  const [result, setResult] = useState("");
  const events = useAsync(() => api.audit({ limit: 100, result }), [result]);
  const [more, setMore] = useState<AuditEvent[]>([]);
  const [cursor, setCursor] = useState<string | null | undefined>(undefined);
  const [verify, setVerify] = useState<{ ok: boolean; events: number; broken_at_seq?: number; reason?: string } | null>(null);
  const next = cursor === undefined ? events.data?.next_cursor ?? null : cursor;
  const rows = [...(events.data?.items ?? []), ...more];

  return (
    <>
      <PageHeader
        title={t("audit.title")}
        subtitle={t("audit.subtitle")}
        actions={
          <>
            <Select aria-label={t("audit.result")} className="w-40" value={result} onChange={(e) => { setMore([]); setCursor(undefined); setResult(e.target.value); }}>
              <option value="">{t("audit.allResults")}</option>
              <option value="success">success</option>
              <option value="failure">failure</option>
              <option value="denied">denied</option>
            </Select>
            <Button variant="outline" onClick={async () => setVerify(await api.auditVerify())}>{t("audit.verify")}</Button>
          </>
        }
      />
      {verify && (
        <div role="status" className={cn("mb-4 flex items-center gap-2 rounded-xl px-4 py-3 text-sm", verify.ok ? "bg-ok-soft text-ok" : "bg-bad-soft text-bad")}>
          {verify.ok ? <ShieldCheck className="size-4" aria-hidden /> : <ShieldX className="size-4" aria-hidden />}
          {verify.ok ? t("audit.chainOk", { events: verify.events }) : t("audit.chainBroken", { seq: verify.broken_at_seq ?? "?", reason: verify.reason ?? "" })}
        </div>
      )}
      <Card>
        {events.status === "error" && !events.data ? (
          <ErrorState error={events.error} onRetry={events.reload} />
        ) : !events.data ? (
          <LoadingState />
        ) : rows.length === 0 ? (
          <EmptyState title={t("audit.empty")} />
        ) : (
          <div className="relative overflow-x-auto">
            <table className="w-full min-w-[820px] text-sm">
              <thead>
                <tr className="border-b border-border text-xs text-fg-muted">
                  {["audit.time", "audit.actor", "audit.action", "audit.target", "audit.result"].map((k) => (
                    <th key={k} scope="col" className="px-4 py-3 text-start font-medium">{t(k as "audit.time")}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {rows.map((e) => (
                  <tr key={e.seq} className="align-top">
                    <td className="whitespace-nowrap px-4 py-2.5 text-xs text-fg-muted">{formatDateTime(e.at)}</td>
                    <td className="px-4 py-2.5"><Ltr className="text-xs">{e.actor_kind}{e.actor_id ? ":" + e.actor_id.slice(-6) : ""}</Ltr></td>
                    <td className="px-4 py-2.5">
                      <Ltr className="text-fg">{e.action}</Ltr>
                      {Object.keys(e.context ?? {}).length > 0 && (
                        <div className="mt-0.5 max-w-md truncate text-[11px] text-fg-muted"><Ltr>{JSON.stringify(e.context)}</Ltr></div>
                      )}
                    </td>
                    <td className="px-4 py-2.5"><Ltr className="text-xs text-fg-muted">{e.target_kind}{e.target_id ? ":" + e.target_id.slice(-6) : ""}</Ltr></td>
                    <td className="px-4 py-2.5"><span className={cn("rounded-full px-2 py-0.5 text-xs font-medium", resultCls[e.result])}>{e.result}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {next && (
          <div className="border-t border-border p-3 text-center">
            <Button size="sm" variant="outline" onClick={async () => { const p = await api.audit({ limit: 100, cursor: next, result }); setMore((m) => [...m, ...p.items]); setCursor(p.next_cursor); }}>
              {t("jobs.loadMore")}
            </Button>
          </div>
        )}
      </Card>
    </>
  );
}
