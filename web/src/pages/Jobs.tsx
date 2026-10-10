import { en, type MessageKey } from "@/i18n/messages";
import { useState } from "react";
import { EmptyState, ErrorState, LoadingState } from "@/components/States";
import { Button, Card, CardHeader, Ltr, PageHeader, cn } from "@/components/ui/primitives";
import { useI18n } from "@/i18n/i18n";
import { api, type Job, type JobState, type Page } from "@/lib/api";
import type { AsyncState } from "@/lib/hooks";

const tone: Record<JobState, string> = {
  Queued: "bg-unknown-soft text-unknown",
  Validating: "bg-accent-soft text-accent",
  ImpactAnalyzed: "bg-accent-soft text-accent",
  Staging: "bg-accent-soft text-accent",
  Preflight: "bg-accent-soft text-accent",
  Applying: "bg-accent-soft text-accent",
  Verifying: "bg-accent-soft text-accent",
  Succeeded: "bg-ok-soft text-ok",
  Blocked: "bg-warn-soft text-warn",
  Failed: "bg-bad-soft text-bad",
  Compensating: "bg-warn-soft text-warn",
  RolledBack: "bg-warn-soft text-warn",
  RecoveryRequired: "bg-bad-soft text-bad",
  Cancelled: "bg-unknown-soft text-unknown",
};

export function JobStateBadge({ state }: { state: JobState }) {
  return (
    <span className={cn("inline-flex rounded-full px-2 py-0.5 text-xs font-medium", tone[state])}>
      <Ltr className="font-sans">{state}</Ltr>
    </span>
  );
}

export function Jobs({ jobs, embedded }: { jobs: AsyncState<Page<Job>> & { reload: () => void }; embedded?: boolean }) {
  const { t, formatDateTime } = useI18n();
  const [extra, setExtra] = useState<Job[]>([]);
  const [cursor, setCursor] = useState<string | null | undefined>(undefined);
  const [moreError, setMoreError] = useState<unknown>(null);
  const [loadingMore, setLoadingMore] = useState(false);

  const nextCursor = cursor === undefined ? jobs.data?.next_cursor ?? null : cursor;
  const rows = [...(jobs.data?.items ?? []), ...extra];

  const loadMore = async () => {
    if (!nextCursor) return;
    setLoadingMore(true);
    setMoreError(null);
    try {
      const p = await api.jobs({ limit: 50, cursor: nextCursor });
      setExtra((e) => [...e, ...p.items]);
      setCursor(p.next_cursor);
    } catch (e) {
      setMoreError(e);
    } finally {
      setLoadingMore(false);
    }
  };

  return (
    <>
      {!embedded && <PageHeader title={t("jobs.title")} subtitle={t("jobs.subtitle")} />}
      <Card>
        {embedded && <CardHeader title={t("dep.jobs")} />}
        {jobs.status === "error" && !jobs.data ? (
          <ErrorState error={jobs.error} onRetry={jobs.reload} />
        ) : !jobs.data ? (
          <LoadingState />
        ) : rows.length === 0 ? (
          <EmptyState title={t("jobs.empty")} body={t("jobs.emptyHint")} />
        ) : (
          <div className="relative overflow-x-auto">
            <table className="w-full min-w-[640px] text-sm">
              <thead>
                <tr className="border-b border-border text-start text-xs text-fg-muted">
                  <th scope="col" className="px-5 py-3 text-start font-medium">{t("jobs.state")}</th>
                  <th scope="col" className="px-5 py-3 text-start font-medium">{t("jobs.kind")}</th>
                  <th scope="col" className="px-5 py-3 text-start font-medium">{t("jobs.id")}</th>
                  <th scope="col" className="px-5 py-3 text-start font-medium">{t("jobs.created")}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {rows.map((j) => (
                  <tr key={j.id} className="hover:bg-surface-2/60">
                    <td className="px-5 py-3"><JobStateBadge state={j.state} /></td>
                    <td className="px-5 py-3" title={j.kind}><JobKind kind={j.kind} /></td>
                    <td className="px-5 py-3 text-fg-muted"><Ltr>{j.id}</Ltr></td>
                    <td className="px-5 py-3 text-fg-muted">
                      <time dateTime={j.created_at}>{formatDateTime(j.created_at)}</time>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {moreError != null && <ErrorState error={moreError} onRetry={loadMore} />}
        {nextCursor && (
          <div className="border-t border-border p-3 text-center">
            <Button variant="outline" size="sm" onClick={loadMore} disabled={loadingMore}>
              {loadingMore ? t("common.loading") : t("jobs.loadMore")}
            </Button>
          </div>
        )}
      </Card>
    </>
  );
}

/** Translated job kind; unknown kinds fall back to the raw identifier. */
export function JobKind({ kind }: { kind: string }) {
  const { t } = useI18n();
  const k = `jobkind.${kind}` as MessageKey;
  return <span title={kind}>{k in en ? t(k) : <Ltr>{kind}</Ltr>}</span>;
}
