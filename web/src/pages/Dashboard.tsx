import { ArrowRight } from "lucide-react";
import { Link } from "react-router-dom";
import { ErrorState, LoadingState } from "@/components/States";
import { StatusBadge } from "@/components/StatusBadge";
import { Card, CardHeader, Ltr, PageHeader } from "@/components/ui/primitives";
import { useI18n } from "@/i18n/i18n";
import type { Health, Job, Page, Version } from "@/lib/api";
import type { AsyncState } from "@/lib/hooks";
import { JobKind, JobStateBadge } from "./Jobs";
import { AlertsSummary } from "./ops6/AlertsSummary";
import { SetupChecklist } from "./ops6/SetupChecklist";

type Props = {
  health: AsyncState<Health> & { reload: () => void };
  version: AsyncState<Version> & { reload: () => void };
  jobs: AsyncState<Page<Job>> & { reload: () => void };
};

export function Dashboard({ health, version, jobs }: Props) {
  const { t, formatDateTime } = useI18n();

  return (
    <>
      <PageHeader title={t("dashboard.title")} subtitle={t("dashboard.subtitle")} />

      <div className="grid gap-5 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader
            title={t("dashboard.components")}
            action={health.data && <StatusBadge status={health.data.status} />}
          />
          {health.status === "error" && !health.data ? (
            <ErrorState error={health.error} onRetry={health.reload} />
          ) : !health.data ? (
            <LoadingState />
          ) : health.data.components.length === 0 ? (
            // Anonymous callers get only the aggregate status from the API.
            <div className="flex flex-col items-center gap-3 px-5 py-10 text-center">
              <StatusBadge status={health.data.status} size="lg" />
              <p className="text-sm text-fg-muted">{t("common.forbidden")}</p>
            </div>
          ) : (
            <ul className="divide-y divide-border">
              {health.data.components.map((c) => (
                <li key={c.name} className="flex flex-wrap items-center gap-x-4 gap-y-1 px-5 py-3">
                  <Ltr className="min-w-32 text-sm text-fg">{c.name}</Ltr>
                  <StatusBadge status={c.status} />
                  {c.detail && <bdi dir="auto" className="text-xs text-fg-muted">{detailText(c.detail, t)}</bdi>}
                  <time className="ms-auto text-xs text-fg-muted" dateTime={c.observed_at}>
                    {formatDateTime(c.observed_at)}
                  </time>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card>
          <CardHeader title={t("dashboard.build")} />
          {version.status === "error" && !version.data ? (
            <ErrorState error={version.error} onRetry={version.reload} />
          ) : !version.data ? (
            <LoadingState />
          ) : (
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2.5 px-5 py-4 text-sm">
              <dt className="text-fg-muted">{t("dashboard.build")}</dt>
              <dd className="text-end">
                <Ltr>{version.data.version}</Ltr>
              </dd>
              <dt className="text-fg-muted">{t("dashboard.schema")}</dt>
              <dd className="text-end">
                <Ltr>v{version.data.schema_version}</Ltr>
              </dd>
              <dt className="text-fg-muted">API</dt>
              <dd className="text-end">
                <Ltr>{version.data.api_version}</Ltr>
              </dd>
              <dt className="text-fg-muted">{t("dashboard.platform")}</dt>
              <dd className="text-end">
                <Ltr>
                  {version.data.os}/{version.data.arch}
                </Ltr>
              </dd>
            </dl>
          )}
        </Card>

        <SetupChecklist />
        <AlertsSummary />

        <Card className="lg:col-span-3">
          <CardHeader
            title={t("dashboard.recentJobs")}
            action={
              <Link to="/ops/deployments" className="inline-flex items-center gap-1 text-sm text-accent hover:underline">
                {t("dashboard.viewAll")}
                <ArrowRight aria-hidden className="size-4 rtl:rotate-180" />
              </Link>
            }
          />
          {jobs.status === "error" && !jobs.data ? (
            <ErrorState error={jobs.error} onRetry={jobs.reload} />
          ) : !jobs.data ? (
            <LoadingState />
          ) : jobs.data.items.length === 0 ? (
            <p className="px-5 py-8 text-center text-sm text-fg-muted">{t("dashboard.noJobs")}</p>
          ) : (
            <ul className="divide-y divide-border">
              {jobs.data.items.slice(0, 5).map((j) => (
                <li key={j.id} className="flex flex-wrap items-center gap-3 px-5 py-3 text-sm">
                  <JobStateBadge state={j.state} />
                  <span className="text-fg"><JobKind kind={j.kind} /></span>
                  <time className="ms-auto text-xs text-fg-muted" dateTime={j.created_at}>
                    {formatDateTime(j.created_at)}
                  </time>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </>
  );
}


/** Localises known server summaries; other details are technical values shown as-is. */
function detailText(d: string, t: (k: "dashboard.backendsSummary", v: Record<string, string>) => string): string {
  const m = /^(\d+) healthy, (\d+) degraded, (\d+) down, (\d+) unknown, (\d+) disabled$/.exec(d);
  return m ? t("dashboard.backendsSummary", { h: m[1]!, g: m[2]!, d: m[3]!, u: m[4]!, x: m[5]! }) : d;
}
