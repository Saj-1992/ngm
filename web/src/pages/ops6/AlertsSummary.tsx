import { ArrowRight } from "lucide-react";
import { Link } from "react-router-dom";
import { ErrorState, LoadingState } from "@/components/States";
import { Card, CardHeader } from "@/components/ui/primitives";
import { useI18n } from "@/i18n/i18n";
import type { MessageKey } from "@/i18n/messages";
import { opsx } from "@/lib/api";
import { useAsync } from "@/lib/hooks";
import { useSession } from "@/lib/session";
import { Pill } from "../gateway/common";
import { AlertText } from "./AlertText";
import { sevTone } from "./Monitoring";

/** Dashboard card: open alerts from evidence (firing + acknowledged). */
export function AlertsSummary() {
  const { t } = useI18n();
  const { can } = useSession();
  const al = useAsync(() => (can("monitoring.read") ? opsx.alerts(true) : Promise.resolve(null)));
  if (!can("monitoring.read")) return null;
  const items = al.data?.items ?? [];
  const count = (s: string) => items.filter((a) => a.severity === s).length;
  return (
    <Card className="lg:col-span-3">
      <CardHeader title={t("dashboard.alerts")}
        action={<Link to="/monitoring" className="inline-flex items-center gap-1 text-sm text-accent hover:underline">{t("dashboard.allAlerts")}<ArrowRight className="size-4 rtl:rotate-180" aria-hidden /></Link>} />
      {al.status === "error" && !al.data ? <ErrorState error={al.error} onRetry={al.reload} /> : !al.data ? <LoadingState /> : (
        <div className="flex flex-col gap-3 px-5 pb-5 text-sm">
          <p className="flex flex-wrap items-center gap-2">
            {items.length === 0 ? <Pill tone="ok">{t("dashboard.noAlerts")}</Pill> : (["critical", "warning", "info"] as const).filter((s) => count(s) > 0).map((s) => (
              <Pill key={s} tone={sevTone[s]}>{count(s)} × {t(`mon.sev.${s}` as MessageKey)}</Pill>
            ))}
          </p>
          {items.slice(0, 3).map((a) => <p key={a.id} className="min-w-0 text-fg-muted"><AlertText rule={a.rule} subject={a.subject} message={a.message} /></p>)}
        </div>
      )}
    </Card>
  );
}
