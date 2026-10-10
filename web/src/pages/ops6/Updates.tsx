import { LoadingState } from "@/components/States";
import { Card, CardHeader, Ltr } from "@/components/ui/primitives";
import { useI18n } from "@/i18n/i18n";
import type { MessageKey } from "@/i18n/messages";
import { lifecycleApi } from "@/lib/api";
import { useAsync } from "@/lib/hooks";
import { Pill } from "../gateway/common";

/** Read-only release status. Installing is an administrator action on the server. */
export function UpdatesCard() {
  const { t, formatDateTime } = useI18n();
  const u = useAsync(lifecycleApi.updates);
  if (!u.data) return <Card><CardHeader title={t("upd.title")} /><LoadingState /></Card>;
  const d = u.data;
  const lu = d.last_update;
  return (
    <Card>
      <CardHeader title={t("upd.title")} />
      <div className="flex flex-col gap-3 px-5 pb-5 text-sm">
        <p>{t("upd.running", { v: d.version, c: d.channel })}</p>
        <ul className="flex flex-wrap gap-2">
          {d.releases.map((r) => <li key={r.version}><Pill tone={r.current ? "accent" : "muted"}><Ltr>{r.version}</Ltr> · {t(r.signed ? "upd.signed" : "upd.unsigned")}</Pill></li>)}
        </ul>
        {lu && <p className="text-fg-muted">{t("upd.last", { from: lu.from, to: lu.to, at: formatDateTime(lu.started_at) })}: <Pill tone={lu.phase === "succeeded" ? "ok" : lu.phase === "rolled_back" ? "warn" : "bad"}>{t(`upd.phase.${lu.phase}` as MessageKey)}</Pill> {lu.error && <Ltr className="text-xs">{lu.error}</Ltr>}</p>}
        <p className="text-fg-muted">{t("upd.how")}</p>
        <pre dir="ltr" className="overflow-x-auto rounded-lg bg-surface-2 p-3 text-xs">{Object.values(d.commands).join("\n")}</pre>
      </div>
    </Card>
  );
}
