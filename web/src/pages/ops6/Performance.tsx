import type { MessageKey } from "@/i18n/messages";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ErrorState, LoadingState } from "@/components/States";
import { FormError, Input, Select } from "@/components/ui/form";
import { Button, Card, Ltr, PageHeader } from "@/components/ui/primitives";
import { useI18n } from "@/i18n/i18n";
import { opsx } from "@/lib/api";
import { useAsync } from "@/lib/hooks";
import { useSession } from "@/lib/session";
import { Pill, errText, tableCls, tdCls, thCls } from "../gateway/common";

export function PerformancePage() {
  const { t } = useI18n();
  const { can } = useSession();
  const d = useAsync(opsx.perf);
  const [profile, setProfile] = useState("");
  const [ov, setOv] = useState<Record<string, string>>({});
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const writable = can("performance.write");
  useEffect(() => {
    if (!d.data) return;
    setProfile(d.data.view.selected ?? "");
    const o: Record<string, string> = {};
    for (const v of d.data.view.values) if (v.override !== undefined) o[v.name] = String(v.override);
    setOv(o);
  }, [d.data]);
  const save = async () => {
    setErr(null);
    setMsg(null);
    const overrides: Record<string, number> = {};
    for (const [k, v] of Object.entries(ov)) if (v !== "") overrides[k] = Number(v);
    try { await opsx.savePerf({ profile, overrides }); setMsg(t("perf.saved")); d.reload(); } catch (e) { setErr(errText(e)); }
  };
  if (d.status === "error" && !d.data) return <ErrorState error={d.error} onRetry={d.reload} />;
  if (!d.data) return <LoadingState />;
  const v = d.data.view;
  return (
    <>
      <PageHeader title={t("perf.title")} subtitle={t("perf.subtitle")} actions={writable && <Button variant="primary" onClick={save}>{t("common.save")}</Button>} />
      <Card className="mb-4 flex flex-wrap items-center gap-4 p-5 text-sm">
        <label className="flex items-center gap-2">{t("perf.profile")}
          <Select value={profile} disabled={!writable} onChange={(e) => setProfile(e.target.value)}>
            <option value="">{t("perf.recommended", { p: t(`perf.p.${v.recommended}` as MessageKey) })}</option>
            {d.data.profiles.map((p) => <option key={p} value={p}>{t(`perf.p.${p}` as MessageKey)}</option>)}
          </Select>
        </label>
        <span className="text-fg-muted">{t("perf.reason")}: <Ltr>{v.reason}</Ltr></span>
        <span className="text-fg-muted">{t("perf.internal", { c: v.internal.monitor_concurrency, b: v.internal.log_batch })}</span>
      </Card>
      <p className="mb-4 text-sm text-fg-muted">{d.data.note} · <Link className="text-accent underline underline-offset-2" to="/ops/deployments">{t("perf.deploy")}</Link></p>
      {msg && <p className="mb-3 text-sm text-ok" role="status">{msg}</p>}
      <FormError>{err}</FormError>
      <Card>
        <div className="relative overflow-x-auto">
          <table className={tableCls}>
            <thead><tr className="border-b border-border"><th className={thCls}>{t("perf.directive")}</th><th className={thCls}>{t("perf.default")}</th><th className={thCls}>{t("perf.override")}</th><th className={thCls}>{t("perf.effective")}</th></tr></thead>
            <tbody className="divide-y divide-border">
              {v.values.map((x) => (
                <tr key={x.name}>
                  <td className={tdCls}><Ltr className="font-medium">{x.name}</Ltr><p className="text-xs text-fg-muted" dir="ltr">{x.unit} · {x.min}–{x.max}{x.note ? ` · ${x.note}` : ""}</p></td>
                  <td className={`${tdCls} tabular-nums`}>{x.default}</td>
                  <td className={tdCls}><Input aria-label={`${t("perf.override")} ${x.name}`} dir="ltr" type="number" min={x.min} max={x.max} className="h-8 w-28" disabled={!writable} value={ov[x.name] ?? ""} placeholder="—" onChange={(e) => setOv({ ...ov, [x.name]: e.target.value })} /></td>
                  <td className={tdCls}><Pill tone={x.override !== undefined ? "accent" : "muted"}>{x.effective}</Pill></td>
                </tr>
              ))}
              {Object.entries(d.data.not_managed).map(([k, why]) => (
                <tr key={k}><td className={tdCls}><Ltr className="font-medium">{k}</Ltr></td><td className={`${tdCls} text-xs text-fg-muted`} colSpan={3}>{t("perf.notManaged")}: <Ltr>{why}</Ltr></td></tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  );
}
