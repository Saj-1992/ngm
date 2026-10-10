import { CloudCog, Globe, RefreshCw, Search, Wand2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { EmptyState, ErrorState, LoadingState } from "@/components/States";
import { Check, Field, FormError, Input, Select } from "@/components/ui/form";
import { Button, Card, CardHeader, Ltr, PageHeader } from "@/components/ui/primitives";
import { useI18n } from "@/i18n/i18n";
import { gw, web, type CfRecord, type CfZone, type Domain } from "@/lib/api";
import { useAsync } from "@/lib/hooks";
import { useSession } from "@/lib/session";
import { Pill, actionKey, errText, tableCls, tdCls, thCls } from "../gateway/common";

type DiscoverResult = { zones: CfZone[]; records?: CfRecord[]; zone_id?: string };
const TERMINAL = ["Succeeded", "Blocked", "Failed", "RolledBack", "RecoveryRequired", "Cancelled"];

/** Runs the read-only discovery job and returns its result (the API never calls Cloudflare itself). */
function useDiscover() {
  const [res, setRes] = useState<DiscoverResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async (zoneId?: string) => {
    setBusy(true);
    setErr(null);
    try {
      const { job_id } = await web.cloudflare.discover(zoneId, actionKey());
      for (let i = 0; i < 90; i++) {
        const j = await gw.job(job_id);
        if (TERMINAL.includes(j.state)) {
          if (j.state === "Succeeded") setRes(j.result as DiscoverResult);
          else setErr(j.error?.message ?? j.state);
          break;
        }
        await new Promise((r) => setTimeout(r, 800));
      }
    } catch (e) {
      setErr(errText(e));
    } finally {
      setBusy(false);
    }
  };
  return { res, err, busy, run };
}

export function CloudflareZonesPage() {
  const { t } = useI18n();
  const { can } = useSession();
  const cf = useAsync(web.cloudflare.get);
  const domains = useAsync(web.domains.list);
  const disc = useDiscover();
  const [zone, setZone] = useState<CfZone | null>(null);
  const [q, setQ] = useState("");
  const writable = can("domains.write");

  useEffect(() => { if (cf.data?.configured) void disc.run(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [cf.data?.configured]);

  const zones = useMemo(() => (disc.res?.zones ?? []).filter((z) => !q || z.name.includes(q.toLowerCase())), [disc.res, q]);
  const registered = (name: string) => (domains.data?.items ?? []).find((d) => d.fqdn === name);

  return (
    <>
      <PageHeader title={t("cfz.title")} subtitle={t("cfz.subtitle")}
        actions={cf.data?.configured && <Button variant="outline" disabled={disc.busy} onClick={() => void disc.run(zone?.id)}><RefreshCw className="size-4" aria-hidden />{t("cfz.refresh")}</Button>} />
      {cf.status === "error" && !cf.data ? <ErrorState error={cf.error} onRetry={cf.reload} /> : !cf.data ? <LoadingState /> : !cf.data.configured ? (
        <Card><EmptyState title={t("cfz.notConfigured")} body={t("cfz.notConfiguredBody")} /><p className="px-5 pb-5 text-sm"><Link className="text-accent underline underline-offset-2" to="/web/domains">{t("cfz.goDomains")}</Link></p></Card>
      ) : (
        <div className="grid gap-4 lg:grid-cols-[20rem_1fr]">
          <Card>
            <CardHeader title={t("cfz.zones")} />
            <div className="px-5 pb-3">
              <div className="relative">
                <Search className="pointer-events-none absolute start-3 top-2.5 size-4 text-fg-muted" aria-hidden />
                <Input aria-label={t("cfz.search")} placeholder={t("cfz.search")} className="ps-9" dir="ltr" value={q} onChange={(e) => setQ(e.target.value)} />
              </div>
            </div>
            {disc.err ? <p className="px-5 pb-4 text-sm text-bad" role="alert" dir="auto">{disc.err}</p> : !disc.res ? <LoadingState /> : zones.length === 0 ? <EmptyState title={t("cfz.noZones")} /> : (
              <ul className="max-h-[60vh] divide-y divide-border overflow-y-auto">
                {zones.map((z) => (
                  <li key={z.id}>
                    <button type="button" onClick={() => { setZone(z); void disc.run(z.id); }} aria-pressed={zone?.id === z.id}
                      className={`flex w-full items-center gap-2 px-5 py-3 text-start text-sm hover:bg-surface-2 ${zone?.id === z.id ? "bg-accent-soft text-accent" : ""}`}>
                      <Globe className="size-4 shrink-0" aria-hidden /><Ltr className="min-w-0 flex-1 truncate">{z.name}</Ltr>
                      {registered(z.name) && <Pill tone="ok">{t("cfz.registered")}</Pill>}
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </Card>
          {zone ? <ZoneDetail zone={zone} records={disc.res?.zone_id === zone.id ? disc.res.records ?? [] : null} parent={registered(zone.name)} writable={writable} onChanged={() => { domains.reload(); void disc.run(zone.id); }} /> : (
            <Card><EmptyState title={t("cfz.pick")} body={t("cfz.pickBody")} /></Card>
          )}
        </div>
      )}
    </>
  );
}

function ZoneDetail({ zone, records, parent, writable, onChanged }: { zone: CfZone; records: CfRecord[] | null; parent?: Domain; writable: boolean; onChanged: () => void }) {
  const { t } = useI18n();
  const [filter, setFilter] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [made, setMade] = useState<Domain | null>(null);
  const [f, setF] = useState({ mode: "auto" as "auto" | "manual", label: "", type: "A" as "A" | "AAAA" | "CNAME", value: "", ttl: 1, proxied: false });
  const shown = (records ?? []).filter((r) => !filter || r.name.includes(filter.toLowerCase()) || r.content.includes(filter));
  const names = (records ?? []).map((r) => r.name);

  const registerParent = async () => {
    setBusy(true);
    setErr(null);
    try { await web.domains.create({ fqdn: zone.name, purpose: "general", notes: "" }); onChanged(); } catch (e) { setErr(errText(e)); } finally { setBusy(false); }
  };
  const create = async () => {
    if (!parent) return;
    setBusy(true);
    setErr(null);
    setMade(null);
    try {
      const d = await web.domains.createSubdomain(parent.id, { label: f.mode === "auto" ? "auto" : f.label.trim().toLowerCase(), type: f.type, value: f.value.trim(), ttl: f.ttl, proxied: f.proxied, existing_names: names });
      setMade(d);
      onChanged();
    } catch (e) { setErr(errText(e)); } finally { setBusy(false); }
  };

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader title={<Ltr>{zone.name}</Ltr>} action={<Pill tone={parent ? "ok" : "warn"}>{t(parent ? "cfz.registered" : "cfz.notRegistered")}</Pill>} />
        {!parent ? (
          <div className="flex flex-col gap-3 px-5 pb-5 text-sm">
            <p className="text-fg-muted">{t("cfz.registerFirst")}</p>
            {writable && <div><Button variant="primary" disabled={busy} onClick={registerParent}>{t("cfz.register")}</Button></div>}
            <FormError>{err}</FormError>
          </div>
        ) : (
          <form className="flex flex-col gap-4 px-5 pb-5" onSubmit={(e) => { e.preventDefault(); void create(); }}>
            <h3 className="font-semibold text-fg">{t("cfz.newSub")}</h3>
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label={t("cfz.naming")}>{({ id }) => (
                <Select id={id} value={f.mode} onChange={(e) => setF({ ...f, mode: e.target.value as "auto" | "manual" })}>
                  <option value="auto">{t("cfz.auto")}</option><option value="manual">{t("cfz.manual")}</option>
                </Select>
              )}</Field>
              {f.mode === "manual" && (
                <Field label={t("cfz.label")} hint={t("cfz.labelHint")}>{({ id, describedBy }) => (
                  <div className="flex items-center gap-2" dir="ltr">
                    <Input id={id} aria-describedby={describedBy} value={f.label} placeholder="app" onChange={(e) => setF({ ...f, label: e.target.value })} />
                    <span className="shrink-0 text-sm text-fg-muted">.{zone.name}</span>
                  </div>
                )}</Field>
              )}
              <Field label={t("cfz.type")}>{({ id }) => (
                <Select id={id} value={f.type} onChange={(e) => setF({ ...f, type: e.target.value as "A" | "AAAA" | "CNAME" })}>
                  <option value="A">A (IPv4)</option><option value="AAAA">AAAA (IPv6)</option><option value="CNAME">CNAME</option>
                </Select>
              )}</Field>
              <Field label={t(f.type === "CNAME" ? "cfz.target" : "cfz.ip")}>{({ id }) => <Input id={id} dir="ltr" value={f.value} onChange={(e) => setF({ ...f, value: e.target.value })} />}</Field>
              <Field label="TTL" hint={t("cfz.ttlHint")}>{({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} dir="ltr" type="number" min={1} max={86400} value={f.ttl} onChange={(e) => setF({ ...f, ttl: Number(e.target.value) })} />}</Field>
            </div>
            <Check checked={f.proxied} onChange={(v) => setF({ ...f, proxied: v })} label={t("cfz.proxied")} hint={t("cfz.proxiedHint")} />
            <FormError>{err}</FormError>
            {made && (
              <p className="rounded-lg bg-ok-soft px-3 py-2 text-sm text-ok" role="status">
                {t("cfz.created", { name: made.fqdn })} <Link className="text-accent underline underline-offset-2" to="/web/domains">{t("cfz.publishNext")}</Link>
              </p>
            )}
            {writable && <div><Button type="submit" variant="primary" disabled={busy || !f.value || (f.mode === "manual" && !f.label)}><Wand2 className="size-4" aria-hidden />{t("cfz.create")}</Button></div>}
            <p className="text-xs text-fg-muted">{t("cfz.noOverwrite")}</p>
          </form>
        )}
      </Card>
      <Card>
        <CardHeader title={t("cfz.records")} action={<Input aria-label={t("cfz.filter")} placeholder={t("cfz.filter")} className="h-8 w-48" dir="ltr" value={filter} onChange={(e) => setFilter(e.target.value)} />} />
        {records === null ? <LoadingState /> : shown.length === 0 ? <EmptyState title={t("cfz.noRecords")} /> : (
          <div className="relative max-h-[50vh] overflow-auto">
            <table className={tableCls}>
              <thead><tr className="border-b border-border"><th className={thCls}>{t("cfz.name")}</th><th className={thCls}>{t("cfz.type")}</th><th className={thCls}>{t("cfz.content")}</th><th className={thCls}>TTL</th><th className={thCls}>{t("cfz.proxy")}</th></tr></thead>
              <tbody className="divide-y divide-border">
                {shown.map((r) => (
                  <tr key={r.id}>
                    <td className={tdCls}><Ltr>{r.name}</Ltr>{(r.comment ?? "").includes("managed-by:ngm") && <span className="ms-2"><Pill tone="accent">NGM</Pill></span>}</td>
                    <td className={tdCls}><Ltr>{r.type}</Ltr></td>
                    <td className={`${tdCls} max-w-[18rem] truncate`}><Ltr>{r.content}</Ltr></td>
                    <td className={`${tdCls} tabular-nums`}>{r.ttl === 1 ? t("cfz.auto") : r.ttl}</td>
                    <td className={tdCls}>{r.proxied === undefined ? "—" : <Pill tone={r.proxied ? "warn" : "muted"}>{t(r.proxied ? "cfz.proxyOn" : "cfz.proxyOff")}</Pill>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <p className="flex items-center gap-2 text-xs text-fg-muted"><CloudCog className="size-4" aria-hidden />{t("cfz.footer")}</p>
    </div>
  );
}
