import { CloudCog, Plus, RefreshCw, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { confirmDialog } from "@/components/Confirm";
import { EmptyState, ErrorState, LoadingState } from "@/components/States";
import { Check, Field, FormError, Input, Modal, Select } from "@/components/ui/form";
import { Button, Card, Ltr, PageHeader } from "@/components/ui/primitives";
import { useI18n } from "@/i18n/i18n";
import type { MessageKey } from "@/i18n/messages";
import { gw, web, type CfPlan, type DnsType, type Domain } from "@/lib/api";
import { useAsync } from "@/lib/hooks";
import { useSession } from "@/lib/session";
import { JobProgress } from "../gateway/Deployments";
import { Pill, actionKey, errText, tableCls, tdCls, thCls } from "../gateway/common";

export const dnsTone = { ok: "ok", attention: "warn", unknown: "muted", match: "ok", mismatch: "bad", missing: "bad", propagating: "warn" } as const;

function CloudflarePanel({ domain, writable }: { domain: Domain; writable: boolean }) {
  const { t } = useI18n();
  const [job, setJob] = useState<string | null>(null);
  const [plan, setPlan] = useState<CfPlan | null>(null);
  const [drift, setDrift] = useState<string[]>([]);
  const [adopt, setAdopt] = useState<string[]>([]);
  const [applyJob, setApplyJob] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    if (!job) return;
    let alive = true;
    const tick = async () => {
      const j = await gw.job(job).catch(() => null);
      if (!alive) return;
      if (j && ["Succeeded", "Blocked", "Failed", "RolledBack", "RecoveryRequired", "Cancelled"].includes(j.state)) {
        if (j.state === "Succeeded") {
          const res = j.result as { plan: CfPlan; drift: string[] | null };
          setPlan(res.plan);
          setDrift(res.drift ?? []);
        } else setErr(j.error?.message ?? j.state);
        setJob(null);
        return;
      }
      setTimeout(tick, 800);
    };
    void tick();
    return () => { alive = false; };
  }, [job]);
  const preview = async () => {
    setErr(null);
    setPlan(null);
    try { setJob((await web.domains.cfPreview(domain.id, actionKey())).job_id); } catch (e) { setErr(errText(e)); }
  };
  const apply = async () => {
    if (!plan || !(await confirmDialog(t("dns.cfApplyConfirm", { n: plan.changes.filter((c) => c.action !== "unchanged").length }), { danger: false }))) return;
    setErr(null);
    try { setApplyJob((await web.domains.cfApply(domain.id, plan.hash, adopt, actionKey())).job_id); } catch (e) { setErr(errText(e)); }
  };
  return (
    <section className="flex flex-col gap-3 border-t border-border pt-4">
      <div className="flex items-center justify-between gap-2">
        <h3 className="font-semibold text-fg">Cloudflare</h3>
        <Button variant="outline" size="sm" disabled={!!job} onClick={preview}><CloudCog className="size-4" aria-hidden />{t("dns.cfPreview")}</Button>
      </div>
      <p className="text-xs text-fg-muted">{t("dns.cfNote")}</p>
      {job && <p className="text-sm text-fg-muted">{t("common.loading")}</p>}
      {drift.length > 0 && <ul className="rounded-lg bg-warn-soft p-3 text-xs text-warn">{drift.map((d) => <li key={d} dir="ltr">{d}</li>)}</ul>}
      {plan && (
        <>
          <ul className="flex flex-col gap-1 text-sm">
            {plan.changes.map((c) => (
              <li key={c.desired.name + c.desired.type + c.desired.value} className="flex flex-wrap items-center gap-2">
                <Pill tone={c.action === "unchanged" ? "muted" : c.action === "conflict" ? "warn" : "accent"}>{t(`dns.cf.${c.action}` as MessageKey)}</Pill>
                <Ltr className="text-xs">{c.desired.type} {c.desired.name} → {c.desired.value}</Ltr>
                {c.action === "conflict" && c.current && writable && (
                  <Check checked={adopt.includes(c.current.id)} onChange={(v) => setAdopt(v ? [...adopt, c.current!.id] : adopt.filter((x) => x !== c.current!.id))}
                    label={t("dns.cfAdopt", { value: c.current.content })} />
                )}
              </li>
            ))}
          </ul>
          <p className="text-xs text-fg-muted">{t("dns.cfExternal", { n: plan.external_records_untouched })}</p>
          {writable && !applyJob && plan.changes.some((c) => c.action === "create" || c.action === "update" || adopt.length > 0) && (
            <div><Button variant="primary" size="sm" onClick={apply}>{t("dns.cfApply")}</Button></div>
          )}
        </>
      )}
      {applyJob && <JobProgress id={applyJob} onDone={() => undefined} />}
      <FormError>{err}</FormError>
    </section>
  );
}

function DomainDetail({ id, onClose, onChanged }: { id: string; onClose: () => void; onChanged: () => void }) {
  const { t, formatDateTime } = useI18n();
  const { can } = useSession();
  const d = useAsync(() => web.domains.get(id), [id]);
  const cf = useAsync(web.cloudflare.get);
  const [f, setF] = useState<{ name: string; type: DnsType; value: string; ttl: string }>({ name: "", type: "A", value: "", ttl: "" });
  const [err, setErr] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const writable = can("domains.write");
  const dom = d.data?.domain;
  useEffect(() => {
    if (!checking) return;
    const iv = setTimeout(() => { d.reload(); setChecking(false); onChanged(); }, 12000);
    return () => clearTimeout(iv);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [checking]);
  const add = async () => {
    setErr(null);
    try {
      await web.domains.addExpectation(id, { name: f.name.trim() || "@", type: f.type, value: f.value.trim(), ttl: f.ttl ? Number(f.ttl) : undefined });
      setF({ ...f, value: "" });
      d.reload();
      onChanged();
    } catch (e) { setErr(errText(e)); }
  };
  const obs = (name: string, type: string, src: string) => dom?.observations.find((o) => o.name === name && o.type === type && o.source === src);
  const rows = dom ? Array.from(new Set(dom.observations.map((o) => o.name + "|" + o.type))).map((k) => k.split("|") as [string, string]) : [];
  return (
    <Modal open wide onOpenChange={(o) => !o && onClose()} title={dom?.fqdn ?? t("common.loading")}
      description={dom?.checked_at ? t("dns.checkedAt", { at: formatDateTime(dom.checked_at) }) : t("dns.neverChecked")}
      footer={<><Button variant="ghost" onClick={onClose}>{t("common.close")}</Button>
        <Button variant="outline" disabled={checking} onClick={async () => { await web.domains.check(id); setChecking(true); }}><RefreshCw className={checking ? "size-4 animate-spin" : "size-4"} aria-hidden />{t("dns.checkNow")}</Button></>}>
      {d.status === "error" && !d.data ? <ErrorState error={d.error} onRetry={d.reload} /> : !dom ? <LoadingState /> : (
        <div className="flex flex-col gap-4 text-sm">
          <section>
            <h3 className="mb-2 font-semibold text-fg">{t("dns.expected")}</h3>
            {dom.comparison.length === 0 ? <p className="text-fg-muted">{t("dns.noExpectations")}</p> : (
              <table className={tableCls}>
                <thead><tr className="border-b border-border"><th className={thCls}>{t("dns.record")}</th><th className={thCls}>{t("dns.status")}</th><th className={thCls}><span className="sr-only">{t("common.actions")}</span></th></tr></thead>
                <tbody className="divide-y divide-border">
                  {dom.comparison.map((c, i) => {
                    const e = dom.expectations.find((x) => x.name === c.name && x.type === c.type && x.value === c.value) ?? dom.expectations[i];
                    return (
                      <tr key={c.name + c.type + c.value}>
                        <td className={tdCls}><Ltr className="text-xs">{c.type} {c.name} → {c.value}</Ltr></td>
                        <td className={tdCls}><Pill tone={dnsTone[c.status]}>{t(`dns.st.${c.status}` as MessageKey)}</Pill>{c.detail && <p className="mt-1 text-xs text-fg-muted" dir="auto">{c.detail}</p>}</td>
                        <td className={`${tdCls} text-end`}>{writable && e && <Button variant="ghost" size="icon" aria-label={t("common.delete")} onClick={async () => { await web.domains.removeExpectation(id, e.id); d.reload(); onChanged(); }}><Trash2 className="size-4" aria-hidden /></Button>}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
            {writable && (
              <form className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-[1fr_6rem_1fr_6rem_auto] sm:items-end" onSubmit={(e) => { e.preventDefault(); void add(); }}>
                <Field label={t("dns.name")}>{({ id: fid }) => <Input id={fid} dir="ltr" placeholder={"@ / www." + dom.fqdn} value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} />}</Field>
                <Field label={t("dns.type")}>{({ id: fid }) => <Select id={fid} value={f.type} onChange={(e) => setF({ ...f, type: e.target.value as DnsType })}>{["A", "AAAA", "CNAME", "TXT", "CAA", "NS"].map((x) => <option key={x}>{x}</option>)}</Select>}</Field>
                <Field label={t("dns.value")}>{({ id: fid }) => <Input id={fid} dir="ltr" value={f.value} onChange={(e) => setF({ ...f, value: e.target.value })} />}</Field>
                <Field label="TTL">{({ id: fid }) => <Input id={fid} dir="ltr" type="number" min={1} value={f.ttl} onChange={(e) => setF({ ...f, ttl: e.target.value })} />}</Field>
                <Button type="submit" variant="outline" disabled={!f.value}><Plus className="size-4" aria-hidden />{t("common.create")}</Button>
              </form>
            )}
            <FormError>{err}</FormError>
          </section>
          <section>
            <h3 className="mb-2 font-semibold text-fg">{t("dns.evidence")}</h3>
            {rows.length === 0 ? <p className="text-fg-muted">{t("dns.neverChecked")}</p> : (
              <div className="relative overflow-x-auto">
                <table className={tableCls}>
                  <thead><tr className="border-b border-border"><th className={thCls}>{t("dns.record")}</th><th className={thCls}>{t("dns.authoritative")}</th><th className={thCls}>{t("dns.resolver")}</th></tr></thead>
                  <tbody className="divide-y divide-border">
                    {rows.map(([n, ty]) => {
                      const a = obs(n, ty, "authoritative"), r = obs(n, ty, "resolver");
                      const cell = (o?: typeof a) => !o ? "—" : o.error ? <span className="text-bad" dir="ltr">{o.error}</span> : (
                        <span dir="ltr" className="text-xs">{o.values.length ? o.values.join(", ") : t("dns.none")}{o.ttl != null && <span className="text-fg-muted"> · TTL {o.ttl}</span>}<span className="block text-fg-muted">{o.server}</span></span>);
                      return <tr key={n + ty}><td className={tdCls}><Ltr className="text-xs">{ty} {n}</Ltr></td><td className={tdCls}>{cell(a)}</td><td className={tdCls}>{cell(r)}</td></tr>;
                    })}
                  </tbody>
                </table>
              </div>
            )}
            <p className="mt-2 text-xs text-fg-muted">{t("dns.ttlNote")}</p>
          </section>
          <section>
            <h3 className="mb-2 font-semibold text-fg">{t("dns.usage")}</h3>
            {d.data!.usage.length === 0 ? <p className="text-fg-muted">{t("dns.unused")}</p> : (
              <ul className="flex flex-wrap gap-1">{d.data!.usage.map((u) => <li key={u.kind + u.name + u.what}><Pill tone="accent">{t(`dns.use.${u.kind}` as MessageKey)}: {u.name}</Pill></li>)}</ul>
            )}
          </section>
          {cf.data?.configured && <CloudflarePanel domain={dom} writable={writable} />}
        </div>
      )}
    </Modal>
  );
}

export function DomainsPage() {
  const { t, formatDateTime } = useI18n();
  const { can } = useSession();
  const list = useAsync(web.domains.list);
  const [adding, setAdding] = useState(false);
  const [sel, setSel] = useState<string | null>(null);
  const [f, setF] = useState({ fqdn: "", purpose: "general", notes: "" });
  const [err, setErr] = useState<string | null>(null);
  const writable = can("domains.write");
  const create = async () => {
    setErr(null);
    try {
      const d = await web.domains.create(f);
      setAdding(false);
      setF({ fqdn: "", purpose: "general", notes: "" });
      list.reload();
      setSel(d.id);
    } catch (e) { setErr(errText(e)); }
  };
  const remove = async (d: Domain) => {
    if (!(await confirmDialog(t("common.confirmDelete", { name: d.fqdn })))) return;
    try { await web.domains.remove(d); list.reload(); } catch (e) { setErr(errText(e)); }
  };
  return (
    <>
      <PageHeader title={t("dom.title")} subtitle={t("dom.subtitle")}
        actions={writable && <Button variant="primary" onClick={() => setAdding(true)}><Plus className="size-4" aria-hidden />{t("dom.add")}</Button>} />
      <FormError>{err && !adding ? err : null}</FormError>
      <Card>
        {list.status === "error" && !list.data ? <ErrorState error={list.error} onRetry={list.reload} /> : !list.data ? <LoadingState /> : list.data.items.length === 0 ? <EmptyState title={t("dom.empty")} body={t("dom.emptyBody")} /> : (
          <div className="relative overflow-x-auto">
            <table className={tableCls}>
              <thead><tr className="border-b border-border"><th className={thCls}>{t("dom.fqdn")}</th><th className={thCls}>{t("dom.purpose")}</th><th className={thCls}>DNS</th><th className={thCls}>{t("dns.lastCheck")}</th><th className={thCls}><span className="sr-only">{t("common.actions")}</span></th></tr></thead>
              <tbody className="divide-y divide-border">
                {list.data.items.map((d) => (
                  <tr key={d.id}>
                    <td className={tdCls}><button type="button" className="font-medium text-accent hover:underline" onClick={() => setSel(d.id)}><Ltr>{d.fqdn}</Ltr></button>{d.dns_provider === "cloudflare" && <span className="ms-2"><Pill>Cloudflare</Pill></span>}</td>
                    <td className={tdCls}>{t(`dom.purpose.${d.purpose}` as MessageKey)}</td>
                    <td className={tdCls}><Pill tone={dnsTone[d.dns_status]}>{t(`dns.st.${d.dns_status}` as MessageKey)}</Pill></td>
                    <td className={`${tdCls} text-xs text-fg-muted`}>{d.checked_at ? formatDateTime(d.checked_at) : t("dns.neverChecked")}</td>
                    <td className={`${tdCls} text-end`}>{writable && <Button variant="ghost" size="icon" aria-label={`${t("common.delete")} ${d.fqdn}`} onClick={() => void remove(d)}><Trash2 className="size-4" aria-hidden /></Button>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      {adding && (
        <Modal open onOpenChange={(o) => !o && setAdding(false)} title={t("dom.add")}
          footer={<><Button variant="ghost" onClick={() => setAdding(false)}>{t("common.cancel")}</Button><Button variant="primary" disabled={!f.fqdn} onClick={create}>{t("common.save")}</Button></>}>
          <form className="flex flex-col gap-4" onSubmit={(e) => { e.preventDefault(); void create(); }}>
            <Field label={t("dom.fqdn")}>{({ id }) => <Input id={id} dir="ltr" placeholder="example.com" value={f.fqdn} onChange={(e) => setF({ ...f, fqdn: e.target.value })} />}</Field>
            <Field label={t("dom.purpose")}>{({ id }) => <Select id={id} value={f.purpose} onChange={(e) => setF({ ...f, purpose: e.target.value })}>{["general", "website", "route", "management"].map((p) => <option key={p} value={p}>{t(`dom.purpose.${p}` as MessageKey)}</option>)}</Select>}</Field>
            <FormError>{err}</FormError>
          </form>
        </Modal>
      )}
      {sel && <DomainDetail id={sel} onClose={() => setSel(null)} onChanged={list.reload} />}
    </>
  );
}
