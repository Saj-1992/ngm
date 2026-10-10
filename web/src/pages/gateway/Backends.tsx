import { confirmDialog } from "@/components/Confirm";
import { Plus, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { EmptyState, ErrorState, LoadingState } from "@/components/States";
import { Check, Field, FormError, Input, Modal, Select, Tabs } from "@/components/ui/form";
import { Button, Card, Ltr, PageHeader } from "@/components/ui/primitives";
import { useI18n } from "@/i18n/i18n";
import type { MessageKey } from "@/i18n/messages";
import { gw, ops, type Endpoint, type EndpointHealth, type Pool, type PoolMember, type Transport } from "@/lib/api";
import { useAsync } from "@/lib/hooks";
import { useSession } from "@/lib/session";
import { DesiredNote, Pill, RowMenu, errText, tableCls, tdCls, thCls } from "./common";

function EndpointForm({ initial, onClose, onDone }: { initial?: Endpoint; onClose: () => void; onDone: () => void }) {
  const { t } = useI18n();
  const [f, setF] = useState({
    name: initial?.name ?? "", host: initial?.host ?? "", port: initial?.port ?? 8080, transport: initial?.transport ?? ("http" as Transport),
    tls_verify: initial?.tls_verify ?? true, tls_server_name: initial?.tls_server_name ?? "", weight: initial?.weight ?? 1, priority: initial?.priority ?? 0,
    connect_timeout_ms: initial?.connect_timeout_ms ?? 5000, read_timeout_ms: initial?.read_timeout_ms ?? 60000, write_timeout_ms: initial?.write_timeout_ms ?? 60000,
    disabled: initial?.disabled ?? false,
  });
  const [err, setErr] = useState<string | null>(null);
  const save = async () => {
    setErr(null);
    try {
      const body = { ...f, host: f.host.trim(), port: Number(f.port), weight: Number(f.weight) };
      if (initial) await gw.endpoints.update(initial, body);
      else await gw.endpoints.create(body);
      onDone();
      onClose();
    } catch (e) {
      setErr(errText(e));
    }
  };
  return (
    <Modal open onOpenChange={(o) => !o && onClose()} title={initial ? initial.name : t("gw.endpoint.new")}
      footer={<><Button variant="ghost" onClick={onClose}>{t("common.cancel")}</Button><Button variant="primary" disabled={!f.name || !f.host} onClick={save}>{t("common.save")}</Button></>}>
      <form className="flex flex-col gap-4" onSubmit={(e) => { e.preventDefault(); void save(); }}>
        <Field label={t("common.name")}>{({ id }) => <Input id={id} value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} />}</Field>
        <div className="grid grid-cols-[1fr_7rem] gap-3">
          <Field label={t("gw.host")}>{({ id }) => <Input id={id} dir="ltr" placeholder="10.0.0.5 / app.internal" value={f.host} onChange={(e) => setF({ ...f, host: e.target.value })} />}</Field>
          <Field label={t("gw.port")}>{({ id }) => <Input id={id} dir="ltr" type="number" value={f.port} onChange={(e) => setF({ ...f, port: Number(e.target.value) })} />}</Field>
        </div>
        <Field label={t("gw.transport")}>
          {({ id }) => (
            <Select id={id} value={f.transport} onChange={(e) => setF({ ...f, transport: e.target.value as Transport })}>
              <option value="http">HTTP</option><option value="https">HTTPS</option><option value="tcp">TCP</option>
            </Select>
          )}
        </Field>
        {f.transport === "https" && (
          <>
            <Check checked={f.tls_verify} onChange={(v) => setF({ ...f, tls_verify: v })} label={t("gw.tlsVerify")} />
            <Field label={t("gw.tlsServerName")}>{({ id }) => <Input id={id} dir="ltr" value={f.tls_server_name} onChange={(e) => setF({ ...f, tls_server_name: e.target.value })} />}</Field>
          </>
        )}
        <div className="grid grid-cols-2 gap-3">
          <Field label={t("gw.connectTimeout")}>{({ id }) => <Input id={id} dir="ltr" type="number" value={f.connect_timeout_ms} onChange={(e) => setF({ ...f, connect_timeout_ms: Number(e.target.value) })} />}</Field>
          <Field label={t("gw.readTimeout")}>{({ id }) => <Input id={id} dir="ltr" type="number" value={f.read_timeout_ms} onChange={(e) => setF({ ...f, read_timeout_ms: Number(e.target.value), write_timeout_ms: Number(e.target.value) })} />}</Field>
        </div>
        <Check checked={f.disabled} onChange={(v) => setF({ ...f, disabled: v })} label={t("common.disabled")} />
        <FormError>{err}</FormError>
      </form>
    </Modal>
  );
}

function PoolForm({ initial, endpoints, onClose, onDone }: { initial?: Pool; endpoints: Endpoint[]; onClose: () => void; onDone: () => void }) {
  const { t } = useI18n();
  const [name, setName] = useState(initial?.name ?? "");
  const [strategy, setStrategy] = useState<Pool["strategy"]>(initial?.strategy ?? "round_robin");
  const [members, setMembers] = useState<PoolMember[]>(initial?.members ?? []);
  const [err, setErr] = useState<string | null>(null);
  const free = endpoints.filter((e) => !members.some((m) => m.endpoint_id === e.id));
  const save = async () => {
    setErr(null);
    try {
      if (initial) await gw.pools.update(initial, { name, strategy, members });
      else await gw.pools.create({ name, strategy, members });
      onDone();
      onClose();
    } catch (e) {
      setErr(errText(e));
    }
  };
  return (
    <Modal open wide onOpenChange={(o) => !o && onClose()} title={initial ? initial.name : t("gw.pool.new")}
      footer={<><Button variant="ghost" onClick={onClose}>{t("common.cancel")}</Button><Button variant="primary" disabled={!name || !members.length} onClick={save}>{t("common.save")}</Button></>}>
      <div className="flex flex-col gap-4">
        <Field label={t("common.name")}>{({ id }) => <Input id={id} value={name} onChange={(e) => setName(e.target.value)} />}</Field>
        <Field label={t("gw.strategy")} hint={strategy === "failover" ? t("gw.failoverNote") : undefined}>
          {({ id, describedBy }) => (
            <Select id={id} aria-describedby={describedBy} value={strategy} onChange={(e) => setStrategy(e.target.value as Pool["strategy"])}>
              {(["round_robin", "least_conn", "hash", "failover"] as const).map((s) => <option key={s} value={s}>{t(`gw.strategy.${s}` as MessageKey)}</option>)}
            </Select>
          )}
        </Field>
        <fieldset className="flex flex-col gap-2">
          <legend className="mb-1 text-sm font-medium text-fg">{t("gw.members")}</legend>
          {members.map((m, i) => {
            const e = endpoints.find((x) => x.id === m.endpoint_id);
            return (
              <div key={m.endpoint_id} className="flex flex-wrap items-center gap-3 rounded-lg border border-border px-3 py-2 text-sm">
                <span className="min-w-28 font-medium">{e?.name}</span>
                <Ltr className="text-fg-muted">{e?.host}:{e?.port}</Ltr>
                <label className="ms-auto flex items-center gap-1 text-xs">{t("gw.weight")}
                  <Input dir="ltr" type="number" min={1} max={1000} className="h-8 w-20" value={m.weight} onChange={(ev) => setMembers(members.map((x, j) => (j === i ? { ...x, weight: Number(ev.target.value) } : x)))} />
                </label>
                <Check checked={m.backup} onChange={(v) => setMembers(members.map((x, j) => (j === i ? { ...x, backup: v } : x)))} label={t("gw.backup")} />
                <Button variant="ghost" size="icon" aria-label={t("common.delete")} onClick={() => setMembers(members.filter((_, j) => j !== i))}><Trash2 className="size-4" aria-hidden /></Button>
              </div>
            );
          })}
          {free.length > 0 && (
            <Select aria-label={t("gw.members")} value="" onChange={(e) => e.target.value && setMembers([...members, { endpoint_id: e.target.value, weight: 1, backup: false }])}>
              <option value="">+ {t("gw.endpoint.new").replace(/^\S+\s/, "")}</option>
              {free.map((e) => <option key={e.id} value={e.id}>{e.name} — {e.host}:{e.port} ({e.transport})</option>)}
            </Select>
          )}
        </fieldset>
        <FormError>{err}</FormError>
      </div>
    </Modal>
  );
}

const healthTone = { healthy: "ok", down: "bad", degraded: "warn", unknown: "muted", disabled: "muted" } as const;

function HealthCell({ h }: { h?: EndpointHealth }) {
  const { t, formatDateTime } = useI18n();
  if (!h) return <Pill>{t("gw.health.unknown")}</Pill>;
  const title = [h.detail, h.observed_at && !h.observed_at.startsWith("0001") ? formatDateTime(h.observed_at) : "", h.stale ? t("gw.health.stale") : ""].filter(Boolean).join(" · ");
  return (
    <span className="inline-flex items-center gap-2" title={title}>
      <Pill tone={healthTone[h.status] ?? "muted"}>{t(`gw.health.${h.status}` as MessageKey)}</Pill>
      {h.status === "healthy" && <Ltr className="text-xs text-fg-muted">{h.latency_ms} ms</Ltr>}
      {h.status === "down" && h.detail && <span className="max-w-48 truncate text-xs text-fg-muted" dir="ltr">{h.detail}</span>}
    </span>
  );
}

export function BackendsPage() {
  const { t } = useI18n();
  const { can } = useSession();
  const [tab, setTab] = useState<"endpoints" | "pools">("endpoints");
  const eps = useAsync(gw.endpoints.list);
  const pools = useAsync(gw.pools.list);
  const health = useAsync(ops.backendHealth);
  useEffect(() => {
    const iv = setInterval(health.reload, 15000);
    return () => clearInterval(iv);
  }, [health.reload]);
  const hOf = (id: string) => health.data?.items.find((x) => x.endpoint_id === id);
  const [editE, setEditE] = useState<Endpoint | "new" | null>(null);
  const [editP, setEditP] = useState<Pool | "new" | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const writable = can("gateway.write");
  const del = async (fn: () => Promise<void>, name: string, reload: () => void) => {
    if (!(await confirmDialog(t("common.confirmDelete", { name })))) return;
    setErr(null);
    try { await fn(); reload(); } catch (e) { setErr(errText(e)); }
  };
  return (
    <>
      <PageHeader
        title={t("gw.backends.title")}
        subtitle={t("gw.backends.subtitle")}
        actions={writable && (tab === "endpoints"
          ? <Button variant="primary" onClick={() => setEditE("new")}><Plus className="size-4" aria-hidden />{t("gw.endpoint.new")}</Button>
          : <Button variant="primary" onClick={() => setEditP("new")} disabled={!eps.data?.items.length}><Plus className="size-4" aria-hidden />{t("gw.pool.new")}</Button>)}
      />
      <DesiredNote />
      <div className="mb-4"><Tabs value={tab} onChange={setTab} items={[{ value: "endpoints", label: t("gw.endpoints") }, { value: "pools", label: t("gw.pools") }]} /></div>
      <FormError>{err}</FormError>
      <Card>
        {tab === "endpoints" ? (
          eps.status === "error" && !eps.data ? <ErrorState error={eps.error} onRetry={eps.reload} /> : !eps.data ? <LoadingState /> : eps.data.items.length === 0 ? <EmptyState title={t("gw.endpoint.new")} /> : (
            <div className="relative overflow-x-auto">
              <table className={tableCls}>
                <thead><tr className="border-b border-border"><th className={thCls}>{t("common.name")}</th><th className={thCls}>{t("gw.target")}</th><th className={thCls}>{t("gw.transport")}</th><th className={thCls}>{t("gw.health")}</th><th className={thCls}><span className="sr-only">{t("common.actions")}</span></th></tr></thead>
                <tbody className="divide-y divide-border">
                  {eps.data.items.map((e) => (
                    <tr key={e.id}>
                      <td className={tdCls}><span className="font-medium">{e.name}</span>{e.disabled && <span className="ms-2"><Pill>{t("common.disabled")}</Pill></span>}</td>
                      <td className={tdCls}><Ltr>{e.host}:{e.port}</Ltr></td>
                      <td className={tdCls}><Pill tone="accent">{e.transport}</Pill>{e.transport === "https" && !e.tls_verify && <span className="ms-1"><Pill tone="warn">no-verify</Pill></span>}</td>
                      <td className={tdCls}><HealthCell h={hOf(e.id)} /></td>
                      <td className={`${tdCls} text-end`}>{writable && <RowMenu label={`${t("common.edit")} ${e.name}`} items={[
                        { label: t("common.edit"), onSelect: () => setEditE(e) },
                        { label: t("common.delete"), danger: true, onSelect: () => del(() => gw.endpoints.remove(e), e.name, eps.reload) },
                      ]} />}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
        ) : pools.status === "error" && !pools.data ? <ErrorState error={pools.error} onRetry={pools.reload} /> : !pools.data ? <LoadingState /> : pools.data.items.length === 0 ? <EmptyState title={t("gw.pool.new")} /> : (
          <div className="relative overflow-x-auto">
            <table className={tableCls}>
              <thead><tr className="border-b border-border"><th className={thCls}>{t("common.name")}</th><th className={thCls}>{t("gw.strategy")}</th><th className={thCls}>{t("gw.members")}</th><th className={thCls}><span className="sr-only">{t("common.actions")}</span></th></tr></thead>
              <tbody className="divide-y divide-border">
                {pools.data.items.map((p) => (
                  <tr key={p.id}>
                    <td className={tdCls}><span className="font-medium">{p.name}</span></td>
                    <td className={tdCls}>{t(`gw.strategy.${p.strategy}` as MessageKey)}</td>
                    <td className={tdCls}>
                      <div className="flex flex-wrap gap-1">
                        {p.members.map((m) => {
                          const e = eps.data?.items.find((x) => x.id === m.endpoint_id);
                          return <Pill key={m.endpoint_id} tone={m.backup ? "warn" : "muted"}>{e?.name ?? "?"} ×{m.weight}{m.backup ? ` · ${t("gw.backup")}` : ""}</Pill>;
                        })}
                      </div>
                    </td>
                    <td className={`${tdCls} text-end`}>{writable && <RowMenu label={`${t("common.edit")} ${p.name}`} items={[
                      { label: t("common.edit"), onSelect: () => setEditP(p) },
                      { label: t("common.delete"), danger: true, onSelect: () => del(() => gw.pools.remove(p), p.name, pools.reload) },
                    ]} />}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      {editE && <EndpointForm initial={editE === "new" ? undefined : editE} onClose={() => setEditE(null)} onDone={eps.reload} />}
      {editP && eps.data && <PoolForm initial={editP === "new" ? undefined : editP} endpoints={eps.data.items} onClose={() => setEditP(null)} onDone={pools.reload} />}
    </>
  );
}
