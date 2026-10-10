import { FlaskConical } from "lucide-react";
import { useState } from "react";
import { Check, Field, FormError, Input, Select } from "@/components/ui/form";
import { Button, Card, CardHeader, Ltr, PageHeader, cn } from "@/components/ui/primitives";
import { useI18n } from "@/i18n/i18n";
import type { MessageKey } from "@/i18n/messages";
import { gw, type SimResult } from "@/lib/api";
import { useAsync } from "@/lib/hooks";
import { bind, errText } from "./common";

const tone: Record<string, string> = {
  proxy_http: "bg-ok-soft text-ok", proxy_tcp: "bg-ok-soft text-ok", passthrough: "bg-ok-soft text-ok", redirect: "bg-accent-soft text-accent",
  reject: "bg-warn-soft text-warn", closed: "bg-warn-soft text-warn", misdirected: "bg-warn-soft text-warn", no_listener: "bg-bad-soft text-bad",
};

export function SimulationPage() {
  const { t } = useI18n();
  const listeners = useAsync(gw.listeners.list);
  const [f, setF] = useState({ model: "desired" as "desired" | "active", listener_id: "", sni: "", alpn: "", host: "", path: "/", ech: false });
  const [res, setRes] = useState<SimResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const l = listeners.data?.items.find((x) => x.id === (f.listener_id || listeners.data?.items[0]?.id));
  const tls = l?.kind === "https" || l?.kind === "stream_tls_front";
  const run = async () => {
    setErr(null);
    try {
      const r = await gw.simulate({
        model: f.model, listener_id: l?.id, sni: tls ? f.sni : undefined, alpn: f.alpn ? f.alpn.split(",").map((s) => s.trim()).filter(Boolean) : undefined,
        host: f.host || undefined, path: f.path || undefined, ech: f.ech,
      });
      setRes(r.result);
    } catch (e) {
      setErr(errText(e));
    }
  };
  return (
    <>
      <PageHeader title={t("sim.title")} subtitle={t("sim.subtitle")} />
      <div className="grid gap-5 lg:grid-cols-[22rem_1fr]">
        <Card className="h-fit p-5">
          <form className="flex flex-col gap-4" onSubmit={(e) => { e.preventDefault(); void run(); }}>
            <Field label={t("sim.model")}>{({ id }) => (
              <Select id={id} value={f.model} onChange={(e) => setF({ ...f, model: e.target.value as "desired" | "active" })}>
                <option value="desired">{t("sim.model.desired")}</option><option value="active">{t("sim.model.active")}</option>
              </Select>
            )}</Field>
            <Field label={t("builder.step.listener")}>{({ id }) => (
              <Select id={id} value={l?.id ?? ""} onChange={(e) => setF({ ...f, listener_id: e.target.value })}>
                {listeners.data?.items.map((x) => <option key={x.id} value={x.id}>{x.name} — {bind(x)} ({x.kind})</option>)}
              </Select>
            )}</Field>
            {tls && <Field label={t("sim.sni")}>{({ id }) => <Input id={id} dir="ltr" value={f.sni} onChange={(e) => setF({ ...f, sni: e.target.value })} />}</Field>}
            {l?.kind === "stream_tls_front" && <Field label={t("sim.alpn")}>{({ id }) => <Input id={id} dir="ltr" placeholder="h2, http/1.1" value={f.alpn} onChange={(e) => setF({ ...f, alpn: e.target.value })} />}</Field>}
            {l?.kind !== "stream" && (
              <>
                <Field label={t("sim.host")}>{({ id }) => <Input id={id} dir="ltr" value={f.host} onChange={(e) => setF({ ...f, host: e.target.value })} />}</Field>
                <Field label={t("sim.path")}>{({ id }) => <Input id={id} dir="ltr" value={f.path} onChange={(e) => setF({ ...f, path: e.target.value })} />}</Field>
              </>
            )}
            {tls && <Check checked={f.ech} onChange={(v) => setF({ ...f, ech: v })} label={t("sim.ech")} />}
            <FormError>{err}</FormError>
            <Button variant="primary" type="submit" disabled={!l}><FlaskConical className="size-4" aria-hidden />{t("sim.run")}</Button>
          </form>
        </Card>
        <div className="flex flex-col gap-5">
          {res && (
            <>
              <Card className="p-5">
                <div className="flex flex-wrap items-center gap-3">
                  <span className="text-sm text-fg-muted">{t("sim.outcome")}</span>
                  <span className={cn("rounded-full px-3 py-1 text-sm font-medium", tone[res.outcome] ?? "bg-surface-2")}>{t(`sim.outcome.${res.outcome}` as MessageKey)}</span>
                  {res.route_name && <span className="text-sm">→ <b>{res.route_name}</b></span>}
                  {res.destination && <Ltr className="text-sm text-fg-muted">{res.destination}</Ltr>}
                </div>
              </Card>
              <Card>
                <CardHeader title={t("sim.trace")} />
                <ol className="divide-y divide-border">
                  {res.trace.map((s, i) => (
                    <li key={i} className="flex gap-3 px-5 py-3 text-sm">
                      <span className="flex size-6 shrink-0 items-center justify-center rounded-full bg-surface-2 text-xs tabular-nums">{i + 1}</span>
                      <div className="min-w-0">
                        <div><Ltr className="text-xs text-fg-muted">{s.stage}</Ltr> <b dir="auto">{s.decision}</b></div>
                        <div className="text-fg-muted" dir="auto">{s.reason}</div>
                      </div>
                    </li>
                  ))}
                </ol>
              </Card>
              <Card className="p-5">
                <h2 className="mb-2 text-sm font-semibold">{t("sim.limits")}</h2>
                <ul className="list-disc ps-5 text-sm text-fg-muted">{res.uncertainty.map((u, i) => <li key={i} dir="auto">{u}</li>)}</ul>
              </Card>
            </>
          )}
        </div>
      </div>
    </>
  );
}
