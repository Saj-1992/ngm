import { confirmDialog } from "@/components/Confirm";
import { ArrowRight, Check as CheckIcon, Plus } from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { EmptyState, ErrorState, LoadingState } from "@/components/States";
import { Check, Field, FormError, Input, IssueList, Modal, Select, Textarea } from "@/components/ui/form";
import { Button, Card, Ltr, PageHeader, cn } from "@/components/ui/primitives";
import { HelpTip } from "@/components/ui/tooltip";
import { useI18n } from "@/i18n/i18n";
import type { MessageKey } from "@/i18n/messages";
import { gw, web, type Website, type Certificate, type DestKind, type Endpoint, type Issue, type Listener, type Match, type Pool, type Protocol, type Route, type RouteInput } from "@/lib/api";
import { useAsync } from "@/lib/hooks";
import { useSession } from "@/lib/session";
import { DesiredNote, Pill, RowMenu, bind, errText, lines, tableCls, tdCls, thCls } from "./common";

const protosFor = (l?: Listener): Protocol[] =>
  !l ? [] : l.kind === "stream" ? ["tcp"] : l.kind === "stream_tls_front" ? ["tls_passthrough", "tls_terminate_http"] : ["http"];

const destsFor = (p: Protocol): DestKind[] => (p === "http" || p === "tls_terminate_http" ? ["pool", "endpoint", "website", "redirect", "reject"] : ["endpoint", "pool", "reject"]);

const wantTransport = (p: Protocol) => (p === "tcp" || p === "tls_passthrough" ? ["tcp"] : ["http", "https"]);

const hostMatch = (field: "host" | "sni", v: string): Match => ({ field, operator: v.startsWith("*.") ? "wildcard" : "exact", value: v.toLowerCase() });

/** Describes a route's matches compactly. */
export function describeMatches(r: Route, t: (k: MessageKey) => string) {
  if (!r.matches.length) return r.is_fallback ? t("gw.fallback").split(" ")[0] : r.protocol === "tcp" ? t("gw.any") : t("gw.defaultServer");
  return r.matches.map((m) => (m.field === "path_prefix" ? m.value + "*" : m.field === "alpn" ? "alpn=" + m.value : m.value)).join("  ");
}

type Draft = {
  name: string; listener_id: string; protocol: Protocol; hosts: string; paths: string; sni: string; alpn: string; fallback: boolean;
  dest: DestKind; dest_id: string; redirect_url: string; redirect_code: number; certificate_id: string; websocket: boolean; preserve_host: boolean;
  backend_proxy_protocol: boolean; priority: number;
  strip_prefix: boolean; ip_allow: string; ip_deny: string; rate_limit_rps: number; rate_limit_burst: number;
  gzip: boolean; grpc: boolean; cors_enabled: boolean; cors_origins: string; cors_creds: boolean;
  req_headers: string; res_headers: string;
};

const fmtHdrs = (m?: Record<string, string>) => m ? Object.entries(m).map(([k, v]) => `${k}: ${v}`).join("\n") : "";
const parseHdrs = (s: string): Record<string, string> | undefined => {
  const out: Record<string, string> = {};
  for (const line of lines(s)) {
    const idx = line.indexOf(":");
    if (idx > 0) out[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
  }
  return Object.keys(out).length ? out : undefined;
};

function toDraft(r: Route | undefined, listeners: Listener[]): Draft {
  const l = listeners.find((x) => x.id === r?.listener_id) ?? listeners[0];
  const by = (f: string) => (r?.matches ?? []).filter((m) => m.field === f).map((m) => m.value).join("\n");
  return {
    name: r?.name ?? "", listener_id: l?.id ?? "", protocol: r?.protocol ?? protosFor(l)[0] ?? "http",
    hosts: by("host"), paths: (r?.matches ?? []).filter((m) => m.field === "path_prefix" || m.field === "path_exact").map((m) => (m.field === "path_exact" ? "=" : "") + m.value).join("\n"),
    sni: by("sni"), alpn: by("alpn"), fallback: r?.is_fallback ?? false,
    dest: r?.destination_kind ?? "pool", dest_id: r?.destination_id ?? "", redirect_url: r?.options.redirect_url ?? "", redirect_code: r?.options.redirect_code ?? 308,
    certificate_id: r?.certificate_id ?? "", websocket: r?.options.websocket ?? false, preserve_host: r?.options.preserve_host ?? true,
    backend_proxy_protocol: r?.options.backend_proxy_protocol ?? false, priority: r?.priority ?? 100,
    strip_prefix: r?.options.strip_prefix ?? false,
    ip_allow: (r?.options.ip_allow ?? []).join("\n"),
    ip_deny: (r?.options.ip_deny ?? []).join("\n"),
    rate_limit_rps: r?.options.rate_limit_rps ?? 0,
    rate_limit_burst: r?.options.rate_limit_burst ?? 0,
    gzip: r?.options.gzip ?? false,
    grpc: r?.options.grpc ?? false,
    cors_enabled: r?.options.cors?.enabled ?? false,
    cors_origins: (r?.options.cors?.allow_origins ?? []).join("\n"),
    cors_creds: r?.options.cors?.allow_credentials ?? false,
    req_headers: fmtHdrs(r?.options.request_headers),
    res_headers: fmtHdrs(r?.options.response_headers),
  };
}

function toInput(d: Draft, enabled: boolean): RouteInput {
  const matches: Match[] = [];
  if (d.protocol === "http") lines(d.hosts).forEach((h) => matches.push(hostMatch("host", h)));
  if (d.protocol === "tls_passthrough" || d.protocol === "tls_terminate_http") {
    if (!d.fallback) lines(d.sni).forEach((h) => matches.push(hostMatch("sni", h)));
  }
  if (d.protocol === "tls_passthrough" && !d.fallback) lines(d.alpn).forEach((a) => matches.push({ field: "alpn", operator: "exact", value: a }));
  if (d.protocol === "http" || d.protocol === "tls_terminate_http") {
    lines(d.paths).forEach((p) => matches.push(p.startsWith("=") ? { field: "path_exact", operator: "exact", value: p.slice(1) } : { field: "path_prefix", operator: "prefix", value: p }));
  }
  const httpish = d.protocol === "http" || d.protocol === "tls_terminate_http";
  const allow = lines(d.ip_allow);
  const deny = lines(d.ip_deny);
  const corsOrigins = lines(d.cors_origins);
  return {
    name: d.name.trim(), listener_id: d.listener_id, protocol: d.protocol, priority: Number(d.priority), destination_kind: d.dest,
    destination_id: d.dest === "pool" || d.dest === "endpoint" ? d.dest_id : undefined, is_fallback: d.protocol !== "http" && d.protocol !== "tcp" && d.fallback,
    certificate_id: d.certificate_id || undefined, matches, enabled,
    options: {
      websocket: httpish && d.websocket ? true : undefined,
      preserve_host: d.preserve_host ? undefined : false,
      redirect_url: d.dest === "redirect" ? d.redirect_url : undefined,
      redirect_code: d.dest === "redirect" ? d.redirect_code : undefined,
      backend_proxy_protocol: d.protocol === "tls_passthrough" && d.backend_proxy_protocol ? true : undefined,
      strip_prefix: httpish && d.strip_prefix ? true : undefined,
      ip_allow: allow.length ? allow : undefined,
      ip_deny: deny.length ? deny : undefined,
      rate_limit_rps: httpish && d.rate_limit_rps > 0 ? Number(d.rate_limit_rps) : undefined,
      rate_limit_burst: httpish && d.rate_limit_rps > 0 && d.rate_limit_burst > 0 ? Number(d.rate_limit_burst) : undefined,
      gzip: httpish && d.gzip ? true : undefined,
      grpc: httpish && d.grpc ? true : undefined,
      request_headers: httpish ? parseHdrs(d.req_headers) : undefined,
      response_headers: httpish ? parseHdrs(d.res_headers) : undefined,
      cors: httpish && d.cors_enabled ? { enabled: true, allow_origins: corsOrigins.length ? corsOrigins : ["*"], allow_credentials: d.cors_creds } : undefined,
    },
  };
}

const STEPS = ["listener", "match", "backend", "security", "review"] as const;

function RouteBuilder(props: { initial?: Route; listeners: Listener[]; endpoints: Endpoint[]; pools: Pool[]; certs: Certificate[]; sites: Website[]; onClose: () => void; onDone: () => void }) {
  const { t } = useI18n();
  const { initial, listeners, endpoints, pools, certs } = props;
  const [d, setD] = useState<Draft>(() => toDraft(initial, listeners));
  const [step, setStep] = useState(0);
  const [err, setErr] = useState<string | null>(null);
  const [issues, setIssues] = useState<Issue[] | null>(null);
  const [saved, setSaved] = useState<Route | null>(initial ?? null);
  const l = listeners.find((x) => x.id === d.listener_id);
  const set = (p: Partial<Draft>) => setD({ ...d, ...p });
  const needsCert = l?.kind === "https" || d.protocol === "tls_terminate_http";
  const httpish = d.protocol === "http" || d.protocol === "tls_terminate_http";
  const destOpts = useMemo(() => {
    const tr = wantTransport(d.protocol);
    if (d.dest === "website") return props.sites.filter((w) => w.active_version_id).map((w) => ({ id: w.id, label: w.name }));
    return d.dest === "pool"
      ? pools.filter((p) => p.members.length && tr.includes(endpoints.find((e) => e.id === p.members[0]!.endpoint_id)?.transport ?? "")).map((p) => ({ id: p.id, label: `${p.name} (${p.members.length})` }))
      : endpoints.filter((e) => tr.includes(e.transport)).map((e) => ({ id: e.id, label: `${e.name} — ${e.host}:${e.port} (${e.transport})` }));
  }, [d.dest, d.protocol, pools, endpoints, props.sites]);

  const save = async (enabled: boolean) => {
    setErr(null);
    try {
      const body = toInput(d, enabled);
      const r = saved ? await gw.routes.update(saved, body) : await gw.routes.create(body);
      setSaved(r);
      const v = await gw.validate(false);
      setIssues(v.issues.filter((i) => i.ref === r.id || i.severity === "error"));
      props.onDone();
    } catch (e) {
      setErr(errText(e));
    }
  };

  const canNext = [
    !!l && !!d.protocol,
    d.protocol === "tcp" || d.fallback || (d.protocol === "http" ? true : lines(d.sni).length > 0),
    d.dest === "reject" || (d.dest === "redirect" ? /^https?:\/\//.test(d.redirect_url) : !!d.dest_id),
    !needsCert || !!d.certificate_id || (l?.kind === "https" && !lines(d.hosts).length),
    !!d.name.trim(),
  ];

  return (
    <Modal open wide onOpenChange={(o) => !o && props.onClose()} title={initial ? t("builder.editTitle") : t("gw.routes.new")}
      footer={
        step < STEPS.length - 1 ? (
          <>
            {step > 0 && <Button variant="ghost" onClick={() => setStep(step - 1)}>{t("builder.back")}</Button>}
            <Button variant="primary" disabled={!canNext[step]} onClick={() => setStep(step + 1)}>{t("builder.next")}<ArrowRight className="size-4 rtl:rotate-180" aria-hidden /></Button>
          </>
        ) : (
          <>
            <Button variant="ghost" onClick={() => setStep(step - 1)}>{t("builder.back")}</Button>
            <Button variant="outline" disabled={!canNext.every(Boolean)} onClick={() => save(false)}>{t("builder.saveDraft")}</Button>
            <Button variant="primary" disabled={!canNext.every(Boolean)} onClick={() => save(true)}>{t("builder.save")}</Button>
          </>
        )
      }>
      <ol className="mb-5 flex flex-wrap gap-2" aria-label="steps">
        {STEPS.map((s, i) => (
          <li key={s}>
            <button type="button" disabled={i > step && !canNext.slice(0, i).every(Boolean)} onClick={() => setStep(i)} aria-current={i === step ? "step" : undefined}
              className={cn("inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs", i === step ? "bg-accent text-accent-fg" : i < step ? "bg-ok-soft text-ok" : "bg-surface-2 text-fg-muted")}>
              {i < step ? <CheckIcon className="size-3" aria-hidden /> : <span className="tabular-nums">{i + 1}</span>}
              {t(`builder.step.${s}` as MessageKey)}
            </button>
          </li>
        ))}
      </ol>

      {step === 0 && (
        <div className="flex flex-col gap-3">
          {!listeners.length && <FormError>{t("builder.noListeners")}</FormError>}
          <div className="grid gap-2 sm:grid-cols-2">
            {listeners.map((x) => (
              <button key={x.id} type="button" onClick={() => set({ listener_id: x.id, protocol: protosFor(x)[0]! })}
                className={cn("rounded-xl border p-3 text-start text-sm", x.id === d.listener_id ? "border-accent bg-accent-soft" : "border-border hover:bg-surface-2")}>
                <div className="font-medium text-fg">{x.name}</div>
                <div className="text-xs text-fg-muted">{t(`gw.kind.${x.kind}` as MessageKey)} · <Ltr>{bind(x)}</Ltr></div>
              </button>
            ))}
          </div>
          {l?.kind === "stream_tls_front" && (
            <Field label={t("gw.protocol")}>
              {({ id }) => (
                <Select id={id} value={d.protocol} onChange={(e) => set({ protocol: e.target.value as Protocol })}>
                  {protosFor(l).map((p) => <option key={p} value={p}>{t(`gw.protocol.${p}` as MessageKey)}</option>)}
                </Select>
              )}
            </Field>
          )}
        </div>
      )}

      {step === 1 && (
        <div className="flex flex-col gap-4">
          {d.protocol === "tcp" && <p className="rounded-lg bg-surface-2 px-3 py-2 text-sm text-fg-muted">{t("builder.visibility.tcp")}</p>}
          {d.protocol === "tls_passthrough" && <p className="rounded-lg bg-surface-2 px-3 py-2 text-sm text-fg-muted">{t("builder.visibility.passthrough")}</p>}
          {d.protocol === "tls_terminate_http" && <p className="rounded-lg bg-surface-2 px-3 py-2 text-sm text-fg-muted">{t("builder.visibility.terminate")}</p>}
          {d.protocol === "http" && (
            <Field label={t("builder.hosts")} hint={t("builder.hostsHint")}>{({ id, describedBy }) => <Textarea id={id} aria-describedby={describedBy} dir="ltr" rows={3} value={d.hosts} onChange={(e) => set({ hosts: e.target.value })} />}</Field>
          )}
          {(d.protocol === "tls_passthrough" || d.protocol === "tls_terminate_http") && (
            <>
              {d.protocol === "tls_passthrough" && <Check checked={d.fallback} onChange={(v) => set({ fallback: v })} label={t("gw.fallback")} />}
              {!d.fallback && <Field label={t("builder.sniHosts")} hint={t("builder.hostsHint")}>{({ id, describedBy }) => <Textarea id={id} aria-describedby={describedBy} dir="ltr" rows={3} value={d.sni} onChange={(e) => set({ sni: e.target.value })} />}</Field>}
              {d.protocol === "tls_passthrough" && !d.fallback && (
                <Field label={t("builder.alpn")} hint={t("builder.alpnHint")}>{({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} dir="ltr" value={d.alpn} onChange={(e) => set({ alpn: e.target.value })} />}</Field>
              )}
            </>
          )}
          {httpish && <Field label={t("builder.paths")} hint={t("builder.pathsHint")}>{({ id, describedBy }) => <Textarea id={id} aria-describedby={describedBy} dir="ltr" rows={2} value={d.paths} onChange={(e) => set({ paths: e.target.value })} />}</Field>}
        </div>
      )}

      {step === 2 && (
        <div className="flex flex-col gap-4">
          <Field label={t("gw.dest")}>
            {({ id }) => (
              <Select id={id} value={d.dest} onChange={(e) => set({ dest: e.target.value as DestKind, dest_id: "" })}>
                {destsFor(d.protocol).map((k) => <option key={k} value={k}>{t(`gw.dest.${k}` as MessageKey)}</option>)}
              </Select>
            )}
          </Field>
          {(d.dest === "pool" || d.dest === "endpoint" || d.dest === "website") && (
            <Field label={t(`gw.dest.${d.dest}` as MessageKey)}>
              {({ id }) => (
                <Select id={id} value={d.dest_id} onChange={(e) => set({ dest_id: e.target.value })}>
                  <option value="">—</option>
                  {destOpts.map((o) => <option key={o.id} value={o.id}>{o.label}</option>)}
                </Select>
              )}
            </Field>
          )}
          {d.dest === "redirect" && (
            <div className="grid grid-cols-[1fr_7rem] gap-3">
              <Field label={t("gw.redirectUrl")}>{({ id }) => <Input id={id} dir="ltr" placeholder="https://example.com/" value={d.redirect_url} onChange={(e) => set({ redirect_url: e.target.value })} />}</Field>
              <Field label={t("gw.redirectCode")}>{({ id }) => (
                <Select id={id} value={d.redirect_code} onChange={(e) => set({ redirect_code: Number(e.target.value) })}>
                  {[301, 302, 307, 308].map((c) => <option key={c} value={c}>{c}</option>)}
                </Select>
              )}</Field>
            </div>
          )}
        </div>
      )}

      {step === 3 && (
        <div className="flex flex-col gap-4">
          {needsCert && (
            <Field label={t("gw.certificate")}>
              {({ id }) => (
                <Select id={id} value={d.certificate_id} onChange={(e) => set({ certificate_id: e.target.value })}>
                  <option value="">—</option>
                  {certs.map((c) => <option key={c.id} value={c.id}>{c.name} — {c.sans.join(", ")} ({c.status})</option>)}
                </Select>
              )}
            </Field>
          )}
          {d.dest === "website" && destOpts.length === 0 && <p className="text-sm text-warn">{t("gw.noPublishedSite")}</p>}
          {httpish && d.dest !== "redirect" && d.dest !== "reject" && d.dest !== "website" && (
            <>
              <Check checked={d.websocket} onChange={(v) => set({ websocket: v })} label={t("gw.websocket")} />
              <Check checked={d.preserve_host} onChange={(v) => set({ preserve_host: v })} label={t("gw.preserveHost")} />
              <div className="flex items-center gap-2"><Check checked={d.strip_prefix} onChange={(v) => set({ strip_prefix: v })} label={t("gw.stripPrefix")} /><HelpTip text={t("gw.stripPrefixTip")} /></div>
              <div className="flex items-center gap-2"><Check checked={d.grpc} onChange={(v) => set({ grpc: v })} label={t("gw.grpc")} /><HelpTip text={t("gw.grpcTip")} /></div>
              <div className="flex items-center gap-2"><Check checked={d.gzip} onChange={(v) => set({ gzip: v })} label={t("gw.gzip")} /><HelpTip text={t("gw.gzipTip")} /></div>
            </>
          )}
          {httpish && (
            <details className="rounded-xl border border-border bg-surface-2/50 p-3">
              <summary className="cursor-pointer text-sm font-semibold text-fg">{t("gw.policies")}</summary>
              <div className="mt-3 flex flex-col gap-3">
                <div className="grid grid-cols-2 gap-3">
                  <Field label={<span className="inline-flex items-center gap-1">{t("gw.rateLimit")}<HelpTip text={t("gw.rateLimitTip")} /></span>}>
                    {({ id }) => <Input id={id} dir="ltr" type="number" min={0} max={100000} value={d.rate_limit_rps} onChange={(e) => set({ rate_limit_rps: Number(e.target.value) })} />}
                  </Field>
                  <Field label={t("gw.rateBurst")}>
                    {({ id }) => <Input id={id} dir="ltr" type="number" min={0} max={100000} value={d.rate_limit_burst} onChange={(e) => set({ rate_limit_burst: Number(e.target.value) })} />}
                  </Field>
                </div>
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <Field label={<span className="inline-flex items-center gap-1">{t("gw.ipAllow")}<HelpTip text={t("gw.ipAllowTip")} /></span>}>
                    {({ id }) => <Textarea id={id} dir="ltr" rows={2} placeholder="10.0.0.0/8" value={d.ip_allow} onChange={(e) => set({ ip_allow: e.target.value })} />}
                  </Field>
                  <Field label={<span className="inline-flex items-center gap-1">{t("gw.ipDeny")}<HelpTip text={t("gw.ipDenyTip")} /></span>}>
                    {({ id }) => <Textarea id={id} dir="ltr" rows={2} placeholder="192.0.2.1" value={d.ip_deny} onChange={(e) => set({ ip_deny: e.target.value })} />}
                  </Field>
                </div>
                <div className="flex items-center gap-2"><Check checked={d.cors_enabled} onChange={(v) => set({ cors_enabled: v })} label={t("gw.cors")} /><HelpTip text={t("gw.corsTip")} /></div>
                {d.cors_enabled && (
                  <div className="flex flex-col gap-2 ps-4">
                    <Field label={t("gw.corsOrigins")}>{({ id }) => <Textarea id={id} dir="ltr" rows={2} placeholder="https://app.example.com" value={d.cors_origins} onChange={(e) => set({ cors_origins: e.target.value })} />}</Field>
                    <Check checked={d.cors_creds} onChange={(v) => set({ cors_creds: v })} label={t("gw.corsCreds")} />
                  </div>
                )}
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <Field label={<span className="inline-flex items-center gap-1">{t("gw.reqHeaders")}<HelpTip text={t("gw.headersTip")} /></span>}>
                    {({ id }) => <Textarea id={id} dir="ltr" rows={2} placeholder="X-Custom: value" value={d.req_headers} onChange={(e) => set({ req_headers: e.target.value })} />}
                  </Field>
                  <Field label={<span className="inline-flex items-center gap-1">{t("gw.resHeaders")}<HelpTip text={t("gw.headersTip")} /></span>}>
                    {({ id }) => <Textarea id={id} dir="ltr" rows={2} placeholder="X-Frame-Options: DENY" value={d.res_headers} onChange={(e) => set({ res_headers: e.target.value })} />}
                  </Field>
                </div>
              </div>
            </details>
          )}
          {d.protocol === "tls_passthrough" && <Check checked={d.backend_proxy_protocol} onChange={(v) => set({ backend_proxy_protocol: v })} label={t("gw.backendProxyProto")} />}
          {!needsCert && !httpish && d.protocol !== "tls_passthrough" && <p className="text-sm text-fg-muted">{t("common.none")}</p>}
        </div>
      )}

      {step === 4 && (
        <div className="flex flex-col gap-4">
          <div className="grid grid-cols-[1fr_7rem] gap-3">
            <Field label={t("common.name")}>{({ id }) => <Input id={id} value={d.name} onChange={(e) => set({ name: e.target.value })} />}</Field>
            <Field label={t("gw.priority")}>{({ id }) => <Input id={id} dir="ltr" type="number" min={0} max={10000} value={d.priority} onChange={(e) => set({ priority: Number(e.target.value) })} />}</Field>
          </div>
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 rounded-xl bg-surface-2 p-4 text-sm">
            <dt className="text-fg-muted">{t("builder.step.listener")}</dt><dd>{l?.name} <Ltr className="text-fg-muted">{l ? bind(l) : ""}</Ltr></dd>
            <dt className="text-fg-muted">{t("gw.protocol")}</dt><dd>{t(`gw.protocol.${d.protocol}` as MessageKey)}</dd>
            <dt className="text-fg-muted">{t("gw.matches")}</dt><dd><Ltr>{toInput(d, true).matches.map((m) => `${m.field}:${m.value}`).join("  ") || (d.fallback ? "fallback" : "*")}</Ltr></dd>
            <dt className="text-fg-muted">{t("gw.dest")}</dt><dd>{t(`gw.dest.${d.dest}` as MessageKey)} {destOpts.find((o) => o.id === d.dest_id)?.label}{d.dest === "redirect" && <Ltr> {d.redirect_code} {d.redirect_url}</Ltr>}</dd>
          </dl>
          <FormError>{err}</FormError>
          {issues && (
            <div className="flex flex-col gap-2">
              <h3 className="text-sm font-medium">{t("builder.reviewIssues")}</h3>
              {issues.length ? <IssueList issues={issues} /> : <p className="text-sm text-ok">{t("dep.noIssues")}</p>}
              <p className="text-sm text-fg-muted">{t("builder.saved")} <Link className="text-accent underline" to="/ops/deployments">{t("dep.title")}</Link></p>
            </div>
          )}
        </div>
      )}
    </Modal>
  );
}

export function RoutesPage() {
  const { t } = useI18n();
  const { can } = useSession();
  const routes = useAsync(gw.routes.list);
  const listeners = useAsync(gw.listeners.list);
  const endpoints = useAsync(gw.endpoints.list);
  const pools = useAsync(gw.pools.list);
  const certs = useAsync(gw.certificates.list);
  const sites = useAsync(web.sites.list);
  const [edit, setEdit] = useState<Route | "new" | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const writable = can("gateway.write");
  const ready = listeners.data && endpoints.data && pools.data && certs.data;
  const destName = (r: Route) => {
    if (r.destination_kind === "pool") return pools.data?.items.find((p) => p.id === r.destination_id)?.name;
    if (r.destination_kind === "endpoint") return endpoints.data?.items.find((e) => e.id === r.destination_id)?.name;
    if (r.destination_kind === "redirect") return r.options.redirect_url;
    if (r.destination_kind === "website") return sites.data?.items.find((w) => w.id === r.destination_id)?.name;
    return "";
  };
  return (
    <>
      <PageHeader title={t("gw.routes.title")} subtitle={t("gw.routes.subtitle")}
        actions={writable && <Button variant="primary" disabled={!ready} onClick={() => setEdit("new")}><Plus className="size-4" aria-hidden />{t("gw.routes.new")}</Button>} />
      <DesiredNote />
      <FormError>{err}</FormError>
      <Card>
        {routes.status === "error" && !routes.data ? <ErrorState error={routes.error} onRetry={routes.reload} /> : !routes.data || !listeners.data ? <LoadingState /> : routes.data.items.length === 0 ? <EmptyState title={t("gw.routes.new")} body={t("gw.routes.subtitle")} /> : (
          <div className="relative overflow-x-auto">
            <table className={tableCls}>
              <thead><tr className="border-b border-border">
                <th className={thCls}>{t("common.name")}</th><th className={thCls}>{t("builder.step.listener")}</th><th className={thCls}>{t("gw.matches")}</th>
                <th className={thCls}>{t("gw.dest")}</th><th className={thCls}><span className="sr-only">{t("common.actions")}</span></th>
              </tr></thead>
              <tbody className="divide-y divide-border">
                {routes.data.items.map((r) => {
                  const l = listeners.data!.items.find((x) => x.id === r.listener_id);
                  return (
                    <tr key={r.id} className={cn(!r.enabled && "opacity-60")}>
                      <td className={tdCls}>
                        <div className="font-medium">{r.name}</div>
                        <div className="mt-0.5 flex flex-wrap gap-1"><Pill tone="accent">{t(`gw.protocol.${r.protocol}` as MessageKey)}</Pill>{!r.enabled && <Pill>{t("common.disabled")}</Pill>}{r.options.websocket && <Pill>WS</Pill>}</div>
                      </td>
                      <td className={tdCls}>{l?.name} <Ltr className="block text-xs text-fg-muted">{l ? bind(l) : ""}</Ltr></td>
                      <td className={tdCls}><Ltr className="text-xs">{describeMatches(r, t)}</Ltr></td>
                      <td className={tdCls}>{t(`gw.dest.${r.destination_kind}` as MessageKey)} <span className="text-fg-muted">{destName(r)}</span></td>
                      <td className={`${tdCls} text-end`}>{writable && <RowMenu label={`${t("common.edit")} ${r.name}`} items={[
                        { label: t("common.edit"), onSelect: () => setEdit(r) },
                        { label: t("common.delete"), danger: true, onSelect: async () => {
                          if (!(await confirmDialog(t("common.confirmDelete", { name: r.name })))) return;
                          try { await gw.routes.remove(r); routes.reload(); } catch (e) { setErr(errText(e)); }
                        } },
                      ]} />}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      {edit && ready && (
        <RouteBuilder initial={edit === "new" ? undefined : edit} listeners={listeners.data!.items} endpoints={endpoints.data!.items} pools={pools.data!.items}
          certs={certs.data!.items} sites={sites.data?.items ?? []} onClose={() => setEdit(null)} onDone={routes.reload} />
      )}
    </>
  );
}
