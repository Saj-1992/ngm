import type { MessageKey } from "@/i18n/messages";
import { useMemo, useState } from "react";
import { EmptyState, ErrorState, LoadingState } from "@/components/States";
import { Input, Tabs } from "@/components/ui/form";
import { Card, Ltr, PageHeader } from "@/components/ui/primitives";
import { useI18n } from "@/i18n/i18n";
import { opsx, type TopoNode } from "@/lib/api";
import { useAsync } from "@/lib/hooks";
import { Pill } from "../gateway/common";

const COLS = ["domain", "listener", "route", "pool", "website", "endpoint"];
const SIDE = ["certificate", "firewall_rule"];
const tone = (s?: string) => (s === "down" || s === "expired" ? "bad" : s === "healthy" || s === "present" || s === "published" ? "ok" : s === "expiring" || s === "unknown" ? "warn" : "muted");

/** Read-only layered graph: columns by node kind, traffic edges solid, dependency edges dashed. */
export function TopologyPage() {
  const { t } = useI18n();
  const [view, setView] = useState<"desired" | "active">("desired");
  const g = useAsync(() => opsx.topology(view), [view]);
  const [sel, setSel] = useState<TopoNode | null>(null);
  const [filter, setFilter] = useState("");
  const imp = useAsync(() => (sel ? opsx.impact(sel.id, view) : Promise.resolve(null)), [sel?.id, view]);
  const layout = useMemo(() => {
    const nodes = (g.data?.nodes ?? []).filter((n) => !filter || n.label.toLowerCase().includes(filter.toLowerCase()) || n.kind === filter);
    const pos = new Map<string, { x: number; y: number }>();
    const cols = [...COLS, ...SIDE];
    const counts: Record<string, number> = {};
    for (const n of nodes) {
      const c = cols.indexOf(n.kind);
      const i = (counts[n.kind] = (counts[n.kind] ?? 0) + 1) - 1;
      pos.set(n.id, { x: 20 + Math.max(0, c) * 170, y: 40 + i * 56 });
    }
    const h = 60 + Math.max(1, ...Object.values(counts)) * 56;
    return { nodes, pos, h, w: 20 + cols.length * 170 };
  }, [g.data, filter]);
  return (
    <>
      <PageHeader title={t("topo.title")} subtitle={t("topo.subtitle")} />
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <Tabs value={view} onChange={setView} items={[{ value: "desired", label: t("topo.desired") }, { value: "active", label: t("topo.active") }]} />
        <Input aria-label={t("topo.filter")} placeholder={t("topo.filter")} className="w-56" value={filter} onChange={(e) => setFilter(e.target.value)} />
      </div>
      <div className="grid gap-4 lg:grid-cols-[1fr_20rem]">
        <Card className="overflow-auto p-2">
          {g.status === "error" && !g.data ? <ErrorState error={g.error} onRetry={g.reload} /> : !g.data ? <LoadingState /> : g.data.nodes.length === 0 ? <EmptyState title={t("topo.empty")} /> : (
            <svg width={layout.w} height={layout.h} role="group" aria-label={t("topo.title")} direction="ltr" className="text-fg">
              {[...COLS, ...SIDE].map((c, i) => <text key={c} x={20 + i * 170} y={20} className="fill-current text-[11px] opacity-60">{t(`topo.kind.${c}` as MessageKey)}</text>)}
              {g.data.edges.map((e, i) => {
                const a = layout.pos.get(e.from), b = layout.pos.get(e.to);
                if (!a || !b) return null;
                return <line key={i} x1={a.x + 150} y1={a.y + 18} x2={b.x} y2={b.y + 18} stroke="currentColor" strokeOpacity={e.traffic ? 0.5 : 0.3} strokeDasharray={e.traffic ? undefined : "4 3"} />;
              })}
              {layout.nodes.map((n) => {
                const p = layout.pos.get(n.id)!;
                const on = sel?.id === n.id;
                return (
                  <g key={n.id} transform={`translate(${p.x},${p.y})`} tabIndex={0} role="button" aria-label={`${n.kind} ${n.label}`} onClick={() => setSel(n)} onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && setSel(n)} className="cursor-pointer outline-none">
                    <rect width={150} height={36} rx={8} className={on ? "fill-accent-soft stroke-accent" : "fill-surface stroke-border"} strokeWidth={on ? 2 : 1} />
                    <circle cx={12} cy={18} r={4} className={{ ok: "fill-ok", bad: "fill-bad", warn: "fill-warn", muted: "fill-fg-muted" }[tone(n.status)]} />
                    <text x={22} y={22} className="fill-current text-[12px]">{n.label.length > 18 ? n.label.slice(0, 17) + "…" : n.label}</text>
                  </g>
                );
              })}
            </svg>
          )}
          {g.data?.truncated && <p className="p-2 text-xs text-warn">{t("topo.truncated")}</p>}
        </Card>
        <Card className="p-4 text-sm">
          {!sel ? <p className="text-fg-muted">{t("topo.pick")}</p> : (
            <>
              <h2 className="font-semibold">{sel.label}</h2>
              <p className="mb-2 text-xs text-fg-muted">{t(`topo.kind.${sel.kind}` as MessageKey)} {sel.status && <Pill tone={tone(sel.status)}>{sel.status}</Pill>}</p>
              <dl className="mb-3 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">{Object.entries(sel.attrs ?? {}).map(([k, v]) => <><dt key={k} className="text-fg-muted">{k}</dt><dd key={k + "v"}><Ltr>{v}</Ltr></dd></>)}</dl>
              <h3 className="font-semibold">{t("topo.impact")}</h3>
              {imp.data && (imp.data.critical.length === 0 ? <p className="text-fg-muted">{t("topo.noImpact")}</p> : <ul className="mt-1 list-disc ps-5 text-bad">{imp.data.critical.map((c) => <li key={c} dir="ltr">{c}</li>)}</ul>)}
              {imp.data && imp.data.affected.length > 0 && <p className="mt-2 text-xs text-fg-muted">{t("topo.affected", { n: imp.data.affected.length })}</p>}
            </>
          )}
        </Card>
      </div>
    </>
  );
}
