import { FallbackCard } from "./FallbackCard";
import { Eye, Hammer, Plus, Rocket, Upload } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { confirmDialog } from "@/components/Confirm";
import { EmptyState, ErrorState, LoadingState } from "@/components/States";
import { Field, FormError, Input, Modal, Select, Tabs } from "@/components/ui/form";
import { Button, Card, CardHeader, Ltr, PageHeader } from "@/components/ui/primitives";
import { useI18n } from "@/i18n/i18n";
import type { MessageKey } from "@/i18n/messages";
import { web, type SiteContent, type SiteVersion, type Website } from "@/lib/api";
import { apiUrl } from "@/lib/base";
import { useAsync } from "@/lib/hooks";
import { useSession } from "@/lib/session";
import { JobProgress } from "../gateway/Deployments";
import { Pill, actionKey, errText, tableCls, tdCls, thCls } from "../gateway/common";
import { SiteEditor } from "./SiteEditor";

const size = (n: number) => (n < 1 << 20 ? `${(n / 1024).toFixed(1)} KiB` : `${(n / (1 << 20)).toFixed(1)} MiB`);

export function WebsitesPage() {
  const { t } = useI18n();
  const { can } = useSession();
  const nav = useNavigate();
  const list = useAsync(web.sites.list);
  const tpls = useAsync(web.sites.templates);
  const [adding, setAdding] = useState(false);
  const [f, setF] = useState({ name: "", kind: "template", template: "landing", default_locale: "fa", locales: ["fa", "en"] });
  const [err, setErr] = useState<string | null>(null);
  const create = async () => {
    setErr(null);
    try {
      const w = await web.sites.create({ ...f, template: f.kind === "template" ? f.template : undefined });
      nav("/web/websites/" + w.id);
    } catch (e) { setErr(errText(e)); }
  };
  const locales = Object.keys(tpls.data?.locales ?? {}).sort();
  return (
    <>
      <PageHeader title={t("site.title.page")} subtitle={t("site.subtitle")}
        actions={can("websites.write") && <Button variant="primary" onClick={() => setAdding(true)}><Plus className="size-4" aria-hidden />{t("site.new")}</Button>} />
      {can("gateway.read") && <FallbackCard />}
      <Card>
        {list.status === "error" && !list.data ? <ErrorState error={list.error} onRetry={list.reload} /> : !list.data ? <LoadingState /> : list.data.items.length === 0 ? <EmptyState title={t("site.empty")} body={t("site.emptyBody")} /> : (
          <ul className="divide-y divide-border">
            {list.data.items.map((w) => (
              <li key={w.id}>
                <Link to={"/web/websites/" + w.id} className="flex flex-wrap items-center gap-3 px-5 py-3 hover:bg-surface-2">
                  <span className="min-w-0 flex-1 truncate font-medium text-fg">{w.name}</span>
                  <Pill>{w.kind === "template" ? t(`site.tpl.${w.template}` as MessageKey) : t("site.kind.static_zip")}</Pill>
                  <Ltr className="text-xs text-fg-muted">{w.locales.join(" · ")}</Ltr>
                  <Pill tone={w.active_version_id ? "ok" : "muted"}>{t(w.active_version_id ? "site.published" : "site.unpublished")}</Pill>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </Card>
      {adding && (
        <Modal open onOpenChange={(o) => !o && setAdding(false)} title={t("site.new")}
          footer={<><Button variant="ghost" onClick={() => setAdding(false)}>{t("common.cancel")}</Button><Button variant="primary" disabled={!f.name || !f.locales.includes(f.default_locale)} onClick={create}>{t("common.create")}</Button></>}>
          <form className="flex flex-col gap-4" onSubmit={(e) => { e.preventDefault(); void create(); }}>
            <Field label={t("common.name")}>{({ id }) => <Input id={id} value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} />}</Field>
            <Field label={t("site.source")}>{({ id }) => (
              <Select id={id} value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })}>
                <option value="template">{t("site.kind.template")}</option><option value="static_zip">{t("site.kind.static_zip")}</option>
              </Select>
            )}</Field>
            {f.kind === "template" && (
              <Field label={t("site.template")}>{({ id }) => (
                <Select id={id} value={f.template} onChange={(e) => setF({ ...f, template: e.target.value })}>
                  {(tpls.data?.templates ?? []).map((x) => <option key={x} value={x}>{t(`site.tpl.${x}` as MessageKey)}</option>)}
                </Select>
              )}</Field>
            )}
            <fieldset>
              <legend className="mb-1 text-sm font-medium">{t("site.locales")}</legend>
              <div className="flex flex-wrap gap-2">
                {locales.map((l) => (
                  <label key={l} className="flex items-center gap-1 text-sm">
                    <input type="checkbox" checked={f.locales.includes(l)} onChange={(e) => setF({ ...f, locales: e.target.checked ? [...f.locales, l] : f.locales.filter((x) => x !== l) })} />
                    <Ltr>{l}</Ltr>
                  </label>
                ))}
              </div>
            </fieldset>
            <Field label={t("site.defaultLocale")}>{({ id }) => <Select id={id} value={f.default_locale} onChange={(e) => setF({ ...f, default_locale: e.target.value })}>{f.locales.map((l) => <option key={l} value={l}>{l}</option>)}</Select>}</Field>
            <FormError>{err}</FormError>
          </form>
        </Modal>
      )}
    </>
  );
}

function Versions({ site, onChanged }: { site: Website; onChanged: () => void }) {
  const { t, formatDateTime } = useI18n();
  const { can } = useSession();
  const vs = useAsync(() => web.sites.versions(site.id), [site.id]);
  const [job, setJob] = useState<string | null>(null);
  const [preview, setPreview] = useState<{ v: SiteVersion; url: string } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const writable = can("websites.write");
  const publish = async (v: SiteVersion) => {
    const back = site.active_version_id && v.status !== "built";
    if (!(await confirmDialog(t(back ? "site.rollbackConfirm" : "site.publishConfirm", { n: v.number }), { danger: false }))) return;
    setErr(null);
    try { setJob((await web.sites.publish(site.id, v.id, actionKey())).job_id); } catch (e) { setErr(errText(e)); }
  };
  const open = async (v: SiteVersion) => {
    try { setPreview({ v, url: (await web.sites.previewLink(site.id, v.id)).url }); } catch (e) { setErr(errText(e)); }
  };
  return (
    <Card>
      <CardHeader title={t("site.versions")} />
      <FormError>{err}</FormError>
      {job && <div className="px-5 pb-4"><JobProgress id={job} onDone={() => { vs.reload(); onChanged(); }} /></div>}
      {vs.status === "error" && !vs.data ? <ErrorState error={vs.error} onRetry={vs.reload} /> : !vs.data ? <LoadingState /> : vs.data.items.length === 0 ? <EmptyState title={t("site.noVersions")} /> : (
        <div className="relative overflow-x-auto">
          <table className={tableCls}>
            <thead><tr className="border-b border-border"><th className={thCls}>#</th><th className={thCls}>{t("site.status")}</th><th className={thCls}>{t("bk.size")}</th><th className={thCls}>{t("bk.created")}</th><th className={thCls}><span className="sr-only">{t("common.actions")}</span></th></tr></thead>
            <tbody className="divide-y divide-border">
              {vs.data.items.map((v) => (
                <tr key={v.id}>
                  <td className={tdCls}>{v.number}<Ltr className="ms-2 text-[11px] text-fg-muted">{v.content_hash.slice(0, 10)}</Ltr></td>
                  <td className={tdCls}><Pill tone={v.status === "published" ? "ok" : v.status === "failed" ? "bad" : "muted"}>{t(`site.st.${v.status}` as MessageKey)}</Pill></td>
                  <td className={`${tdCls} text-xs`}><Ltr>{size(v.size_bytes)}</Ltr></td>
                  <td className={`${tdCls} text-xs`}>{formatDateTime(v.created_at)}</td>
                  <td className={`${tdCls} text-end`}>
                    <div className="flex justify-end gap-1">
                      <Button variant="ghost" size="sm" onClick={() => void open(v)}><Eye className="size-4" aria-hidden />{t("site.preview")}</Button>
                      {writable && v.status !== "published" && <Button variant="outline" size="sm" disabled={!!job} onClick={() => void publish(v)}><Rocket className="size-4" aria-hidden />{t(site.active_version_id && v.status === "superseded" ? "site.rollback" : "site.publish")}</Button>}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {preview && (
        <Modal open wide onOpenChange={(o) => !o && setPreview(null)} title={t("site.previewOf", { n: preview.v.number })} description={t("site.previewNote")}>
          <iframe title={t("site.preview")} src={apiUrl(preview.url)} sandbox="allow-scripts allow-popups" referrerPolicy="no-referrer" className="h-[70dvh] w-full rounded-lg border border-border bg-white" />
        </Modal>
      )}
    </Card>
  );
}

export function WebsiteDetailPage() {
  const { t } = useI18n();
  const { can } = useSession();
  const { id = "" } = useParams();
  const nav = useNavigate();
  const d = useAsync(() => web.sites.get(id), [id]);
  const tpls = useAsync(web.sites.templates);
  const media = useAsync(() => web.sites.media(id), [id]);
  const [tab, setTab] = useState<"content" | "media" | "versions">("content");
  const [draft, setDraft] = useState<SiteContent | null>(null);
  const [dirty, setDirty] = useState(false);
  const [check, setCheck] = useState<{ errors: string[]; warnings: string[] } | null>(null);
  const [job, setJob] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const zipRef = useRef<HTMLInputElement>(null);
  const site = d.data?.website;
  const writable = can("websites.write");
  useEffect(() => {
    if (site?.content && !dirty) setDraft(site.content);
    if (d.data) setCheck({ errors: d.data.errors, warnings: d.data.warnings });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [d.data]);
  // Unsaved-changes protection.
  useEffect(() => {
    if (!dirty) return;
    const h = (e: BeforeUnloadEvent) => { e.preventDefault(); };
    window.addEventListener("beforeunload", h);
    return () => window.removeEventListener("beforeunload", h);
  }, [dirty]);
  const rtlOf = useCallback((l: string) => tpls.data?.locales[l] === "rtl", [tpls.data]);
  const save = async () => {
    if (!site || !draft) return;
    setErr(null);
    try {
      const r = await web.sites.saveContent(site.id, site.draft_revision, draft);
      setDirty(false);
      setCheck({ errors: r.errors, warnings: r.warnings });
      setMsg(t("site.saved"));
      d.reload();
    } catch (e) { setErr(errText(e)); }
  };
  const build = async () => {
    if (dirty && !(await confirmDialog(t("site.unsavedBuild"), { danger: false }))) return;
    setErr(null);
    try { setJob((await web.sites.build(id, actionKey())).job_id); setTab("versions"); } catch (e) { setErr(errText(e)); }
  };
  const remove = async () => {
    if (!site || !(await confirmDialog(t("site.deleteConfirm", { name: site.name }), { typed: site.name }))) return;
    try { await web.sites.remove(site.id, actionKey()); nav("/web/websites"); } catch (e) { setErr(errText(e)); }
  };
  if (d.status === "error" && !d.data) return <ErrorState error={d.error} onRetry={d.reload} />;
  if (!site) return <LoadingState />;
  return (
    <>
      <PageHeader title={site.name} subtitle={<span><Link className="text-accent" to="/web/websites">{t("site.title.page")}</Link> · {site.kind === "template" ? t(`site.tpl.${site.template}` as MessageKey) : t("site.kind.static_zip")}</span>}
        actions={writable && (
          <>
            {site.kind === "template" && <Button variant="outline" disabled={!dirty} onClick={save}>{t("common.save")}</Button>}
            <Button variant="primary" onClick={build}><Hammer className="size-4" aria-hidden />{t("site.build")}</Button>
          </>
        )} />
      {d.data!.routes.length > 0
        ? <p className="mb-4 text-sm text-fg-muted">{t("site.servedBy", { routes: d.data!.routes.join(", ") })}</p>
        : <p className="mb-4 rounded-xl bg-accent-soft px-4 py-2.5 text-sm text-accent">{t("site.noRoute")}</p>}
      <FormError>{err}</FormError>
      {msg && !dirty && <p className="mb-3 text-sm text-ok" role="status">{msg}</p>}
      {job && <Card className="mb-4 p-5"><JobProgress id={job} onDone={() => setJob(null)} /></Card>}
      <div className="mb-4"><Tabs value={tab} onChange={setTab} items={[
        ...(site.kind === "template" ? [{ value: "content" as const, label: t("site.content") }, { value: "media" as const, label: t("site.media") }] : [{ value: "content" as const, label: t("site.upload") }]),
        { value: "versions" as const, label: t("site.versions") }]} /></div>
      {tab === "content" && site.kind === "template" && draft && (
        <Card className="p-5">
          {check && (check.errors.length > 0 || check.warnings.length > 0) && (
            <div className="mb-4 flex flex-col gap-2 text-sm">
              {check.errors.map((e) => <p key={e} className="rounded-lg bg-bad-soft px-3 py-2 text-bad" dir="auto">{e}</p>)}
              {check.warnings.slice(0, 8).map((w) => <p key={w} className="rounded-lg bg-warn-soft px-3 py-2 text-warn" dir="auto">{w}</p>)}
            </div>
          )}
          <SiteEditor content={draft} onChange={(c) => { setDraft(c); setDirty(true); setMsg(null); }} locales={site.locales} defLocale={site.default_locale} rtlOf={rtlOf} media={media.data?.items ?? []} />
        </Card>
      )}
      {tab === "content" && site.kind === "static_zip" && (
        <Card className="p-5 text-sm">
          <p className="text-fg-muted">{t("site.zipRules")}</p>
          <p className="mt-2">{site.has_upload ? t("site.zipPending") : t("site.zipNone")}</p>
          {writable && (
            <>
              <input ref={zipRef} type="file" accept=".zip,application/zip" className="sr-only" onChange={async (e) => {
                const file = e.target.files?.[0];
                e.target.value = "";
                if (!file) return;
                setErr(null);
                try { await web.sites.upload(site.id, file); setMsg(t("site.zipUploaded")); d.reload(); } catch (er) { setErr(errText(er)); }
              }} />
              <Button className="mt-3" variant="outline" onClick={() => zipRef.current?.click()}><Upload className="size-4" aria-hidden />{t("site.uploadZip")}</Button>
            </>
          )}
        </Card>
      )}
      {tab === "media" && (
        <Card className="p-5">
          {writable && (
            <>
              <input ref={fileRef} type="file" accept="image/png,image/jpeg,image/gif,image/webp,image/avif" className="sr-only" onChange={async (e) => {
                const file = e.target.files?.[0];
                e.target.value = "";
                if (!file) return;
                setErr(null);
                try { await web.sites.addMedia(site.id, file); media.reload(); } catch (er) { setErr(errText(er)); }
              }} />
              <Button variant="outline" onClick={() => fileRef.current?.click()}><Upload className="size-4" aria-hidden />{t("site.addImage")}</Button>
              <p className="mt-2 text-xs text-fg-muted">{t("site.mediaRules")}</p>
            </>
          )}
          <ul className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
            {(media.data?.items ?? []).map((m) => (
              <li key={m.name} className="overflow-hidden rounded-lg border border-border">
                <img src={web.sites.mediaUrl(site.id, m.name)} alt={m.name} className="aspect-video w-full object-cover" />
                <div className="flex items-center justify-between gap-1 p-2 text-xs"><Ltr className="truncate">{m.name}</Ltr>
                  {writable && <Button variant="ghost" size="sm" onClick={async () => { await web.sites.removeMedia(site.id, m.name); media.reload(); }}>{t("common.delete")}</Button>}</div>
              </li>
            ))}
          </ul>
        </Card>
      )}
      {tab === "versions" && <Versions site={site} onChanged={d.reload} />}
      {writable && (
        <div className="mt-6"><Button variant="ghost" className="text-bad" disabled={d.data!.routes.length > 0} onClick={remove}>{t("site.delete")}</Button></div>
      )}
    </>
  );
}
