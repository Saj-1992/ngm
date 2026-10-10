import { ArrowDown, ArrowUp, Plus, Trash2 } from "lucide-react";
import { useState } from "react";
import { Check, Field, Input, Select, Tabs, Textarea } from "@/components/ui/form";
import { Button, cn } from "@/components/ui/primitives";
import { useI18n } from "@/i18n/i18n";
import type { MessageKey } from "@/i18n/messages";
import type { L10n, SiteBlock, SiteContent, SiteItem, SiteMedia, SitePage } from "@/lib/api";

const BLOCKS = ["hero", "text", "features", "gallery", "cta", "faq", "quote", "links", "posts"] as const;
const hasItems = (t: string) => ["features", "gallery", "faq", "links"].includes(t);
const hasLink = (t: string) => ["hero", "cta"].includes(t);
const hasImage = (t: string) => ["hero", "text"].includes(t);

function move<T>(xs: T[], i: number, d: number): T[] {
  const j = i + d;
  if (j < 0 || j >= xs.length) return xs;
  const out = [...xs];
  [out[i], out[j]] = [out[j]!, out[i]!];
  return out;
}

/** A field edited per locale (the active locale tab decides which text). */
function LText({ label, value, loc, rtl, onChange, multiline, hint }: { label: string; value?: L10n; loc: string; rtl: boolean; onChange: (v: L10n) => void; multiline?: boolean; hint?: string }) {
  const v = value?.[loc] ?? "";
  const set = (s: string) => onChange({ ...(value ?? {}), [loc]: s });
  return (
    <Field label={label} hint={hint}>
      {({ id, describedBy }) => multiline
        ? <Textarea id={id} aria-describedby={describedBy} rows={4} dir={rtl ? "rtl" : "ltr"} value={v} onChange={(e) => set(e.target.value)} />
        : <Input id={id} aria-describedby={describedBy} dir={rtl ? "rtl" : "ltr"} value={v} onChange={(e) => set(e.target.value)} />}
    </Field>
  );
}

function ImagePick({ value, media, onChange }: { value?: string; media: SiteMedia[]; onChange: (v: string) => void }) {
  const { t } = useI18n();
  return (
    <Field label={t("site.image")}>
      {({ id }) => (
        <Select id={id} value={value ?? ""} onChange={(e) => onChange(e.target.value)}>
          <option value="">—</option>
          {media.map((m) => <option key={m.name} value={m.name}>{m.name}</option>)}
        </Select>
      )}
    </Field>
  );
}

export function SiteEditor({ content, onChange, locales, defLocale, rtlOf, media }: {
  content: SiteContent; onChange: (c: SiteContent) => void; locales: string[]; defLocale: string; rtlOf: (l: string) => boolean; media: SiteMedia[];
}) {
  const { t } = useI18n();
  const [loc, setLoc] = useState(defLocale);
  const [pageIdx, setPageIdx] = useState(0);
  const rtl = rtlOf(loc);
  const page = content.pages[pageIdx];
  const setSite = (p: Partial<SiteContent["site"]>) => onChange({ ...content, site: { ...content.site, ...p } });
  const setPage = (p: Partial<SitePage>) => onChange({ ...content, pages: content.pages.map((x, i) => (i === pageIdx ? { ...x, ...p } : x)) });
  const setBlock = (bi: number, b: Partial<SiteBlock>) => setPage({ blocks: page!.blocks.map((x, i) => (i === bi ? { ...x, ...b } : x)) });
  const setItem = (bi: number, ii: number, it: Partial<SiteItem>) => setBlock(bi, { items: (page!.blocks[bi]!.items ?? []).map((x, i) => (i === ii ? { ...x, ...it } : x)) });
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-sm text-fg-muted">{t("site.editingLocale")}</span>
        <Tabs value={loc} onChange={setLoc} items={locales.map((l) => ({ value: l, label: l.toUpperCase() + (l === defLocale ? " ★" : "") }))} />
      </div>
      <fieldset className="grid gap-3 rounded-xl border border-border p-4 sm:grid-cols-2">
        <legend className="px-1 text-sm font-semibold">{t("site.settings")}</legend>
        <LText label={t("site.title")} value={content.site.title} loc={loc} rtl={rtl} onChange={(v) => setSite({ title: v })} />
        <LText label={t("site.tagline")} value={content.site.tagline} loc={loc} rtl={rtl} onChange={(v) => setSite({ tagline: v })} />
        <Field label={t("site.baseUrl")} hint={t("site.baseUrlHint")}>{({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} dir="ltr" placeholder="https://example.com" value={content.site.base_url ?? ""} onChange={(e) => setSite({ base_url: e.target.value })} />}</Field>
        <Field label={t("site.accent")}>{({ id }) => <Input id={id} dir="ltr" type="color" value={content.site.accent || "#2563eb"} onChange={(e) => setSite({ accent: e.target.value })} />}</Field>
        <div className="sm:col-span-2"><LText label={t("site.footer")} value={content.site.footer} loc={loc} rtl={rtl} onChange={(v) => setSite({ footer: v })} multiline /></div>
      </fieldset>
      <div className="grid gap-4 lg:grid-cols-[14rem_1fr]">
        <nav aria-label={t("site.pages")} className="flex flex-col gap-1">
          {content.pages.map((p, i) => (
            <div key={i} className="flex items-center gap-1">
              <button type="button" onClick={() => setPageIdx(i)} className={cn("flex-1 truncate rounded-lg px-3 py-2 text-start text-sm", i === pageIdx ? "bg-accent-soft text-accent" : "hover:bg-surface-2")}>
                {p.title[loc] || p.title[defLocale] || "—"} <span className="text-xs text-fg-muted" dir="ltr">/{p.slug}</span>
              </button>
              <Button variant="ghost" size="icon" aria-label={t("site.moveUp")} disabled={i === 0} onClick={() => { onChange({ ...content, pages: move(content.pages, i, -1) }); setPageIdx(Math.max(0, i - 1)); }}><ArrowUp className="size-3.5" aria-hidden /></Button>
            </div>
          ))}
          <Button variant="outline" size="sm" onClick={() => { onChange({ ...content, pages: [...content.pages, { slug: "page-" + content.pages.length, title: { [defLocale]: t("site.newPage") }, blocks: [{ type: "text", text: {} }] }] }); setPageIdx(content.pages.length); }}>
            <Plus className="size-4" aria-hidden />{t("site.addPage")}
          </Button>
        </nav>
        {page && (
          <div className="flex flex-col gap-4">
            <div className="grid gap-3 sm:grid-cols-3">
              <Field label={t("site.slug")} hint={page.slug === "" ? t("site.home") : undefined}>{({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} dir="ltr" value={page.slug} disabled={page.slug === "" && pageIdx === 0} onChange={(e) => setPage({ slug: e.target.value.toLowerCase() })} />}</Field>
              <Field label={t("site.kind")}>{({ id }) => <Select id={id} value={page.kind ?? "page"} onChange={(e) => setPage({ kind: e.target.value })}>{["page", "post", "doc"].map((k) => <option key={k} value={k}>{t(`site.kind.${k}` as MessageKey)}</option>)}</Select>}</Field>
              {page.kind === "post" && <Field label={t("site.date")}>{({ id }) => <Input id={id} dir="ltr" type="date" value={page.date ?? ""} onChange={(e) => setPage({ date: e.target.value })} />}</Field>}
            </div>
            <LText label={t("site.pageTitle")} value={page.title} loc={loc} rtl={rtl} onChange={(v) => setPage({ title: v })} />
            <LText label={t("site.description")} value={page.description} loc={loc} rtl={rtl} onChange={(v) => setPage({ description: v })} hint={t("site.descriptionHint")} />
            <Check checked={!!page.hidden} onChange={(v) => setPage({ hidden: v })} label={t("site.hidden")} />
            {page.blocks.map((b, bi) => (
              <fieldset key={bi} className="flex flex-col gap-3 rounded-xl border border-border p-4">
                <legend className="flex items-center gap-2 px-1 text-sm font-semibold">
                  {t(`site.block.${b.type}` as MessageKey)}
                  <Button variant="ghost" size="icon" aria-label={t("site.moveUp")} disabled={bi === 0} onClick={() => setPage({ blocks: move(page.blocks, bi, -1) })}><ArrowUp className="size-3.5" aria-hidden /></Button>
                  <Button variant="ghost" size="icon" aria-label={t("site.moveDown")} disabled={bi === page.blocks.length - 1} onClick={() => setPage({ blocks: move(page.blocks, bi, 1) })}><ArrowDown className="size-3.5" aria-hidden /></Button>
                  <Button variant="ghost" size="icon" aria-label={t("common.delete")} onClick={() => setPage({ blocks: page.blocks.filter((_, i) => i !== bi) })}><Trash2 className="size-3.5" aria-hidden /></Button>
                </legend>
                {b.type !== "posts" && <LText label={t("site.heading")} value={b.heading} loc={loc} rtl={rtl} onChange={(v) => setBlock(bi, { heading: v })} />}
                {b.type !== "posts" && b.type !== "faq" && <LText label={t("site.text")} value={b.text} loc={loc} rtl={rtl} multiline onChange={(v) => setBlock(bi, { text: v })} hint={t("site.textHint")} />}
                {hasLink(b.type) && (
                  <div className="grid gap-3 sm:grid-cols-2">
                    <LText label={t("site.label")} value={b.label} loc={loc} rtl={rtl} onChange={(v) => setBlock(bi, { label: v })} />
                    <Field label={t("site.link")}>{({ id }) => <Input id={id} dir="ltr" placeholder="https://… / mailto:… / #id" value={b.href ?? ""} onChange={(e) => setBlock(bi, { href: e.target.value })} />}</Field>
                  </div>
                )}
                {hasImage(b.type) && <ImagePick value={b.image} media={media} onChange={(v) => setBlock(bi, { image: v || undefined })} />}
                {hasItems(b.type) && (
                  <div className="flex flex-col gap-2">
                    {(b.items ?? []).map((it, ii) => (
                      <div key={ii} className="grid gap-2 rounded-lg bg-surface-2 p-3 sm:grid-cols-2">
                        <LText label={t("site.itemTitle")} value={it.title} loc={loc} rtl={rtl} onChange={(v) => setItem(bi, ii, { title: v })} />
                        <LText label={t("site.text")} value={it.text} loc={loc} rtl={rtl} onChange={(v) => setItem(bi, ii, { text: v })} />
                        {b.type !== "faq" && <Field label={t("site.link")}>{({ id }) => <Input id={id} dir="ltr" value={it.href ?? ""} onChange={(e) => setItem(bi, ii, { href: e.target.value })} />}</Field>}
                        {b.type === "gallery" && <ImagePick value={it.image} media={media} onChange={(v) => setItem(bi, ii, { image: v || undefined })} />}
                        <div className="sm:col-span-2"><Button variant="ghost" size="sm" onClick={() => setBlock(bi, { items: (b.items ?? []).filter((_, i) => i !== ii) })}><Trash2 className="size-3.5" aria-hidden />{t("common.delete")}</Button></div>
                      </div>
                    ))}
                    <div><Button variant="outline" size="sm" onClick={() => setBlock(bi, { items: [...(b.items ?? []), { title: {} }] })}><Plus className="size-4" aria-hidden />{t("site.addItem")}</Button></div>
                  </div>
                )}
              </fieldset>
            ))}
            <div className="flex flex-wrap items-center gap-2">
              <Select aria-label={t("site.addBlock")} value="" onChange={(e) => e.target.value && setPage({ blocks: [...page.blocks, { type: e.target.value }] })}>
                <option value="">+ {t("site.addBlock")}</option>
                {BLOCKS.map((k) => <option key={k} value={k}>{t(`site.block.${k}` as MessageKey)}</option>)}
              </Select>
              {pageIdx !== 0 && <Button variant="ghost" className="text-bad" onClick={() => { onChange({ ...content, pages: content.pages.filter((_, i) => i !== pageIdx) }); setPageIdx(0); }}><Trash2 className="size-4" aria-hidden />{t("site.deletePage")}</Button>}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
