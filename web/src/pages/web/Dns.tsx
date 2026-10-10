import { KeyRound } from "lucide-react";
import { useState } from "react";
import { confirmDialog } from "@/components/Confirm";
import { EmptyState, ErrorState, LoadingState } from "@/components/States";
import { Field, FormError, Input, Modal } from "@/components/ui/form";
import { Button, Card, CardHeader, Ltr, PageHeader } from "@/components/ui/primitives";
import { useI18n } from "@/i18n/i18n";
import type { MessageKey } from "@/i18n/messages";
import { web } from "@/lib/api";
import { useAsync } from "@/lib/hooks";
import { useSession } from "@/lib/session";
import { Pill, errText, tableCls, tdCls, thCls } from "../gateway/common";
import { dnsTone } from "./Domains";

/** DNS overview: every expectation of every domain, plus the Cloudflare integration. */
export function DnsPage() {
  const { t } = useI18n();
  const { can } = useSession();
  const list = useAsync(web.domains.list);
  const cf = useAsync(web.cloudflare.get);
  const [tok, setTok] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const writable = can("secrets.write");
  const save = async () => {
    setErr(null);
    try { await web.cloudflare.set(tok ?? ""); setTok(null); cf.reload(); } catch (e) { setErr(errText(e)); }
  };
  const rows = (list.data?.items ?? []).flatMap((d) => d.comparison.map((c) => ({ d, c })));
  return (
    <>
      <PageHeader title={t("dns.title")} subtitle={t("dns.subtitle")} />
      <div className="flex flex-col gap-4">
        <Card>
          <CardHeader title={t("dns.overview")} />
          {list.status === "error" && !list.data ? <ErrorState error={list.error} onRetry={list.reload} /> : !list.data ? <LoadingState /> : rows.length === 0 ? <EmptyState title={t("dns.noExpectations")} body={t("dns.noExpectationsBody")} /> : (
            <div className="relative overflow-x-auto">
              <table className={tableCls}>
                <thead><tr className="border-b border-border"><th className={thCls}>{t("dom.fqdn")}</th><th className={thCls}>{t("dns.record")}</th><th className={thCls}>{t("dns.status")}</th></tr></thead>
                <tbody className="divide-y divide-border">
                  {rows.map(({ d, c }) => (
                    <tr key={d.id + c.name + c.type + c.value}>
                      <td className={tdCls}><Ltr className="text-xs">{d.fqdn}</Ltr></td>
                      <td className={tdCls}><Ltr className="text-xs">{c.type} {c.name} → {c.value}</Ltr></td>
                      <td className={tdCls}><Pill tone={dnsTone[c.status]}>{t(`dns.st.${c.status}` as MessageKey)}</Pill>{c.detail && <p className="mt-1 text-xs text-fg-muted" dir="auto">{c.detail}</p>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
        <Card className="p-5 text-sm">
          <h2 className="font-semibold text-fg">Cloudflare</h2>
          {cf.data ? (
            <>
              <p className="mt-1 text-fg-muted">{cf.data.note}</p>
              <p className="mt-1 text-fg-muted">{t("dns.cfPerms")}: <Ltr>{cf.data.required_permissions}</Ltr></p>
              <div className="mt-3 flex flex-wrap items-center gap-2">
                <Pill tone={cf.data.configured ? "ok" : "muted"}>{t(cf.data.configured ? "dns.cfConfigured" : "dns.cfNotConfigured")}</Pill>
                {writable && <Button variant="outline" size="sm" onClick={() => setTok("")}><KeyRound className="size-4" aria-hidden />{t(cf.data.configured ? "dns.cfReplace" : "dns.cfSet")}</Button>}
                {writable && cf.data.configured && <Button variant="ghost" size="sm" className="text-bad" onClick={async () => {
                  if (await confirmDialog(t("dns.cfRemoveConfirm"))) { await web.cloudflare.remove(); cf.reload(); }
                }}>{t("common.delete")}</Button>}
              </div>
            </>
          ) : <LoadingState />}
        </Card>
      </div>
      {tok !== null && (
        <Modal open onOpenChange={(o) => !o && setTok(null)} title={t("dns.cfSet")} description={t("dns.cfTokenNote")}
          footer={<><Button variant="ghost" onClick={() => setTok(null)}>{t("common.cancel")}</Button><Button variant="primary" disabled={tok.length < 20} onClick={save}>{t("common.save")}</Button></>}>
          <Field label={t("dns.cfToken")}>{({ id }) => <Input id={id} type="password" autoComplete="off" dir="ltr" value={tok} onChange={(e) => setTok(e.target.value)} />}</Field>
          <FormError>{err}</FormError>
        </Modal>
      )}
    </>
  );
}
