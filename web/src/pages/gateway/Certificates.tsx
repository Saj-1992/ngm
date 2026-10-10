import { confirmDialog } from "@/components/Confirm";
import { BadgeCheck, FilePlus2, KeyRound } from "lucide-react";
import { useState } from "react";
import { EmptyState, ErrorState, LoadingState } from "@/components/States";
import { Field, FormError, Input, Modal, Textarea } from "@/components/ui/form";
import { Button, Card, Ltr, PageHeader } from "@/components/ui/primitives";
import { useI18n } from "@/i18n/i18n";
import { gw, web, type Certificate, downloadFile } from "@/lib/api";
import { Select } from "@/components/ui/form";
import { JobProgress } from "./Deployments";
import { useAsync } from "@/lib/hooks";
import { useSession } from "@/lib/session";
import { Pill, RowMenu, actionKey, errText, lines, tableCls, tdCls, thCls } from "./common";

const statusTone = (s: string) => (s === "valid" ? "ok" : s === "expiring" ? "warn" : s === "expired" ? "bad" : "muted");

export function CertificatesPage() {
  const { t, formatDateTime } = useI18n();
  const { can } = useSession();
  const certs = useAsync(gw.certificates.list);
  const [mode, setMode] = useState<"import" | "self" | "acme" | null>(null);
  const [f, setF] = useState({ name: "", cert: "", key: "", hosts: "", days: 90, directory: "letsencrypt-staging", email: "" });
  const [job, setJob] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const writable = can("certificates.write");
  const submit = async () => {
    setErr(null);
    try {
      if (mode === "import") await gw.certificates.import({ name: f.name, cert_pem: f.cert, key_pem: f.key });
      else if (mode === "acme") setJob((await web.acme({ name: f.name, identifiers: lines(f.hosts), directory: f.directory, email: f.email }, actionKey())).job_id);
      else await gw.certificates.selfSigned({ name: f.name, hosts: lines(f.hosts), days: Number(f.days) });
      setF({ name: "", cert: "", key: "", hosts: "", days: 90, directory: "letsencrypt-staging", email: "" });
      setMode(null);
      certs.reload();
    } catch (e) {
      setErr(errText(e));
    }
  };
  return (
    <>
      <PageHeader title={t("ssl.title")} subtitle={t("ssl.subtitle")}
        actions={writable && (
          <>
            <Button variant="outline" onClick={() => setMode("self")}><KeyRound className="size-4" aria-hidden />{t("ssl.selfSigned")}</Button>
            <Button variant="outline" onClick={() => setMode("acme")}><BadgeCheck className="size-4" aria-hidden />{t("ssl.acme")}</Button>
            <Button variant="primary" onClick={() => setMode("import")}><FilePlus2 className="size-4" aria-hidden />{t("ssl.import")}</Button>
          </>
        )} />
      <FormError>{err && !mode ? err : null}</FormError>
      {job && <Card className="mb-4 p-5"><JobProgress id={job} onDone={certs.reload} /></Card>}
      <Card>
        {certs.status === "error" && !certs.data ? <ErrorState error={certs.error} onRetry={certs.reload} /> : !certs.data ? <LoadingState /> : certs.data.items.length === 0 ? <EmptyState title={t("ssl.empty")} /> : (
          <div className="relative overflow-x-auto">
            <table className={tableCls}>
              <thead><tr className="border-b border-border">
                <th className={thCls}>{t("common.name")}</th><th className={thCls}>SAN</th><th className={thCls}>{t("ssl.expires")}</th>
                <th className={thCls}>{t("ssl.fingerprint")}</th><th className={thCls}><span className="sr-only">{t("common.actions")}</span></th>
              </tr></thead>
              <tbody className="divide-y divide-border">
                {certs.data.items.map((c: Certificate) => (
                  <tr key={c.id}>
                    <td className={tdCls}><div className="font-medium">{c.name}</div><div className="mt-0.5 flex gap-1"><Pill tone={statusTone(c.status)}>{c.status}</Pill><Pill>{c.source}</Pill></div>
                      {c.acme && <p className="mt-1 text-xs text-fg-muted">{t("ssl.acmeState", { dir: c.acme.directory, n: c.acme.renewals })}{c.acme.last_error && <span className="block text-bad" dir="ltr">{c.acme.last_error}</span>}</p>}</td>
                    <td className={tdCls}><Ltr className="text-xs">{c.sans.join(", ")}</Ltr></td>
                    <td className={`${tdCls} text-xs`}>{formatDateTime(c.not_after)}</td>
                    <td className={tdCls}><Ltr className="text-[11px] text-fg-muted">{c.fingerprint_sha256.slice(0, 23)}…</Ltr></td>
                    <td className={`${tdCls} text-end`}>{writable && <RowMenu label={`${t("common.delete")} ${c.name}`} items={[{ label: t("ssl.dlChain"), onSelect: async () => { try { await downloadFile(`/api/v1/certificates/${c.id}/fullchain`, `${c.name}-fullchain.pem`); } catch (e) { setErr(errText(e)); } } }, ...(c.has_key ? [{ label: t("ssl.dlKey"), danger: true, onSelect: async () => { try { await downloadFile(`/api/v1/certificates/${c.id}/privkey`, `${c.name}-privkey.pem`); } catch (e) { setErr(errText(e)); } } }] : []), ...(c.source === "acme" ? [{ label: t("ssl.renew"), onSelect: async () => {
                      try { setJob((await web.renew(c.id, actionKey())).job_id); } catch (e) { setErr(errText(e)); }
                    } }] : []), { label: t("common.delete"), danger: true, onSelect: async () => {
                      if (!(await confirmDialog(t("common.confirmDelete", { name: c.name }), { typed: c.name }))) return;
                      try { await gw.certificates.remove(c); certs.reload(); } catch (e) { setErr(errText(e)); }
                    } }]} />}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <Modal open={!!mode} wide onOpenChange={(o) => !o && setMode(null)} title={mode === "import" ? t("ssl.import") : mode === "acme" ? t("ssl.acme") : t("ssl.selfSigned")}
        description={mode === "self" ? t("ssl.selfSignedWarn") : mode === "acme" ? t("ssl.acmeNote") : undefined}
        footer={<><Button variant="ghost" onClick={() => setMode(null)}>{t("common.cancel")}</Button><Button variant="primary" disabled={!f.name} onClick={submit}>{t("common.save")}</Button></>}>
        <div className="flex flex-col gap-4">
          <Field label={t("common.name")}>{({ id }) => <Input id={id} value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} />}</Field>
          {mode === "import" ? (
            <>
              <Field label={t("ssl.certPem")}>{({ id }) => <Textarea id={id} dir="ltr" rows={6} className="font-mono text-xs" value={f.cert} onChange={(e) => setF({ ...f, cert: e.target.value })} />}</Field>
              <Field label={t("ssl.keyPem")}>{({ id }) => <Textarea id={id} dir="ltr" rows={4} className="font-mono text-xs" autoComplete="off" spellCheck={false} value={f.key} onChange={(e) => setF({ ...f, key: e.target.value })} />}</Field>
            </>
          ) : mode === "acme" ? (
            <>
              <Field label={t("ssl.hosts")} hint={t("ssl.acmeHosts")}>{({ id, describedBy }) => <Textarea id={id} aria-describedby={describedBy} dir="ltr" rows={3} value={f.hosts} onChange={(e) => setF({ ...f, hosts: e.target.value })} />}</Field>
              <Field label={t("ssl.directory")} hint={f.directory === "letsencrypt" ? t("ssl.prodWarn") : t("ssl.stagingNote")}>{({ id, describedBy }) => (
                <Select id={id} aria-describedby={describedBy} value={f.directory} onChange={(e) => setF({ ...f, directory: e.target.value })}>
                  <option value="letsencrypt-staging">Let&apos;s Encrypt (staging)</option><option value="letsencrypt">Let&apos;s Encrypt</option>
                </Select>
              )}</Field>
              <Field label={t("ssl.email")}>{({ id }) => <Input id={id} dir="ltr" type="email" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} />}</Field>
            </>
          ) : (
            <>
              <Field label={t("ssl.hosts")}>{({ id }) => <Textarea id={id} dir="ltr" rows={3} value={f.hosts} onChange={(e) => setF({ ...f, hosts: e.target.value })} />}</Field>
              <Field label={t("ssl.days")}>{({ id }) => <Input id={id} dir="ltr" type="number" min={1} max={825} value={f.days} onChange={(e) => setF({ ...f, days: Number(e.target.value) })} />}</Field>
            </>
          )}
          <FormError>{err}</FormError>
        </div>
      </Modal>
    </>
  );
}
