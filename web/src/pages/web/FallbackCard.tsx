import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Field, FormError, Select } from "@/components/ui/form";
import { Button, Card, CardHeader } from "@/components/ui/primitives";
import { useI18n } from "@/i18n/i18n";
import { fallbackApi, gw, web } from "@/lib/api";
import { useAsync } from "@/lib/hooks";
import { useSession } from "@/lib/session";
import { Pill, errText } from "../gateway/common";

/**
 * Fallback website (ADR-036): what unknown hosts, IP-only visitors, scanners
 * and crawlers see instead of a closed connection or a TLS error.
 */
export function FallbackCard() {
  const { t } = useI18n();
  const { can } = useSession();
  const cur = useAsync(fallbackApi.get);
  const sites = useAsync(web.sites.list);
  const certs = useAsync(() => (can("certificates.read") ? gw.certificates.list() : Promise.resolve({ items: [] })));
  const [site, setSite] = useState("");
  const [cert, setCert] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  useEffect(() => {
    if (cur.data) {
      setSite(cur.data.fallback.website_id ?? "");
      setCert(cur.data.fallback.certificate_id ?? "");
    }
  }, [cur.data]);
  const writable = can("gateway.write");
  const save = async (w: string, c: string) => {
    setErr(null);
    setMsg(null);
    try {
      await fallbackApi.put({ website_id: w, certificate_id: c });
      setMsg(t("fb.saved"));
      cur.reload();
    } catch (e) {
      setErr(errText(e));
    }
  };
  const published = (sites.data?.items ?? []).filter((s) => s.active_version_id);
  return (
    <Card className="mb-4">
      <CardHeader title={t("fb.title")} action={<Pill tone={cur.data?.enabled ? "ok" : "warn"}>{t(cur.data?.enabled ? "fb.on" : "fb.off")}</Pill>} />
      <div className="flex flex-col gap-3 px-5 pb-5 text-sm">
        <p className="text-fg-muted">{t("fb.body")}</p>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label={t("fb.website")}>{({ id }) => (
            <Select id={id} value={site} disabled={!writable} onChange={(e) => setSite(e.target.value)}>
              <option value="">{t("fb.none")}</option>
              {published.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
            </Select>
          )}</Field>
          <Field label={t("fb.certificate")}>{({ id }) => (
            <Select id={id} value={cert} disabled={!writable} onChange={(e) => setCert(e.target.value)}>
              <option value="">{t("fb.none")}</option>
              {(certs.data?.items ?? []).filter((c) => c.has_key && c.status !== "expired").map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </Select>
          )}</Field>
        </div>
        <FormError>{err}</FormError>
        {msg && <p className="text-ok" role="status">{msg} <Link className="text-accent underline underline-offset-2" to="/ops/deployments">{t("perf.deploy")}</Link></p>}
        {writable && (
          <div className="flex flex-wrap gap-2">
            <Button variant="primary" disabled={!site || !cert} onClick={() => save(site, cert)}>{t("common.save")}</Button>
            {cur.data?.enabled && <Button variant="ghost" onClick={() => save("", "")}>{t("fb.disable")}</Button>}
          </div>
        )}
      </div>
    </Card>
  );
}
