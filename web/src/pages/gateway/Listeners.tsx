import { confirmDialog } from "@/components/Confirm";
import { Plus } from "lucide-react";
import { useState } from "react";
import { EmptyState, ErrorState, LoadingState } from "@/components/States";
import { Check, Field, FormError, Input, Modal, Select } from "@/components/ui/form";
import { Button, Card, Ltr, PageHeader } from "@/components/ui/primitives";
import { useI18n } from "@/i18n/i18n";
import type { MessageKey } from "@/i18n/messages";
import { gw, type Listener, type ListenerKind } from "@/lib/api";
import { useAsync } from "@/lib/hooks";
import { useSession } from "@/lib/session";
import { DesiredNote, Pill, RowMenu, bind, errText, tableCls, tdCls, thCls } from "./common";

const KINDS: ListenerKind[] = ["http", "https", "stream", "stream_tls_front"];

function ListenerForm({ initial, onClose, onDone }: { initial?: Listener; onClose: () => void; onDone: () => void }) {
  const { t } = useI18n();
  const [f, setF] = useState({
    name: initial?.name ?? "",
    kind: initial?.kind ?? ("http" as ListenerKind),
    address: initial?.address ?? "0.0.0.0",
    port: initial?.port ?? 80,
    enabled: initial?.enabled ?? true,
    http2: initial?.options.http2 ?? false,
    udp: initial?.options.udp ?? false,
  });
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const save = async () => {
    setBusy(true);
    setErr(null);
    const body = { name: f.name, kind: f.kind, address: f.address.trim(), port: Number(f.port), enabled: f.enabled, options: { http2: f.kind === "https" && f.http2, udp: f.kind === "stream" && f.udp } };
    try {
      if (initial) await gw.listeners.update(initial, body);
      else await gw.listeners.create(body);
      onDone();
      onClose();
    } catch (e) {
      setErr(errText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      open
      onOpenChange={(o) => !o && onClose()}
      title={initial ? initial.name : t("gw.listeners.new")}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>{t("common.cancel")}</Button>
          <Button variant="primary" disabled={busy || !f.name || !f.address || !f.port} onClick={save}>{t("common.save")}</Button>
        </>
      }
    >
      <form className="flex flex-col gap-4" onSubmit={(e) => { e.preventDefault(); void save(); }}>
        <Field label={t("common.name")}>{({ id }) => <Input id={id} value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} />}</Field>
        <Field label={t("gw.kind")} hint={t(`gw.kindHint.${f.kind}` as MessageKey)}>
          {({ id, describedBy }) => (
            <Select id={id} aria-describedby={describedBy} value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value as ListenerKind })}>
              {KINDS.map((k) => <option key={k} value={k}>{t(`gw.kind.${k}` as MessageKey)}</option>)}
            </Select>
          )}
        </Field>
        <div className="grid grid-cols-[1fr_7rem] gap-3">
          <Field label={t("gw.address")} hint={t("gw.addressHint")}>
            {({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} dir="ltr" value={f.address} onChange={(e) => setF({ ...f, address: e.target.value })} />}
          </Field>
          <Field label={t("gw.port")}>{({ id }) => <Input id={id} dir="ltr" type="number" min={1} max={65535} value={f.port} onChange={(e) => setF({ ...f, port: Number(e.target.value) })} />}</Field>
        </div>
        {f.kind === "https" && <Check checked={f.http2} onChange={(v) => setF({ ...f, http2: v })} label={t("gw.http2")} />}
        {f.kind === "stream" && <Check checked={f.udp} onChange={(v) => setF({ ...f, udp: v })} label={t("gw.udp")} hint={t("gw.udpHint")} />}
        <Check checked={f.enabled} onChange={(v) => setF({ ...f, enabled: v })} label={t("common.enabled")} />
        <FormError>{err}</FormError>
      </form>
    </Modal>
  );
}

export function ListenersPage() {
  const { t } = useI18n();
  const { can } = useSession();
  const ls = useAsync(gw.listeners.list);
  const routes = useAsync(gw.routes.list);
  const [edit, setEdit] = useState<Listener | "new" | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const writable = can("gateway.write");
  const count = (id: string) => routes.data?.items.filter((r) => r.listener_id === id).length ?? 0;
  return (
    <>
      <PageHeader
        title={t("gw.listeners.title")}
        subtitle={t("gw.listeners.subtitle")}
        actions={writable && <Button variant="primary" onClick={() => setEdit("new")}><Plus className="size-4" aria-hidden />{t("gw.listeners.new")}</Button>}
      />
      <DesiredNote />
      <FormError>{err}</FormError>
      <Card>
        {ls.status === "error" && !ls.data ? (
          <ErrorState error={ls.error} onRetry={ls.reload} />
        ) : !ls.data ? (
          <LoadingState />
        ) : ls.data.items.length === 0 ? (
          <EmptyState title={t("gw.listeners.new")} body={t("gw.listeners.subtitle")} />
        ) : (
          <div className="relative overflow-x-auto">
            <table className={tableCls}>
              <thead>
                <tr className="border-b border-border">
                  <th className={thCls}>{t("common.name")}</th>
                  <th className={thCls}>{t("gw.kind")}</th>
                  <th className={thCls}>{t("gw.address")}</th>
                  <th className={thCls}>{t("gw.routesCount")}</th>
                  <th className={thCls}><span className="sr-only">{t("common.actions")}</span></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {ls.data.items.map((l) => (
                  <tr key={l.id}>
                    <td className={tdCls}>
                      <span className="font-medium text-fg">{l.name}</span>
                      {!l.enabled && <span className="ms-2"><Pill>{t("common.disabled")}</Pill></span>}
                    </td>
                    <td className={tdCls}><Pill tone="accent">{t(`gw.kind.${l.kind}` as MessageKey)}</Pill>{l.options.http2 && <span className="ms-1"><Pill>h2</Pill></span>}</td>
                    <td className={tdCls}><Ltr>{bind(l)}</Ltr></td>
                    <td className={tdCls}>{count(l.id)}</td>
                    <td className={`${tdCls} text-end`}>
                      {writable && (
                        <RowMenu
                          label={`${t("common.edit")} ${l.name}`}
                          items={[
                            { label: t("common.edit"), onSelect: () => setEdit(l) },
                            { label: t("common.delete"), danger: true, onSelect: async () => {
                              if (!(await confirmDialog(t("common.confirmDelete", { name: l.name })))) return;
                              try { await gw.listeners.remove(l); ls.reload(); } catch (e) { setErr(errText(e)); }
                            } },
                          ]}
                        />
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      {edit && <ListenerForm initial={edit === "new" ? undefined : edit} onClose={() => setEdit(null)} onDone={ls.reload} />}
    </>
  );
}
