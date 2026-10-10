import { confirmDialog } from "@/components/Confirm";
import { Lock, Plus, ShieldAlert } from "lucide-react";
import { useMemo, useState } from "react";
import { ErrorState, LoadingState } from "@/components/States";
import { Field, FormError, Input, Modal } from "@/components/ui/form";
import { Button, Card, Ltr, PageHeader } from "@/components/ui/primitives";
import { useI18n } from "@/i18n/i18n";
import { api, ApiError, type Permission, type Role } from "@/lib/api";
import { useAsync } from "@/lib/hooks";
import { useSession } from "@/lib/session";

const RESERVED = new Set(["owner.transfer", "system.purge"]);

function RoleEditor({ role, perms, onClose, onDone }: { role: Role | "new"; perms: Permission[]; onClose: () => void; onDone: () => void }) {
  const { t } = useI18n();
  const { can } = useSession();
  const init = role === "new" ? { name: "", description: "", permissions: [] as string[] } : role;
  const [name, setName] = useState(init.name);
  const [desc, setDesc] = useState(init.description);
  const [sel, setSel] = useState(new Set(init.permissions));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const groups = useMemo(() => {
    const m = new Map<string, Permission[]>();
    for (const p of perms) {
      if (RESERVED.has(p.id)) continue;
      const g = p.id.split(".")[0]!;
      m.set(g, [...(m.get(g) ?? []), p]);
    }
    return [...m.entries()];
  }, [perms]);
  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      const body = { name, description: desc, permissions: [...sel] };
      if (role === "new") await api.createRole(body);
      else await api.updateRole(role, body);
      onDone();
      onClose();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      open
      wide
      onOpenChange={(o) => !o && onClose()}
      title={role === "new" ? t("roles.new") : role.name}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>{t("common.cancel")}</Button>
          <Button variant="primary" disabled={busy || !name || sel.size === 0} onClick={save}>{t("common.save")}</Button>
        </>
      }
    >
      <div className="flex flex-col gap-4">
        <Field label={t("roles.name")}>{({ id }) => <Input id={id} value={name} maxLength={48} onChange={(e) => setName(e.target.value)} />}</Field>
        <Field label={t("roles.description")}>{({ id }) => <Input id={id} value={desc} maxLength={200} onChange={(e) => setDesc(e.target.value)} />}</Field>
        <fieldset>
          <legend className="mb-2 text-sm font-medium text-fg">{t("roles.permissions")}</legend>
          <div className="grid gap-3 sm:grid-cols-2">
            {groups.map(([g, ps]) => (
              <div key={g} className="rounded-lg border border-border p-3">
                <div className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-fg-muted"><Ltr className="font-sans">{g}</Ltr></div>
                {ps.map((p) => {
                  const holdable = can(p.id);
                  return (
                    <label key={p.id} className="flex items-center gap-2 py-0.5 text-sm">
                      <input
                        type="checkbox"
                        className="size-4 accent-[var(--accent)]"
                        checked={sel.has(p.id)}
                        disabled={!holdable}
                        onChange={(e) => {
                          const n = new Set(sel);
                          if (e.target.checked) n.add(p.id);
                          else n.delete(p.id);
                          setSel(n);
                        }}
                      />
                      <Ltr className="text-fg">{p.id}</Ltr>
                      {p.step_up && <ShieldAlert className="size-3.5 text-warn" aria-label={t("roles.stepUp")} />}
                    </label>
                  );
                })}
              </div>
            ))}
          </div>
        </fieldset>
        <FormError>{error}</FormError>
      </div>
    </Modal>
  );
}

export function RolesPage() {
  const { t } = useI18n();
  const { can } = useSession();
  const roles = useAsync(api.roles);
  const perms = useAsync(api.permissions);
  const [editing, setEditing] = useState<Role | "new" | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const writable = can("roles.write");
  return (
    <>
      <PageHeader
        title={t("roles.title")}
        subtitle={t("roles.subtitle")}
        actions={writable && (
          <Button variant="primary" onClick={() => setEditing("new")}>
            <Plus className="size-4" aria-hidden />
            {t("roles.new")}
          </Button>
        )}
      />
      <FormError>{err}</FormError>
      {roles.status === "error" && !roles.data ? (
        <Card><ErrorState error={roles.error} onRetry={roles.reload} /></Card>
      ) : !roles.data ? (
        <Card><LoadingState /></Card>
      ) : (
        <div className="grid gap-4 md:grid-cols-2">
          {roles.data.items.map((r) => (
            <Card key={r.id} className="flex flex-col p-5">
              <div className="mb-1 flex items-center gap-2">
                <h2 className="font-semibold text-fg">{r.name}</h2>
                {r.builtin && (
                  <span className="inline-flex items-center gap-1 rounded-full bg-surface-2 px-2 py-0.5 text-[11px] text-fg-muted">
                    <Lock className="size-3" aria-hidden />
                    {t("roles.builtin")}
                  </span>
                )}
              </div>
              <p className="mb-3 text-sm text-fg-muted">{r.description}</p>
              <div className="mb-3 flex flex-wrap gap-1">
                {r.permissions.map((p) => (
                  <span key={p} className="rounded bg-surface-2 px-1.5 py-0.5 text-[11px]"><Ltr>{p}</Ltr></span>
                ))}
              </div>
              {!r.builtin && writable && (
                <div className="mt-auto flex gap-2">
                  <Button size="sm" variant="outline" onClick={() => setEditing(r)}>{t("common.edit")}</Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="text-bad"
                    onClick={async () => {
                      if (!(await confirmDialog(t("common.confirmDelete", { name: r.name })))) return;
                      setErr(null);
                      try {
                        await api.deleteRole(r);
                        roles.reload();
                      } catch (e) {
                        setErr(e instanceof ApiError ? e.message : String(e));
                      }
                    }}
                  >
                    {t("common.delete")}
                  </Button>
                </div>
              )}
            </Card>
          ))}
        </div>
      )}
      {editing && perms.data && <RoleEditor role={editing} perms={perms.data.items} onClose={() => setEditing(null)} onDone={roles.reload} />}
    </>
  );
}
