import { confirmDialog } from "@/components/Confirm";
import { MoreHorizontal, Plus, ShieldCheck, ShieldOff } from "lucide-react";
import * as Dropdown from "@radix-ui/react-dropdown-menu";
import { useState } from "react";
import { EmptyState, ErrorState, LoadingState } from "@/components/States";
import { Field, FormError, Input, Modal, Select } from "@/components/ui/form";
import { Button, Card, Ltr, PageHeader, cn } from "@/components/ui/primitives";
import { useI18n } from "@/i18n/i18n";
import { api, ApiError, type Role, type User } from "@/lib/api";
import { useAsync } from "@/lib/hooks";
import { useSession } from "@/lib/session";

const menuItem = "flex cursor-pointer select-none items-center gap-2 rounded-md px-2 py-1.5 text-sm text-fg outline-none data-[highlighted]:bg-surface-2";
const menuContent = "z-50 min-w-44 rounded-xl border border-border bg-surface p-1 shadow-card";

function errMsg(e: unknown) {
  return e instanceof ApiError ? e.message : String(e);
}

function CreateUser({ roles, onDone }: { roles: Role[]; onDone: () => void }) {
  const { t } = useI18n();
  const [open, setOpen] = useState(false);
  const [f, setF] = useState({ username: "", display: "", pw: "", role: roles.find((r) => r.name === "Viewer")?.id ?? "", locale: "fa" });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.createUser({ username: f.username.trim().toLowerCase(), display_name: f.display, password: f.pw, locale: f.locale, grants: [{ role_id: f.role, scope_kind: "global", scope_id: "" }] });
      setOpen(false);
      setF({ ...f, username: "", display: "", pw: "" });
      onDone();
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <Button variant="primary" onClick={() => setOpen(true)}>
        <Plus className="size-4" aria-hidden />
        {t("users.new")}
      </Button>
      <Modal
        open={open}
        onOpenChange={setOpen}
        title={t("users.new")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setOpen(false)}>{t("common.cancel")}</Button>
            <Button variant="primary" disabled={busy || !f.username || !f.pw || !f.role} onClick={submit}>{t("common.create")}</Button>
          </>
        }
      >
        <form className="flex flex-col gap-4" onSubmit={(e) => { e.preventDefault(); void submit(); }}>
          <Field label={t("auth.username")}>{({ id }) => <Input id={id} dir="ltr" autoCapitalize="none" value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} />}</Field>
          <Field label={t("setup.displayName")}>{({ id }) => <Input id={id} value={f.display} onChange={(e) => setF({ ...f, display: e.target.value })} />}</Field>
          <Field label={t("auth.password")} hint={t("setup.passwordRules")}>
            {({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} dir="ltr" type="password" autoComplete="new-password" value={f.pw} onChange={(e) => setF({ ...f, pw: e.target.value })} />}
          </Field>
          <Field label={t("users.role")}>
            {({ id }) => (
              <Select id={id} value={f.role} onChange={(e) => setF({ ...f, role: e.target.value })}>
                {roles.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
              </Select>
            )}
          </Field>
          <Field label={t("setup.language")}>
            {({ id }) => (
              <Select id={id} value={f.locale} onChange={(e) => setF({ ...f, locale: e.target.value })}>
                <option value="fa">فارسی</option>
                <option value="en">English</option>
              </Select>
            )}
          </Field>
          <FormError>{error}</FormError>
        </form>
      </Modal>
    </>
  );
}

function RoleModal({ user, roles, onClose, onDone }: { user: User | null; roles: Role[]; onClose: () => void; onDone: () => void }) {
  const { t } = useI18n();
  const [role, setRole] = useState(user?.grants.find((g) => g.scope_kind === "global")?.role_id ?? "");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  if (!user) return null;
  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      const scoped = user.grants.filter((g) => g.scope_kind !== "global");
      await api.updateUser(user, { grants: [{ role_id: role, scope_kind: "global", scope_id: "" }, ...scoped] });
      onDone();
      onClose();
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      open
      onOpenChange={(o) => !o && onClose()}
      title={<>{t("users.role")}: <Ltr>{user.username}</Ltr></>}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>{t("common.cancel")}</Button>
          <Button variant="primary" disabled={busy || !role} onClick={save}>{t("common.save")}</Button>
        </>
      }
    >
      <div className="flex flex-col gap-3">
        <Field label={t("users.role")}>
          {({ id }) => (
            <Select id={id} value={role} onChange={(e) => setRole(e.target.value)}>
              {roles.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
            </Select>
          )}
        </Field>
        <FormError>{error}</FormError>
      </div>
    </Modal>
  );
}

export function UsersPage() {
  const { t, formatDateTime } = useI18n();
  const { state, can } = useSession();
  const users = useAsync(api.users);
  const roles = useAsync(api.roles);
  const [editing, setEditing] = useState<User | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const me = state.status === "ready" ? state.session?.user.id : undefined;
  const writable = can("users.write");

  const act = async (fn: () => Promise<unknown>) => {
    setActionError(null);
    try {
      await fn();
      users.reload();
    } catch (e) {
      setActionError(errMsg(e));
    }
  };

  return (
    <>
      <PageHeader title={t("users.title")} subtitle={t("users.subtitle")} actions={writable && roles.data && <CreateUser roles={roles.data.items} onDone={users.reload} />} />
      <FormError>{actionError}</FormError>
      <Card className={cn(actionError && "mt-4")}>
        {users.status === "error" && !users.data ? (
          <ErrorState error={users.error} onRetry={users.reload} />
        ) : !users.data ? (
          <LoadingState />
        ) : users.data.items.length === 0 ? (
          <EmptyState title={t("users.title")} />
        ) : (
          <div className="relative overflow-x-auto">
            <table className="w-full min-w-[720px] text-sm">
              <thead>
                <tr className="border-b border-border text-xs text-fg-muted">
                  <th scope="col" className="px-5 py-3 text-start font-medium">{t("auth.username")}</th>
                  <th scope="col" className="px-5 py-3 text-start font-medium">{t("users.role")}</th>
                  <th scope="col" className="px-5 py-3 text-start font-medium">{t("users.status")}</th>
                  <th scope="col" className="px-5 py-3 text-start font-medium">{t("users.mfa")}</th>
                  <th scope="col" className="px-5 py-3 text-start font-medium">{t("users.lastLogin")}</th>
                  <th scope="col" className="px-5 py-3"><span className="sr-only">{t("common.edit")}</span></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {users.data.items.map((u) => (
                  <tr key={u.id}>
                    <td className="px-5 py-3">
                      <div className="font-medium text-fg">
                        <Ltr className="font-sans">{u.username}</Ltr>
                        {u.id === me && <span className="ms-2 rounded bg-accent-soft px-1.5 text-[11px] text-accent">{t("users.you")}</span>}
                      </div>
                      {u.display_name && <div className="text-xs text-fg-muted">{u.display_name}</div>}
                    </td>
                    <td className="px-5 py-3">
                      {u.grants.map((g) => (
                        <span key={g.role_id + g.scope_id} className="me-1 inline-flex rounded-full bg-surface-2 px-2 py-0.5 text-xs text-fg">
                          {g.role_name}
                          {g.scope_kind !== "global" && <span className="ms-1 text-fg-muted">({t("users.scoped")})</span>}
                        </span>
                      ))}
                    </td>
                    <td className="px-5 py-3">
                      <span className={cn("rounded-full px-2 py-0.5 text-xs font-medium", u.status === "active" ? "bg-ok-soft text-ok" : "bg-unknown-soft text-unknown")}>
                        {u.status === "active" ? t("users.active") : t("users.disabled")}
                      </span>
                    </td>
                    <td className="px-5 py-3">
                      <span className={cn("inline-flex items-center gap-1 text-xs", u.mfa_enabled ? "text-ok" : "text-warn")}>
                        {u.mfa_enabled ? <ShieldCheck className="size-3.5" aria-hidden /> : <ShieldOff className="size-3.5" aria-hidden />}
                        {u.mfa_enabled ? t("users.mfaOn") : t("users.mfaOff")}
                      </span>
                    </td>
                    <td className="px-5 py-3 text-xs text-fg-muted">{u.last_login_at ? formatDateTime(u.last_login_at) : t("common.never")}</td>
                    <td className="px-5 py-3 text-end">
                      {writable && u.id !== me && (
                        <Dropdown.Root>
                          <Dropdown.Trigger asChild>
                            <Button variant="ghost" size="icon" aria-label={`${t("common.edit")} ${u.username}`}>
                              <MoreHorizontal className="size-4" aria-hidden />
                            </Button>
                          </Dropdown.Trigger>
                          <Dropdown.Portal>
                            <Dropdown.Content align="end" sideOffset={4} className={menuContent}>
                              <Dropdown.Item className={menuItem} onSelect={() => setEditing(u)}>{t("users.role")}</Dropdown.Item>
                              <Dropdown.Item className={menuItem} onSelect={() => act(() => api.updateUser(u, { status: u.status === "active" ? "disabled" : "active" }))}>
                                {u.status === "active" ? t("users.disable") : t("users.enable")}
                              </Dropdown.Item>
                              <Dropdown.Item className={menuItem} onSelect={() => act(() => api.resetUserMFA(u))}>{t("users.resetMfa")}</Dropdown.Item>
                              <Dropdown.Separator className="my-1 h-px bg-border" />
                              <Dropdown.Item
                                className={cn(menuItem, "text-bad")}
                                onSelect={async () => { if (await confirmDialog(t("common.confirmDelete", { name: u.username }), { typed: u.username })) act(() => api.deleteUser(u)); }}
                              >
                                {t("common.delete")}
                              </Dropdown.Item>
                            </Dropdown.Content>
                          </Dropdown.Portal>
                        </Dropdown.Root>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      {editing && roles.data && <RoleModal user={editing} roles={roles.data.items} onClose={() => setEditing(null)} onDone={users.reload} />}
    </>
  );
}
