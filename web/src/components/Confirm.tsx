import { useEffect, useState } from "react";
import { Input, Modal } from "@/components/ui/form";
import { Button } from "@/components/ui/primitives";
import { useI18n } from "@/i18n/i18n";

type Req = { message: string; danger: boolean; typed?: string; resolve: (ok: boolean) => void };
let open: ((r: Req) => void) | null = null;

/** Accessible replacement for window.confirm (Radix dialog, localised, RTL-aware). */
/** With typed set, the action stays disabled until that exact text is typed (critical deletions). */
export function confirmDialog(message: string, opts: { danger?: boolean; typed?: string } = {}): Promise<boolean> {
  return new Promise((resolve) => {
    if (!open) return resolve(false); // fail closed if no host is mounted
    open({ message, danger: opts.danger ?? true, typed: opts.typed, resolve });
  });
}

export function ConfirmHost() {
  const { t } = useI18n();
  const [req, setReq] = useState<Req | null>(null);
  const [text, setText] = useState("");
  useEffect(() => {
    open = setReq;
    return () => {
      open = null;
    };
  }, []);
  const done = (ok: boolean) => {
    req?.resolve(ok);
    setReq(null);
    setText("");
  };
  return (
    <Modal open={!!req} onOpenChange={(o) => !o && done(false)} title={t("common.confirmTitle")}
      footer={<><Button variant="ghost" onClick={() => done(false)}>{t("common.cancel")}</Button>
        <Button variant={req?.danger ? "danger" : "primary"} autoFocus={!req?.typed} disabled={!!req?.typed && text !== req.typed} onClick={() => done(true)}>{t("common.confirm")}</Button></>}>
      <p className="text-sm text-fg" dir="auto">{req?.message}</p>
      {req?.typed && (
        <label className="mt-3 flex flex-col gap-1 text-sm">
          <span>{t("common.typeToConfirm", { text: req.typed })}</span>
          <Input dir="ltr" autoFocus autoComplete="off" value={text} onChange={(e) => setText(e.target.value)} />
        </label>
      )}
    </Modal>
  );
}
