import { Construction, Inbox, Loader2, Lock, RefreshCw, ShieldAlert, WifiOff } from "lucide-react";
import type { ReactNode } from "react";
import { ApiError } from "@/lib/api";
import { useI18n } from "@/i18n/i18n";
import { Button, Card, Ltr } from "./ui/primitives";

function Shell({ icon, title, body, action }: { icon: ReactNode; title: ReactNode; body?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-14 text-center">
      <div className="flex size-12 items-center justify-center rounded-2xl bg-surface-2 text-fg-muted">{icon}</div>
      <div className="text-base font-semibold text-fg">{title}</div>
      {body && <div className="max-w-md text-sm text-fg-muted">{body}</div>}
      {action}
    </div>
  );
}

export function LoadingState() {
  const { t } = useI18n();
  return (
    <div role="status" aria-live="polite" className="flex items-center justify-center gap-2 py-14 text-sm text-fg-muted">
      <Loader2 aria-hidden className="size-4 animate-spin" />
      {t("common.loading")}
    </div>
  );
}

export function EmptyState({ title, body }: { title: ReactNode; body?: ReactNode }) {
  return <Shell icon={<Inbox aria-hidden className="size-6" />} title={title} body={body} />;
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const { t } = useI18n();
  const e = error instanceof ApiError ? error : undefined;
  if (e?.status === 401) {
    return <Shell icon={<Lock aria-hidden className="size-6" />} title={t("common.unauthenticated")} body={t("common.unauthenticatedHint")} />;
  }
  if (e?.status === 403) {
    return <Shell icon={<ShieldAlert aria-hidden className="size-6" />} title={t("common.forbidden")} />;
  }
  return (
    <Shell
      icon={e?.status === 0 ? <WifiOff aria-hidden className="size-6" /> : <ShieldAlert aria-hidden className="size-6" />}
      title={t("common.error")}
      body={
        <>
          {e?.message ?? String(error)}
          {e?.requestId && (
            <div className="mt-1 text-xs">
              {t("common.requestId")}: <Ltr>{e.requestId}</Ltr>
            </div>
          )}
        </>
      }
      action={
        onRetry && (
          <Button variant="outline" size="sm" onClick={onRetry}>
            <RefreshCw aria-hidden className="size-4" />
            {t("common.retry")}
          </Button>
        )
      }
    />
  );
}

/** Honest placeholder for V1 areas not yet built. Shows no fake data. */
export function PlannedState({ phase }: { phase: number }) {
  const { t } = useI18n();
  return (
    <Card>
      <Shell
        icon={<Construction aria-hidden className="size-6" />}
        title={t("planned.title")}
        body={t("planned.body", { phase })}
        action={<span className="rounded-full bg-accent-soft px-3 py-1 text-xs font-medium text-accent">{t("planned.phase", { phase })}</span>}
      />
    </Card>
  );
}
