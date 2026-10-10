import { CheckCircle2, Circle } from "lucide-react";
import { Link } from "react-router-dom";
import { Card, CardHeader, Ltr } from "@/components/ui/primitives";
import { useI18n } from "@/i18n/i18n";
import type { MessageKey } from "@/i18n/messages";
import { api } from "@/lib/api";
import { useAsync } from "@/lib/hooks";

const LINKS: Record<string, string> = {
  certificate: "/web/ssl", default_website: "/web/websites", first_route: "/gateway/routes", verification: "/ops/deployments", management_origin: "/system/help",
};

/** First-run steps 3–7, evidence-based; hidden once everything is complete. */
export function SetupChecklist() {
  const { t } = useI18n();
  const s = useAsync(api.setupStatus);
  const steps = (s.data?.steps ?? []).filter((x) => x.id in LINKS);
  if (!steps.length || steps.every((x) => x.status === "complete")) return null;
  return (
    <Card className="lg:col-span-3">
      <CardHeader title={t("setup.checklist")} />
      <ul className="grid gap-2 px-5 pb-5 text-sm sm:grid-cols-2 lg:grid-cols-3">
        {steps.map((x) => (
          <li key={x.id} className="flex items-center gap-2">
            {x.status === "complete" ? <CheckCircle2 className="size-4 text-ok" aria-hidden /> : <Circle className="size-4 text-fg-muted" aria-hidden />}
            {x.status === "complete" ? <span>{t(`setup.step.${x.id}` as MessageKey)}</span> : <Link className="text-accent underline underline-offset-2" to={LINKS[x.id] ?? "/"}>{t(`setup.step.${x.id}` as MessageKey)}</Link>}
            {x.id === "management_origin" && x.status !== "complete" && <Ltr className="text-xs text-fg-muted">ngm admin set-origin https://…</Ltr>}
          </li>
        ))}
      </ul>
    </Card>
  );
}
