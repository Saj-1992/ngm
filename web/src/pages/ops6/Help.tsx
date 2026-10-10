import type { MessageKey } from "@/i18n/messages";
import { Card, PageHeader } from "@/components/ui/primitives";
import { useI18n } from "@/i18n/i18n";

const TOPICS = ["origin", "safeApply", "shared443", "firewall", "backups", "recovery", "websites", "acme", "logs", "cli"] as const;

/** Built-in help: short, accurate explanations of how NGM behaves. */
export function HelpPage() {
  const { t } = useI18n();
  return (
    <>
      <PageHeader title={t("help.title")} subtitle={t("help.subtitle")} />
      <div className="grid gap-4 md:grid-cols-2">
        {TOPICS.map((k) => (
          <Card key={k} className="p-5 text-sm">
            <h2 className="mb-1 font-semibold text-fg">{t(`help.${k}.t` as MessageKey)}</h2>
            <p className="text-fg-muted" dir="auto">{t(`help.${k}.b` as MessageKey)}</p>
          </Card>
        ))}
      </div>
    </>
  );
}
