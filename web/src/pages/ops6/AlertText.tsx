import { Ltr } from "@/components/ui/primitives";
import { useI18n } from "@/i18n/i18n";
import { en, type MessageKey } from "@/i18n/messages";

/**
 * Alert messages are produced by the server in English. In Persian, the rule
 * code selects a translated headline and the original text stays visible as
 * an LTR detail (it carries exact values: names, versions, errors).
 */
export function AlertText({ rule, subject, message }: { rule: string; subject: string; message: string }) {
  const { t, locale } = useI18n();
  const k = `alert.rule.${rule}` as MessageKey;
  if (locale !== "fa" || !(k in en)) return <span dir="auto">{message}</span>;
  return (
    <span className="flex min-w-0 flex-col">
      <span>{t(k, { subject })}</span>
      <Ltr className="truncate text-xs text-fg-muted">{message}</Ltr>
    </span>
  );
}
