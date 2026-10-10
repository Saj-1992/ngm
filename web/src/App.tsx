import { useCallback } from "react";
import { Link, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { Layout } from "@/components/Layout";
import { ErrorState, LoadingState, PlannedState } from "@/components/States";
import { Button, PageHeader } from "@/components/ui/primitives";
import { useI18n } from "@/i18n/i18n";
import { api } from "@/lib/api";
import { useAsync, useLiveEvents } from "@/lib/hooks";
import { useSession } from "@/lib/session";
import { navGroups } from "@/nav";
import { AuditPage } from "@/pages/Audit";
import { LoginPage, MfaEnrollPage, MfaVerifyPage } from "@/pages/AuthPages";
import { Dashboard } from "@/pages/Dashboard";
import { BackendsPage } from "@/pages/gateway/Backends";
import { CertificatesPage } from "@/pages/gateway/Certificates";
import { DeploymentsPage } from "@/pages/gateway/Deployments";
import { ListenersPage } from "@/pages/gateway/Listeners";
import { RoutesPage } from "@/pages/gateway/Routes";
import { SimulationPage } from "@/pages/gateway/Simulation";
import { RolesPage } from "@/pages/Roles";
import { SettingsPage } from "@/pages/Settings";
import { SetupPage } from "@/pages/Setup";
import { UsersPage } from "@/pages/Users";
import { BackupsPage } from "@/pages/ops/Backups";
import { DnsPage } from "@/pages/web/Dns";
import { DomainsPage } from "@/pages/web/Domains";
import { CloudflareZonesPage } from "@/pages/web/CloudflareZones";
import { WebsiteDetailPage, WebsitesPage } from "@/pages/web/Websites";
import { FirewallPage } from "@/pages/ops/Firewall";
import { RecoveryPage } from "@/pages/ops/Recovery";
import { ConfirmHost } from "@/components/Confirm";
import { CommandPalette } from "@/components/CommandPalette";
import { MonitoringPage } from "@/pages/ops6/Monitoring";
import { LogsPage } from "@/pages/ops6/Logs";
import { PerformancePage } from "@/pages/ops6/Performance";
import { TopologyPage } from "@/pages/ops6/Topology";
import { HelpPage } from "@/pages/ops6/Help";

function NotFound() {
  const { t } = useI18n();
  return (
    <div className="py-16 text-center">
      <h1 className="text-xl font-semibold text-fg">{t("notFound.title")}</h1>
      <Button asChild variant="outline" className="mt-4">
        <Link to="/">{t("notFound.back")}</Link>
      </Button>
    </div>
  );
}

function Console() {
  const { t } = useI18n();
  const health = useAsync(api.health);
  const version = useAsync(api.version);
  const jobs = useAsync(() => api.jobs({ limit: 50 }));

  const onEvent = useCallback(
    (type: string) => {
      if (type.startsWith("job.") || type === "gateway.active") jobs.reload();
      if (type === "health.changed") health.reload();
    },
    [jobs.reload, health.reload],
  );
  const onResync = useCallback(() => {
    health.reload();
    jobs.reload();
  }, [health.reload, jobs.reload]);
  const live = useLiveEvents(onEvent, onResync);
  const planned = navGroups.flatMap((g) => g.items).filter((i) => i.phase);

  return (
    <Layout live={live}>
      <ConfirmHost />
      <CommandPalette />
      <Routes>
        <Route path="/" element={<Dashboard health={health} version={version} jobs={jobs} />} />
        <Route path="/ops/deployments" element={<DeploymentsPage jobs={jobs} />} />
        <Route path="/ops/firewall" element={<FirewallPage />} />
        <Route path="/ops/backups" element={<BackupsPage />} />
        <Route path="/ops/recovery" element={<RecoveryPage />} />
        <Route path="/gateway/listeners" element={<ListenersPage />} />
        <Route path="/gateway/routes" element={<RoutesPage />} />
        <Route path="/gateway/backends" element={<BackendsPage />} />
        <Route path="/gateway/simulation" element={<SimulationPage />} />
        <Route path="/web/ssl" element={<CertificatesPage />} />
        <Route path="/web/websites" element={<WebsitesPage />} />
        <Route path="/web/websites/:id" element={<WebsiteDetailPage />} />
        <Route path="/web/domains" element={<DomainsPage />} />
        <Route path="/web/cloudflare" element={<CloudflareZonesPage />} />
        <Route path="/web/dns" element={<DnsPage />} />
        <Route path="/system/users" element={<UsersPage />} />
        <Route path="/system/roles" element={<RolesPage />} />
        <Route path="/system/audit" element={<AuditPage />} />
        <Route path="/system/settings" element={<SettingsPage />} />
        <Route path="/monitoring" element={<MonitoringPage />} />
        <Route path="/logs" element={<LogsPage />} />
        <Route path="/topology" element={<TopologyPage />} />
        <Route path="/system/performance" element={<PerformancePage />} />
        <Route path="/system/help" element={<HelpPage />} />
        <Route path="/setup" element={<Navigate to="/" replace />} />
        <Route path="/login" element={<Navigate to="/" replace />} />
        {planned.map((p) => (
          <Route
            key={p.path}
            path={p.path}
            element={
              <>
                <PageHeader title={t(p.label)} />
                <PlannedState phase={p.phase!} />
              </>
            }
          />
        ))}
        <Route path="*" element={<NotFound />} />
      </Routes>
    </Layout>
  );
}

/**
 * Routes by authentication state: first-run setup → sign-in → MFA → console.
 * The server enforces every rule; this only chooses the right screen.
 */
export function App() {
  const { state, refresh } = useSession();
  const loc = useLocation();
  if (state.status === "loading") return <LoadingState />;
  if (state.status === "error") return <ErrorState error={state.error} onRetry={() => void refresh()} />;
  const { setup, session } = state;
  const onSetup = loc.pathname.startsWith("/setup");
  // First run: no user exists yet → wizard (always under /setup).
  if (!setup.initialized) return onSetup ? <SetupPage /> : <Navigate to="/setup" replace />;
  if (!session) return <LoginPage />;
  if (session.stage === "mfa_enroll") {
    // Continue the wizard right after owner creation; otherwise (e.g. after
    // `ngm admin reset` or an MFA reset) use the standalone enrolment screen.
    return onSetup && !setup.owner_ready ? <SetupPage /> : <MfaEnrollPage />;
  }
  if (session.stage === "pending_mfa") return <MfaVerifyPage />;
  return <Console />;
}
