import { Suspense, lazy, useCallback } from "react";
import { Link, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { Layout } from "@/components/Layout";
import { ErrorState, LoadingState, PlannedState } from "@/components/States";
import { Button, PageHeader } from "@/components/ui/primitives";
import { AppTooltipProvider } from "@/components/ui/tooltip";
import { useI18n } from "@/i18n/i18n";
import { api } from "@/lib/api";
import { useAsync, useLiveEvents } from "@/lib/hooks";
import { useSession } from "@/lib/session";
import { navGroups } from "@/nav";
import { LoginPage, MfaEnrollPage, MfaVerifyPage } from "@/pages/AuthPages";
import { Dashboard } from "@/pages/Dashboard";
import { SetupPage } from "@/pages/Setup";
import { ConfirmHost } from "@/components/Confirm";
import { CommandPalette } from "@/components/CommandPalette";

const AuditPage = lazy(() => import("@/pages/Audit").then((m) => ({ default: m.AuditPage })));
const BackendsPage = lazy(() => import("@/pages/gateway/Backends").then((m) => ({ default: m.BackendsPage })));
const CertificatesPage = lazy(() => import("@/pages/gateway/Certificates").then((m) => ({ default: m.CertificatesPage })));
const DeploymentsPage = lazy(() => import("@/pages/gateway/Deployments").then((m) => ({ default: m.DeploymentsPage })));
const ListenersPage = lazy(() => import("@/pages/gateway/Listeners").then((m) => ({ default: m.ListenersPage })));
const RoutesPage = lazy(() => import("@/pages/gateway/Routes").then((m) => ({ default: m.RoutesPage })));
const SimulationPage = lazy(() => import("@/pages/gateway/Simulation").then((m) => ({ default: m.SimulationPage })));
const RolesPage = lazy(() => import("@/pages/Roles").then((m) => ({ default: m.RolesPage })));
const SettingsPage = lazy(() => import("@/pages/Settings").then((m) => ({ default: m.SettingsPage })));
const UsersPage = lazy(() => import("@/pages/Users").then((m) => ({ default: m.UsersPage })));
const BackupsPage = lazy(() => import("@/pages/ops/Backups").then((m) => ({ default: m.BackupsPage })));
const FirewallPage = lazy(() => import("@/pages/ops/Firewall").then((m) => ({ default: m.FirewallPage })));
const RecoveryPage = lazy(() => import("@/pages/ops/Recovery").then((m) => ({ default: m.RecoveryPage })));
const DnsPage = lazy(() => import("@/pages/web/Dns").then((m) => ({ default: m.DnsPage })));
const DomainsPage = lazy(() => import("@/pages/web/Domains").then((m) => ({ default: m.DomainsPage })));
const CloudflareZonesPage = lazy(() => import("@/pages/web/CloudflareZones").then((m) => ({ default: m.CloudflareZonesPage })));
const WebsitesPage = lazy(() => import("@/pages/web/Websites").then((m) => ({ default: m.WebsitesPage })));
const WebsiteDetailPage = lazy(() => import("@/pages/web/Websites").then((m) => ({ default: m.WebsiteDetailPage })));
const MonitoringPage = lazy(() => import("@/pages/ops6/Monitoring").then((m) => ({ default: m.MonitoringPage })));
const LogsPage = lazy(() => import("@/pages/ops6/Logs").then((m) => ({ default: m.LogsPage })));
const PerformancePage = lazy(() => import("@/pages/ops6/Performance").then((m) => ({ default: m.PerformancePage })));
const TopologyPage = lazy(() => import("@/pages/ops6/Topology").then((m) => ({ default: m.TopologyPage })));
const HelpPage = lazy(() => import("@/pages/ops6/Help").then((m) => ({ default: m.HelpPage })));

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
      <Suspense fallback={<LoadingState />}>
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
      </Suspense>
    </Layout>
  );
}

/**
 * Routes by authentication state: first-run setup → sign-in → MFA → console.
 * The server enforces every rule; this only chooses the right screen.
 */
export function App() {
  return (
    <AppTooltipProvider>
      <AppInner />
    </AppTooltipProvider>
  );
}

function AppInner() {
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
