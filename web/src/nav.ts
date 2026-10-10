import {
  Activity, Archive, FileClock, ArrowLeftRight, BookOpen, Cable, FlaskConical, Gauge, Globe, LayoutDashboard, LifeBuoy,
  Lock, Network, Rocket, ScrollText, Server, Settings, Shield, ShieldCheck, Users, Waypoints,
} from "lucide-react";
import type { MessageKey } from "./i18n/messages";

export type NavItem = {
  path: string;
  label: MessageKey;
  icon: typeof Activity;
  /** Phase in which the page is delivered; undefined = available now. */
  phase?: number;
  /** Permission required to see the entry (hidden otherwise; the API enforces it regardless). */
  perm?: string;
};

export type NavGroup = { label: MessageKey; items: NavItem[] };

// MASTER_SPEC §15 primary navigation.
export const navGroups: NavGroup[] = [
  {
    label: "nav.overview",
    items: [
      { path: "/", label: "nav.dashboard", icon: LayoutDashboard },
      { path: "/monitoring", label: "nav.monitoring", icon: Activity, perm: "monitoring.read" },
      { path: "/logs", label: "nav.logs", icon: ScrollText, perm: "logs.read" },
      { path: "/topology", label: "nav.topology", icon: Waypoints, perm: "topology.read" },
    ],
  },
  {
    label: "nav.gateway",
    items: [
      { path: "/gateway/listeners", label: "nav.listeners", icon: Cable },
      { path: "/gateway/routes", label: "nav.routes", icon: Waypoints },
      { path: "/gateway/backends", label: "nav.backends", icon: Server },
      { path: "/gateway/simulation", label: "nav.simulation", icon: FlaskConical },
    ],
  },
  {
    label: "nav.web",
    items: [
      { path: "/web/websites", label: "nav.websites", icon: Globe, perm: "websites.read" },
      { path: "/web/domains", label: "nav.domains", icon: Network, perm: "domains.read" },
      { path: "/web/dns", label: "nav.dns", icon: ArrowLeftRight, perm: "domains.read" },
      { path: "/web/ssl", label: "nav.ssl", icon: Lock, perm: "certificates.read" },
    ],
  },
  {
    label: "nav.operations",
    items: [
      { path: "/ops/firewall", label: "nav.firewall", icon: Shield, perm: "firewall.read" },
      { path: "/ops/backups", label: "nav.backups", icon: Archive, perm: "backups.read" },
      { path: "/ops/deployments", label: "nav.deployments", icon: Rocket },
      { path: "/ops/recovery", label: "nav.recovery", icon: LifeBuoy, perm: "recovery.read" },
    ],
  },
  {
    label: "nav.system",
    items: [
      { path: "/system/performance", label: "nav.performance", icon: Gauge, perm: "performance.read" },
      { path: "/system/users", label: "nav.users", icon: Users, perm: "users.read" },
      { path: "/system/roles", label: "nav.roles", icon: ShieldCheck, perm: "roles.read" },
      { path: "/system/audit", label: "nav.audit", icon: FileClock, perm: "audit.read" },
      { path: "/system/settings", label: "nav.settings", icon: Settings },
      { path: "/system/help", label: "nav.help", icon: BookOpen },
    ],
  },
];
