// The Control Center is normally served at the origin root (SSH tunnel) but
// can be published under a secret base path through Nginx (e.g. /a1b2c3d4/).
// The Go server injects <base href>; here we derive the base pathname so API
// calls, EventSource, download links and the router resolve under the mount.
function detect(): string {
  try {
    const el = document.querySelector("base");
    if (!el) return "";
    const p = new URL(el.getAttribute("href") || "/", location.origin).pathname;
    if (p.includes("__NGM_BASE__") || p === "/") return "";
    return p.replace(/\/+$/, "");
  } catch {
    return "";
  }
}

/** Base pathname with no trailing slash ("" at the root). */
export const BASE = detect();

/** Prefix a same-origin absolute path ("/api/...") with the panel base. */
export const apiUrl = (path: string): string => (path.startsWith("/") ? BASE + path : path);
