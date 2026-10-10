import { useCallback, useEffect, useRef, useState } from "react";
import { apiUrl } from "./base";

export type AsyncState<T> =
  | { status: "loading"; data?: T; error?: undefined }
  | { status: "success"; data: T; error?: undefined }
  | { status: "error"; data?: T; error: unknown };

/** Loads data with fn; `reload` re-runs it while keeping stale data visible. */
export function useAsync<T>(fn: () => Promise<T>, deps: unknown[] = []) {
  const [state, setState] = useState<AsyncState<T>>({ status: "loading" });
  const seq = useRef(0);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const run = useCallback(fn, deps);

  const reload = useCallback(() => {
    const my = ++seq.current;
    setState((s) => ({ status: "loading", data: s.data }));
    run().then(
      (data) => my === seq.current && setState({ status: "success", data }),
      (error) => my === seq.current && setState((s) => ({ status: "error", error, data: s.data })),
    );
  }, [run]);

  useEffect(() => {
    reload();
  }, [reload]);

  return { ...state, reload };
}

export type LiveStatus = "connecting" | "connected" | "offline" | "resync";

/**
 * Subscribes to /api/v1/events. The browser's EventSource sends Last-Event-ID
 * on reconnect, so the server replays missed events; on `resync` the caller
 * refetches authoritative state (SSE is notification only, not state).
 */
export function useLiveEvents(onEvent: (type: string, data: unknown) => void, onResync: () => void): LiveStatus {
  const [status, setStatus] = useState<LiveStatus>("connecting");
  const handlers = useRef({ onEvent, onResync });
  handlers.current = { onEvent, onResync };

  useEffect(() => {
    if (typeof EventSource === "undefined") {
      setStatus("offline");
      return;
    }
    const es = new EventSource(apiUrl("/api/v1/events"));
    es.onopen = () => setStatus("connected");
    es.onerror = () => setStatus(es.readyState === EventSource.CLOSED ? "offline" : "connecting");
    es.addEventListener("resync", () => {
      setStatus("resync");
      handlers.current.onResync();
      setStatus("connected");
    });
    const relay = (ev: MessageEvent) => {
      try {
        handlers.current.onEvent(ev.type, JSON.parse(ev.data));
      } catch {
        /* ignore malformed */
      }
    };
    for (const t of ["job.updated", "job.created", "health.changed", "gateway.changed", "gateway.active"]) es.addEventListener(t, relay);
    return () => es.close();
  }, []);

  return status;
}
