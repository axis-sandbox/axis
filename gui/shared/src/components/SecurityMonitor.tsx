import { createSignal, onMount, onCleanup, For } from "solid-js";
import { subscribeEvents, type AuditEvent } from "../api/client";

export function SecurityMonitor() {
  const [events, setEvents] = createSignal<AuditEvent[]>([]);
  const [connected, setConnected] = createSignal(false);
  const MAX_EVENTS = 500;

  let ws: WebSocket | null = null;

  function connect() {
    ws = subscribeEvents((event) => {
      setEvents((prev) => {
        const next = [event, ...prev];
        return next.length > MAX_EVENTS ? next.slice(0, MAX_EVENTS) : next;
      });
    });
    ws.onopen = () => setConnected(true);
    ws.onclose = () => {
      setConnected(false);
      // Reconnect after 2s.
      setTimeout(connect, 2000);
    };
  }

  onMount(() => connect());
  onCleanup(() => ws?.close());

  function formatTime(ts: string): string {
    const d = new Date(ts);
    return d.toLocaleTimeString([], { hour12: false, fractionalSecondDigits: 1 } as any);
  }

  return (
    <div class="panel">
      <div style={{ display: "flex", "align-items": "center", gap: "12px", "margin-bottom": "12px" }}>
        <h2 style={{ "font-size": "16px", "font-weight": "600" }}>Security Monitor</h2>
        <span style={{
          "font-size": "11px",
          padding: "2px 8px",
          "border-radius": "3px",
          background: connected() ? "#3fb95033" : "#f8514933",
          color: connected() ? "var(--success)" : "var(--danger)",
        }}>
          {connected() ? "LIVE" : "DISCONNECTED"}
        </span>
        <span style={{ "font-size": "12px", color: "var(--text-secondary)" }}>
          {events().length} events
        </span>
      </div>

      <div style={{ "overflow-y": "auto", "max-height": "calc(100vh - 120px)" }}>
        <For each={events()}>
          {(event) => (
            <div class="event-item">
              <span class="timestamp">{formatTime(event.timestamp)}</span>
              <span class={`severity ${event.severity}`}>{event.severity}</span>
              <span class="message">{event.message}</span>
            </div>
          )}
        </For>

        {events().length === 0 && (
          <div style={{ color: "var(--text-secondary)", "font-size": "13px", padding: "20px 0" }}>
            No events yet. Events will appear when sandboxes are running.
          </div>
        )}
      </div>
    </div>
  );
}
