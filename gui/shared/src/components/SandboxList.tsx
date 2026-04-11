import { createSignal, createResource, For } from "solid-js";
import { listSandboxes, destroySandbox, type Sandbox } from "../api/client";

interface SandboxListProps {
  onOpenTerminal: (sandboxId: string) => void;
}

export function SandboxList(props: SandboxListProps) {
  const [sandboxes, { refetch }] = createResource(listSandboxes);
  const [destroying, setDestroying] = createSignal<string | null>(null);

  async function handleDestroy(id: string) {
    setDestroying(id);
    try {
      await destroySandbox(id);
      refetch();
    } catch (e: any) {
      console.error("destroy failed:", e);
    } finally {
      setDestroying(null);
    }
  }

  return (
    <div class="panel">
      <div style={{ display: "flex", "align-items": "center", gap: "12px", "margin-bottom": "16px" }}>
        <h2 style={{ "font-size": "16px", "font-weight": "600" }}>Running Sandboxes</h2>
        <button class="btn" onClick={() => refetch()}>Refresh</button>
      </div>

      <For each={sandboxes()} fallback={
        <div style={{ color: "var(--text-secondary)", "font-size": "13px" }}>
          {sandboxes.loading ? "Loading..." : "No sandboxes running."}
        </div>
      }>
        {(sandbox) => (
          <div style={{
            padding: "12px",
            background: "var(--bg-secondary)",
            border: "1px solid var(--border)",
            "border-radius": "var(--radius)",
            "margin-bottom": "8px",
            display: "flex",
            "align-items": "center",
            gap: "12px",
          }}>
            <div class={`status ${sandbox.status === "running" ? "running" : ""}`}
              style={{ width: "8px", height: "8px", "border-radius": "50%", background: sandbox.status === "running" ? "var(--success)" : "var(--text-secondary)" }}
            />
            <div style={{ flex: "1" }}>
              <div style={{ "font-size": "13px", "font-weight": "500" }}>
                {sandbox.policy_name || sandbox.id.slice(0, 8)}
              </div>
              <div style={{ "font-size": "11px", color: "var(--text-secondary)" }}>
                PID: {sandbox.pid ?? "N/A"} | {sandbox.status}
              </div>
            </div>
            <button class="btn" onClick={() => props.onOpenTerminal(sandbox.id)}>
              Terminal
            </button>
            <button
              class="btn"
              style={{ color: "var(--danger)", "border-color": "var(--danger)" }}
              onClick={() => handleDestroy(sandbox.id)}
              disabled={destroying() === sandbox.id}
            >
              {destroying() === sandbox.id ? "..." : "Stop"}
            </button>
          </div>
        )}
      </For>
    </div>
  );
}
