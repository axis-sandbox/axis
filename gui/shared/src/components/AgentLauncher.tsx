import { createSignal, createResource, For } from "solid-js";
import { listAgents, runAgent, type Agent } from "../api/client";

interface AgentLauncherProps {
  onLaunch: (sandboxId: string) => void;
}

export function AgentLauncher(props: AgentLauncherProps) {
  const [agents] = createResource(listAgents);
  const [launching, setLaunching] = createSignal<string | null>(null);
  const [error, setError] = createSignal<string | null>(null);

  async function handleRun(agent: Agent) {
    setLaunching(agent.name);
    setError(null);
    try {
      const sandboxId = await runAgent(agent.name);
      props.onLaunch(sandboxId);
    } catch (e: any) {
      setError(`Failed to launch ${agent.name}: ${e.message}`);
    } finally {
      setLaunching(null);
    }
  }

  return (
    <div class="panel">
      <div style={{ display: "flex", "align-items": "center", gap: "12px", "margin-bottom": "16px" }}>
        <h2 style={{ "font-size": "16px", "font-weight": "600" }}>Agents</h2>
        <span style={{ "font-size": "12px", color: "var(--text-secondary)" }}>
          Click Run to launch in sandbox
        </span>
      </div>

      {error() && (
        <div style={{
          padding: "8px 12px",
          background: "#f8514922",
          border: "1px solid var(--danger)",
          "border-radius": "var(--radius)",
          "font-size": "12px",
          "margin-bottom": "12px",
          color: "var(--danger)",
        }}>
          {error()}
        </div>
      )}

      <div style={{ display: "grid", "grid-template-columns": "repeat(auto-fill, minmax(280px, 1fr))", gap: "12px" }}>
        <For each={agents()} fallback={
          <div style={{ color: "var(--text-secondary)", "font-size": "13px" }}>
            {agents.loading ? "Loading agents..." : "No agents installed. Run `axis install --all` to install."}
          </div>
        }>
          {(agent) => (
            <div style={{
              padding: "14px",
              background: "var(--bg-secondary)",
              border: "1px solid var(--border)",
              "border-radius": "var(--radius)",
              display: "flex",
              "align-items": "center",
              gap: "12px",
            }}>
              <div style={{ flex: "1" }}>
                <div style={{ "font-size": "14px", "font-weight": "500" }}>{agent.name}</div>
                <div style={{ "font-size": "11px", color: "var(--text-secondary)", "margin-top": "2px" }}>
                  {agent.installed ? "Installed" : "Not installed"}
                </div>
              </div>
              <button
                class="btn btn-primary"
                onClick={() => handleRun(agent)}
                disabled={launching() === agent.name}
              >
                {launching() === agent.name ? "..." : "Run"}
              </button>
            </div>
          )}
        </For>
      </div>
    </div>
  );
}
