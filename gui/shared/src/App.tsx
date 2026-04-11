import { createSignal, Show } from "solid-js";
import { Sidebar } from "./components/Sidebar";
import { Terminal } from "./components/Terminal";
import { SecurityMonitor } from "./components/SecurityMonitor";
import { AgentLauncher } from "./components/AgentLauncher";
import { SandboxList } from "./components/SandboxList";

export type View = "agents" | "terminal" | "security" | "sandboxes";

export default function App() {
  const [activeView, setActiveView] = createSignal<View>("agents");
  const [activeSandboxId, setActiveSandboxId] = createSignal<string | null>(null);

  function openTerminal(sandboxId: string) {
    setActiveSandboxId(sandboxId);
    setActiveView("terminal");
  }

  return (
    <>
      <Sidebar activeView={activeView()} onNavigate={setActiveView} />
      <div class="main-content">
        <div class="tab-bar">
          <div
            class={`tab ${activeView() === "agents" ? "active" : ""}`}
            onClick={() => setActiveView("agents")}
          >
            Agents
          </div>
          <div
            class={`tab ${activeView() === "sandboxes" ? "active" : ""}`}
            onClick={() => setActiveView("sandboxes")}
          >
            Sandboxes
          </div>
          <div
            class={`tab ${activeView() === "terminal" ? "active" : ""}`}
            onClick={() => setActiveView("terminal")}
          >
            Terminal
          </div>
          <div
            class={`tab ${activeView() === "security" ? "active" : ""}`}
            onClick={() => setActiveView("security")}
          >
            Security
          </div>
        </div>

        <Show when={activeView() === "agents"}>
          <AgentLauncher onLaunch={openTerminal} />
        </Show>
        <Show when={activeView() === "sandboxes"}>
          <SandboxList onOpenTerminal={openTerminal} />
        </Show>
        <Show when={activeView() === "terminal"}>
          <Terminal sandboxId={activeSandboxId()} />
        </Show>
        <Show when={activeView() === "security"}>
          <SecurityMonitor />
        </Show>
      </div>
    </>
  );
}
