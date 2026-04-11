import type { View } from "../App";

interface SidebarProps {
  activeView: View;
  onNavigate: (view: View) => void;
}

export function Sidebar(props: SidebarProps) {
  return (
    <div class="sidebar">
      <div class="sidebar-header">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" />
        </svg>
        AXIS
      </div>
      <div class="sidebar-section">
        <h3>Navigation</h3>
        <NavItem
          label="Agents"
          active={props.activeView === "agents"}
          onClick={() => props.onNavigate("agents")}
        />
        <NavItem
          label="Sandboxes"
          active={props.activeView === "sandboxes"}
          onClick={() => props.onNavigate("sandboxes")}
        />
        <NavItem
          label="Terminal"
          active={props.activeView === "terminal"}
          onClick={() => props.onNavigate("terminal")}
        />
        <NavItem
          label="Security Monitor"
          active={props.activeView === "security"}
          onClick={() => props.onNavigate("security")}
        />
      </div>
    </div>
  );
}

function NavItem(props: { label: string; active: boolean; onClick: () => void }) {
  return (
    <div
      class="agent-card"
      style={{ background: props.active ? "var(--bg-tertiary)" : "" }}
      onClick={props.onClick}
    >
      <span class="name">{props.label}</span>
    </div>
  );
}
