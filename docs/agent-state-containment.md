# Agent State Containment

## Problem

AI agents write state to well-known directories in the user's home:

```
~/.claude/          Claude Code sessions, settings, history
~/.codex/           Codex CLI config and cache
~/.openclaw/        OpenClaw workspace, skills, memory
~/.ironclaw/        Ironclaw config, secrets, routines
~/.config/          Shared config (various agents)
~/Library/          macOS app data
```

Without containment, these directories:
- **Accumulate persistent state** that can be poisoned (Microsoft's "indirect prompt injection persistence" attack)
- **Cross-contaminate** between agents (one agent reads another's state)
- **Survive sandbox destruction** (data lingers after the sandbox is gone)
- **Mix with real user data** (hard to audit what the agent wrote vs what the user created)

## Solution: ~/.axis/agents/

AXIS contains all agent-writable state under a single directory tree:

```
~/.axis/
└── agents/
    ├── agent-claude-code/        ← one dir per policy
    │   ├── claude/               ← was ~/.claude
    │   ├── claude-share/         ← was ~/.local/share/claude
    │   ├── config/               ← was ~/.config
    │   └── library/              ← was ~/Library (macOS)
    │
    ├── agent-codex/
    │   ├── codex/                ← was ~/.codex
    │   └── config/
    │
    ├── agent-openclaw/
    │   └── openclaw/             ← was ~/.openclaw
    │
    └── agent-hermes/
        └── hermes/               ← was ~/.hermes
```

Agents still see their expected paths (e.g., `~/.claude`) via symlinks:

```
~/.claude     →  ~/.axis/agents/agent-claude-code/claude
~/.codex      →  ~/.axis/agents/agent-codex/codex
~/.openclaw   →  ~/.axis/agents/agent-openclaw/openclaw
```

### Lifecycle

1. **Sandbox creation** — `prepare_agent_workspace()` runs:
   - Creates `~/.axis/agents/<policy-name>/` directory tree
   - If `~/.claude` already exists as a real directory, backs it up to `~/.claude.axis-backup` and copies contents to the containment dir
   - Creates symlink: `~/.claude → ~/.axis/agents/<name>/claude`

2. **Agent runs** — the agent writes to `~/.claude` which is actually `~/.axis/agents/<name>/claude`. The agent doesn't know it's contained.

3. **Sandbox destruction** — `cleanup_agent_symlinks()` runs:
   - Removes symlinks
   - Restores original directories from `.axis-backup` if they existed

### Benefits

| Benefit | How |
|---|---|
| **Auditability** | `ls ~/.axis/agents/` shows all agent state. `du -sh ~/.axis/agents/*` shows disk usage per agent. |
| **Isolation** | Each agent policy gets its own directory. Claude can't read Codex's state. |
| **Disposability** | `rm -rf ~/.axis/agents/agent-claude-code/` destroys all Claude state. |
| **Backup** | Back up `~/.axis/agents/` to capture all agent state without home-dir noise. |
| **Forensics** | After a suspected compromise, inspect `~/.axis/agents/<name>/` to see exactly what the agent wrote. |

### Policy Configuration

In the YAML policy, `read_write` paths that start with `~/` are automatically mapped to the containment directory:

```yaml
filesystem:
  read_write:
    - "{workspace}"         # sandbox workspace
    - "{tmpdir}"            # /tmp
    - "~/.claude"           # → ~/.axis/agents/<name>/claude
    - "~/.local/share/claude"  # → ~/.axis/agents/<name>/claude-share
    - "~/.config"           # → ~/.axis/agents/<name>/config
    - "~/.axis"             # containment root (always needed)
```

---

## SSH Key Policy

### Problem

AI agents often need SSH access for `git clone`, `scp`, or connecting to remote servers. But exposing `~/.ssh/` gives the agent access to **all** private keys, `known_hosts`, and SSH config — far more than needed.

### Solution: Scoped SSH Key Exposure

AXIS can expose specific SSH keys to the sandbox while denying access to the rest of `~/.ssh/`. The policy uses a new `ssh` section:

```yaml
# In the agent policy YAML
ssh:
  # Expose only specific keys (copied to sandbox, not symlinked).
  allowed_keys:
    - name: github-deploy
      private_key: "~/.ssh/id_ed25519_github"
      # Optional: restrict which hosts this key can connect to.
      allowed_hosts:
        - "github.com"
        - "gitlab.com"

    - name: staging-server
      private_key: "~/.ssh/id_rsa_staging"
      allowed_hosts:
        - "staging.example.com"
        - "10.0.1.*"

  # Auto-generate a known_hosts file with only the allowed hosts.
  # Prevents the agent from discovering other hosts via ~/.ssh/known_hosts.
  generate_known_hosts: true

  # SSH config restrictions.
  # AXIS generates a minimal ~/.ssh/config that only allows the specified hosts.
  generate_config: true
```

### How It Works

1. **Key isolation**: AXIS copies (not symlinks) the specified private keys into the sandbox workspace at `.ssh/`. The sandbox's `~/.ssh/` is a contained directory, not the real one.

2. **Host restriction**: AXIS generates a sandbox-local `~/.ssh/config` that uses `Match` directives to restrict which hosts each key can connect to:

   ```
   # Auto-generated by AXIS — only allowed SSH hosts
   Host github.com gitlab.com
       IdentityFile ~/.ssh/id_ed25519_github
       IdentitiesOnly yes

   Host staging.example.com 10.0.1.*
       IdentityFile ~/.ssh/id_rsa_staging
       IdentitiesOnly yes

   # Block all other SSH connections
   Host *
       IdentityFile /dev/null
       IdentitiesOnly yes
   ```

3. **known_hosts scoping**: AXIS generates a `known_hosts` file containing only the fingerprints of allowed hosts (obtained via `ssh-keyscan`). The agent can't discover other hosts from the user's real `known_hosts`.

4. **Network policy alignment**: The SSH allowed hosts are automatically added to the proxy's network whitelist (port 22), so the agent can only SSH to the specified destinations.

### Example: Claude Code with GitHub SSH

```yaml
version: 1
name: agent-claude-code-with-ssh

filesystem:
  read_write:
    - "{workspace}"
    - "~/.claude"
    - "~/.axis"
  deny:
    - "~/.ssh"              # deny the REAL ~/.ssh
    - "~/.gnupg"
    - "~/.aws"

ssh:
  allowed_keys:
    - name: github
      private_key: "~/.ssh/id_ed25519"
      allowed_hosts:
        - "github.com"
  generate_known_hosts: true
  generate_config: true

network:
  mode: proxy
  policies:
    - name: anthropic
      endpoints:
        - host: "api.anthropic.com"
          port: 443
    - name: github-ssh
      endpoints:
        - host: "github.com"
          port: 22          # SSH added automatically from ssh.allowed_hosts
    - name: github-https
      endpoints:
        - host: "github.com"
          port: 443
        - host: "api.github.com"
          port: 443
```

### What the Agent Sees

```
~/.ssh/                         ← AXIS-generated, not the real one
├── config                      ← only allows github.com
├── id_ed25519                  ← copied from real ~/.ssh/id_ed25519
├── known_hosts                 ← only github.com fingerprints
└── .axis-managed               ← marker file (AXIS manages this dir)
```

The agent can `git clone git@github.com:...` but cannot:
- Read other SSH keys (`~/.ssh/id_rsa_work`, `~/.ssh/id_rsa_prod`)
- Connect to other hosts (SSH config blocks `Host *` with `/dev/null` identity)
- Read the real `known_hosts` (which reveals what servers the user has connected to)

### Security Properties

| Property | Mechanism |
|---|---|
| Key scoping | Only named keys are copied to sandbox |
| Host restriction | SSH config `IdentitiesOnly yes` + proxy whitelist on port 22 |
| No key discovery | Real `~/.ssh/` is Landlock/Seatbelt denied |
| No host discovery | known_hosts is AXIS-generated, not copied from real |
| Network enforcement | Proxy blocks SSH to non-whitelisted hosts |
| Audit trail | OCSF event logged for each SSH connection through proxy |

### Alternatives Considered

| Approach | Drawback |
|---|---|
| **SSH agent forwarding** | Exposes all keys via the agent socket. Agent can use any key for any host. |
| **Deploy keys only** | Requires separate key per repo. Doesn't cover non-GitHub SSH use. |
| **Full ~/.ssh/ exposure** | Agent sees all keys, known_hosts, and config. |
| **No SSH at all** | Many agent workflows require `git clone` via SSH. |

The AXIS approach is the most granular: per-key, per-host, with network-layer enforcement.
