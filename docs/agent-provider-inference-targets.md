# Agent, Provider, And Inference Targets

This document records the AXIS agent, provider, and inference targets that must
remain compatible when any backend substrate is selected. Backend adapters are
responsible for proving exact isolation semantics before launch; this document
only describes workload coverage and the public status of each target.

## Agent Targets

| Target | Status | Public fixture or contract |
| --- | --- | --- |
| Claude Code | Bundled policy fixture | `policies/agents/claude-code.yaml` |
| Claude Code with scoped SSH | Bundled policy fixture | `policies/agents/claude-code-ssh.yaml` |
| Codex | Bundled policy fixture | `policies/agents/codex.yaml` |
| OpenCode | Bundled policy fixture | `policies/agents/opencode.yaml` |
| GitHub Copilot CLI | BYO-command only until a dedicated fixture is added | Use an explicit user policy; no bundled first-party fixture currently exists |
| Gemini CLI | Bundled policy fixture | `policies/agents/gemini-cli.yaml` |
| OpenClaw | Bundled policy fixture | `policies/agents/openclaw.yaml` |
| Hermes-style agents | Bundled policy fixture | `policies/agents/hermes.yaml` |
| Ironclaw | Bundled policy fixture | `policies/agents/ironclaw.yaml` |
| Nanoclaw | Bundled policy fixture | `policies/agents/nanoclaw.yaml` |
| ZeroClaw | Bundled policy fixture | `policies/agents/zeroclaw.yaml` |
| BYO commands | Bundled deny-by-default baseline | `policies/agents/base-deny.yaml` and user-provided policies |

Bundled agent fixtures must keep real credential stores denied, including
`~/.ssh`, `~/.gnupg`, and `~/.aws`. Scoped SSH support is mediated by AXIS SSH
policy and must not expose the user's real SSH directory directly.

## Provider Targets

| Provider target | Status | Boundary behavior |
| --- | --- | --- |
| OpenAI | Host-boundary credential injection supported | `provider: openai` resolves to `api.openai.com`; sandbox-visible values stay placeholders |
| Anthropic | Host-boundary credential injection supported | `provider: anthropic` resolves to `api.anthropic.com`; sandbox-visible values stay placeholders |
| GitHub | Network endpoint policy supported | Agent fixtures allow GitHub API and repository endpoints where needed; raw tokens are not injected by the inference credential path |
| GitLab | Generic endpoint policy only | Use an explicit endpoint policy or generic provider route; no bundled first-party fixture currently exists |
| Copilot | Generic endpoint policy only | GitHub Copilot CLI is BYO-command only until a dedicated fixture and credential boundary are added |
| Google Vertex AI | Generic endpoint policy only | Gemini CLI fixtures cover Gemini API and auth endpoints; Vertex-specific inference profiles are not bundled yet |
| generic providers | Endpoint-scoped credential route supported | Explicit `http://` or `https://` inference endpoints may use host-boundary placeholders |
| local OpenAI-compatible endpoints | Supported through `inference.local` or explicit local routes | Local endpoints do not require raw provider credentials inside the sandbox |

Provider credentials must remain outside sandbox environment variables, backend
configuration JSON, command-line arguments, logs, and child stdio. The proxy or
router resolves real secrets only for requests that match the approved provider
route, host, scheme, port, and inference path.

## Inference API Targets

AXIS recognizes the following inference APIs for host-boundary routing and
credential decisions:

| API target | Supported path pattern | Method |
| --- | --- | --- |
| OpenAI-compatible chat completions | `/v1/chat/completions` | `POST` |
| OpenAI-compatible completions | `/v1/completions` | `POST` |
| OpenAI-compatible responses | `/v1/responses` | `POST` |
| OpenAI-compatible embeddings | `/v1/embeddings` | `POST` |
| OpenAI-compatible model discovery | `/v1/models` | `GET` |
| Anthropic messages | `/v1/messages` | `POST` |

Streaming uses the same approved request paths as the corresponding provider
API. The proxy must relay streaming response bodies without requiring real cloud
provider credentials in tests. `inference.local` is the explicit managed local
inference endpoint; external provider hosts remain governed by ordinary network
and provider policy rather than implicit local rewrites.

HIP Remote compatibility remains part of the broader inference story, but this
target matrix does not add new HIP Remote behavior.
