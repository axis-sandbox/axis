# Contributing to AXIS

AXIS is a security-sensitive sandbox runtime. Changes should preserve
explicit policy semantics across supported platforms and fail closed when a
requested control cannot be enforced.

## Development Setup

Install the Rust toolchain declared by `rust-toolchain.toml`, then build the
workspace:

```bash
cargo build --locked
```

Platform-specific runtime dependencies and optional privileged test tiers are
documented in [Setup and Install](docs/setup-and-install.md) and
[Security Test Tiers](docs/security-test-tiers.md). Ordinary unit and
integration tests must not depend on installing locally built artifacts with
elevated privileges.

The shared desktop UI is built separately:

```bash
cd gui/shared
npm ci
npm run typecheck
npm run build
```

## Submitting Changes

Keep changes focused and include tests for intended behavior, edge cases, error
paths, and security boundaries. Match the existing code and commit style. A
commit message should explain why the change is needed and what behavior it
changes; low-level implementation details belong in the code and review.

Before opening a pull request, run the checks relevant to the change:

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
bash scripts/test_security_tier0.sh
```

For UI changes, also run `npm ci`, `npm run typecheck`, `npm run build`, and
`npm audit` from `gui/shared`.

Pull requests should describe the motivation, user-visible behavior, security
impact, and validation performed. Changes to policy translation, process
launch, filesystem controls, network enforcement, credentials, or release
workflows require especially defensive review. Reviewers should question
whether the change can weaken isolation, cross platform boundaries, expose
host state, or turn an enforcement failure into permissive behavior.

## Reporting Security Issues

Do not open a public issue for a vulnerability. Follow
[SECURITY.md](SECURITY.md) instead.
