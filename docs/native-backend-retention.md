# Native Backend Retention

AXIS keeps native process backends only where they provide a current capability,
dependency, or performance advantage that MXC-backed paths have not yet matched.
The retention decisions below are represented in
`axis_core::process_backend` and use the same backend capability vocabulary as
MXC process backends. Current default-backend status and benchmark evidence
requirements are documented in
[Backend Default Decisions](backend-default-decisions.md).

## Current Decisions

| Platform | Native backend | Decision | Why it remains |
| --- | --- | --- | --- |
| Linux | `axis-native-linux` | Retain | Direct Landlock plus seccomp keeps the no-container quickstart path, direct syscall filtering, lightweight process startup, strict proxy integration, and seccomp-notify binary attribution available while MXC process behavior is still being proven. |
| macOS | `axis-native-macos-seatbelt` | Retain | Direct Seatbelt profile generation preserves the no-extra-runtime process sandbox and platform-native filesystem/network-deny controls while the MXC Seatbelt path is compared for equivalent profile, lifecycle, and packaging behavior. |
| Windows | `axis-native-windows` | Retain | Job Object, Low Integrity, and process-container primitives remain the current native Windows process sandbox vocabulary, with AXIS-owned credential, lifecycle, and resource handling retained until MXC ProcessContainer proves equivalent behavior. |

## Replacement Rule

No native process backend should be removed or made non-selectable merely because
an MXC backend exists for the same platform. Replacement requires:

- matching AXIS policy semantics for filesystem, process, network, credentials,
  inference, resources, lifecycle, cleanup, and audit surfaces;
- equivalent native backend tests and negative security coverage;
- benchmark evidence for startup, teardown, memory, descriptor/process overhead,
  and density on the relevant platform;
- public documentation of any weaker behavior that remains and explicit user
  selection when weaker behavior is accepted.

Until that evidence exists, native backends remain selectable through the shared
planner vocabulary. Backend adapters must continue to reject unsupported or
weaker policy/backend combinations before spawning user code.
