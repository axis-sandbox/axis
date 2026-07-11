# Pinned MXC patches

AXIS builds the Windows `wxc-exec.exe` artifact from MXC commit
`1736b48398c3fe4d1315b2311c0951cc893eb3ae` and applies the patches in
`patches/` before compilation.

`0001-wxc-processcontainer-resource-limits.patch` adds process-count,
aggregate-memory, and CPU-rate fields to MXC's ProcessContainer schema and Job
Object implementation. Remove the patch when upstream MXC exposes equivalent
resource fields and enforcement.

`0002-wxc-job-list-resource-assignment.patch` makes process count,
aggregate memory, and CPU-rate limits child-only. BaseContainer explicitly
breaks away from AXIS's outer lifecycle Job while suspended, then MXC assigns
it to the inner resource Job before resuming it. Silent breakaway stays
disabled, and closing either executor boundary still kills the sandbox tree.
Remove this patch when upstream MXC exposes equivalent ProcessContainer
resource fields and atomic BaseContainer Job assignment.

`0003-axis-wfp-strict-proxy.patch` adds the narrow AXIS WFP lease contract
to MXC's BaseContainer runner. It creates the child suspended, sends its PID and
the exact proxy endpoint to the installed broker, validates the broker's
SID/filter response, and resumes only after the lease is active. It also injects
sanitized proxy environment variables. A pipe watchdog terminates the child if
the broker disappears. Remove this patch when upstream MXC provides an
equivalent pre-resume broker hook and fail-closed lease lifecycle.

AXIS uses MXC BaseContainer only. The generated configuration leaves
`fallback.allowDaclMutation=false`, so an unavailable BaseContainer fails closed
instead of selecting an AppContainer/DACL tier.

The supported
`Experimental_CreateProcessInSandbox` API rejects
`PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` with `ERROR_INVALID_HANDLE` on Windows
build 26300. AXIS does not downgrade to AppContainer/DACL solely to provide
ConPTY. Enable the BaseContainer interactive path only after a runtime
capability probe proves the OS accepts pseudoconsole startup handles.
