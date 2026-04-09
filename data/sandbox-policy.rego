# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# AXIS sandbox policy rules.
# Evaluated by the regorus (pure-Rust OPA) engine.

package axis

import rego.v1

# ─── Network layer ───────────────────────────────────────────────────────────

network.decision := result if {
    input.host
    input.port
    result := _network_eval
}

# Default deny.
default _network_eval := {"allowed": false, "matched_policy": null, "reason": "no matching network policy"}

# Allow if any endpoint policy matches the host:port and binary.
_network_eval := {"allowed": true, "matched_policy": pol.name, "reason": null} if {
    some pol in data.network.policies
    some ep in pol.endpoints
    ep.host == input.host
    ep.port == input.port
    _binary_matches(pol, input.binary_path)
}

# Binary matching: allow if no binaries specified (open policy) or binary matches.
_binary_matches(pol, _) if {
    count(pol.binaries) == 0
}

_binary_matches(pol, binary_path) if {
    some bin in pol.binaries
    glob.match(bin.path, ["/"], binary_path)
}

# ─── L7 HTTP layer ──────────────────────────────────────────────────────────

http.decision := result if {
    input.method
    input.path
    result := _http_eval
}

default _http_eval := {"allowed": false, "matched_policy": null, "reason": "no matching L7 rule"}

# Allow if any L7 rule in the matched network policy allows this method+path.
_http_eval := {"allowed": true, "matched_policy": input.matched_network_policy, "reason": null} if {
    some pol in data.network.policies
    pol.name == input.matched_network_policy
    some ep in pol.endpoints
    some rule in ep.rules
    rule.allow.method == input.method
    glob.match(rule.allow.path, ["/"], input.path)
}

# If a network policy has no L7 rules, allow all HTTP through it.
_http_eval := {"allowed": true, "matched_policy": input.matched_network_policy, "reason": "no L7 rules, default allow"} if {
    some pol in data.network.policies
    pol.name == input.matched_network_policy
    some ep in pol.endpoints
    count(ep.rules) == 0
}

# ─── Inference layer ─────────────────────────────────────────────────────────

inference.decision := result if {
    input.model
    result := _inference_eval
}

default _inference_eval := {"allowed": false, "matched_policy": null, "reason": "no matching inference route"}

_inference_eval := {"allowed": true, "matched_policy": route.name, "reason": null} if {
    some route in data.inference.routes
    route.model == input.model
}

# Allow if no specific model is required and a default provider exists.
_inference_eval := {"allowed": true, "matched_policy": data.inference.default_provider, "reason": "using default provider"} if {
    data.inference.default_provider
    not _specific_model_match
}

_specific_model_match if {
    some route in data.inference.routes
    route.model == input.model
}
