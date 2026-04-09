// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Per-sandbox token budget tracking and enforcement.

use axis_core::policy::{ExhaustAction, TokenBudget};
use axis_core::types::SandboxId;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Per-sandbox budget tracker.
struct BudgetState {
    config: TokenBudget,
    tokens_used: u64,
    window_start: Instant,
}

impl BudgetState {
    fn new(config: TokenBudget) -> Self {
        Self {
            config,
            tokens_used: 0,
            window_start: Instant::now(),
        }
    }

    /// Reset the window if an hour has passed.
    fn maybe_reset_window(&mut self) {
        if self.window_start.elapsed() >= Duration::from_secs(3600) {
            self.tokens_used = 0;
            self.window_start = Instant::now();
        }
    }

    fn remaining(&mut self) -> u64 {
        self.maybe_reset_window();
        self.config.max_tokens_per_hour.saturating_sub(self.tokens_used)
    }
}

/// Result of checking a token budget.
#[derive(Debug)]
pub enum BudgetCheck {
    /// Within budget, proceed.
    Allowed,
    /// Budget exhausted, take the configured action.
    Exhausted {
        action: ExhaustAction,
        fallback_route: Option<String>,
        tokens_used: u64,
        max_tokens: u64,
    },
    /// Single request exceeds per-request limit.
    RequestTooLarge {
        requested: u64,
        max_per_request: u64,
    },
}

/// Tracks token budgets across sandboxes.
pub struct BudgetTracker {
    budgets: HashMap<SandboxId, BudgetState>,
}

impl BudgetTracker {
    pub fn new() -> Self {
        Self {
            budgets: HashMap::new(),
        }
    }

    /// Register a sandbox with its token budget configuration.
    pub fn register(&mut self, sandbox_id: SandboxId, config: TokenBudget) {
        self.budgets.insert(sandbox_id, BudgetState::new(config));
    }

    /// Remove a sandbox's budget tracker.
    pub fn unregister(&mut self, sandbox_id: &SandboxId) {
        self.budgets.remove(sandbox_id);
    }

    /// Check if a request with estimated token count is within budget.
    pub fn check(&mut self, sandbox_id: &SandboxId, estimated_tokens: u64) -> BudgetCheck {
        let Some(state) = self.budgets.get_mut(sandbox_id) else {
            return BudgetCheck::Allowed; // No budget configured = unlimited.
        };

        // Check per-request limit.
        if estimated_tokens > state.config.max_tokens_per_request {
            return BudgetCheck::RequestTooLarge {
                requested: estimated_tokens,
                max_per_request: state.config.max_tokens_per_request,
            };
        }

        // Check hourly budget.
        if state.remaining() < estimated_tokens {
            return BudgetCheck::Exhausted {
                action: state.config.action_on_exhaust.clone(),
                fallback_route: state.config.fallback_route.clone(),
                tokens_used: state.tokens_used,
                max_tokens: state.config.max_tokens_per_hour,
            };
        }

        BudgetCheck::Allowed
    }

    /// Record actual token usage after a request completes.
    pub fn record_usage(&mut self, sandbox_id: &SandboxId, tokens: u64) {
        if let Some(state) = self.budgets.get_mut(sandbox_id) {
            state.maybe_reset_window();
            state.tokens_used += tokens;
        }
    }

    /// Get remaining tokens for a sandbox.
    pub fn remaining(&mut self, sandbox_id: &SandboxId) -> Option<u64> {
        self.budgets.get_mut(sandbox_id).map(|s| s.remaining())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axis_core::policy::ExhaustAction;

    fn test_budget() -> TokenBudget {
        TokenBudget {
            max_tokens_per_hour: 10_000,
            max_tokens_per_request: 1_000,
            action_on_exhaust: ExhaustAction::Reject,
            fallback_route: None,
        }
    }

    #[test]
    fn within_budget() {
        let mut tracker = BudgetTracker::new();
        let id = SandboxId::new();
        tracker.register(id, test_budget());

        assert!(matches!(tracker.check(&id, 500), BudgetCheck::Allowed));
    }

    #[test]
    fn request_too_large() {
        let mut tracker = BudgetTracker::new();
        let id = SandboxId::new();
        tracker.register(id, test_budget());

        assert!(matches!(
            tracker.check(&id, 2_000),
            BudgetCheck::RequestTooLarge { .. }
        ));
    }

    #[test]
    fn budget_exhaustion() {
        let mut tracker = BudgetTracker::new();
        let id = SandboxId::new();
        tracker.register(id, test_budget());

        // Use up most of the budget.
        tracker.record_usage(&id, 9_500);

        // This should exhaust.
        assert!(matches!(
            tracker.check(&id, 600),
            BudgetCheck::Exhausted { .. }
        ));
    }

    #[test]
    fn no_budget_means_unlimited() {
        let mut tracker = BudgetTracker::new();
        let id = SandboxId::new();
        // Don't register — no budget.
        assert!(matches!(tracker.check(&id, 999_999), BudgetCheck::Allowed));
    }
}
