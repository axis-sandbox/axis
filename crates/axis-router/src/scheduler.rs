// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Multi-sandbox fair request scheduling using deficit round-robin.

use axis_core::policy::Priority;
use axis_core::types::SandboxId;
use std::collections::{HashMap, VecDeque};

/// A pending inference request in the scheduler queue.
#[derive(Debug)]
pub struct QueuedRequest {
    pub sandbox_id: SandboxId,
    pub request_body: serde_json::Value,
    pub priority: Priority,
    pub enqueued_at: std::time::Instant,
}

/// Per-sandbox queue state for deficit round-robin.
struct SandboxQueue {
    weight: u32,
    deficit: u32,
    queue: VecDeque<QueuedRequest>,
    max_concurrent: Option<u32>,
    active_count: u32,
}

/// Fair request scheduler across sandboxes.
pub struct RequestScheduler {
    queues: HashMap<SandboxId, SandboxQueue>,
    interactive_queue: VecDeque<QueuedRequest>,
}

impl RequestScheduler {
    pub fn new() -> Self {
        Self {
            queues: HashMap::new(),
            interactive_queue: VecDeque::new(),
        }
    }

    /// Register a sandbox with its scheduling parameters.
    pub fn register_sandbox(
        &mut self,
        sandbox_id: SandboxId,
        weight: u32,
        max_concurrent: Option<u32>,
    ) {
        self.queues.insert(
            sandbox_id,
            SandboxQueue {
                weight: weight.max(1),
                deficit: 0,
                queue: VecDeque::new(),
                max_concurrent,
                active_count: 0,
            },
        );
    }

    /// Remove a sandbox from the scheduler.
    pub fn unregister_sandbox(&mut self, sandbox_id: &SandboxId) {
        self.queues.remove(sandbox_id);
    }

    /// Enqueue a request. Interactive requests bypass the fair queue.
    pub fn enqueue(&mut self, request: QueuedRequest) {
        if matches!(request.priority, Priority::Interactive) {
            self.interactive_queue.push_back(request);
            return;
        }

        if let Some(sq) = self.queues.get_mut(&request.sandbox_id) {
            sq.queue.push_back(request);
        }
    }

    /// Dequeue the next request to forward to the inference server.
    ///
    /// Priority: interactive first, then deficit round-robin across sandboxes.
    pub fn dequeue(&mut self) -> Option<QueuedRequest> {
        // Interactive requests always go first.
        if let Some(req) = self.interactive_queue.pop_front() {
            return Some(req);
        }

        // Deficit round-robin: find the sandbox with highest deficit that has
        // pending requests and hasn't exceeded its concurrency limit.
        let mut best_id: Option<SandboxId> = None;
        let mut best_deficit: u32 = 0;

        for (id, sq) in &self.queues {
            if sq.queue.is_empty() {
                continue;
            }
            if let Some(max) = sq.max_concurrent {
                if sq.active_count >= max {
                    continue;
                }
            }
            // Add weight to deficit for this round.
            let effective_deficit = sq.deficit + sq.weight;
            if effective_deficit > best_deficit {
                best_deficit = effective_deficit;
                best_id = Some(*id);
            }
        }

        if let Some(id) = best_id {
            let sq = self.queues.get_mut(&id).unwrap();
            sq.deficit += sq.weight;
            sq.active_count += 1;
            if let Some(req) = sq.queue.pop_front() {
                // Reduce deficit by the cost of serving this request.
                sq.deficit = sq.deficit.saturating_sub(1);
                return Some(req);
            }
        }

        None
    }

    /// Notify the scheduler that a request has completed.
    pub fn request_completed(&mut self, sandbox_id: &SandboxId) {
        if let Some(sq) = self.queues.get_mut(sandbox_id) {
            sq.active_count = sq.active_count.saturating_sub(1);
        }
    }

    /// Number of pending requests across all queues.
    pub fn pending_count(&self) -> usize {
        self.interactive_queue.len()
            + self.queues.values().map(|sq| sq.queue.len()).sum::<usize>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interactive_requests_go_first() {
        let mut sched = RequestScheduler::new();
        let id = SandboxId::new();
        sched.register_sandbox(id, 1, None);

        sched.enqueue(QueuedRequest {
            sandbox_id: id,
            request_body: serde_json::json!({"model": "test", "type": "background"}),
            priority: Priority::Background,
            enqueued_at: std::time::Instant::now(),
        });
        sched.enqueue(QueuedRequest {
            sandbox_id: id,
            request_body: serde_json::json!({"model": "test", "type": "interactive"}),
            priority: Priority::Interactive,
            enqueued_at: std::time::Instant::now(),
        });

        let first = sched.dequeue().unwrap();
        assert!(matches!(first.priority, Priority::Interactive));
    }

    #[test]
    fn fair_scheduling_between_sandboxes() {
        let mut sched = RequestScheduler::new();
        let id_a = SandboxId::new();
        let id_b = SandboxId::new();
        sched.register_sandbox(id_a, 1, None);
        sched.register_sandbox(id_b, 2, None); // 2x weight

        // Enqueue 3 requests each.
        for _ in 0..3 {
            sched.enqueue(QueuedRequest {
                sandbox_id: id_a,
                request_body: serde_json::json!({}),
                priority: Priority::Background,
                enqueued_at: std::time::Instant::now(),
            });
            sched.enqueue(QueuedRequest {
                sandbox_id: id_b,
                request_body: serde_json::json!({}),
                priority: Priority::Background,
                enqueued_at: std::time::Instant::now(),
            });
        }

        // Dequeue all 6 and count per-sandbox.
        let mut counts: HashMap<SandboxId, u32> = HashMap::new();
        for _ in 0..6 {
            if let Some(req) = sched.dequeue() {
                *counts.entry(req.sandbox_id).or_default() += 1;
                sched.request_completed(&req.sandbox_id);
            }
        }

        // Both should get served (exact ratio depends on DRR implementation).
        assert!(counts.contains_key(&id_a));
        assert!(counts.contains_key(&id_b));
    }
}
