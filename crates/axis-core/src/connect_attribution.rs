// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Connect-time socket attribution shared by sandbox launchers and proxies.

use crate::policy::Policy;
use crate::types::SandboxId;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;

const DEFAULT_ATTRIBUTION_TTL: Duration = Duration::from_secs(5);

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConnectAttributionError {
    #[error("invalid connect attribution record: {0}")]
    InvalidRecord(String),

    #[error("missing connect-time attribution for {peer_addr} -> {proxy_addr}")]
    Missing {
        peer_addr: SocketAddr,
        proxy_addr: SocketAddr,
    },

    #[error("stale connect-time attribution for {peer_addr} -> {proxy_addr}")]
    Stale {
        peer_addr: SocketAddr,
        proxy_addr: SocketAddr,
    },

    #[error("ambiguous connect-time attribution for {peer_addr} -> {proxy_addr}")]
    Ambiguous {
        peer_addr: SocketAddr,
        proxy_addr: SocketAddr,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectAttributionSource {
    SeccompNotify,
    Test,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectAttributionRecord {
    pub sandbox_id: SandboxId,
    pub peer_addr: SocketAddr,
    pub proxy_addr: SocketAddr,
    pub pid: u32,
    pub executable_path: PathBuf,
    pub executable_sha256: String,
    pub source: ConnectAttributionSource,
}

#[derive(Debug, Clone)]
struct StoredAttributionRecord {
    record: ConnectAttributionRecord,
    observed_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct AttributionKey {
    sandbox_id: SandboxId,
    peer_addr: SocketAddr,
    proxy_addr: SocketAddr,
}

#[derive(Debug)]
struct ConnectAttributionState {
    ttl: Duration,
    records: HashMap<AttributionKey, Vec<StoredAttributionRecord>>,
}

/// In-memory handoff from a Linux connect-time observer to a proxy instance.
#[derive(Debug, Clone)]
pub struct ConnectAttributionStore {
    state: Arc<Mutex<ConnectAttributionState>>,
}

impl Default for ConnectAttributionStore {
    fn default() -> Self {
        Self::new(DEFAULT_ATTRIBUTION_TTL)
    }
}

impl ConnectAttributionStore {
    pub fn new(ttl: Duration) -> Self {
        Self {
            state: Arc::new(Mutex::new(ConnectAttributionState {
                ttl,
                records: HashMap::new(),
            })),
        }
    }

    pub fn insert(&self, record: ConnectAttributionRecord) -> Result<(), ConnectAttributionError> {
        self.insert_at(record, Instant::now())
    }

    fn insert_at(
        &self,
        record: ConnectAttributionRecord,
        observed_at: Instant,
    ) -> Result<(), ConnectAttributionError> {
        validate_record(&record)?;
        let key = AttributionKey {
            sandbox_id: record.sandbox_id,
            peer_addr: record.peer_addr,
            proxy_addr: record.proxy_addr,
        };
        let mut state = self
            .state
            .lock()
            .expect("connect attribution lock poisoned");
        purge_expired_locked(&mut state, Instant::now());
        state
            .records
            .entry(key)
            .or_default()
            .push(StoredAttributionRecord {
                record,
                observed_at,
            });
        Ok(())
    }

    pub fn consume(
        &self,
        sandbox_id: SandboxId,
        peer_addr: SocketAddr,
        proxy_addr: SocketAddr,
    ) -> Result<ConnectAttributionRecord, ConnectAttributionError> {
        self.consume_at(sandbox_id, peer_addr, proxy_addr, Instant::now())
    }

    fn consume_at(
        &self,
        sandbox_id: SandboxId,
        peer_addr: SocketAddr,
        proxy_addr: SocketAddr,
        now: Instant,
    ) -> Result<ConnectAttributionRecord, ConnectAttributionError> {
        let key = AttributionKey {
            sandbox_id,
            peer_addr,
            proxy_addr,
        };
        let mut state = self
            .state
            .lock()
            .expect("connect attribution lock poisoned");
        let ttl = state.ttl;
        let Some(records) = state.records.get_mut(&key) else {
            return Err(ConnectAttributionError::Missing {
                peer_addr,
                proxy_addr,
            });
        };

        let had_records = !records.is_empty();
        records.retain(|record| now.duration_since(record.observed_at) <= ttl);

        let result = match records.len() {
            0 if had_records => Err(ConnectAttributionError::Stale {
                peer_addr,
                proxy_addr,
            }),
            0 => Err(ConnectAttributionError::Missing {
                peer_addr,
                proxy_addr,
            }),
            1 => Ok(records.remove(0).record),
            _ => Err(ConnectAttributionError::Ambiguous {
                peer_addr,
                proxy_addr,
            }),
        };

        if records.is_empty() {
            state.records.remove(&key);
        }
        result
    }
}

pub fn policy_requires_connect_attribution(policy: &Policy) -> bool {
    policy
        .network
        .policies
        .iter()
        .any(|endpoint_policy| !endpoint_policy.binaries.is_empty())
}

fn purge_expired_locked(state: &mut ConnectAttributionState, now: Instant) {
    let ttl = state.ttl;
    state.records.retain(|_, records| {
        records.retain(|record| now.duration_since(record.observed_at) <= ttl);
        !records.is_empty()
    });
}

fn validate_record(record: &ConnectAttributionRecord) -> Result<(), ConnectAttributionError> {
    if record.peer_addr.port() == 0 {
        return Err(ConnectAttributionError::InvalidRecord(
            "peer port must be non-zero".into(),
        ));
    }
    if record.proxy_addr.port() == 0 {
        return Err(ConnectAttributionError::InvalidRecord(
            "proxy port must be non-zero".into(),
        ));
    }
    if record.pid == 0 {
        return Err(ConnectAttributionError::InvalidRecord(
            "pid must be non-zero".into(),
        ));
    }
    if record.executable_path.as_os_str().is_empty() {
        return Err(ConnectAttributionError::InvalidRecord(
            "executable path must be non-empty".into(),
        ));
    }
    if !is_sha256_hex(&record.executable_sha256) {
        return Err(ConnectAttributionError::InvalidRecord(
            "executable sha256 must be 64 lowercase hex characters".into(),
        ));
    }
    Ok(())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(port: u16) -> SocketAddr {
        format!("10.200.0.2:{port}").parse().unwrap()
    }

    fn proxy() -> SocketAddr {
        "10.200.0.1:3128".parse().unwrap()
    }

    fn record(sandbox_id: SandboxId, peer_addr: SocketAddr) -> ConnectAttributionRecord {
        ConnectAttributionRecord {
            sandbox_id,
            peer_addr,
            proxy_addr: proxy(),
            pid: 42,
            executable_path: "/usr/bin/curl".into(),
            executable_sha256: "a".repeat(64),
            source: ConnectAttributionSource::Test,
        }
    }

    #[test]
    fn consumes_single_record_once() {
        let store = ConnectAttributionStore::default();
        let sandbox_id = SandboxId::new();
        let peer_addr = peer(49152);
        store.insert(record(sandbox_id, peer_addr)).unwrap();

        let consumed = store.consume(sandbox_id, peer_addr, proxy()).unwrap();
        assert_eq!(consumed.executable_path, PathBuf::from("/usr/bin/curl"));
        assert!(matches!(
            store.consume(sandbox_id, peer_addr, proxy()),
            Err(ConnectAttributionError::Missing { .. })
        ));
    }

    #[test]
    fn rejects_missing_record() {
        let store = ConnectAttributionStore::default();
        let sandbox_id = SandboxId::new();
        assert!(matches!(
            store.consume(sandbox_id, peer(49152), proxy()),
            Err(ConnectAttributionError::Missing { .. })
        ));
    }

    #[test]
    fn rejects_wrong_sandbox_record() {
        let store = ConnectAttributionStore::default();
        let first = SandboxId::new();
        let second = SandboxId::new();
        let peer_addr = peer(49152);
        store.insert(record(first, peer_addr)).unwrap();

        assert!(matches!(
            store.consume(second, peer_addr, proxy()),
            Err(ConnectAttributionError::Missing { .. })
        ));
        assert!(store.consume(first, peer_addr, proxy()).is_ok());
    }

    #[test]
    fn rejects_stale_record_and_allows_fresh_tuple_reuse() {
        let store = ConnectAttributionStore::new(Duration::from_millis(10));
        let sandbox_id = SandboxId::new();
        let peer_addr = peer(49152);
        let now = Instant::now();
        store
            .insert_at(
                record(sandbox_id, peer_addr),
                now - Duration::from_millis(20),
            )
            .unwrap();

        assert!(matches!(
            store.consume_at(sandbox_id, peer_addr, proxy(), now),
            Err(ConnectAttributionError::Stale { .. })
        ));

        store.insert_at(record(sandbox_id, peer_addr), now).unwrap();
        assert!(
            store
                .consume_at(sandbox_id, peer_addr, proxy(), now)
                .is_ok()
        );
    }

    #[test]
    fn rejects_conflicting_duplicate_records() {
        let store = ConnectAttributionStore::default();
        let sandbox_id = SandboxId::new();
        let peer_addr = peer(49152);
        store.insert(record(sandbox_id, peer_addr)).unwrap();
        let mut second = record(sandbox_id, peer_addr);
        second.executable_path = "/usr/bin/wget".into();
        second.executable_sha256 = "b".repeat(64);
        store.insert(second).unwrap();

        assert!(matches!(
            store.consume(sandbox_id, peer_addr, proxy()),
            Err(ConnectAttributionError::Ambiguous { .. })
        ));
    }

    #[test]
    fn rejects_duplicate_records_even_when_same_binary() {
        let store = ConnectAttributionStore::default();
        let sandbox_id = SandboxId::new();
        let peer_addr = peer(49152);
        store.insert(record(sandbox_id, peer_addr)).unwrap();
        store.insert(record(sandbox_id, peer_addr)).unwrap();

        assert!(matches!(
            store.consume(sandbox_id, peer_addr, proxy()),
            Err(ConnectAttributionError::Ambiguous { .. })
        ));
    }

    #[test]
    fn validates_record_shape() {
        let store = ConnectAttributionStore::default();
        let sandbox_id = SandboxId::new();

        let mut zero_peer = record(sandbox_id, "10.200.0.2:0".parse().unwrap());
        assert!(matches!(
            store.insert(zero_peer.clone()),
            Err(ConnectAttributionError::InvalidRecord(_))
        ));

        zero_peer.peer_addr = peer(49152);
        zero_peer.pid = 0;
        assert!(matches!(
            store.insert(zero_peer.clone()),
            Err(ConnectAttributionError::InvalidRecord(_))
        ));

        zero_peer.pid = 42;
        zero_peer.executable_sha256 = "A".repeat(64);
        assert!(matches!(
            store.insert(zero_peer),
            Err(ConnectAttributionError::InvalidRecord(_))
        ));
    }

    #[test]
    fn policy_requires_attribution_only_for_binary_restrictions() {
        let unrestricted = Policy::from_yaml(
            r#"
version: 1
name: unrestricted
network:
  mode: proxy
  policies:
    - name: pypi
      endpoints:
        - host: pypi.org
          port: 443
"#,
        )
        .unwrap();
        assert!(!policy_requires_connect_attribution(&unrestricted));

        let restricted = Policy::from_yaml(
            r#"
version: 1
name: restricted
network:
  mode: proxy
  policies:
    - name: github
      endpoints:
        - host: api.github.com
          port: 443
      binaries:
        - path: /usr/bin/git
"#,
        )
        .unwrap();
        assert!(policy_requires_connect_attribution(&restricted));
    }
}
