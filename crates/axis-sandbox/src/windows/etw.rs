// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! ETW (Event Tracing for Windows) network bypass detection.
//!
//! Monitors sandbox processes for network connections that bypass the AXIS
//! proxy. Uses Windows Filtering Platform (WFP) audit events via ETW.

use std::collections::HashSet;

/// A detected network bypass attempt.
#[derive(Debug, Clone)]
pub struct BypassEvent {
    pub pid: u32,
    pub exe: String,
    pub remote_addr: String,
    pub remote_port: u16,
    pub timestamp: std::time::SystemTime,
}

/// Monitors sandbox processes for network bypass attempts.
pub struct BypassDetector {
    monitored_pids: HashSet<u32>,
    proxy_port: u16,
    events: Vec<BypassEvent>,
}

impl BypassDetector {
    pub fn new(proxy_port: u16) -> Self {
        Self {
            monitored_pids: HashSet::new(),
            proxy_port,
            events: Vec::new(),
        }
    }

    pub fn monitor_pid(&mut self, pid: u32) {
        self.monitored_pids.insert(pid);
        tracing::info!("etw: monitoring pid {pid} for network bypass");
    }

    pub fn unmonitor_pid(&mut self, pid: u32) {
        self.monitored_pids.remove(&pid);
    }

    /// Check if a connection from a monitored PID is a bypass attempt.
    pub fn check_connection(&mut self, pid: u32, remote_addr: &str, remote_port: u16) -> bool {
        if !self.monitored_pids.contains(&pid) {
            return false;
        }

        // Proxy loopback is allowed.
        if remote_addr == "127.0.0.1" && remote_port == self.proxy_port {
            return false;
        }

        // Any other connection is a bypass.
        if remote_addr != "127.0.0.1" || remote_port != self.proxy_port {
            self.record_bypass(pid, remote_addr, remote_port);
            return true;
        }

        false
    }

    fn record_bypass(&mut self, pid: u32, remote_addr: &str, remote_port: u16) {
        let exe = resolve_pid_exe(pid);
        let event = BypassEvent {
            pid,
            exe: exe.clone(),
            remote_addr: remote_addr.to_string(),
            remote_port,
            timestamp: std::time::SystemTime::now(),
        };
        tracing::warn!(
            "etw: BYPASS — pid={pid} ({exe}) -> {remote_addr}:{remote_port}"
        );
        self.events.push(event);
    }

    pub fn events(&self) -> &[BypassEvent] {
        &self.events
    }

    /// Start real-time ETW trace for network events.
    ///
    /// Subscribes to the Microsoft-Windows-Kernel-Network provider and
    /// filters for TCP connect events from monitored PIDs.
    #[cfg(target_os = "windows")]
    pub fn start_trace(&self) -> Result<std::thread::JoinHandle<()>, String> {
        // The WFP audit approach uses FwpmNetEventSubscribe0 from fwpuclnt.dll.
        //
        // Simpler alternative: use netsh + parsing, or the
        // Microsoft-Windows-Kernel-Network ETW provider (GUID below).
        //
        // For the initial implementation, we poll /proc-equivalent via
        // GetTcpTable2 periodically and check for new connections from
        // monitored PIDs.

        let pids = self.monitored_pids.clone();
        let proxy_port = self.proxy_port;

        let handle = std::thread::spawn(move || {
            tracing::info!("etw: starting network monitor for {} PIDs", pids.len());
            poll_tcp_connections(pids, proxy_port);
        });

        Ok(handle)
    }
}

/// Poll TCP connections and detect bypass attempts.
#[cfg(target_os = "windows")]
fn poll_tcp_connections(pids: HashSet<u32>, proxy_port: u16) {
    use std::time::Duration;

    // Use GetExtendedTcpTable to enumerate connections with PIDs.
    // This requires iphlpapi.dll.

    #[repr(C)]
    #[allow(non_snake_case)]
    struct MIB_TCPROW_OWNER_PID {
        dwState: u32,
        dwLocalAddr: u32,
        dwLocalPort: u32,
        dwRemoteAddr: u32,
        dwRemotePort: u32,
        dwOwningPid: u32,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct MIB_TCPTABLE_OWNER_PID {
        dwNumEntries: u32,
        table: [MIB_TCPROW_OWNER_PID; 1], // variable-length
    }

    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn GetExtendedTcpTable(
            pTcpTable: *mut u8,
            pdwSize: *mut u32,
            bOrder: i32,
            ulAf: u32,       // AF_INET = 2
            TableClass: u32, // TCP_TABLE_OWNER_PID_ALL = 5
            Reserved: u32,
        ) -> u32;
    }

    let mut seen_connections: HashSet<(u32, u32, u16)> = HashSet::new(); // (pid, remote_ip, remote_port)

    loop {
        let mut size: u32 = 0;
        // First call to get required buffer size.
        unsafe { GetExtendedTcpTable(std::ptr::null_mut(), &mut size, 0, 2, 5, 0); }

        if size == 0 {
            std::thread::sleep(Duration::from_secs(1));
            continue;
        }

        let mut buffer = vec![0u8; size as usize];
        let result = unsafe {
            GetExtendedTcpTable(buffer.as_mut_ptr(), &mut size, 0, 2, 5, 0)
        };

        if result != 0 {
            std::thread::sleep(Duration::from_secs(1));
            continue;
        }

        let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
        let entries = unsafe {
            std::slice::from_raw_parts(
                &table.table[0] as *const MIB_TCPROW_OWNER_PID,
                table.dwNumEntries as usize,
            )
        };

        for entry in entries {
            let pid = entry.dwOwningPid;
            if !pids.contains(&pid) {
                continue;
            }

            // State 5 = ESTABLISHED
            if entry.dwState != 5 {
                continue;
            }

            let remote_ip = entry.dwRemoteAddr;
            let remote_port = ((entry.dwRemotePort & 0xFF) << 8 | (entry.dwRemotePort >> 8)) as u16;

            let key = (pid, remote_ip, remote_port);
            if seen_connections.contains(&key) {
                continue;
            }
            seen_connections.insert(key);

            // Check if this is a bypass (not going through proxy).
            let is_loopback = remote_ip == 0x0100007F; // 127.0.0.1 in network byte order
            if is_loopback && remote_port == proxy_port {
                continue; // Allowed: connection to proxy.
            }

            let ip_bytes = remote_ip.to_ne_bytes();
            let addr_str = format!("{}.{}.{}.{}", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);

            tracing::warn!(
                "etw: BYPASS — pid={pid} -> {addr_str}:{remote_port} (not via proxy)"
            );
        }

        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Resolve a PID to its executable path.
fn resolve_pid_exe(pid: u32) -> String {
    #[cfg(target_os = "windows")]
    {
        // QueryFullProcessImageNameW via kernel32.
        format!("pid:{pid}")
    }
    #[cfg(not(target_os = "windows"))]
    {
        format!("pid:{pid}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_connection_is_not_bypass() {
        let mut d = BypassDetector::new(13100);
        d.monitor_pid(1234);
        assert!(!d.check_connection(1234, "127.0.0.1", 13100));
        assert!(d.events().is_empty());
    }

    #[test]
    fn direct_internet_is_bypass() {
        let mut d = BypassDetector::new(13100);
        d.monitor_pid(1234);
        assert!(d.check_connection(1234, "93.184.216.34", 443));
        assert_eq!(d.events().len(), 1);
    }

    #[test]
    fn wrong_loopback_port_is_bypass() {
        let mut d = BypassDetector::new(13100);
        d.monitor_pid(1234);
        assert!(d.check_connection(1234, "127.0.0.1", 8080));
    }

    #[test]
    fn unmonitored_pid_ignored() {
        let mut d = BypassDetector::new(13100);
        d.monitor_pid(1234);
        assert!(!d.check_connection(5678, "93.184.216.34", 443));
    }
}
