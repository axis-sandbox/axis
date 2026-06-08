// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! seccomp-BPF syscall filtering — default-deny whitelist mode.
//!
//! Builds a BPF program that ALLOWS only explicitly whitelisted syscalls
//! and BLOCKS everything else with EPERM. This is the strongest seccomp
//! mode — a compromised sandbox process cannot use any syscall not on
//! the whitelist.

use axis_core::policy::ProcessPolicy;

// ── seccomp constants ─────────────────────────────────────────────────────

const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;

const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JEQ: u16 = 0x10;
const BPF_JSET: u16 = 0x40;
const BPF_K: u16 = 0x00;

const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
const SECCOMP_DATA_ARGS_OFFSET: u32 = 16;
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

const ARG_SIZE: u32 = 8;

const AF_UNIX: u32 = 1;

const SYS_SOCKET: u32 = 41;
const SYS_CONNECT: u32 = 42;
const SYS_SOCKETPAIR: u32 = 53;
const SYS_CLONE: u32 = 56;
const SYS_KILL: u32 = 62;
const SYS_SETPGID: u32 = 109;
const SYS_SETSID: u32 = 112;
const SYS_TKILL: u32 = 200;
const SYS_UNSHARE: u32 = 272;
const SYS_EXECVEAT: u32 = 322;
const SYS_CLONE3: u32 = 435;

const EXECVEAT_FLAGS_ARG: usize = 4;
const AT_EMPTY_PATH: u32 = 0x1000;
const DANGEROUS_UNSHARE_FLAGS: u32 = libc::CLONE_NEWNS as u32
    | libc::CLONE_NEWUTS as u32
    | libc::CLONE_NEWIPC as u32
    | libc::CLONE_NEWUSER as u32
    | libc::CLONE_NEWPID as u32
    | libc::CLONE_NEWNET as u32
    | libc::CLONE_NEWCGROUP as u32;

/// Syscalls that are always allowed in default-deny mode.
/// These are the minimum set needed for Python, shell, and most userspace
/// programs to function. Carefully curated to avoid sandbox escape vectors.
const WHITELIST: &[(u32, &str)] = &[
    // File I/O
    (0, "read"),
    (1, "write"),
    (2, "open"),
    (3, "close"),
    (4, "stat"),
    (5, "fstat"),
    (6, "lstat"),
    (7, "poll"),
    (8, "lseek"),
    (9, "mmap"),
    (10, "mprotect"),
    (11, "munmap"),
    (12, "brk"),
    (13, "rt_sigaction"),
    (14, "rt_sigprocmask"),
    (15, "rt_sigreturn"),
    (16, "ioctl"),
    (17, "pread64"),
    (18, "pwrite64"),
    (19, "readv"),
    (20, "writev"),
    (21, "access"),
    (22, "pipe"),
    (23, "select"),
    (24, "sched_yield"),
    (25, "mremap"),
    (28, "madvise"),
    (32, "dup"),
    (33, "dup2"),
    (34, "pause"),
    (35, "nanosleep"),
    (37, "alarm"),
    (38, "setitimer"),
    (39, "getpid"),
    (40, "sendfile"),
    (41, "socket"),
    (42, "connect"),
    (43, "accept"),
    (44, "sendto"),
    (45, "recvfrom"),
    (46, "sendmsg"),
    (47, "recvmsg"),
    (48, "shutdown"),
    (49, "bind"),
    (50, "listen"),
    (51, "getsockname"),
    (52, "getpeername"),
    (53, "socketpair"),
    (54, "setsockopt"),
    (55, "getsockopt"),
    (56, "clone"), // namespace flags are blocked by conditional rules
    (57, "fork"),
    (58, "vfork"),
    (59, "execve"),
    (60, "exit"),
    (61, "wait4"),
    (63, "uname"),
    (72, "fcntl"),
    (73, "flock"),
    (74, "fsync"),
    (75, "fdatasync"),
    (76, "truncate"),
    (77, "ftruncate"),
    (78, "getdents"),
    (79, "getcwd"),
    (80, "chdir"),
    (82, "rename"),
    (83, "mkdir"),
    (84, "rmdir"),
    (85, "creat"),
    (86, "link"),
    (87, "unlink"),
    (88, "symlink"),
    (89, "readlink"),
    (90, "chmod"),
    (92, "chown"),
    (95, "umask"),
    (96, "gettimeofday"),
    (97, "getrlimit"),
    (98, "getrusage"),
    (99, "sysinfo"),
    (100, "times"),
    (102, "getuid"),
    (104, "getgid"),
    (107, "geteuid"),
    (108, "getegid"),
    (110, "getppid"),
    (111, "getpgrp"),
    (124, "getsid"),
    (131, "sigaltstack"),
    (137, "statfs"),
    (138, "fstatfs"),
    (140, "getpriority"),
    (144, "sched_setscheduler"),
    (145, "sched_getscheduler"),
    (146, "sched_get_priority_max"),
    (147, "sched_get_priority_min"),
    (157, "prctl"),
    (158, "arch_prctl"),
    (186, "gettid"),
    (202, "futex"),
    (204, "sched_getaffinity"),
    (217, "getdents64"),
    (218, "set_tid_address"),
    (228, "clock_gettime"),
    (229, "clock_getres"),
    (230, "clock_nanosleep"),
    (231, "exit_group"),
    (232, "epoll_wait"),
    (233, "epoll_ctl"),
    (257, "openat"),
    (258, "mkdirat"),
    (260, "fchownat"),
    (262, "newfstatat"),
    (263, "unlinkat"),
    (264, "renameat"),
    (268, "fchmodat"),
    (269, "faccessat"),
    (270, "pselect6"),
    (271, "ppoll"),
    (280, "utimensat"),
    (281, "epoll_pwait"),
    (284, "eventfd"),
    (288, "accept4"),
    (290, "eventfd2"),
    (291, "epoll_create1"),
    (292, "dup3"),
    (293, "pipe2"),
    (302, "prlimit64"),
    (309, "getcpu"),
    (316, "renameat2"),
    (318, "getrandom"),
    (322, "execveat"),
    (332, "statx"),
    (334, "rseq"),
    (439, "faccessat2"),
    (448, "process_mrelease"),
];

/// BPF instruction.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct BpfInsn {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct BpfProg {
    len: u16,
    filter: *const BpfInsn,
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedSeccompFilter {
    insns: Vec<BpfInsn>,
}

impl PreparedSeccompFilter {
    pub(crate) fn apply_current_process(&self) -> Result<(), i32> {
        self.apply_current_process_with_flags(libc::SECCOMP_FILTER_FLAG_TSYNC as libc::c_long)
            .map(|_| ())
    }

    pub(crate) fn apply_current_process_with_listener(&self) -> Result<i32, i32> {
        self.apply_current_process_with_flags(
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER as libc::c_long,
        )
    }

    fn apply_current_process_with_flags(&self, flags: libc::c_long) -> Result<i32, i32> {
        let prog = BpfProg {
            len: self.insns.len() as u16,
            filter: self.insns.as_ptr(),
        };

        let ret = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                1 as libc::c_long, // SECCOMP_SET_MODE_FILTER
                flags,
                &prog as *const BpfProg as libc::c_long,
            )
        };

        if ret < 0 {
            Err(current_errno())
        } else {
            Ok(ret as i32)
        }
    }

    pub(crate) fn export_bpf_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.insns.len() * std::mem::size_of::<BpfInsn>());
        for insn in &self.insns {
            bytes.extend_from_slice(&insn.code.to_ne_bytes());
            bytes.push(insn.jt);
            bytes.push(insn.jf);
            bytes.extend_from_slice(&insn.k.to_ne_bytes());
        }
        bytes
    }
}

fn bpf_stmt(code: u16, k: u32) -> BpfInsn {
    BpfInsn {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> BpfInsn {
    BpfInsn { code, jt, jf, k }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilterDecision {
    Allow,
    Errno(i32),
    UserNotify,
    KillProcess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FlagDenyRule {
    syscall_nr: u32,
    arg_index: usize,
    mask: u32,
    reason: &'static str,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SocketDomainPolicy {
    AllowAll,
    DenyAllExcept(Vec<u32>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SeccompOptions {
    socket_domain_policy: SocketDomainPolicy,
    notify_connect: bool,
}

impl Default for SeccompOptions {
    fn default() -> Self {
        Self {
            socket_domain_policy: SocketDomainPolicy::AllowAll,
            notify_connect: false,
        }
    }
}

impl SeccompOptions {
    #[allow(dead_code)]
    pub(crate) fn deny_network_socket_domains() -> Self {
        Self {
            socket_domain_policy: SocketDomainPolicy::DenyAllExcept(vec![AF_UNIX]),
            notify_connect: false,
        }
    }

    pub(crate) fn notify_connect(mut self) -> Self {
        self.notify_connect = true;
        self
    }

    #[cfg(test)]
    pub(crate) fn denies_non_unix_socket_domains(&self) -> bool {
        matches!(
            &self.socket_domain_policy,
            SocketDomainPolicy::DenyAllExcept(allowed_domains)
                if allowed_domains.as_slice() == [AF_UNIX]
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SeccompFilterSpec {
    allowed_syscalls: Vec<u32>,
    socket_domain_policy: SocketDomainPolicy,
    notify_connect: bool,
    flag_deny_rules: Vec<FlagDenyRule>,
}

impl SeccompFilterSpec {
    fn from_policy(policy: &ProcessPolicy, options: SeccompOptions) -> Result<Self, String> {
        let mut allowed_syscalls: Vec<u32> = WHITELIST.iter().map(|(nr, _)| *nr).collect();

        for name in &policy.blocked_syscalls {
            let nr = syscall_number(name)
                .ok_or_else(|| format!("unknown syscall in blocked_syscalls: '{name}'"))?;
            allowed_syscalls.retain(|&n| n != nr);
        }

        allowed_syscalls.sort();
        allowed_syscalls.dedup();

        let notify_connect =
            options.notify_connect && allowed_syscalls.binary_search(&SYS_CONNECT).is_ok();

        Ok(Self {
            allowed_syscalls,
            socket_domain_policy: options.socket_domain_policy,
            notify_connect,
            flag_deny_rules: vec![
                FlagDenyRule {
                    syscall_nr: SYS_CLONE,
                    arg_index: 0,
                    mask: DANGEROUS_UNSHARE_FLAGS,
                    reason: "dangerous namespace clone",
                },
                FlagDenyRule {
                    syscall_nr: SYS_UNSHARE,
                    arg_index: 0,
                    mask: DANGEROUS_UNSHARE_FLAGS,
                    reason: "dangerous namespace unshare",
                },
                FlagDenyRule {
                    syscall_nr: SYS_EXECVEAT,
                    arg_index: EXECVEAT_FLAGS_ARG,
                    mask: AT_EMPTY_PATH,
                    reason: "execveat AT_EMPTY_PATH",
                },
            ],
        })
    }

    #[allow(dead_code)]
    fn decision_for(&self, arch: u32, syscall_nr: u32, args: [u64; 6]) -> FilterDecision {
        if arch != AUDIT_ARCH_X86_64 {
            return FilterDecision::KillProcess;
        }

        if self.denies_socket_domain(syscall_nr, args[0] as u32) {
            return FilterDecision::Errno(libc::EPERM);
        }

        if self.notify_connect && syscall_nr == SYS_CONNECT {
            return FilterDecision::UserNotify;
        }

        for rule in &self.flag_deny_rules {
            if rule.syscall_nr == syscall_nr && ((args[rule.arg_index] as u32) & rule.mask) != 0 {
                return FilterDecision::Errno(libc::EPERM);
            }
        }

        if self.allowed_syscalls.binary_search(&syscall_nr).is_ok() {
            FilterDecision::Allow
        } else {
            FilterDecision::Errno(libc::EPERM)
        }
    }

    #[allow(dead_code)]
    fn denies_socket_domain(&self, syscall_nr: u32, domain: u32) -> bool {
        if !matches!(syscall_nr, SYS_SOCKET | SYS_SOCKETPAIR) {
            return false;
        }
        match &self.socket_domain_policy {
            SocketDomainPolicy::AllowAll => false,
            SocketDomainPolicy::DenyAllExcept(allowed_domains) => {
                !allowed_domains.contains(&domain)
            }
        }
    }

    fn to_bpf(&self) -> Vec<BpfInsn> {
        let mut insns = Vec::new();

        insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH_OFFSET));
        insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0));
        insns.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

        append_socket_domain_denies(&mut insns, &self.socket_domain_policy);
        for rule in &self.flag_deny_rules {
            append_flag_deny(&mut insns, *rule);
        }
        if self.notify_connect {
            append_syscall_return(&mut insns, SYS_CONNECT, user_notify_return());
        }

        insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));

        let n_allowed = self.allowed_syscalls.len();
        for (i, nr) in self.allowed_syscalls.iter().enumerate() {
            let remaining = n_allowed - i - 1;
            insns.push(bpf_jump(
                BPF_JMP | BPF_JEQ | BPF_K,
                *nr,
                checked_skip(remaining + 1),
                0,
            ));
        }

        insns.push(errno_return());
        insns.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
        insns
    }
}

fn append_syscall_return(insns: &mut Vec<BpfInsn>, syscall_nr: u32, ret: BpfInsn) {
    insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));
    insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, syscall_nr, 0, 1));
    insns.push(ret);
}

fn append_socket_domain_denies(insns: &mut Vec<BpfInsn>, policy: &SocketDomainPolicy) {
    match policy {
        SocketDomainPolicy::AllowAll => {}
        SocketDomainPolicy::DenyAllExcept(allowed_domains) => {
            for syscall_nr in [SYS_SOCKET, SYS_SOCKETPAIR] {
                append_socket_domain_deny_all_except(insns, syscall_nr, allowed_domains);
            }
        }
    };
}

fn append_socket_domain_deny_all_except(
    insns: &mut Vec<BpfInsn>,
    syscall_nr: u32,
    allowed_domains: &[u32],
) {
    if allowed_domains.is_empty() {
        insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));
        insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, syscall_nr, 0, 1));
        insns.push(errno_return());
        return;
    }

    let body_len = 1 + allowed_domains.len() + 1;
    insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));
    insns.push(bpf_jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        syscall_nr,
        0,
        checked_skip(body_len),
    ));
    insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, arg_low_offset(0)));
    for (i, domain) in allowed_domains.iter().enumerate() {
        let remaining_allowed_checks = allowed_domains.len() - i - 1;
        insns.push(bpf_jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            *domain,
            checked_skip(remaining_allowed_checks + 1),
            0,
        ));
    }
    insns.push(errno_return());
}

fn append_flag_deny(insns: &mut Vec<BpfInsn>, rule: FlagDenyRule) {
    let body_len = 3;
    insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));
    insns.push(bpf_jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        rule.syscall_nr,
        0,
        checked_skip(body_len),
    ));
    insns.push(bpf_stmt(
        BPF_LD | BPF_W | BPF_ABS,
        arg_low_offset(rule.arg_index),
    ));
    insns.push(bpf_jump(BPF_JMP | BPF_JSET | BPF_K, rule.mask, 0, 1));
    insns.push(errno_return());
}

fn errno_return() -> BpfInsn {
    bpf_stmt(
        BPF_RET | BPF_K,
        SECCOMP_RET_ERRNO | (libc::EPERM as u32 & 0xFFFF),
    )
}

fn user_notify_return() -> BpfInsn {
    bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF)
}

fn checked_skip(len: usize) -> u8 {
    u8::try_from(len).expect("seccomp BPF conditional block too large")
}

fn arg_low_offset(index: usize) -> u32 {
    SECCOMP_DATA_ARGS_OFFSET + (index as u32 * ARG_SIZE)
}

pub(crate) fn prepare_seccomp(policy: &ProcessPolicy) -> Result<PreparedSeccompFilter, String> {
    prepare_seccomp_with_options(policy, SeccompOptions::default())
}

pub(crate) fn prepare_seccomp_with_options(
    policy: &ProcessPolicy,
    options: SeccompOptions,
) -> Result<PreparedSeccompFilter, String> {
    let spec = SeccompFilterSpec::from_policy(policy, options)?;
    let insns = spec.to_bpf();

    tracing::info!(
        "seccomp: prepared default-deny mode — {} syscalls whitelisted, {} BPF instructions",
        spec.allowed_syscalls.len(),
        insns.len(),
    );
    Ok(PreparedSeccompFilter { insns })
}

/// Apply seccomp-BPF in default-deny whitelist mode.
///
/// Only syscalls in the whitelist are allowed. Everything else returns EPERM.
pub fn apply_seccomp(policy: &ProcessPolicy) -> Result<(), String> {
    let filter = prepare_seccomp(policy)?;
    filter.apply_current_process().map_err(|errno| {
        format!(
            "seccomp(SET_MODE_FILTER) failed: {}",
            std::io::Error::from_raw_os_error(errno)
        )
    })?;
    tracing::info!("seccomp: applied default-deny mode");
    Ok(())
}

fn current_errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

/// Map syscall name to x86_64 number.
fn syscall_number(name: &str) -> Option<u32> {
    WHITELIST
        .iter()
        .find(|(_, n)| *n == name)
        .map(|(nr, _)| *nr)
        .or({
            // Also map commonly-blocked names that aren't in the whitelist.
            match name {
                "ptrace" => Some(101),
                "mount" => Some(165),
                "umount2" => Some(166),
                "bpf" => Some(321),
                "io_uring_setup" => Some(425),
                "memfd_create" => Some(319),
                "process_vm_readv" => Some(310),
                "process_vm_writev" => Some(311),
                "userfaultfd" => Some(323),
                "kexec_load" => Some(246),
                "reboot" => Some(169),
                "pivot_root" => Some(155),
                "chroot" => Some(161),
                "kill" => Some(SYS_KILL),
                "setpgid" => Some(SYS_SETPGID),
                "setsid" => Some(SYS_SETSID),
                "tkill" => Some(SYS_TKILL),
                "unshare" => Some(272),
                "clone3" => Some(SYS_CLONE3),
                _ => None,
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, ExitStatus};

    const DOCUMENTED_NETWORK_SOCKET_DOMAINS: &[u32] = &[
        2,  // AF_INET
        10, // AF_INET6
        16, // AF_NETLINK
        17, // AF_PACKET
        29, // AF_CAN
        31, // AF_BLUETOOTH
        36, // AF_IEEE802154
        39, // AF_NFC
        40, // AF_VSOCK
        44, // AF_XDP
    ];

    const PROBE_DENIED: i32 = 0;
    const PROBE_ALLOWED: i32 = 1;
    const PROBE_UNEXPECTED_ERRNO: i32 = 2;
    const PROBE_SECCOMP_SETUP_FAILED: i32 = 101;
    const PROBE_NO_NEW_PRIVS_FAILED: i32 = 102;
    const PROBE_SIGNALLED: i32 = 128;

    #[test]
    fn whitelist_has_essential_syscalls() {
        let nrs: Vec<u32> = WHITELIST.iter().map(|(nr, _)| *nr).collect();
        assert!(nrs.contains(&0), "read missing");
        assert!(nrs.contains(&1), "write missing");
        assert!(nrs.contains(&59), "execve missing");
        assert!(nrs.contains(&231), "exit_group missing");
        assert!(nrs.contains(&9), "mmap missing");
        assert!(nrs.contains(&56), "clone missing");
    }

    #[test]
    fn whitelist_excludes_dangerous() {
        let nrs: Vec<u32> = WHITELIST.iter().map(|(nr, _)| *nr).collect();
        assert!(!nrs.contains(&101), "ptrace should not be in whitelist");
        assert!(!nrs.contains(&165), "mount should not be in whitelist");
        assert!(!nrs.contains(&321), "bpf should not be in whitelist");
        assert!(
            !nrs.contains(&425),
            "io_uring_setup should not be in whitelist"
        );
        assert!(!nrs.contains(&169), "reboot should not be in whitelist");
        assert!(
            !nrs.contains(&SYS_CLONE3),
            "clone3 should not be in whitelist"
        );
        assert!(!nrs.contains(&SYS_KILL), "kill should not be in whitelist");
        assert!(
            !nrs.contains(&SYS_TKILL),
            "tkill should not be in whitelist"
        );
        assert!(
            !nrs.contains(&SYS_SETPGID),
            "setpgid should not be in whitelist"
        );
        assert!(
            !nrs.contains(&SYS_SETSID),
            "setsid should not be in whitelist"
        );
    }

    #[test]
    fn policy_can_remove_from_whitelist() {
        let policy = ProcessPolicy {
            blocked_syscalls: vec!["fork".into(), "execve".into()],
            ..Default::default()
        };
        let spec = SeccompFilterSpec::from_policy(&policy, SeccompOptions::default()).unwrap();

        assert!(
            !spec.allowed_syscalls.contains(&57),
            "fork should be removed"
        );
        assert!(
            !spec.allowed_syscalls.contains(&59),
            "execve should be removed"
        );
        assert!(spec.allowed_syscalls.contains(&0), "read should remain");
    }

    #[test]
    fn unknown_blocked_syscall_is_fatal() {
        let policy = ProcessPolicy {
            blocked_syscalls: vec!["not_a_real_syscall".into()],
            ..Default::default()
        };

        let err = prepare_seccomp(&policy).unwrap_err();

        assert!(err.contains("unknown syscall"));
    }

    #[test]
    fn decision_kills_wrong_architecture() {
        let spec =
            SeccompFilterSpec::from_policy(&ProcessPolicy::default(), SeccompOptions::default())
                .unwrap();

        assert_eq!(spec.decision_for(0, 0, [0; 6]), FilterDecision::KillProcess);
    }

    #[test]
    fn decision_denies_documented_escape_syscalls() {
        let spec =
            SeccompFilterSpec::from_policy(&ProcessPolicy::default(), SeccompOptions::default())
                .unwrap();

        for syscall in [
            "ptrace",
            "mount",
            "umount2",
            "bpf",
            "io_uring_setup",
            "process_vm_readv",
            "process_vm_writev",
            "userfaultfd",
            "clone3",
        ] {
            let nr = syscall_number(syscall).unwrap();
            assert_eq!(
                spec.decision_for(AUDIT_ARCH_X86_64, nr, [0; 6]),
                FilterDecision::Errno(libc::EPERM),
                "{syscall} should be denied"
            );
        }
    }

    #[test]
    fn decision_denies_broad_signal_syscalls() {
        let spec =
            SeccompFilterSpec::from_policy(&ProcessPolicy::default(), SeccompOptions::default())
                .unwrap();

        for syscall in [SYS_KILL, SYS_TKILL] {
            assert_eq!(
                spec.decision_for(AUDIT_ARCH_X86_64, syscall, [0; 6]),
                FilterDecision::Errno(libc::EPERM),
                "signal syscall {syscall} should be denied"
            );
        }
    }

    #[test]
    fn decision_denies_process_group_escape_syscalls() {
        let spec =
            SeccompFilterSpec::from_policy(&ProcessPolicy::default(), SeccompOptions::default())
                .unwrap();

        for syscall in [SYS_SETPGID, SYS_SETSID] {
            assert_eq!(
                spec.decision_for(AUDIT_ARCH_X86_64, syscall, [0; 6]),
                FilterDecision::Errno(libc::EPERM),
                "process group syscall {syscall} should be denied"
            );
        }
    }

    #[test]
    fn decision_denies_policy_blocked_syscall() {
        let policy = ProcessPolicy {
            blocked_syscalls: vec!["getpid".into()],
            ..Default::default()
        };
        let spec = SeccompFilterSpec::from_policy(&policy, SeccompOptions::default()).unwrap();

        assert_eq!(
            spec.decision_for(AUDIT_ARCH_X86_64, 39, [0; 6]),
            FilterDecision::Errno(libc::EPERM)
        );
        assert_eq!(
            spec.decision_for(AUDIT_ARCH_X86_64, 0, [0; 6]),
            FilterDecision::Allow
        );
    }

    #[test]
    fn socket_domain_policy_denies_network_domains_but_allows_unix() {
        let spec = SeccompFilterSpec::from_policy(
            &ProcessPolicy::default(),
            SeccompOptions::deny_network_socket_domains(),
        )
        .unwrap();

        for domain in DOCUMENTED_NETWORK_SOCKET_DOMAINS
            .iter()
            .copied()
            .chain([9_999])
        {
            assert_eq!(
                spec.decision_for(
                    AUDIT_ARCH_X86_64,
                    SYS_SOCKET,
                    [domain as u64, 0, 0, 0, 0, 0]
                ),
                FilterDecision::Errno(libc::EPERM),
                "socket domain {domain} should be denied"
            );
        }
        assert_eq!(
            spec.decision_for(
                AUDIT_ARCH_X86_64,
                SYS_SOCKET,
                [AF_UNIX as u64, 0, 0, 0, 0, 0]
            ),
            FilterDecision::Allow
        );
    }

    #[test]
    fn connect_notification_is_opt_in() {
        let default_spec =
            SeccompFilterSpec::from_policy(&ProcessPolicy::default(), SeccompOptions::default())
                .unwrap();
        assert_eq!(
            default_spec.decision_for(AUDIT_ARCH_X86_64, SYS_CONNECT, [0; 6]),
            FilterDecision::Allow
        );

        let notify_spec = SeccompFilterSpec::from_policy(
            &ProcessPolicy::default(),
            SeccompOptions::default().notify_connect(),
        )
        .unwrap();
        assert_eq!(
            notify_spec.decision_for(AUDIT_ARCH_X86_64, SYS_CONNECT, [0; 6]),
            FilterDecision::UserNotify
        );
        assert_eq!(
            notify_spec.decision_for(AUDIT_ARCH_X86_64, 0, [0; 6]),
            FilterDecision::Allow
        );
    }

    #[test]
    fn connect_notification_respects_policy_blocked_connect() {
        let policy = ProcessPolicy {
            blocked_syscalls: vec!["connect".into()],
            ..Default::default()
        };
        let spec =
            SeccompFilterSpec::from_policy(&policy, SeccompOptions::default().notify_connect())
                .unwrap();

        assert!(!spec.allowed_syscalls.contains(&SYS_CONNECT));
        assert!(!spec.notify_connect);
        assert_eq!(
            spec.decision_for(AUDIT_ARCH_X86_64, SYS_CONNECT, [0; 6]),
            FilterDecision::Errno(libc::EPERM)
        );
        assert_eq!(
            bpf_decision_for(&spec, AUDIT_ARCH_X86_64, SYS_CONNECT, [0; 6]),
            FilterDecision::Errno(libc::EPERM)
        );
    }

    #[test]
    fn conditional_rules_deny_dangerous_clone_and_unshare_flags() {
        let mut spec =
            SeccompFilterSpec::from_policy(&ProcessPolicy::default(), SeccompOptions::default())
                .unwrap();
        spec.allowed_syscalls.push(SYS_UNSHARE);
        spec.allowed_syscalls.sort();

        assert_eq!(
            spec.decision_for(
                AUDIT_ARCH_X86_64,
                SYS_CLONE,
                [libc::CLONE_NEWUSER as u64, 0, 0, 0, 0, 0],
            ),
            FilterDecision::Errno(libc::EPERM)
        );
        assert_eq!(
            spec.decision_for(
                AUDIT_ARCH_X86_64,
                SYS_CLONE,
                [libc::SIGCHLD as u64, 0, 0, 0, 0, 0]
            ),
            FilterDecision::Allow
        );
        assert_eq!(
            spec.decision_for(
                AUDIT_ARCH_X86_64,
                SYS_UNSHARE,
                [libc::CLONE_NEWUSER as u64, 0, 0, 0, 0, 0],
            ),
            FilterDecision::Errno(libc::EPERM)
        );
        assert_eq!(
            spec.decision_for(AUDIT_ARCH_X86_64, SYS_UNSHARE, [0; 6]),
            FilterDecision::Allow
        );
    }

    #[test]
    fn generated_bpf_denies_security_sensitive_syscalls() {
        let spec =
            SeccompFilterSpec::from_policy(&ProcessPolicy::default(), SeccompOptions::default())
                .unwrap();

        for syscall in [
            "ptrace",
            "mount",
            "umount2",
            "bpf",
            "io_uring_setup",
            "process_vm_readv",
            "process_vm_writev",
            "userfaultfd",
            "clone3",
        ] {
            let nr = syscall_number(syscall).unwrap();
            assert_eq!(
                bpf_decision_for(&spec, AUDIT_ARCH_X86_64, nr, [0; 6]),
                FilterDecision::Errno(libc::EPERM),
                "{syscall} should be denied by generated BPF"
            );
        }
    }

    #[test]
    fn generated_bpf_denies_broad_signal_syscalls() {
        let spec =
            SeccompFilterSpec::from_policy(&ProcessPolicy::default(), SeccompOptions::default())
                .unwrap();

        for syscall in [SYS_KILL, SYS_TKILL] {
            assert_eq!(
                bpf_decision_for(&spec, AUDIT_ARCH_X86_64, syscall, [0; 6]),
                FilterDecision::Errno(libc::EPERM),
                "signal syscall {syscall} should be denied by generated BPF"
            );
        }
    }

    #[test]
    fn generated_bpf_denies_process_group_escape_syscalls() {
        let spec =
            SeccompFilterSpec::from_policy(&ProcessPolicy::default(), SeccompOptions::default())
                .unwrap();

        for syscall in [SYS_SETPGID, SYS_SETSID] {
            assert_eq!(
                bpf_decision_for(&spec, AUDIT_ARCH_X86_64, syscall, [0; 6]),
                FilterDecision::Errno(libc::EPERM),
                "process group syscall {syscall} should be denied by generated BPF"
            );
        }
    }

    #[test]
    fn generated_bpf_applies_conditional_flag_rules() {
        let mut spec =
            SeccompFilterSpec::from_policy(&ProcessPolicy::default(), SeccompOptions::default())
                .unwrap();
        spec.allowed_syscalls.push(SYS_UNSHARE);
        spec.allowed_syscalls.sort();

        assert_eq!(
            bpf_decision_for(
                &spec,
                AUDIT_ARCH_X86_64,
                SYS_CLONE,
                [libc::CLONE_NEWNS as u64, 0, 0, 0, 0, 0],
            ),
            FilterDecision::Errno(libc::EPERM)
        );
        assert_eq!(
            bpf_decision_for(
                &spec,
                AUDIT_ARCH_X86_64,
                SYS_CLONE,
                [libc::SIGCHLD as u64, 0, 0, 0, 0, 0],
            ),
            FilterDecision::Allow
        );
        assert_eq!(
            bpf_decision_for(
                &spec,
                AUDIT_ARCH_X86_64,
                SYS_UNSHARE,
                [libc::CLONE_NEWUSER as u64, 0, 0, 0, 0, 0],
            ),
            FilterDecision::Errno(libc::EPERM)
        );
        assert_eq!(
            bpf_decision_for(&spec, AUDIT_ARCH_X86_64, SYS_UNSHARE, [0; 6]),
            FilterDecision::Allow
        );

        let mut args = [0u64; 6];
        args[EXECVEAT_FLAGS_ARG] = AT_EMPTY_PATH as u64;
        assert_eq!(
            bpf_decision_for(&spec, AUDIT_ARCH_X86_64, SYS_EXECVEAT, args),
            FilterDecision::Errno(libc::EPERM)
        );
        assert_eq!(
            bpf_decision_for(&spec, AUDIT_ARCH_X86_64, SYS_EXECVEAT, [0; 6]),
            FilterDecision::Allow
        );
    }

    #[test]
    fn generated_bpf_denies_network_socket_domains_when_requested() {
        let spec = SeccompFilterSpec::from_policy(
            &ProcessPolicy::default(),
            SeccompOptions::deny_network_socket_domains(),
        )
        .unwrap();

        for domain in DOCUMENTED_NETWORK_SOCKET_DOMAINS
            .iter()
            .copied()
            .chain([9_999])
        {
            assert_eq!(
                bpf_decision_for(
                    &spec,
                    AUDIT_ARCH_X86_64,
                    SYS_SOCKET,
                    [domain as u64, 0, 0, 0, 0, 0],
                ),
                FilterDecision::Errno(libc::EPERM),
                "socket domain {domain} should be denied by generated BPF"
            );
            assert_eq!(
                bpf_decision_for(
                    &spec,
                    AUDIT_ARCH_X86_64,
                    SYS_SOCKETPAIR,
                    [domain as u64, 0, 0, 0, 0, 0],
                ),
                FilterDecision::Errno(libc::EPERM),
                "socketpair domain {domain} should be denied by generated BPF"
            );
        }
        assert_eq!(
            bpf_decision_for(
                &spec,
                AUDIT_ARCH_X86_64,
                SYS_SOCKET,
                [AF_UNIX as u64, 0, 0, 0, 0, 0],
            ),
            FilterDecision::Allow
        );
    }

    #[test]
    fn generated_bpf_connect_notification_is_opt_in() {
        let default_spec =
            SeccompFilterSpec::from_policy(&ProcessPolicy::default(), SeccompOptions::default())
                .unwrap();
        assert_eq!(
            bpf_decision_for(&default_spec, AUDIT_ARCH_X86_64, SYS_CONNECT, [0; 6]),
            FilterDecision::Allow
        );

        let notify_spec = SeccompFilterSpec::from_policy(
            &ProcessPolicy::default(),
            SeccompOptions::default().notify_connect(),
        )
        .unwrap();
        assert_eq!(
            bpf_decision_for(&notify_spec, AUDIT_ARCH_X86_64, SYS_CONNECT, [0; 6]),
            FilterDecision::UserNotify
        );
        assert_eq!(
            bpf_decision_for(&notify_spec, AUDIT_ARCH_X86_64, 0, [0; 6]),
            FilterDecision::Allow
        );
    }

    #[test]
    fn conditional_rules_deny_execveat_empty_path() {
        let spec =
            SeccompFilterSpec::from_policy(&ProcessPolicy::default(), SeccompOptions::default())
                .unwrap();
        let mut args = [0u64; 6];
        args[EXECVEAT_FLAGS_ARG] = AT_EMPTY_PATH as u64;

        assert_eq!(
            spec.decision_for(AUDIT_ARCH_X86_64, SYS_EXECVEAT, args),
            FilterDecision::Errno(libc::EPERM)
        );
        assert_eq!(
            spec.decision_for(AUDIT_ARCH_X86_64, SYS_EXECVEAT, [0; 6]),
            FilterDecision::Allow
        );
    }

    #[test]
    fn runtime_execveat_empty_path_flag_is_denied_by_kernel_filter() {
        assert_eq!(
            run_seccomp_probe(
                &ProcessPolicy::default(),
                SeccompOptions::default(),
                probe_execveat_empty_path,
            ),
            PROBE_DENIED
        );
    }

    #[test]
    fn runtime_socket_domain_filter_denies_ip_sockets_and_preserves_unix() {
        let options = SeccompOptions::deny_network_socket_domains();

        assert_eq!(
            run_seccomp_probe(
                &ProcessPolicy::default(),
                options.clone(),
                probe_inet_socket
            ),
            PROBE_DENIED
        );
        assert_eq!(
            run_seccomp_probe(
                &ProcessPolicy::default(),
                options.clone(),
                probe_inet6_socket
            ),
            PROBE_DENIED
        );
        assert_eq!(
            run_seccomp_probe(&ProcessPolicy::default(), options, probe_unix_socketpair),
            PROBE_ALLOWED
        );
    }

    #[test]
    fn runtime_shell_smoke_under_filter() {
        let Some(status) = run_with_seccomp("/bin/sh", &["-c", "true"], &ProcessPolicy::default())
        else {
            eprintln!("/bin/sh unavailable (test skipped)");
            return;
        };

        assert!(status.success(), "shell smoke failed: {status}");
    }

    #[test]
    fn runtime_python_smoke_under_filter_when_available() {
        let Some(python) = find_on_path("python3") else {
            eprintln!("python3 unavailable (test skipped)");
            return;
        };
        let Ok(baseline) = Command::new(&python).arg("-c").arg("pass").status() else {
            eprintln!("python3 baseline failed to start (test skipped)");
            return;
        };
        if !baseline.success() {
            eprintln!("python3 baseline failed (test skipped)");
            return;
        }

        let status = run_with_seccomp(&python, &["-c", "pass"], &ProcessPolicy::default())
            .expect("python3 should exist after baseline check");

        assert!(status.success(), "python smoke failed: {status}");
    }

    #[test]
    fn runtime_configured_blocked_syscall_denies_process() {
        let policy = ProcessPolicy {
            blocked_syscalls: vec!["write".into()],
            ..Default::default()
        };
        let Some(status) = run_with_seccomp("/bin/sh", &["-c", "echo denied"], &policy) else {
            eprintln!("/bin/sh unavailable (test skipped)");
            return;
        };

        assert!(
            !status.success(),
            "write-blocked shell unexpectedly succeeded"
        );
    }

    fn run_with_seccomp(
        program: &str,
        args: &[&str],
        policy: &ProcessPolicy,
    ) -> Option<ExitStatus> {
        if !std::path::Path::new(program).exists() {
            return None;
        }

        let filter = prepare_seccomp(policy).expect("test policy should prepare seccomp");
        let mut cmd = Command::new(program);
        cmd.args(args);
        unsafe {
            cmd.pre_exec(move || {
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                filter
                    .apply_current_process()
                    .map_err(std::io::Error::from_raw_os_error)
            });
        }
        Some(cmd.status().expect("seccomp runtime child should start"))
    }

    fn run_seccomp_probe(
        policy: &ProcessPolicy,
        options: SeccompOptions,
        probe: unsafe fn() -> libc::c_long,
    ) -> i32 {
        let filter =
            prepare_seccomp_with_options(policy, options).expect("test policy should prepare");
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());

        if pid == 0 {
            unsafe {
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
                    libc::_exit(PROBE_NO_NEW_PRIVS_FAILED);
                }
            }
            if filter.apply_current_process().is_err() {
                unsafe {
                    libc::_exit(PROBE_SECCOMP_SETUP_FAILED);
                }
            }

            let ret = unsafe { probe() };
            if ret == -1 {
                let errno = current_errno();
                let code = if errno == libc::EPERM {
                    PROBE_DENIED
                } else {
                    PROBE_UNEXPECTED_ERRNO
                };
                unsafe {
                    libc::_exit(code);
                }
            }

            unsafe {
                libc::_exit(PROBE_ALLOWED);
            }
        }

        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(waited, pid, "waitpid failed for seccomp probe");

        if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            PROBE_SIGNALLED
        }
    }

    unsafe fn probe_execveat_empty_path() -> libc::c_long {
        unsafe {
            libc::syscall(
                SYS_EXECVEAT as libc::c_long,
                -1,
                c"".as_ptr(),
                std::ptr::null::<*const libc::c_char>(),
                std::ptr::null::<*const libc::c_char>(),
                AT_EMPTY_PATH,
            )
        }
    }

    unsafe fn probe_inet_socket() -> libc::c_long {
        unsafe {
            libc::syscall(
                SYS_SOCKET as libc::c_long,
                libc::AF_INET,
                libc::SOCK_STREAM,
                0,
            )
        }
    }

    unsafe fn probe_inet6_socket() -> libc::c_long {
        unsafe {
            libc::syscall(
                SYS_SOCKET as libc::c_long,
                libc::AF_INET6,
                libc::SOCK_STREAM,
                0,
            )
        }
    }

    unsafe fn probe_unix_socketpair() -> libc::c_long {
        let mut fds = [0; 2];
        unsafe {
            libc::syscall(
                SYS_SOCKETPAIR as libc::c_long,
                AF_UNIX,
                libc::SOCK_STREAM,
                0,
                fds.as_mut_ptr(),
            )
        }
    }

    fn bpf_decision_for(
        spec: &SeccompFilterSpec,
        arch: u32,
        syscall_nr: u32,
        args: [u64; 6],
    ) -> FilterDecision {
        decode_seccomp_action(interpret_bpf(&spec.to_bpf(), arch, syscall_nr, args))
    }

    fn interpret_bpf(insns: &[BpfInsn], arch: u32, syscall_nr: u32, args: [u64; 6]) -> u32 {
        let mut pc = 0usize;
        let mut accumulator = 0u32;

        loop {
            let insn = insns
                .get(pc)
                .unwrap_or_else(|| panic!("seccomp BPF program fell off at pc {pc}"));
            match insn.code {
                code if code == (BPF_LD | BPF_W | BPF_ABS) => {
                    accumulator = load_seccomp_word(insn.k, arch, syscall_nr, args);
                    pc += 1;
                }
                code if code == (BPF_JMP | BPF_JEQ | BPF_K) => {
                    let skip = if accumulator == insn.k {
                        insn.jt
                    } else {
                        insn.jf
                    };
                    pc += 1 + usize::from(skip);
                }
                code if code == (BPF_JMP | BPF_JSET | BPF_K) => {
                    let skip = if (accumulator & insn.k) != 0 {
                        insn.jt
                    } else {
                        insn.jf
                    };
                    pc += 1 + usize::from(skip);
                }
                code if code == (BPF_RET | BPF_K) => return insn.k,
                other => panic!("unsupported seccomp BPF opcode {other:#x} at pc {pc}"),
            }
        }
    }

    fn load_seccomp_word(offset: u32, arch: u32, syscall_nr: u32, args: [u64; 6]) -> u32 {
        match offset {
            SECCOMP_DATA_NR_OFFSET => syscall_nr,
            SECCOMP_DATA_ARCH_OFFSET => arch,
            offset
                if (SECCOMP_DATA_ARGS_OFFSET..SECCOMP_DATA_ARGS_OFFSET + ARG_SIZE * 6)
                    .contains(&offset) =>
            {
                let relative = offset - SECCOMP_DATA_ARGS_OFFSET;
                let arg = args[(relative / ARG_SIZE) as usize];
                match relative % ARG_SIZE {
                    0 => arg as u32,
                    4 => (arg >> 32) as u32,
                    _ => panic!("unaligned seccomp argument load offset {offset}"),
                }
            }
            _ => panic!("unsupported seccomp data load offset {offset}"),
        }
    }

    fn decode_seccomp_action(action: u32) -> FilterDecision {
        if action == SECCOMP_RET_KILL_PROCESS {
            FilterDecision::KillProcess
        } else if action == SECCOMP_RET_ALLOW {
            FilterDecision::Allow
        } else if action == SECCOMP_RET_USER_NOTIF {
            FilterDecision::UserNotify
        } else if (action & 0xffff_0000) == SECCOMP_RET_ERRNO {
            FilterDecision::Errno((action & 0xffff) as i32)
        } else {
            panic!("unsupported seccomp return action {action:#x}")
        }
    }

    fn find_on_path(binary: &str) -> Option<String> {
        let path = std::env::var_os("PATH")?;
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(binary);
            if candidate.exists() {
                return Some(candidate.to_string_lossy().into_owned());
            }
        }
        None
    }
}
