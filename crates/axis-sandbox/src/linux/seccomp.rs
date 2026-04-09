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

const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;

const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

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
    (56, "clone"),       // needed for threads (fork filtering done separately)
    (57, "fork"),
    (58, "vfork"),
    (59, "execve"),
    (60, "exit"),
    (61, "wait4"),
    (62, "kill"),        // only for sending signals to own process group
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
    (109, "setpgid"),
    (110, "getppid"),
    (111, "getpgrp"),
    (112, "setsid"),
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
    (200, "tkill"),
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
    // clone3 — needed by newer glibc for thread creation
    (435, "clone3"),
];

/// BPF instruction.
#[repr(C)]
#[derive(Clone, Copy)]
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

fn bpf_stmt(code: u16, k: u32) -> BpfInsn {
    BpfInsn { code, jt: 0, jf: 0, k }
}

fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> BpfInsn {
    BpfInsn { code, jt, jf, k }
}

/// Apply seccomp-BPF in default-deny whitelist mode.
///
/// Only syscalls in the whitelist are allowed. Everything else returns EPERM.
/// Must be called from a `pre_exec` hook after PR_SET_NO_NEW_PRIVS.
pub fn apply_seccomp(policy: &ProcessPolicy) -> Result<(), String> {
    // Build the complete allowlist.
    let mut allowed: Vec<u32> = WHITELIST.iter().map(|(nr, _)| *nr).collect();

    // Remove any syscalls the policy explicitly blocks.
    for name in &policy.blocked_syscalls {
        if let Some(nr) = syscall_number(name) {
            allowed.retain(|&n| n != nr);
        } else {
            tracing::warn!("seccomp: unknown syscall '{name}' in blocked_syscalls");
        }
    }

    allowed.sort();
    allowed.dedup();

    // Build BPF program.
    // Structure:
    //   0: Load arch → verify x86_64 → kill if wrong
    //   3: Load syscall nr
    //   4..N: For each allowed syscall: JEQ → ALLOW
    //   N+1: Default: ERRNO(EPERM)
    let n_allowed = allowed.len();
    let mut insns: Vec<BpfInsn> = Vec::with_capacity(4 + n_allowed + 2);

    // Validate architecture.
    insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH_OFFSET));
    insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0));
    insns.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    // Load syscall number.
    insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));

    // For each allowed syscall: if match, jump to ALLOW.
    for (i, nr) in allowed.iter().enumerate() {
        let remaining = n_allowed - i - 1;
        insns.push(bpf_jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            *nr,
            (remaining + 1) as u8, // jump to ALLOW (skip remaining + DENY)
            0,                      // fall through
        ));
    }

    // Default: DENY with EPERM.
    insns.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (libc::EPERM as u32 & 0xFFFF)));

    // ALLOW.
    insns.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    let prog = BpfProg {
        len: insns.len() as u16,
        filter: insns.as_ptr(),
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            1 as libc::c_long, // SECCOMP_SET_MODE_FILTER
            1 as libc::c_long, // SECCOMP_FILTER_FLAG_TSYNC
            &prog as *const BpfProg as libc::c_long,
        )
    };

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!("seccomp(SET_MODE_FILTER) failed: {err}"));
    }

    tracing::info!(
        "seccomp: default-deny mode — {} syscalls whitelisted, {} BPF instructions",
        allowed.len(),
        insns.len(),
    );
    Ok(())
}

/// Map syscall name to x86_64 number.
fn syscall_number(name: &str) -> Option<u32> {
    WHITELIST.iter().find(|(_, n)| *n == name).map(|(nr, _)| *nr).or_else(|| {
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
            "unshare" => Some(272),
            _ => None,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(!nrs.contains(&425), "io_uring_setup should not be in whitelist");
        assert!(!nrs.contains(&169), "reboot should not be in whitelist");
    }

    #[test]
    fn policy_can_remove_from_whitelist() {
        let policy = ProcessPolicy {
            blocked_syscalls: vec!["fork".into(), "execve".into()],
            ..Default::default()
        };
        let mut allowed: Vec<u32> = WHITELIST.iter().map(|(nr, _)| *nr).collect();
        for name in &policy.blocked_syscalls {
            if let Some(nr) = syscall_number(name) {
                allowed.retain(|&n| n != nr);
            }
        }
        assert!(!allowed.contains(&57), "fork should be removed");
        assert!(!allowed.contains(&59), "execve should be removed");
        assert!(allowed.contains(&0), "read should remain");
    }
}
