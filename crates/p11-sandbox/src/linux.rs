//! seccomp: an allow-list of the system calls the running daemon makes.
//!
//! The list was measured, not guessed: `scripts/regen-seccomp.sh` runs the
//! end-to-end tests under strace on aarch64 and lists the calls made after
//! startup; the x86-64 legacy equivalents (open, stat, poll, ...) are added
//! by hand below. Anything else kills the process (SIGSYS with `debug`).
//! Calls that only startup makes (bind, listen, execve, ...) are deliberately
//! absent; sockets can only be local ones, for syslog.

use crate::{Applied, Options};
use seccompiler::{
    apply_filter_all_threads, BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
    SeccompFilter, SeccompRule, TargetArch,
};
use std::collections::BTreeMap;

macro_rules! allow {
    ($m:ident; $($sys:ident),* $(,)?) => { $( $m.insert(libc::$sys as i64, vec![]); )* };
}

pub fn allowed_syscalls() -> BTreeMap<i64, Vec<SeccompRule>> {
    let mut m: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    // files: token stores, keys, /dev/urandom
    allow!(m; SYS_read, SYS_write, SYS_writev, SYS_readv, SYS_pread64, SYS_pwrite64, SYS_lseek, SYS_close,
        SYS_fcntl, SYS_ioctl, SYS_openat, SYS_faccessat, SYS_newfstatat, SYS_statx, SYS_fstat, SYS_getdents64,
        SYS_readlinkat, SYS_getcwd, SYS_ftruncate, SYS_fsync, SYS_fdatasync, SYS_unlinkat, SYS_renameat,
        SYS_mkdirat, SYS_fchmod, SYS_fchmodat, SYS_flock, SYS_umask, SYS_dup, SYS_dup3);
    // sockets that already exist
    allow!(m; SYS_accept4, SYS_recvfrom, SYS_sendto, SYS_recvmsg, SYS_sendmsg, SYS_shutdown, SYS_setsockopt,
        SYS_getsockopt, SYS_getsockname, SYS_getpeername, SYS_ppoll, SYS_pselect6);
    // memory, threads, signals, time, identity
    allow!(m; SYS_brk, SYS_munmap, SYS_madvise, SYS_mremap, SYS_futex, SYS_clone, SYS_clone3, SYS_set_robust_list,
        SYS_rseq, SYS_set_tid_address, SYS_sigaltstack, SYS_rt_sigaction, SYS_rt_sigprocmask, SYS_rt_sigreturn,
        SYS_rt_sigtimedwait, SYS_sched_getaffinity, SYS_sched_yield, SYS_gettid, SYS_getpid, SYS_tgkill,
        SYS_exit, SYS_exit_group, SYS_prctl, SYS_prlimit64, SYS_sysinfo, SYS_getrandom, SYS_clock_gettime,
        SYS_clock_nanosleep, SYS_nanosleep, SYS_gettimeofday, SYS_getuid, SYS_geteuid, SYS_getgid, SYS_getegid,
        SYS_uname, SYS_membarrier, SYS_mlock, SYS_munlock);
    // the calls of older x86-64 kernels' ABI that the ones above replaced
    #[cfg(target_arch = "x86_64")]
    allow!(m; SYS_open, SYS_stat, SYS_lstat, SYS_access, SYS_readlink, SYS_unlink, SYS_rename, SYS_mkdir, SYS_chmod,
        SYS_poll, SYS_select, SYS_dup2, SYS_getdents, SYS_time, SYS_arch_prctl, SYS_accept, SYS_pipe, SYS_faccessat2);
    #[cfg(target_arch = "aarch64")]
    allow!(m; SYS_faccessat2);

    // syslog(3), which modules use for their logs, talks to /dev/log over a
    // local datagram socket; nothing else may open sockets
    allow!(m; SYS_connect);
    m.insert(
        libc::SYS_socket as i64,
        vec![SeccompRule::new(vec![SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            libc::AF_UNIX as u64,
        )
        .unwrap()])
        .unwrap()],
    );

    // memory that can be mapped or protected must not become executable
    let no_exec = |arg: u8| {
        vec![SeccompRule::new(vec![SeccompCondition::new(
            arg,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::MaskedEq(libc::PROT_EXEC as u64),
            0,
        )
        .unwrap()])
        .unwrap()]
    };
    m.insert(libc::SYS_mmap as i64, no_exec(2));
    m.insert(libc::SYS_mprotect as i64, no_exec(2));
    m
}

pub fn apply(o: &Options) -> Result<Applied, String> {
    let arch = match std::env::consts::ARCH {
        "x86_64" => TargetArch::x86_64,
        "aarch64" => TargetArch::aarch64,
        other => return Err(format!("no seccomp filter for {other}")),
    };
    // no privilege can be gained through exec from here on, and the process
    // can't be inspected by an unprivileged tracer
    // SAFETY: prctl with integer arguments.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(format!("PR_SET_NO_NEW_PRIVS: {}", std::io::Error::last_os_error()));
        }
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
    let mismatch = if o.debug || std::env::var_os("PKCS11_DAEMON_SECCOMP_TRAP").is_some() {
        SeccompAction::Trap
    } else {
        SeccompAction::KillProcess
    };
    let filter =
        SeccompFilter::new(allowed_syscalls(), mismatch, SeccompAction::Allow, arch).map_err(|e| e.to_string())?;
    let prog: BpfProgram = filter.try_into().map_err(|e: seccompiler::BackendError| e.to_string())?;
    apply_filter_all_threads(&prog).map_err(|e| e.to_string())?;
    Ok(Applied::Confined("seccomp system call filter"))
}
