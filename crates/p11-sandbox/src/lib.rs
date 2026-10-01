//! Confining the daemon once it has opened its module and bound its sockets.
//!
//! - [`drop_privileges`]: become an unprivileged user (any Unix)
//! - Linux: `PR_SET_NO_NEW_PRIVS`, no ptrace of the process, and a seccomp
//!   allow-list of the system calls the running daemon needs
//! - macOS: a Seatbelt profile that forbids exec, fork and outbound network
//!   connections, and optionally file writes outside given paths
//!
//! Other systems get [`Applied::Unsupported`]; whether that is acceptable is
//! the caller's [`Mode`].

use std::ffi::CString;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

/// How firmly confinement is wanted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Confine where the platform allows, and carry on (with a warning) where it doesn't.
    #[default]
    Auto,
    Off,
    /// Refuse to run unconfined.
    Require,
}

impl Mode {
    pub fn parse(s: &str) -> Result<Mode, String> {
        match s {
            "auto" => Ok(Mode::Auto),
            "off" => Ok(Mode::Off),
            "require" => Ok(Mode::Require),
            _ => Err(format!("sandbox mode must be auto, off or require, not {s:?}")),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Options {
    pub mode: Mode,
    /// macOS: paths the process may still write to (the token store, ...).
    /// Empty means writes are not restricted.
    pub write_paths: Vec<std::path::PathBuf>,
    /// Report forbidden system calls (SIGSYS) instead of killing the process:
    /// for finding out what a module needs. Linux only.
    pub debug: bool,
}

/// What [`apply`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Applied {
    Off,
    /// Applied, with a description.
    Confined(&'static str),
    Unsupported,
}

/// Confine the process as `o` asks. Call after everything that needs
/// privileges or system calls the running daemon doesn't (opening the
/// module, binding sockets), and before starting threads that serve clients.
pub fn apply(o: &Options) -> Result<Applied, String> {
    if o.mode == Mode::Off {
        return Ok(Applied::Off);
    }
    let r = platform(o);
    match (&r, o.mode) {
        (Ok(Applied::Unsupported), Mode::Require) => Err("confinement is not available on this platform".into()),
        (Err(e), Mode::Auto) => Ok({
            eprintln!("p11-daemon: warning: could not confine the process: {e}");
            Applied::Unsupported
        }),
        _ => r,
    }
}

#[cfg(target_os = "linux")]
fn platform(o: &Options) -> Result<Applied, String> {
    linux::apply(o)
}
#[cfg(target_os = "macos")]
fn platform(o: &Options) -> Result<Applied, String> {
    macos::apply(o)
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn platform(_o: &Options) -> Result<Applied, String> {
    Ok(Applied::Unsupported)
}

/// Become `user`: supplementary groups, gid, then uid, and check it stuck.
/// A process that isn't root can only "become" itself.
pub fn drop_privileges(user: &str) -> Result<(), String> {
    let cname = CString::new(user).map_err(|_| "user name contains a NUL".to_string())?;
    let mut buf = vec![0u8; 4096];
    // SAFETY: a zeroed passwd is a valid out parameter for getpwnam_r.
    let mut pwd: libc::passwd = unsafe { core::mem::zeroed() };
    let mut res: *mut libc::passwd = core::ptr::null_mut();
    // SAFETY: buffers valid for the sizes passed.
    let rc = unsafe {
        libc::getpwnam_r(cname.as_ptr(), &mut pwd, buf.as_mut_ptr() as *mut libc::c_char, buf.len(), &mut res)
    };
    if rc != 0 || res.is_null() {
        return Err(format!("no such user: {user}"));
    }
    let (uid, gid) = (pwd.pw_uid, pwd.pw_gid);
    // SAFETY: plain credential queries.
    let (cur_uid, cur_euid) = unsafe { (libc::getuid(), libc::geteuid()) };
    if cur_euid != 0 {
        return if uid == cur_uid && uid == cur_euid {
            Ok(())
        } else {
            Err(format!("cannot become {user}: not running as root"))
        };
    }
    // SAFETY: credential changes in the documented order; each return value is checked.
    unsafe {
        #[cfg(not(target_os = "macos"))]
        if libc::initgroups(cname.as_ptr(), gid) != 0 {
            return Err(format!("initgroups: {}", std::io::Error::last_os_error()));
        }
        #[cfg(target_os = "macos")]
        if libc::initgroups(cname.as_ptr(), gid as i32) != 0 {
            return Err(format!("initgroups: {}", std::io::Error::last_os_error()));
        }
        if libc::setgid(gid) != 0 {
            return Err(format!("setgid: {}", std::io::Error::last_os_error()));
        }
        if libc::setuid(uid) != 0 {
            return Err(format!("setuid: {}", std::io::Error::last_os_error()));
        }
        if uid != 0 && libc::setuid(0) == 0 {
            return Err("privileges could be regained".into());
        }
        if libc::getuid() != uid || libc::geteuid() != uid || libc::getgid() != gid || libc::getegid() != gid {
            return Err("credentials did not change as expected".into());
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::undocumented_unsafe_blocks, clippy::manual_c_str_literals)]
mod tests {
    use super::*;

    #[test]
    fn modes() {
        assert_eq!(Mode::parse("auto").unwrap(), Mode::Auto);
        assert_eq!(Mode::parse("require").unwrap(), Mode::Require);
        assert!(Mode::parse("yes").is_err());
        assert_eq!(apply(&Options { mode: Mode::Off, ..Default::default() }).unwrap(), Applied::Off);
    }

    #[test]
    fn dropping_to_yourself_or_a_stranger() {
        // SAFETY: getuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return; // as root this would really change the test process
        }
        let me = std::env::var("USER").unwrap_or_default();
        if !me.is_empty() {
            drop_privileges(&me).unwrap();
        }
        assert!(drop_privileges("root").is_err(), "an ordinary user can't become root");
        assert!(drop_privileges("no-such-user-here").is_err());
    }

    /// Runs in a child process (see `seccomp_kills_forbidden_calls`).
    #[cfg(target_os = "linux")]
    #[test]
    fn child_of_seccomp_probe() {
        let Ok(what) = std::env::var("P11_SANDBOX_PROBE") else { return };
        let r = apply(&Options { mode: Mode::Require, ..Default::default() }).unwrap();
        assert!(matches!(r, Applied::Confined(_)));
        // calls the daemon needs still work
        let n = unsafe { libc::write(2, b"alive\n".as_ptr().cast(), 6) };
        assert_eq!(n, 6);
        match what.as_str() {
            // opening a network socket is not allowed
            "socket" => unsafe {
                libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            },
            // neither is running another program
            "exec" => unsafe {
                libc::execve(b"/bin/true\0".as_ptr().cast(), core::ptr::null(), core::ptr::null());
            },
            // a local socket (syslog) is
            "unix-socket" => unsafe {
                let fd = libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0);
                assert!(fd >= 0);
                libc::close(fd);
            },
            // executable memory is not
            "mmap-exec" => unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    4096,
                    libc::PROT_READ | libc::PROT_EXEC,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );
            },
            _ => {}
        }
        // still here: only the allowed ones get this far
        std::process::exit(0);
    }

    /// Runs in a child process as root (see `dropping_privileges_as_root`).
    #[test]
    fn child_of_drop_probe() {
        let Ok(user) = std::env::var("P11_DROP_PROBE") else { return };
        drop_privileges(&user).unwrap();
        // SAFETY: credential queries and one attempt to regain root.
        unsafe {
            assert_ne!(libc::getuid(), 0);
            assert_ne!(libc::geteuid(), 0);
            assert_eq!(libc::setuid(0), -1, "root can't be regained");
        }
    }

    #[test]
    fn dropping_privileges_as_root() {
        // SAFETY: getuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            return; // needs root, e.g. in a container
        }
        let user = "nobody";
        let o = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tests::child_of_drop_probe", "--nocapture"])
            .env("P11_DROP_PROBE", user)
            .output()
            .unwrap();
        assert!(o.status.success(), "{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn seccomp_kills_forbidden_calls() {
        use std::os::unix::process::ExitStatusExt;
        let run = |what: &str| {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "tests::child_of_seccomp_probe", "--nocapture"])
                .env("P11_SANDBOX_PROBE", what)
                .output()
                .unwrap()
        };
        for forbidden in ["socket", "exec", "mmap-exec"] {
            let o = run(forbidden);
            assert_eq!(
                o.status.signal(),
                Some(libc::SIGSYS),
                "{forbidden}: {:?} {}",
                o.status,
                String::from_utf8_lossy(&o.stderr)
            );
        }
        let o = run("unix-socket");
        assert!(o.status.success(), "{:?} {}", o.status, String::from_utf8_lossy(&o.stderr));
        let o = run("nothing");
        assert!(o.status.success());
    }
}
