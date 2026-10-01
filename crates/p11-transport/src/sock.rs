//! Small socket helpers shared by the transports.

use std::io;
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::time::Duration;

pub fn tune_tcp(s: &TcpStream) -> io::Result<()> {
    s.set_nodelay(true)?;
    let fd = s.as_raw_fd();
    let on: libc::c_int = 1;
    // SAFETY: setsockopt on a live socket with a c_int value.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            &on as *const _ as *const libc::c_void,
            core::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        // start probing after a minute of silence, so a dead peer is noticed
        let idle: libc::c_int = 60;
        #[cfg(target_os = "macos")]
        let opt = libc::TCP_KEEPALIVE;
        #[cfg(not(target_os = "macos"))]
        let opt = libc::TCP_KEEPIDLE;
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            opt,
            &idle as *const _ as *const libc::c_void,
            core::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
    Ok(())
}

pub fn set_timeouts(s: &TcpStream, r: Option<Duration>, w: Option<Duration>) -> io::Result<()> {
    s.set_read_timeout(r)?;
    s.set_write_timeout(w)
}

/// A non-blocking check whether a socket's peer has closed it or sent
/// something nobody asked for.
pub fn probe_fd(fd: i32) -> bool {
    let mut b = 0u8;
    // SAFETY: recv into a one-byte buffer with MSG_PEEK | MSG_DONTWAIT never blocks or consumes.
    let n = unsafe { libc::recv(fd, &mut b as *mut _ as *mut libc::c_void, 1, libc::MSG_PEEK | libc::MSG_DONTWAIT) };
    if n < 0 {
        let e = io::Error::last_os_error();
        return matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted);
    }
    false // 0: closed; 1: data nobody asked for
}
