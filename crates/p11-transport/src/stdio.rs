//! The daemon's standard input and output as one connection, for launchers
//! that hand it an already accepted socket (inetd, xinetd, systemd
//! `Accept=yes`, stunnel with `exec`). Whoever launched the daemon is
//! responsible for the link's security; the identity is `stdio`.

use crate::{Closer, Conn, Identity, Incoming, Listener};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::FromRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub struct StdioConn {
    r: File,
    w: File,
}

impl StdioConn {
    /// Takes over file descriptors 0 and 1.
    pub fn take() -> io::Result<StdioConn> {
        // SAFETY: duplicating the standard descriptors gives files we own.
        let (r, w) = unsafe {
            let a = libc::dup(0);
            let b = libc::dup(1);
            if a < 0 || b < 0 {
                return Err(io::Error::last_os_error());
            }
            (File::from_raw_fd(a), File::from_raw_fd(b))
        };
        Ok(StdioConn { r, w })
    }
}

impl Read for StdioConn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.r.read(buf)
    }
}
impl Write for StdioConn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.w.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }
}

impl Conn for StdioConn {
    fn set_timeouts(&self, _r: Option<Duration>, _w: Option<Duration>) -> io::Result<()> {
        Ok(()) // pipes have no timeouts; the launcher owns the link
    }
    fn closer(&self) -> io::Result<Closer> {
        Ok(Arc::new(|| {}))
    }
}

/// Yields the standard streams once, then reports that nothing more will come.
pub struct StdioListener {
    used: AtomicBool,
}

impl StdioListener {
    pub fn new() -> StdioListener {
        StdioListener { used: AtomicBool::new(false) }
    }
}

impl Default for StdioListener {
    fn default() -> Self {
        Self::new()
    }
}

struct StdioIncoming;
impl Incoming for StdioIncoming {
    fn establish(self: Box<Self>) -> io::Result<(Box<dyn Conn>, Identity)> {
        Ok((Box::new(StdioConn::take()?), Identity::new("stdio")))
    }
}

impl Listener for StdioListener {
    fn accept(&self) -> io::Result<Box<dyn Incoming>> {
        if self.used.swap(true, Ordering::SeqCst) {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "the standard streams were already used"));
        }
        Ok(Box::new(StdioIncoming))
    }
    fn describe(&self) -> String {
        "stdio".into()
    }
}
