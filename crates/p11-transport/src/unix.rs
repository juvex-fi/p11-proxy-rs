//! Local sockets.

use crate::{Closer, Conn, Connector, Identity, Incoming, Listener, Prober};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

impl Conn for UnixStream {
    fn set_timeouts(&self, read: Option<Duration>, write: Option<Duration>) -> io::Result<()> {
        self.set_read_timeout(read)?;
        self.set_write_timeout(write)
    }
    fn closer(&self) -> io::Result<Closer> {
        let s = self.try_clone()?;
        Ok(Arc::new(move || {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }))
    }
    fn probe(&self) -> bool {
        crate::sock::probe_fd(self.as_raw_fd())
    }
    fn prober(&self) -> Option<Prober> {
        let s = self.try_clone().ok()?;
        Some(Arc::new(move || crate::sock::probe_fd(s.as_raw_fd())))
    }
}

#[derive(Debug, Clone)]
pub struct UnixConnector(pub PathBuf);

impl Connector for UnixConnector {
    fn connect(&self) -> io::Result<Box<dyn Conn>> {
        Ok(Box::new(UnixStream::connect(&self.0)?))
    }
}

/// The user id of the process at the other end of a local socket.
pub fn peer_uid(s: &UnixStream) -> io::Result<u32> {
    let fd = s.as_raw_fd();
    #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
    {
        let (mut uid, mut gid) = (0 as libc::uid_t, 0 as libc::gid_t);
        // SAFETY: getpeereid on a live socket with valid out pointers.
        if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(uid)
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let mut cred: libc::ucred = libc::ucred { pid: 0, uid: 0, gid: 0 };
        let mut len = core::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: SO_PEERCRED fills a ucred of the size given.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(cred.uid)
    }
}

/// The identity of a local peer. Only the uid: turning it into a user name
/// would go through NSS, which may open sockets and load libraries, and the
/// daemon must be free to forbid both.
pub fn identity_of(uid: u32) -> Identity {
    Identity::new(format!("unix:uid={uid}"))
}

pub struct UnixIncoming(UnixStream);

impl Incoming for UnixIncoming {
    fn establish(self: Box<Self>) -> io::Result<(Box<dyn Conn>, Identity)> {
        let uid = peer_uid(&self.0)?;
        Ok((Box::new(self.0), identity_of(uid)))
    }
}

pub struct UnixAcceptor {
    l: UnixListener,
    path: PathBuf,
}

impl UnixAcceptor {
    /// Listen on `path`. A stale socket file is replaced; anything else in
    /// the way is an error. The socket is accessible to its owner and
    /// group only (mode 0660) unless `mode` says otherwise.
    pub fn bind(path: &Path, mode: Option<u32>) -> io::Result<UnixAcceptor> {
        if let Ok(md) = std::fs::symlink_metadata(path) {
            use std::os::unix::fs::FileTypeExt;
            if md.file_type().is_socket() {
                // only remove it if nobody is listening
                if UnixStream::connect(path).is_ok() {
                    return Err(io::Error::new(io::ErrorKind::AddrInUse, "another process is listening there"));
                }
                std::fs::remove_file(path)?;
            } else {
                return Err(io::Error::new(io::ErrorKind::AlreadyExists, "path exists and is not a socket"));
            }
        }
        let l = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode.unwrap_or(0o660)))?;
        Ok(UnixAcceptor { l, path: path.to_path_buf() })
    }
}

impl Drop for UnixAcceptor {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Listener for UnixAcceptor {
    fn accept(&self) -> io::Result<Box<dyn Incoming>> {
        let (s, _) = self.l.accept()?;
        Ok(Box::new(UnixIncoming(s)))
    }
    fn describe(&self) -> String {
        format!("unix://{}", self.path.display())
    }
}
