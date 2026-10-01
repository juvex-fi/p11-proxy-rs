//! Running the real `p11-daemon` binary in a test.

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

#[derive(Debug)]
pub struct DaemonProc {
    pub child: Child,
    /// The addresses it reported listening on (`unix:///...`, `tcp://127.0.0.1:PORT`).
    pub listening: Vec<String>,
    pub log: mpsc::Receiver<String>,
}

impl DaemonProc {
    /// Start the daemon and wait until it has reported `expect` listeners.
    pub fn spawn(
        exe: &Path,
        args: &[&str],
        envs: &[(&str, &std::ffi::OsStr)],
        expect: usize,
    ) -> Result<DaemonProc, String> {
        // P11_TEST_WRAPPER="strace -f -o /tmp/trace" runs the daemon under a tool
        let mut cmd = match std::env::var("P11_TEST_WRAPPER") {
            Ok(w) if !w.trim().is_empty() => {
                let mut parts = w.split_whitespace();
                let mut c = Command::new(parts.next().unwrap());
                c.args(parts).arg(exe);
                c
            }
            _ => Command::new(exe),
        };
        cmd.args(args).stderr(Stdio::piped()).stdout(Stdio::null());
        for (k, v) in envs {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().map_err(|e| format!("cannot start {}: {e}", exe.display()))?;
        let stderr = child.stderr.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let mut listening = Vec::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while listening.len() < expect {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            match rx.recv_timeout(left) {
                Ok(l) => {
                    if let Some(rest) = l.split("ready: ").nth(1) {
                        listening.push(rest.split_whitespace().next().unwrap_or("").to_string());
                    }
                    if l.contains("ERROR") || l.contains("p11-daemon:") {
                        let _ = child.kill();
                        return Err(l);
                    }
                }
                Err(_) => {
                    let _ = child.kill();
                    return Err("the daemon did not report ready in time".into());
                }
            }
        }
        Ok(DaemonProc { child, listening, log: rx })
    }

    /// Ask it to stop (SIGTERM) and wait for it to exit.
    pub fn stop(&mut self) -> std::io::Result<std::process::ExitStatus> {
        // SAFETY: signalling a child process we own.
        unsafe { libc::kill(self.child.id() as i32, libc::SIGTERM) };
        self.child.wait()
    }

    /// Kill it without warning.
    pub fn crash(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for DaemonProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
