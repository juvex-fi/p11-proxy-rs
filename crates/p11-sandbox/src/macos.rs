//! A Seatbelt profile: the daemon may not start programs, fork, or open
//! outbound network connections, and (optionally) may write only where told.

use crate::{Applied, Options};
use std::ffi::{c_char, c_int, CStr, CString};

extern "C" {
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;
    fn sandbox_free_error(errorbuf: *mut c_char);
}

fn quote(p: &std::path::Path) -> String {
    let s = p.to_string_lossy();
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

pub fn profile(o: &Options) -> String {
    let mut p = String::from("(version 1)\n(allow default)\n(deny process-exec*)\n(deny process-fork)\n(deny network-outbound (remote ip))\n");
    if !o.write_paths.is_empty() {
        p.push_str("(deny file-write*)\n(allow file-write*\n  (literal \"/dev/null\") (literal \"/dev/tty\") (subpath \"/dev/fd\")\n");
        for w in &o.write_paths {
            p.push_str(&format!("  (subpath {})\n", quote(w)));
        }
        p.push_str(")\n");
    }
    p
}

pub fn apply(o: &Options) -> Result<Applied, String> {
    let prof = CString::new(profile(o)).map_err(|e| e.to_string())?;
    let mut err: *mut c_char = core::ptr::null_mut();
    // SAFETY: sandbox_init with a NUL-terminated profile string and flags 0 (the string is a profile, not a name).
    let rc = unsafe { sandbox_init(prof.as_ptr(), 0, &mut err) };
    if rc != 0 {
        let msg = if err.is_null() {
            "sandbox_init failed".to_string()
        } else {
            // SAFETY: on failure errorbuf is a NUL-terminated string to free with sandbox_free_error.
            let m = unsafe { CStr::from_ptr(err) }.to_string_lossy().into_owned();
            // SAFETY: `err` came from sandbox_init and is freed exactly once.
            unsafe { sandbox_free_error(err) };
            m
        };
        return Err(msg);
    }
    Ok(Applied::Confined("Seatbelt profile (no exec, fork or outbound connections)"))
}
