//! The same scenario through three routes must give the same transcript:
//!
//! 1. straight to SoftHSM,
//! 2. through the Rust proxy (the cdylib loaded by `dlopen`, and the daemon process),
//! 3. through the C proxy this project replaces (if built; see the README).
//!
//! Needs SoftHSM (see p11_testkit::softhsm) and a built workspace; builds what
//! it needs.
#![allow(clippy::undocumented_unsafe_blocks)]

use p11_testkit::proc::DaemonProc;
use p11_testkit::softhsm::Token;
use std::path::{Path, PathBuf};
use std::process::Command;

fn target_dir() -> PathBuf {
    // .../target/debug/deps/parity-HASH
    std::env::current_exe().unwrap().parent().unwrap().parent().unwrap().to_path_buf()
}

fn dylib(dir: &Path, stem: &str) -> PathBuf {
    let ext = if cfg!(target_os = "macos") { "dylib" } else { "so" };
    dir.join(format!("lib{stem}.{ext}"))
}

/// Build the binaries and the cdylib (once), returning (scenario, daemon, client library).
fn build() -> (PathBuf, PathBuf, PathBuf) {
    static ONCE: std::sync::OnceLock<(PathBuf, PathBuf, PathBuf)> = std::sync::OnceLock::new();
    ONCE.get_or_init(|| {
        let dir = target_dir();
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let release = dir.file_name().unwrap() == "release";
        let mut cmd = Command::new(cargo);
        cmd.args(["build", "-q", "-p", "p11-client", "-p", "p11-daemon", "-p", "p11-conformance", "--bins", "--lib"]);
        cmd.arg("--manifest-path").arg(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml"));
        if release {
            cmd.arg("--release");
        }
        assert!(cmd.status().unwrap().success(), "building the workspace");
        (dir.join("p11-scenario"), dir.join("p11-daemon"), dylib(&dir, "p11_proxy"))
    })
    .clone()
}

fn c_ref() -> Option<(PathBuf, PathBuf)> {
    let d = std::env::var_os("P11_C_REF_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share/p11-proxy-rs/c-ref")))?;
    let (lib, daemon) = (dylib(&d, "pkcs11-proxy"), d.join("pkcs11-daemon"));
    (lib.exists() && daemon.exists()).then_some((lib, daemon))
}

fn scenario(bin: &Path, module: &Path, envs: &[(&str, &std::ffi::OsStr)]) -> String {
    let mut cmd = Command::new(bin);
    cmd.arg(module).env_remove("PKCS11_PROXY_DEBUG");
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    assert!(out.status.success(), "scenario failed: {:?}\n{}", out.status, String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap()
}

fn direct(bin: &Path) -> String {
    let t = Token::create().expect("softhsm");
    scenario(bin, &t.module, &t.envs())
}

fn rust_proxy(bin: &Path, daemon: &Path, lib: &Path) -> String {
    let t = Token::create().expect("softhsm");
    let sock = t.path().join("rust.sock");
    let module = t.module.to_str().unwrap().to_string();
    let listen = format!("unix://{}", sock.display());
    let _d = DaemonProc::spawn(daemon, &["--listen", &listen, &module], &t.envs(), 1).unwrap();
    scenario(bin, lib, &[("PKCS11_PROXY_SOCKET", listen.as_ref())])
}

fn c_proxy(bin: &Path, cd: &Path, clib: &Path) -> String {
    let t = Token::create().expect("softhsm");
    // the C daemon takes a directory and makes `socket.pkcs11` in it; its client
    // is given the path without the suffix
    let dir = t.path().join("csock");
    std::fs::create_dir_all(&dir).unwrap();
    let mut child = Command::new(cd)
        .arg(&t.module)
        .envs(t.envs())
        .env("PKCS11_DAEMON_SOCKET", &dir)
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let real = dir.join("socket.pkcs11");
    for _ in 0..100 {
        if real.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let r = scenario(bin, clib, &[("PKCS11_PROXY_SOCKET", dir.join("socket").as_os_str())]);
    let _ = child.kill();
    let _ = child.wait();
    r
}

/// Where a proxy answers differently from the module on purpose: it refuses what it cannot carry
/// before anything is sent (both this proxy and the C one do). Each entry is the step's label and
/// what a proxy says.
const DOCUMENTED: &[(&str, &str)] = &[
    // an attribute whose value is a template of a size that is not a whole number of attributes
    ("template of a bad size", "CKR_ATTRIBUTE_VALUE_INVALID"),
    // a mechanism the proxy does not carry
    ("derive with an unknown mechanism", "CKR_MECHANISM_INVALID"),
];

fn diff(a: &str, b: &str) -> Vec<String> {
    // the documented steps must say what the documentation says, and are then left out
    for (label, says) in DOCUMENTED {
        let line = b.lines().find(|l| l.starts_with(&format!("{label}:"))).unwrap_or_else(|| panic!("no step {label}"));
        assert_eq!(line, format!("{label}: {says}"), "documented divergence");
    }
    let keep = |t: &str| -> String {
        t.lines()
            .filter(|l| !DOCUMENTED.iter().any(|(label, _)| l.starts_with(&format!("{label}:"))))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let (a, b) = (keep(a), keep(b));
    let (a, b): (Vec<&str>, Vec<&str>) = (a.lines().collect(), b.lines().collect());
    let mut out = Vec::new();
    for i in 0..a.len().max(b.len()) {
        let (x, y) = (a.get(i).copied().unwrap_or("<missing>"), b.get(i).copied().unwrap_or("<missing>"));
        if x != y {
            out.push(format!("line {}:\n  direct: {x}\n  proxy:  {y}", i + 1));
        }
    }
    out
}

#[test]
fn the_rust_proxy_is_transparent() {
    if Token::create().is_none() {
        eprintln!("SKIP: no SoftHSM");
        return;
    }
    let (bin, daemon, lib) = build();
    let base = direct(&bin);
    assert!(base.lines().count() > 100, "the scenario ran: {base}");
    let via_rust = rust_proxy(&bin, &daemon, &lib);
    let d = diff(&base, &via_rust);
    assert!(d.is_empty(), "the Rust proxy differs from the module it fronts:\n{}", d.join("\n"));
}

#[test]
fn the_c_proxy_for_comparison() {
    let Some((clib, cdaemon)) = c_ref() else {
        eprintln!("SKIP: no C reference build (set P11_C_REF_DIR)");
        return;
    };
    if Token::create().is_none() {
        eprintln!("SKIP: no SoftHSM");
        return;
    }
    let (bin, _daemon, _lib) = build();
    let base = direct(&bin);
    let via_c = c_proxy(&bin, &cdaemon, &clib);
    let d = diff(&base, &via_c);
    assert!(d.is_empty(), "the C proxy differs from the module in {} lines:\n{}", d.len(), d.join("\n"));
}
