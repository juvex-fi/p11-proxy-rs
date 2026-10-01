//! A token for conformance tests: SoftHSM by default, any other module on request.
//!
//! SoftHSM reads its configuration once per process, so the fixture is a
//! process-wide singleton: one token, one module. Tests in a binary share it
//! and use their own sessions. The fixture needs a SoftHSM build; point
//! `P11_SOFTHSM_MODULE` (libsofthsm2) and `P11_SOFTHSM_UTIL` (softhsm2-util)
//! at it, or put both in `~/.local/share/p11-proxy-rs/softhsm/`. Without one,
//! [`SoftHsm::global`] returns `None` and the tests skip themselves.
//!
//! `P11_TEST_MODULE=/path/to/module` uses that module instead: the token must
//! already exist (user PIN [`USER_PIN`]) and is shared by all the tests, so run
//! them with `--test-threads=1`. `P11_TEST_SLOT=N` names its slot by its index
//! in the slot list (default 0), for modules that list an admin slot first, and
//! `P11_TEST_TOKEN_LABEL` its label (default `testkit`).
//! Whatever the module needs in its environment (a data directory, say) is
//! inherited by the daemons the tests start.

use p11_module::DlBackend;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, OnceLock};

pub const USER_PIN: &str = "1234";
pub const SO_PIN: &str = "5678";

/// A SoftHSM token directory with an initialised token, not yet loaded by
/// this process (so daemons started by a test can serve it).
#[derive(Debug)]
pub struct Token {
    pub module: PathBuf,
    /// SoftHSM's configuration file; empty for an external module.
    pub conf: PathBuf,
    dir: tempfile::TempDir,
}

/// The module named by `P11_TEST_MODULE`, if any.
fn external_module() -> Option<PathBuf> {
    std::env::var_os("P11_TEST_MODULE").filter(|m| !m.is_empty()).map(PathBuf::from)
}

/// Whether the tests run on a module named by `P11_TEST_MODULE` rather than SoftHSM.
/// Tests may then tolerate what that module does differently (a mechanism it
/// lacks, a label), where with SoftHSM they must not.
pub fn external() -> bool {
    external_module().is_some()
}

/// The label of the token the tests use: SoftHSM's, or `P11_TEST_TOKEN_LABEL`.
pub fn token_label() -> String {
    std::env::var("P11_TEST_TOKEN_LABEL").unwrap_or_else(|_| "testkit".into())
}

/// The index in the slot list of the slot the tests use (`P11_TEST_SLOT`).
pub fn slot_index() -> usize {
    std::env::var("P11_TEST_SLOT").ok().and_then(|v| v.parse().ok()).unwrap_or(0)
}

impl Token {
    /// Create a configuration and an initialised token. Returns `None` if
    /// there is no SoftHSM to use.
    pub fn create() -> Option<Token> {
        if let Some(module) = external_module() {
            if !module.exists() {
                eprintln!("P11_TEST_MODULE {} does not exist", module.display());
                return None;
            }
            return Some(Token { module, conf: PathBuf::new(), dir: tempfile::tempdir().ok()? });
        }
        let (module, util) = locate()?;
        let dir = tempfile::tempdir().ok()?;
        let tokens = dir.path().join("tokens");
        std::fs::create_dir_all(&tokens).ok()?;
        let conf = dir.path().join("softhsm2.conf");
        std::fs::write(
            &conf,
            format!(
                "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n",
                tokens.display()
            ),
        )
        .ok()?;
        let st = Command::new(&util)
            .args(["--init-token", "--free", "--label", "testkit", "--so-pin", SO_PIN, "--pin", USER_PIN])
            .arg("--module")
            .arg(&module)
            .env("SOFTHSM2_CONF", &conf)
            .output()
            .ok()?;
        if !st.status.success() {
            eprintln!("softhsm2-util failed: {}", String::from_utf8_lossy(&st.stderr));
            return None;
        }
        Some(Token { module, conf, dir })
    }

    /// What a process that uses this token needs in its environment.
    pub fn envs(&self) -> Vec<(&'static str, &std::ffi::OsStr)> {
        if self.conf.as_os_str().is_empty() {
            Vec::new()
        } else {
            vec![("SOFTHSM2_CONF", self.conf.as_os_str())]
        }
    }

    /// The directory holding the token (deleted when this is dropped).
    pub fn path(&self) -> &std::path::Path {
        self.dir.path()
    }
}

#[derive(Debug)]
pub struct SoftHsm {
    pub module: PathBuf,
    pub slot: u64,
    pub backend: Arc<DlBackend>,
    _token: Token,
}

fn locate() -> Option<(PathBuf, PathBuf)> {
    let default = std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share/p11-proxy-rs/softhsm"));
    let module = std::env::var_os("P11_SOFTHSM_MODULE").map(PathBuf::from).or_else(|| {
        let d = default.as_ref()?;
        ["libsofthsm2.dylib", "libsofthsm2.so"].iter().map(|n| d.join(n)).find(|p| p.exists())
    })?;
    let util =
        std::env::var_os("P11_SOFTHSM_UTIL").map(PathBuf::from).or_else(|| default.map(|d| d.join("softhsm2-util")))?;
    (module.exists() && util.exists()).then_some((module, util))
}

impl SoftHsm {
    pub fn global() -> Option<&'static SoftHsm> {
        static G: OnceLock<Option<SoftHsm>> = OnceLock::new();
        G.get_or_init(Self::create).as_ref()
    }

    fn create() -> Option<SoftHsm> {
        let token = Token::create()?;
        if !token.conf.as_os_str().is_empty() {
            std::env::set_var("SOFTHSM2_CONF", &token.conf);
        }
        // the token got a new slot id; find it through the module
        let backend = Arc::new(DlBackend::open(&token.module, false).ok()?);
        let slots = crate::call::slot_list(&*backend, true)?;
        let slot = *slots.get(slot_index())?;
        Some(SoftHsm { module: token.module.clone(), slot, backend, _token: token })
    }
}
