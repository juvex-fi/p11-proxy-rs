/// Who is on the other end, as the transport established it. The name and
/// aliases carry a prefix that says how the peer proved itself, so a
/// certificate whose common name looks like a PSK identity is still just a
/// certificate:
///
/// | prefix | meaning |
/// |---|---|
/// | `cert:cn=` | subject common name of the client certificate |
/// | `cert:san:dns=`, `cert:san:email=`, `cert:san:uri=` | subject alternative names |
/// | `cert:sha256=` | fingerprint of the certificate (lower-case hex) |
/// | `psk:` | the PSK identity |
/// | `unix:uid=`, `unix:user=` | the peer's uid and user name |
/// | `stdio` | whoever started the daemon on a pipe |
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Identity {
    pub name: String,
    pub aliases: Vec<String>,
}

impl Identity {
    pub fn new(name: impl Into<String>) -> Identity {
        Identity { name: name.into(), aliases: Vec::new() }
    }
    pub fn with_aliases(name: impl Into<String>, aliases: Vec<String>) -> Identity {
        Identity { name: name.into(), aliases }
    }
    pub fn anonymous() -> Identity {
        Identity::new("anonymous")
    }
    /// The name and every alias.
    pub fn labels(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.name.as_str()).chain(self.aliases.iter().map(|s| s.as_str()))
    }
    pub fn matches(&self, label: &str) -> bool {
        self.labels().any(|l| l == label)
    }
}

impl core::fmt::Display for Identity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.name)
    }
}
