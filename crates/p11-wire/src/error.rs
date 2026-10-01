use core::fmt;

/// Why decoding or framing failed. None of these carry peer-supplied text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// The input ended before the value did.
    Truncated,
    /// A length or count is above its limit.
    TooLarge,
    /// Bytes remain after the message was fully decoded.
    Trailing,
    /// A tag, kind or enum value is not one this version knows.
    BadTag,
    /// Nesting is deeper than [`crate::limits::MAX_DEPTH`].
    TooDeep,
    /// A field violates an invariant (bad magic, reserved bits, ...).
    Invalid,
    /// The peer speaks the old C protocol (it sent its text handshake).
    LegacyPeer,
    /// The underlying stream failed or reached end of file.
    Io(std::io::ErrorKind),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::Truncated => f.write_str("message truncated"),
            WireError::TooLarge => f.write_str("length above limit"),
            WireError::Trailing => f.write_str("trailing bytes after message"),
            WireError::BadTag => f.write_str("unknown tag"),
            WireError::TooDeep => f.write_str("nesting too deep"),
            WireError::Invalid => f.write_str("invalid field"),
            WireError::LegacyPeer => f.write_str("peer speaks the legacy pkcs11-proxy protocol; upgrade it"),
            WireError::Io(k) => write!(f, "i/o error: {k}"),
        }
    }
}

impl std::error::Error for WireError {}

impl From<std::io::Error> for WireError {
    fn from(e: std::io::Error) -> Self {
        WireError::Io(e.kind())
    }
}

pub type Result<T> = core::result::Result<T, WireError>;
