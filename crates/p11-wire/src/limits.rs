//! Every resource limit of the protocol, in one place. A decoder checks a
//! length against these before it allocates, so a hostile peer can't make
//! either side reserve memory by claiming a large count.

/// Largest frame payload the peers accept.
pub const MAX_FRAME: usize = 16 << 20;
/// Largest single byte string (PKCS#11 buffers travel as byte strings).
pub const MAX_BYTES: usize = MAX_FRAME;
/// Longest array of scalars or of small records (slot lists, handle lists, templates).
pub const MAX_ARRAY: usize = 65_536;
/// Most attributes in one template, top level or nested.
pub const MAX_ATTRS: usize = 4_096;
/// Deepest nesting of attribute templates or parameter trees.
pub const MAX_DEPTH: usize = 8;
/// Most nodes in one decoded parameter tree.
pub const MAX_TREE_NODES: usize = 16_384;
/// Total bytes held by one decoded parameter tree.
pub const MAX_TREE_BYTES: usize = 4 << 20;
/// Longest text field in the handshake.
pub const MAX_TEXT: usize = 256;
/// Vendor-defined mechanisms a daemon may declare.
pub const MAX_VENDOR_MECHS: usize = 1_024;
/// Object handle offsets one vendor-defined mechanism parameter may declare.
pub const MAX_HANDLE_OFFSETS: usize = 64;
/// Structures one daemon may declare for vendor mechanism parameters, members in each, and the longest
/// name of either.
pub const MAX_VENDOR_LAYOUTS: usize = 64;
pub const MAX_LAYOUT_FIELDS: usize = 64;
pub const MAX_LAYOUT_NAME: usize = 64;
/// Vendor-defined functions a daemon may declare.
pub const MAX_VENDOR_FNS: usize = 256;
