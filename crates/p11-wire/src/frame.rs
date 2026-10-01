//! Frames: `u32 payload length`, `u8 kind`, payload. The length is checked
//! against the limit before any payload byte is read or allocated.

use crate::codec::{Decode, Encode, Reader, Writer};
use crate::error::{Result, WireError};
use crate::limits::MAX_FRAME;
use std::io::{Read, Write};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Hello = 1,
    HelloAck = 2,
    Request = 3,
    Response = 4,
    /// The sender is closing the connection because of a protocol error.
    Abort = 5,
    /// The vendor-defined mechanisms the daemon carries, sent once right after `HelloAck` to a
    /// client that asked for them (see `handshake::features::VENDOR_MECHANISMS`).
    VendorMechanisms = 6,
    /// The vendor-defined functions the daemon carries, after the mechanisms (see
    /// `handshake::features::VENDOR_FUNCTIONS`).
    VendorFunctions = 7,
}

impl Kind {
    fn from_u8(v: u8) -> Result<Kind> {
        Ok(match v {
            1 => Kind::Hello,
            2 => Kind::HelloAck,
            3 => Kind::Request,
            4 => Kind::Response,
            5 => Kind::Abort,
            6 => Kind::VendorMechanisms,
            7 => Kind::VendorFunctions,
            _ => return Err(WireError::BadTag),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub kind: Kind,
    pub payload: Vec<u8>,
}

/// What a peer speaking the old C protocol sends first: the ASCII text
/// `PRIVATE-GNOME-KEYRING-PKCS11-PROTOCOL-V-4`.
const LEGACY_PREFIX: &[u8; 4] = b"PRIV";

pub fn write_frame<W: Write>(w: &mut W, kind: Kind, payload: &[u8]) -> Result<()> {
    if payload.len() > MAX_FRAME {
        return Err(WireError::TooLarge);
    }
    let mut head = [0u8; 5];
    head[..4].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    head[4] = kind as u8;
    // one write for small frames keeps a request in one TCP segment
    if payload.len() <= 1024 {
        let mut all = Vec::with_capacity(5 + payload.len());
        all.extend_from_slice(&head);
        all.extend_from_slice(payload);
        w.write_all(&all)?;
    } else {
        w.write_all(&head)?;
        w.write_all(payload)?;
    }
    w.flush()?;
    Ok(())
}

pub fn read_frame<R: Read>(r: &mut R) -> Result<Frame> {
    let mut head = [0u8; 5];
    r.read_exact(&mut head)?;
    if &head[..4] == LEGACY_PREFIX {
        return Err(WireError::LegacyPeer);
    }
    let len = u32::from_be_bytes(head[..4].try_into().unwrap()) as usize;
    if len > MAX_FRAME {
        return Err(WireError::TooLarge);
    }
    let kind = Kind::from_u8(head[4])?;
    // Read in chunks so a peer claiming a large frame has to actually send it
    // before we reserve memory for it.
    let mut payload = Vec::new();
    let mut left = len;
    while left > 0 {
        let n = left.min(64 * 1024);
        let start = payload.len();
        payload.resize(start + n, 0);
        r.read_exact(&mut payload[start..])?;
        left -= n;
    }
    Ok(Frame { kind, payload })
}

/// Reads frames from a stream, taking whatever the stream has ready in one
/// system call (a small request arrives with its header) instead of one call
/// per field. Bytes read past the end of a frame wait for the next one.
#[derive(Debug)]
pub struct FrameReader {
    buf: Vec<u8>,
    start: usize,
}

const READ_CHUNK: usize = 16 * 1024;

impl Default for FrameReader {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameReader {
    pub fn new() -> FrameReader {
        FrameReader { buf: Vec::new(), start: 0 }
    }

    fn have(&self) -> usize {
        self.buf.len() - self.start
    }

    /// Read until at least `n` bytes are buffered.
    fn fill<R: Read>(&mut self, r: &mut R, n: usize) -> Result<()> {
        if self.start > 0 && self.have() == 0 {
            self.buf.clear();
            self.start = 0;
        }
        while self.have() < n {
            let want = READ_CHUNK;
            let at = self.buf.len();
            // never reserve more than the frame limit allows, and never
            // more than has been claimed and is being read in chunks
            self.buf.resize(at + want, 0);
            let got = loop {
                match r.read(&mut self.buf[at..]) {
                    Ok(g) => break g,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        self.buf.truncate(at);
                        return Err(e.into());
                    }
                }
            };
            self.buf.truncate(at + got);
            if got == 0 {
                return Err(WireError::Io(std::io::ErrorKind::UnexpectedEof));
            }
        }
        Ok(())
    }

    pub fn read<R: Read>(&mut self, r: &mut R) -> Result<Frame> {
        self.fill(r, 5)?;
        let head = &self.buf[self.start..self.start + 5];
        if &head[..4] == LEGACY_PREFIX {
            return Err(WireError::LegacyPeer);
        }
        let len = u32::from_be_bytes(head[..4].try_into().unwrap()) as usize;
        if len > MAX_FRAME {
            return Err(WireError::TooLarge);
        }
        let kind = Kind::from_u8(head[4])?;
        // the payload is read as it arrives, so a peer claiming a large frame
        // has to send it before memory is reserved for it
        self.fill(r, 5 + len)?;
        let payload = self.buf[self.start + 5..self.start + 5 + len].to_vec();
        self.start += 5 + len;
        if self.have() == 0 {
            // a request may have carried a PIN
            crate::secret::wipe(&mut self.buf);
            self.buf.clear();
            self.start = 0;
            if self.buf.capacity() > 1 << 20 {
                self.buf.shrink_to(READ_CHUNK);
            }
        }
        Ok(Frame { kind, payload })
    }
}

/// Body of a `Request` frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead {
    pub id: u32,
    pub call: u16,
}

/// Split a request payload into its head and the call's body.
pub fn parse_request(payload: &[u8]) -> Result<(RequestHead, &[u8])> {
    let mut r = Reader::new(payload);
    let id = r.u32()?;
    let call = r.u16()?;
    let n = r.remaining();
    Ok((RequestHead { id, call }, r.raw(n)?))
}

pub fn build_request(id: u32, call: u16, body: &[u8]) -> Vec<u8> {
    let mut w = Writer::with_capacity(6 + body.len());
    w.u32(id);
    w.u16(call);
    w.raw(body);
    w.into_vec()
}

/// Body of a `Response` frame: the request id, the `CK_RV`, and, when the
/// call produced outputs, their encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHead {
    pub id: u32,
    pub rv: u64,
    pub has_body: bool,
}

pub fn parse_response(payload: &[u8]) -> Result<(ResponseHead, &[u8])> {
    let mut r = Reader::new(payload);
    let id = r.u32()?;
    let rv = r.u64()?;
    let has_body = r.bool()?;
    let n = r.remaining();
    let body = r.raw(n)?;
    if !has_body && !body.is_empty() {
        return Err(WireError::Trailing);
    }
    Ok((ResponseHead { id, rv, has_body }, body))
}

pub fn build_response(id: u32, rv: u64, body: Option<&[u8]>) -> Vec<u8> {
    let b = body.unwrap_or(&[]);
    let mut w = Writer::with_capacity(13 + b.len());
    w.u32(id);
    w.u64(rv);
    w.bool(body.is_some());
    w.raw(b);
    w.into_vec()
}

/// Reason codes in an `Abort` frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AbortReason {
    Protocol = 1,
    Version = 2,
    Unauthorized = 3,
    Busy = 4,
    Shutdown = 5,
}

impl Encode for AbortReason {
    fn encode(&self, w: &mut Writer) {
        w.u16(*self as u16)
    }
}
impl Decode for AbortReason {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(match r.u16()? {
            1 => AbortReason::Protocol,
            2 => AbortReason::Version,
            3 => AbortReason::Unauthorized,
            4 => AbortReason::Busy,
            5 => AbortReason::Shutdown,
            _ => return Err(WireError::BadTag),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn frame_roundtrip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, Kind::Request, &[1, 2, 3]).unwrap();
        assert_eq!(buf, [0, 0, 0, 3, 3, 1, 2, 3]);
        let f = read_frame(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(f, Frame { kind: Kind::Request, payload: vec![1, 2, 3] });
    }

    #[test]
    fn oversized_frame_is_refused_before_reading() {
        let mut head = ((MAX_FRAME as u32) + 1).to_be_bytes().to_vec();
        head.push(3);
        assert_eq!(read_frame(&mut Cursor::new(head)).unwrap_err(), WireError::TooLarge);
    }

    #[test]
    fn claimed_but_missing_payload_fails_without_reserving_it() {
        let mut head = (MAX_FRAME as u32).to_be_bytes().to_vec();
        head.push(3);
        assert!(matches!(read_frame(&mut Cursor::new(head)).unwrap_err(), WireError::Io(_)));
    }

    #[test]
    fn legacy_peer_is_recognised() {
        let hello = b"PRIVATE-GNOME-KEYRING-PKCS11-PROTOCOL-V-4";
        assert_eq!(read_frame(&mut Cursor::new(&hello[..])).unwrap_err(), WireError::LegacyPeer);
    }

    #[test]
    fn frame_reader_handles_split_and_joined_frames() {
        struct Trickle(Vec<u8>, usize);
        impl Read for Trickle {
            fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
                let n = self.1.min(self.0.len()).min(b.len());
                b[..n].copy_from_slice(&self.0[..n]);
                self.0.drain(..n);
                Ok(n)
            }
        }
        let mut wire = Vec::new();
        write_frame(&mut wire, Kind::Request, &[1, 2, 3]).unwrap();
        write_frame(&mut wire, Kind::Response, &vec![7u8; 5_000]).unwrap();
        write_frame(&mut wire, Kind::Abort, &[]).unwrap();
        for chunk in [1usize, 3, 7, 100, 100_000] {
            let mut r = Trickle(wire.clone(), chunk);
            let mut fr = FrameReader::new();
            assert_eq!(fr.read(&mut r).unwrap(), Frame { kind: Kind::Request, payload: vec![1, 2, 3] });
            assert_eq!(fr.read(&mut r).unwrap().payload.len(), 5_000);
            assert_eq!(fr.read(&mut r).unwrap(), Frame { kind: Kind::Abort, payload: vec![] });
            assert_eq!(fr.read(&mut r).unwrap_err(), WireError::Io(std::io::ErrorKind::UnexpectedEof));
        }
        // limits are checked before anything is read
        let mut r = Trickle(((MAX_FRAME as u32) + 1).to_be_bytes().into_iter().chain([3]).collect(), 100);
        assert_eq!(FrameReader::new().read(&mut r).unwrap_err(), WireError::TooLarge);
        assert_eq!(
            FrameReader::new().read(&mut Trickle(b"PRIVATE-GNOME".to_vec(), 100)).unwrap_err(),
            WireError::LegacyPeer
        );
    }

    #[test]
    fn unknown_kind() {
        assert_eq!(read_frame(&mut Cursor::new([0, 0, 0, 0, 99])).unwrap_err(), WireError::BadTag);
    }

    #[test]
    fn request_and_response_heads() {
        let p = build_request(7, 33, b"body");
        let (h, b) = parse_request(&p).unwrap();
        assert_eq!((h.id, h.call, b), (7, 33, &b"body"[..]));
        let p = build_response(7, 0x150, Some(b"xy"));
        let (h, b) = parse_response(&p).unwrap();
        assert_eq!((h.id, h.rv, h.has_body, b), (7, 0x150, true, &b"xy"[..]));
        let p = build_response(7, 5, None);
        let (h, b) = parse_response(&p).unwrap();
        assert!(!h.has_body && b.is_empty());
        // body bytes without the flag are malformed
        let mut bad = build_response(7, 5, None);
        bad.push(0);
        assert_eq!(parse_response(&bad).unwrap_err(), WireError::Trailing);
    }
}
