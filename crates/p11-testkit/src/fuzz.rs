//! The bodies of the fuzz targets, as ordinary functions of a byte slice. The
//! libFuzzer targets in `fuzz/` call them; so does the mutation test in
//! `tests/fuzz_smoke.rs`, so every `cargo test` exercises them a little.
//!
//! None of them may panic, whatever the input.

use crate::mock::Mock;
use p11_daemon::dispatch::handle;
use p11_daemon::{ClientCtx, Identity, Limits, Policy, Rules, Server};
use p11_params::mech::{apply_mech_out, MechBuf, MsgBuf};
use p11_wire::calls::{call_info, Request, Response};
use p11_wire::codec::from_slice;
use p11_wire::frame::{parse_request, parse_response, FrameReader};
use p11_wire::handshake::{Hello, HelloAck};
use p11_wire::structs::{Mech, MsgParam};
use p11_wire::Node;
use std::io::Cursor;
use std::sync::Arc;

/// Frames, request and response heads, the handshake messages.
pub fn frame(data: &[u8]) {
    let mut r = Cursor::new(data);
    let mut fr = FrameReader::new();
    while let Ok(f) = fr.read(&mut r) {
        let _ = parse_request(&f.payload);
        let _ = parse_response(&f.payload);
        let _ = from_slice::<Hello>(&f.payload);
        let _ = from_slice::<HelloAck>(&f.payload);
    }
}

/// Every call's request and response decoder. The first two bytes pick the call.
pub fn request(data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let call = u16::from_be_bytes([data[0], data[1]]);
    let body = &data[2..];
    if let Ok(r) = Request::decode(call, body) {
        // what decodes re-encodes to the same bytes: no two encodings of one message
        assert_eq!(r.encode_body(), body);
    }
    if let Ok(r) = Response::decode(call, body) {
        assert_eq!(r.encode_body(), body);
    }
}

/// A sequence of requests against a daemon context over a mock token. The input is
/// a series of `u16 call | u16 length | body` records.
pub fn dispatch(data: &[u8]) {
    let mock = Mock::new();
    let ctx = ClientCtx::new([7; 16], Identity::new("fuzz"), Rules::default());
    let mut rest = data;
    // start initialised half the time, so both paths are explored
    if data.first().is_some_and(|b| b & 1 == 1) {
        let _ = handle(&ctx, &mock, 1, &[]);
    }
    while rest.len() >= 4 {
        let call = u16::from_be_bytes([rest[0], rest[1]]);
        let len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
        rest = &rest[4..];
        let n = len.min(rest.len());
        let (body, tail) = rest.split_at(n);
        rest = tail;
        // a malformed body ends the connection in real life; here just go on.
        // (A wait for a slot event legitimately waits, so the fuzzer leaves it out.)
        let call = call % 110;
        if call != p11_wire::calls::CALL_WAIT_FOR_SLOT_EVENT {
            let _ = handle(&ctx, &mock, call, body);
        }
        let _ = call_info(call);
    }
}

fn node_from(data: &mut &[u8], depth: usize) -> Node {
    let Some((&tag, rest)) = data.split_first() else { return Node::Absent };
    *data = rest;
    match tag % 5 {
        0 => Node::Absent,
        1 => {
            let n = data.len().min(8);
            let mut b = [0u8; 8];
            b[8 - n..].copy_from_slice(&data[..n]);
            *data = &data[n..];
            Node::U(u64::from_be_bytes(b))
        }
        2 => {
            let n = data.first().copied().unwrap_or(0) as usize % 40;
            let n = n.min(data.len().saturating_sub(1));
            let v = data.get(1..1 + n).unwrap_or(&[]).to_vec();
            *data = &data[(1 + n).min(data.len())..];
            Node::B(v)
        }
        _ if depth > 5 => Node::Absent,
        _ => {
            let n = data.first().copied().unwrap_or(0) as usize % 8;
            *data = data.get(1..).unwrap_or(&[]);
            Node::L((0..n).map(|_| node_from(data, depth + 1)).collect())
        }
    }
}

/// Mechanism parameters: any mechanism, any tree.
pub fn mech(data: &[u8]) {
    if data.len() < 3 {
        return;
    }
    // the mechanism: often one the proxy knows, sometimes anything
    let pick = [
        0x1087u64,
        0x9,
        0x40,
        0x1055,
        0x1050,
        0x1061,
        0x1062,
        0x1087,
        0x3e0,
        0x3e4,
        0x0011,
        0x1 << 31,
        0x371,
        0x372,
        0x373,
        0x374,
        0x375,
        0x376,
        0x3d0,
        0x3d2,
        0x3d3,
        0x3d4,
        0x3d5,
        0x3c0,
        0x3c1,
        0x3c2,
        0x3c3,
        0x3c4,
        0x3c5,
        0x3c6,
        0x3c7,
        0x3c8,
        0x3c9,
        0x3ca,
        0x3cb,
        0x3cc,
        0x3cd,
        0x3ce,
        0x3cf,
        0x1e,
        0x1d,
        0x21,
        0x23,
        0x450,
        0x451,
        0x452,
    ];
    let mechanism =
        if data[0] < 200 { pick[data[0] as usize % pick.len()] } else { u16::from_be_bytes([data[1], data[2]]) as u64 };
    let mut rest = &data[3..];
    let tree = node_from(&mut rest, 0);
    let param = if tree.is_absent() { None } else { Some(tree) };
    let m = Mech { mechanism, param: param.clone() };
    if let Ok(mut b) = MechBuf::build(&m) {
        let out = b.extract_out();
        // a made-up reply must not write outside what a caller could have given
        let mut p = std::mem::MaybeUninit::<[u64; 64]>::zeroed();
        let mut cm =
            p11_types::CK_MECHANISM { mechanism: mechanism as _, pParameter: p.as_mut_ptr().cast(), ulParameterLen: 8 };
        // SAFETY: a zeroed, writable buffer of 512 bytes; the length given is only 8, and the
        // apply code refuses anything that doesn't fit the descriptor's own layout.
        let _ = unsafe { apply_mech_out(&out, &mut cm, 0) };
        let _ = b.as_mut_ptr();
    }
    for phase in [p11_wire::structs::MSG_ENCRYPT, p11_wire::structs::MSG_DECRYPT] {
        if let Ok(mut b) = MsgBuf::build(&MsgParam { mechanism, phase, param: param.clone() }) {
            let _ = b.extract_out();
            let _ = b.as_mut_ptr();
        }
    }
}

/// A whole connection: arbitrary bytes after (and instead of) a valid hello.
pub fn stream(data: &[u8]) {
    use p11_wire::codec::to_vec;
    use p11_wire::frame::{write_frame, Kind};
    use p11_wire::handshake::*;
    let server = Server::new(Arc::new(Mock::new()), Policy::allow_all(Rules::default()), Limits::default());
    // the server reads from `input` and writes into a sink
    let mut input = Vec::new();
    if data.first().is_some_and(|b| b & 1 == 1) {
        let hello = Hello {
            min_version: 1,
            max_version: 1,
            features: 0,
            join: false,
            token: [0; TOKEN_LEN],
            client: "fuzz".into(),
        };
        write_frame(&mut input, Kind::Hello, &to_vec(&hello)).unwrap();
    }
    input.extend_from_slice(data);
    struct Duplex(Cursor<Vec<u8>>, std::io::Sink);
    impl std::io::Read for Duplex {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(b)
        }
    }
    impl std::io::Write for Duplex {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.1.write(b)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let _ = server.serve(Duplex(Cursor::new(input), std::io::sink()), &Identity::new("fuzz"));
    assert_eq!(server.context_count(), 0, "a connection that ends leaves no context behind");
}
