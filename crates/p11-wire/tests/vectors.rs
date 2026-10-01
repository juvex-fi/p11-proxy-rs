//! Golden vectors: the exact bytes of one example request and response for
//! every call. If one of these fails, the wire format changed. That needs a
//! new protocol version (docs/PROTOCOL.md), not a quiet regeneration; after
//! bumping it, `UPDATE_VECTORS=1 cargo test -p p11-wire --test vectors`
//! rewrites the files.

use p11_wire::calls::samples::{sample_requests, sample_responses};
use p11_wire::calls::{Request, Response, CALLS};
use p11_wire::frame::{build_request, build_response, parse_request, parse_response};
use std::path::PathBuf;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn hex(b: &[u8]) -> String {
    let mut s = String::new();
    for (i, c) in b.chunks(32).enumerate() {
        if i > 0 {
            s.push('\n');
        }
        s.extend(c.iter().map(|x| format!("{x:02x}")));
    }
    s.push('\n');
    s
}

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

fn check(name: &str, bytes: &[u8]) {
    let path = dir().join(name);
    if std::env::var_os("UPDATE_VECTORS").is_some() {
        std::fs::create_dir_all(dir()).unwrap();
        std::fs::write(&path, hex(bytes)).unwrap();
        return;
    }
    let want =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing vector {name}; run with UPDATE_VECTORS=1"));
    assert_eq!(unhex(&want), bytes, "vector {name} changed: the wire format is different");
}

#[test]
fn every_call_has_vectors_that_round_trip() {
    let reqs = sample_requests();
    let resps = sample_responses();
    assert_eq!(reqs.len(), CALLS.len());
    assert_eq!(resps.len(), CALLS.len());
    for (i, info) in CALLS.iter().enumerate() {
        let stem = format!("{:03}-{}", info.id, &info.name[2..]);
        let (rq, rs) = (&reqs[i], &resps[i]);
        assert_eq!(rq.call_id(), info.id);
        assert_eq!(rs.call_id(), info.id);

        let body = rq.encode_body();
        check(&format!("{stem}.req"), &body);
        assert_eq!(&Request::decode(info.id, &body).unwrap(), rq, "{stem} request");
        // as a whole frame payload too
        let payload = build_request(7, info.id, &body);
        let (head, b) = parse_request(&payload).unwrap();
        assert_eq!((head.id, head.call, b), (7, info.id, &body[..]));

        let body = rs.encode_body();
        check(&format!("{stem}.resp"), &body);
        assert_eq!(&Response::decode(info.id, &body).unwrap(), rs, "{stem} response");
        let payload = build_response(7, 0, Some(&body));
        let (head, b) = parse_response(&payload).unwrap();
        assert_eq!((head.id, head.rv, head.has_body, b), (7, 0, true, &body[..]));
    }
}

#[test]
fn no_stray_vector_files() {
    if std::env::var_os("UPDATE_VECTORS").is_some() {
        return;
    }
    let mut want: Vec<String> = Vec::new();
    for info in CALLS.iter() {
        for kind in ["req", "resp"] {
            want.push(format!("{:03}-{}.{kind}", info.id, &info.name[2..]));
        }
    }
    want.sort();
    let mut have: Vec<String> = std::fs::read_dir(dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| !n.starts_with("frame.") && !n.starts_with("handshake.") && !n.starts_with("vendorfn."))
        .collect();
    have.sort();
    assert_eq!(have, want, "the vector directory doesn't match the call table");
}

/// Frames and the handshake: fixed bytes.
#[test]
fn framing_and_handshake_vectors() {
    use p11_wire::codec::to_vec;
    use p11_wire::frame::{write_frame, Kind};
    use p11_wire::handshake::*;
    let mut f = Vec::new();
    write_frame(&mut f, Kind::Request, &build_request(0x01020304, 33, &[0xaa])).unwrap();
    check("frame.request", &f);
    let hello =
        Hello { min_version: 1, max_version: 1, features: 0, join: false, token: [0; TOKEN_LEN], client: "c".into() };
    check("handshake.hello", &to_vec(&hello));
    let ack = HelloAck { version: 1, features: 0, token: [0x11; TOKEN_LEN], server: "s".into() };
    check("handshake.ack", &to_vec(&ack));
    let vendor = VendorMechs(
        vec![
            VendorEntry { id: 0x8000_0123, param: VendorParam::Exact(16) },
            VendorEntry { id: 0x8000_0124, param: VendorParam::Max(64) },
            VendorEntry { id: 0x8000_0125, param: VendorParam::Handle },
            VendorEntry { id: 0x8000_0126, param: VendorParam::Handles { len: 40, offs: vec![8, 16] } },
            VendorEntry { id: 0x8000_0127, param: VendorParam::SameAs(0x1087) },
            VendorEntry { id: 0x8000_0128, param: VendorParam::Struct("outer".into()) },
        ],
        vec![VendorLayout {
            name: "outer".into(),
            size: 24,
            fields: vec![
                VendorField {
                    name: "n".into(),
                    off: 0,
                    kind: FieldKind::Ulong,
                    dir: Dir::In,
                    of: String::new(),
                    by: String::new(),
                    n: 0,
                },
                VendorField {
                    name: "items".into(),
                    off: 8,
                    kind: FieldKind::Array,
                    dir: Dir::In,
                    of: "outer".into(),
                    by: "n".into(),
                    n: 0,
                },
                VendorField {
                    name: "made".into(),
                    off: 16,
                    kind: FieldKind::HandlePtr,
                    dir: Dir::Out,
                    of: String::new(),
                    by: String::new(),
                    n: 0,
                },
            ],
        }],
    );
    let mut f = Vec::new();
    write_frame(&mut f, Kind::VendorMechanisms, &to_vec(&vendor)).unwrap();
    check("frame.vendor_mechanisms", &f);

    // vendor-defined functions: the announcement frame and the two bodies of call 1000
    use p11_wire::vendorfn::*;
    let desc =
        FnDesc { name: "Vnd_FetchData".into(), rw: false, args: vec![ArgKind::U64, ArgKind::U64, ArgKind::OBytes] };
    let fns = VendorFns(vec![
        desc.clone(),
        FnDesc { name: "Vnd_SetPin".into(), rw: true, args: vec![ArgKind::Session, ArgKind::U64, ArgKind::Secret] },
    ]);
    let mut f = Vec::new();
    write_frame(&mut f, Kind::VendorFunctions, &to_vec(&fns)).unwrap();
    check("frame.vendor_functions", &f);
    let req = VendorRequest { name: desc.name.clone(), args: vec![InVal::Int(3), InVal::Int(9), InVal::Cap(Some(16))] };
    check("vendorfn.request", &req.encode());
    let reply = VendorReply(vec![OutVal::Bytes(p11_wire::structs::OutBytes { len: 5, data: Some(b"CERT!".to_vec()) })]);
    check("vendorfn.reply", &reply.encode());
}
