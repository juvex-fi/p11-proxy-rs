//! Vendor-defined mechanisms reach the client library from the daemon, in the handshake, and a
//! declared one goes through the client's C entry points, the daemon and the mock token. The
//! declaration is process-wide, so this is its own test binary.
#![cfg(feature = "vendor")]
#![allow(clippy::undocumented_unsafe_blocks, unsafe_op_in_unsafe_fn)]

use p11_daemon::{Limits, Policy, Rules, Server};
use p11_params::mech::is_supported;
use p11_params::vendor::VendorMech;
use p11_proxy::core::CoreConfig;
use p11_proxy::testing;
use p11_proxy::*;
use p11_testkit::mock::{Mock, VENDOR_DIGEST};
use p11_testkit::raw::Loopback;
use p11_types::*;
use std::ptr::null_mut;
use std::sync::Arc;

const SLOT: CK_SLOT_ID = 7;

fn connect(mock: &Arc<Mock>, vendor: &[VendorMech]) -> testing::Session {
    let server = Server::new(mock.clone(), Policy::allow_all(Rules::default()), Limits::default())
        .with_vendor_mechanisms(vendor, &[])
        .unwrap();
    let lb = Loopback { server: Arc::new(server), identity: "test".into() };
    testing::install(Box::new(lb), CoreConfig::default()).expect("initialize")
}

fn declared(length: usize) -> Vec<VendorMech> {
    vec![VendorMech { id: VENDOR_DIGEST, length: Some(length), ..Default::default() }]
}

#[test]
fn the_daemon_tells_the_client_which_vendor_mechanisms_it_carries() {
    let mock = Arc::new(Mock::new());
    assert!(!is_supported(VENDOR_DIGEST), "nothing is declared before a daemon says so");
    let mut param = [9u8, 8, 7, 6];
    let mut m = CK_MECHANISM {
        mechanism: VENDOR_DIGEST as CK_MECHANISM_TYPE,
        pParameter: param.as_mut_ptr().cast(),
        ulParameterLen: 4,
    };
    let open = || unsafe {
        let mut s = 0;
        assert_eq!(C_OpenSession(SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION, null_mut(), None, &mut s), CKR_OK);
        s
    };

    // a daemon without any: the mechanism is refused before it leaves the client
    let session = connect(&mock, &[]);
    unsafe {
        let s = open();
        assert_eq!(C_DigestInit(s, &mut m), CKR_MECHANISM_INVALID);
    }
    assert_eq!(mock.vendor_param(), None);
    drop(session);

    // a daemon that carries it with a 4 byte parameter
    let session = connect(&mock, &declared(4));
    assert!(is_supported(VENDOR_DIGEST), "the handshake installed it");
    unsafe {
        let s = open();
        assert_eq!(C_DigestInit(s, &mut m), CKR_OK);
        assert_eq!(mock.vendor_param(), Some(vec![9, 8, 7, 6]), "the module got the bytes");
        // the wrong size never leaves the client
        m.ulParameterLen = 3;
        assert_eq!(C_DigestInit(s, &mut m), CKR_MECHANISM_PARAM_INVALID);
    }
    drop(session);

    // another daemon, declaring it without a parameter: what the last one said is replaced
    let session = connect(&mock, &declared(0));
    unsafe {
        let s = open();
        m.ulParameterLen = 4;
        assert_eq!(C_DigestInit(s, &mut m), CKR_MECHANISM_PARAM_INVALID);
        m.pParameter = null_mut();
        m.ulParameterLen = 0;
        assert_eq!(C_DigestInit(s, &mut m), CKR_OK);
        assert_eq!(mock.vendor_param(), Some(vec![]));
    }
    drop(session);

    // and a daemon that declares none takes it away again
    let session = connect(&mock, &[]);
    assert!(!is_supported(VENDOR_DIGEST));
    drop(session);
}

/// A data object in the mock token: the client's handle for it.
unsafe fn data_object(s: CK_SESSION_HANDLE) -> CK_OBJECT_HANDLE {
    let mut class = CKO_DATA;
    let mut t = [CK_ATTRIBUTE { type_: CKA_CLASS, pValue: (&mut class as *mut CK_ULONG).cast(), ulValueLen: 8 }];
    let mut o = 0;
    assert_eq!(C_CreateObject(s, t.as_mut_ptr(), 1, &mut o), CKR_OK);
    o
}

#[test]
fn a_handle_in_a_vendor_parameter_reaches_the_module_as_its_own() {
    use p11_testkit::mock::FIRST_OBJECT;
    let mock = Arc::new(Mock::new());
    unsafe {
        // the parameter is one object handle
        let session = connect(&mock, &[VendorMech { id: VENDOR_DIGEST, handle: true, ..Default::default() }]);
        let mut s = 0;
        assert_eq!(C_OpenSession(SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION, null_mut(), None, &mut s), CKR_OK);
        let mut obj = data_object(s);
        assert_ne!(obj, FIRST_OBJECT, "the client's handle is not the module's");
        let mut m = CK_MECHANISM {
            mechanism: VENDOR_DIGEST as CK_MECHANISM_TYPE,
            pParameter: (&mut obj as *mut CK_ULONG).cast(),
            ulParameterLen: 8,
        };
        assert_eq!(C_DigestInit(s, &mut m), CKR_OK);
        assert_eq!(mock.vendor_param(), Some(FIRST_OBJECT.to_ne_bytes().to_vec()), "the module got its own handle");
        // a handle the client never had goes on as one no object has
        *(m.pParameter as *mut CK_ULONG) = 0x7777;
        assert_eq!(C_DigestInit(s, &mut m), CKR_OK);
        assert_ne!(mock.vendor_param(), Some(0x7777u64.to_ne_bytes().to_vec()));
        drop(session);

        // a structure with a handle at an offset: the handle is translated, the rest is not
        let mock = Arc::new(Mock::new());
        let session = connect(
            &mock,
            &[VendorMech { id: VENDOR_DIGEST, length: Some(24), handles: vec![8], ..Default::default() }],
        );
        assert_eq!(C_OpenSession(SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION, null_mut(), None, &mut s), CKR_OK);
        let obj = data_object(s);
        let mut p = [0u8; 24];
        p[..8].copy_from_slice(&30u64.to_ne_bytes());
        p[8..16].copy_from_slice(&obj.to_ne_bytes());
        p[16..].copy_from_slice(&[0x5a; 8]);
        let mut m = CK_MECHANISM {
            mechanism: VENDOR_DIGEST as CK_MECHANISM_TYPE,
            pParameter: p.as_mut_ptr().cast(),
            ulParameterLen: 24,
        };
        assert_eq!(C_DigestInit(s, &mut m), CKR_OK);
        let got = mock.vendor_param().unwrap();
        assert_eq!(&got[..8], &30u64.to_ne_bytes());
        assert_eq!(&got[8..16], &FIRST_OBJECT.to_ne_bytes(), "the module got its own handle");
        assert_eq!(&got[16..], &[0x5a; 8]);
        m.ulParameterLen = 16;
        assert_eq!(C_DigestInit(s, &mut m), CKR_MECHANISM_PARAM_INVALID, "the size is exact");
        drop(session);
    }
}

#[test]
fn a_declared_structure_with_nested_handles_reaches_the_module_translated() {
    use p11_params::vendor::{VendorStruct, VendorStructField};
    use p11_testkit::mock::FIRST_OBJECT;
    use p11_wire::Node;
    let fld = |name: &str, offset: u32, kind: &str| VendorStructField {
        name: Some(name.into()),
        offset,
        kind: kind.into(),
        dir: None,
        of: None,
        by: None,
        n: None,
    };
    let structs = [
        VendorStruct { name: "item".into(), size: 16, fields: vec![fld("a", 0, "ulong"), fld("h", 8, "handle")] },
        VendorStruct {
            name: "outer".into(),
            size: 24,
            fields: vec![
                fld("n", 0, "ulong"),
                VendorStructField { of: Some("item".into()), by: Some("n".into()), ..fld("items", 8, "array") },
                fld("key", 16, "handle"),
            ],
        },
    ];
    #[repr(C)]
    struct Item {
        a: CK_ULONG,
        h: CK_OBJECT_HANDLE,
    }
    #[repr(C)]
    struct Outer {
        n: CK_ULONG,
        items: *mut Item,
        key: CK_OBJECT_HANDLE,
    }
    let mock = Arc::new(Mock::new());
    let server = Server::new(mock.clone(), Policy::allow_all(Rules::default()), Limits::default())
        .with_vendor_mechanisms(
            &[VendorMech { id: VENDOR_DIGEST, layout: Some("outer".into()), ..Default::default() }],
            &structs,
        )
        .unwrap();
    let lb = Loopback { server: Arc::new(server), identity: "test".into() };
    let _session = testing::install(Box::new(lb), CoreConfig::default()).expect("initialize");
    unsafe {
        let mut s = 0;
        assert_eq!(C_OpenSession(SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION, null_mut(), None, &mut s), CKR_OK);
        let (o1, o2, o3) = (data_object(s), data_object(s), data_object(s));
        let mut items = [Item { a: 7, h: o1 }, Item { a: 8, h: o2 }];
        let mut p = Outer { n: 2, items: items.as_mut_ptr(), key: o3 };
        let mut m = CK_MECHANISM {
            mechanism: VENDOR_DIGEST as CK_MECHANISM_TYPE,
            pParameter: (&mut p as *mut Outer).cast(),
            ulParameterLen: 24,
        };
        assert_eq!(C_DigestInit(s, &mut m), CKR_OK);
        let u = |x: u64| Node::U(x);
        assert_eq!(
            mock.vendor_node(),
            Some(Node::L(vec![
                u(2),
                Node::L(vec![Node::L(vec![u(7), u(FIRST_OBJECT)]), Node::L(vec![u(8), u(FIRST_OBJECT + 1)])]),
                u(FIRST_OBJECT + 2),
            ])),
            "the module got its own handles, in the nested structures too"
        );
        // a structure of another size, or with a count that promises more than it holds, is refused before it leaves
        m.ulParameterLen = 16;
        assert_eq!(C_DigestInit(s, &mut m), CKR_MECHANISM_PARAM_INVALID);
        m.ulParameterLen = 24;
        (*(m.pParameter as *mut Outer)).n = 100_000;
        assert_eq!(C_DigestInit(s, &mut m), CKR_MECHANISM_PARAM_INVALID);
    }
}
