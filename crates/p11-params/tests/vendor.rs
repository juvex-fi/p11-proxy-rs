//! Vendor-defined mechanisms declared in the configuration. The declaration is
//! process-wide, so everything that depends on it is one test.
#![cfg(feature = "vendor")]
#![allow(clippy::undocumented_unsafe_blocks)]

use core::ffi::c_void;
use p11_params::mech::{capture_mech, is_supported, MechBuf};
use p11_params::vendor::{VendorMech, MAX_LENGTH};

fn set(list: &[VendorMech]) -> Result<(), String> {
    p11_params::vendor::set(list, &[])
}
use p11_types::*;

/// The declaration is process-wide: tests that change it take turns.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn v(id: u64, length: Option<usize>, max_length: Option<usize>) -> VendorMech {
    VendorMech { id, length, max_length, ..Default::default() }
}

fn mech(id: u64, p: &mut [u8]) -> CK_MECHANISM {
    CK_MECHANISM {
        mechanism: id as CK_MECHANISM_TYPE,
        pParameter: if p.is_empty() { core::ptr::null_mut() } else { p.as_mut_ptr() as *mut c_void },
        ulParameterLen: p.len() as CK_ULONG,
    }
}

#[test]
fn declared_vendor_mechanisms_are_carried_as_bytes() {
    let _g = serial();
    const NONE: u64 = 0x8000_0001;
    const EXACT: u64 = 0x8000_0002;
    const UPTO: u64 = 0x8000_0003;

    // an unknown vendor mechanism is refused
    assert!(!is_supported(EXACT));
    let mut four = [1u8, 2, 3, 4];
    assert_eq!(unsafe { capture_mech(&mech(EXACT, &mut four)) }.unwrap_err(), CKR_MECHANISM_INVALID);

    // what may not be declared, and that a bad list changes nothing
    let bad = |list: &[VendorMech]| assert!(set(list).is_err(), "{list:?}");
    bad(&[v(CKM_AES_GCM as u64, Some(0), None)]); // a standard mechanism
    bad(&[v(0x1234, Some(0), None)]); // outside the vendor range
    bad(&[v(0x1_0000_0000 + 0x8000_0000, Some(0), None)]); // does not fit a CK_MECHANISM_TYPE
    bad(&[v(EXACT, None, None)]); // no length
    bad(&[v(EXACT, Some(4), Some(8))]); // two lengths
    bad(&[v(EXACT, Some(MAX_LENGTH + 1), None)]);
    bad(&[v(EXACT, Some(4), None), v(EXACT, Some(8), None)]); // twice
    assert!(!is_supported(EXACT));

    set(&[v(NONE, Some(0), None), v(EXACT, Some(4), None), v(UPTO, None, Some(8))]).unwrap();
    assert!(is_supported(NONE) && is_supported(EXACT) && is_supported(UPTO));

    unsafe {
        // no parameter
        let m = capture_mech(&mech(NONE, &mut [])).unwrap();
        assert_eq!((m.mechanism, m.param), (NONE, None));
        // a parameter where none is declared
        assert_eq!(capture_mech(&mech(NONE, &mut four)).unwrap_err(), CKR_MECHANISM_PARAM_INVALID);
        // the exact length, and no other; none at all is allowed too
        let m = capture_mech(&mech(EXACT, &mut four)).unwrap();
        assert_eq!(m.param, Some(p11_wire::Node::B(four.to_vec())));
        assert_eq!(capture_mech(&mech(EXACT, &mut [1, 2, 3])).unwrap_err(), CKR_MECHANISM_PARAM_INVALID);
        assert!(capture_mech(&mech(EXACT, &mut [])).is_ok());
        // up to a length
        assert!(capture_mech(&mech(UPTO, &mut [7; 8])).is_ok());
        assert_eq!(capture_mech(&mech(UPTO, &mut [7; 9])).unwrap_err(), CKR_MECHANISM_PARAM_INVALID);

        // the daemon's copy holds the bytes, in its own memory
        let m = capture_mech(&mech(EXACT, &mut four)).unwrap();
        let mut b = MechBuf::build(&m).unwrap();
        let built = &*b.as_mut_ptr();
        assert_eq!((built.mechanism, built.ulParameterLen), (EXACT as CK_ULONG, 4));
        assert_ne!(built.pParameter as *const u8, four.as_ptr());
        assert_eq!(core::slice::from_raw_parts(built.pParameter as *const u8, 4), &four);
        assert!(b.extract_out().is_none(), "nothing comes back from a flat parameter");
    }

    // replaced as a whole, and cleared
    set(&[v(NONE, Some(0), None)]).unwrap();
    assert!(!is_supported(EXACT));
    set(&[]).unwrap();
    assert!(!is_supported(NONE));
}

// ---- the forms that carry handles, and a parameter shaped like a built-in one ----

use p11_params::mech::walk_handles;
use p11_params::vendor::NameOrNum;

fn entry(id: u64) -> VendorMech {
    VendorMech { id, ..Default::default() }
}

#[test]
fn the_forms_of_a_declaration_are_checked() {
    let _g = serial();
    use p11_wire::handshake::VendorParam::*;
    let ok = |m: VendorMech| m.param().unwrap();
    assert_eq!(ok(VendorMech { handle: true, ..entry(0x8000_0010) }), Handle);
    assert_eq!(
        ok(VendorMech { length: Some(40), handles: vec![8, 24], ..entry(0x8000_0010) }),
        Handles { len: 40, offs: vec![8, 24] }
    );
    assert_eq!(
        ok(VendorMech { same_as: Some(NameOrNum::Name("CKM_AES_GCM".into())), ..entry(0x8000_0010) }),
        SameAs(CKM_AES_GCM as u64)
    );
    assert_eq!(ok(VendorMech { same_as: Some(NameOrNum::Num(0x1234)), ..entry(0x8000_0010) }), SameAs(0x1234));
    // each form stands alone
    let bad = |m: VendorMech| assert!(m.param().is_err(), "{m:?}");
    bad(VendorMech { handle: true, length: Some(8), ..entry(0x8000_0010) });
    bad(VendorMech { handle: true, handles: vec![0], ..entry(0x8000_0010) });
    bad(VendorMech { same_as: Some(NameOrNum::Num(1)), length: Some(8), ..entry(0x8000_0010) });
    bad(VendorMech { same_as: Some(NameOrNum::Name("CKM_NO_SUCH".into())), ..entry(0x8000_0010) });
    bad(VendorMech { max_length: Some(40), handles: vec![8], ..entry(0x8000_0010) }); // handles need an exact length
    bad(VendorMech { handles: vec![8], ..entry(0x8000_0010) });
    bad(entry(0x8000_0010));
    // what `set` refuses: offsets outside the parameter, overlapping, not increasing, none; a mechanism the proxy lacks
    let refused = |m: VendorMech| assert!(set(std::slice::from_ref(&m)).is_err(), "{m:?}");
    refused(VendorMech { length: Some(16), handles: vec![9], ..entry(0x8000_0010) });
    refused(VendorMech { length: Some(24), handles: vec![8, 12], ..entry(0x8000_0010) });
    refused(VendorMech { length: Some(24), handles: vec![16, 8], ..entry(0x8000_0010) });
    refused(VendorMech { same_as: Some(NameOrNum::Num(0x7777_0001)), ..entry(0x8000_0010) });
    refused(VendorMech { same_as: Some(NameOrNum::Num(0x8000_0011)), ..entry(0x8000_0010) });
    // another vendor mechanism
}

#[test]
fn a_handle_parameter_is_translated() {
    let _g = serial();
    const H: u64 = 0x8000_0020;
    set(&[VendorMech { handle: true, ..entry(H) }]).unwrap();
    unsafe {
        let mut handle: CK_ULONG = 7;
        let m = CK_MECHANISM {
            mechanism: H as CK_MECHANISM_TYPE,
            pParameter: (&mut handle as *mut CK_ULONG).cast(),
            ulParameterLen: 8,
        };
        let mut w = capture_mech(&m).unwrap();
        assert_eq!(w.param, Some(p11_wire::Node::U(7)));
        // the daemon maps the client's handle to the module's
        walk_handles(H, w.param.as_mut().unwrap(), &mut |h| *h += 1000);
        let mut b = MechBuf::build(&w).unwrap();
        let built = &*b.as_mut_ptr();
        assert_eq!(built.ulParameterLen, 8);
        assert_eq!((built.pParameter as *const CK_ULONG).read_unaligned(), 1007);
        // a parameter of another size is refused
        let short = CK_MECHANISM { ulParameterLen: 4, ..m };
        assert_eq!(capture_mech(&short).unwrap_err(), CKR_MECHANISM_PARAM_INVALID);
    }
    set(&[]).unwrap();
}

#[test]
fn only_the_declared_bytes_of_a_flat_structure_are_translated() {
    let _g = serial();
    const H: u64 = 0x8000_0021;
    // { CK_ULONG function; CK_OBJECT_HANDLE key; CK_BYTE random[16]; CK_OBJECT_HANDLE other }
    set(&[VendorMech { length: Some(40), handles: vec![8, 32], ..entry(H) }]).unwrap();
    unsafe {
        let mut p = [0u8; 40];
        p[..8].copy_from_slice(&30u64.to_ne_bytes());
        p[8..16].copy_from_slice(&5u64.to_ne_bytes());
        p[16..32].copy_from_slice(&[0x55; 16]);
        p[32..40].copy_from_slice(&6u64.to_ne_bytes());
        let m =
            CK_MECHANISM { mechanism: H as CK_MECHANISM_TYPE, pParameter: p.as_mut_ptr().cast(), ulParameterLen: 40 };
        let mut w = capture_mech(&m).unwrap();
        walk_handles(H, w.param.as_mut().unwrap(), &mut |h| *h += 1000);
        let mut b = MechBuf::build(&w).unwrap();
        let built = std::slice::from_raw_parts((*b.as_mut_ptr()).pParameter as *const u8, 40);
        assert_eq!(&built[..8], &30u64.to_ne_bytes(), "the function code is left alone");
        assert_eq!(&built[8..16], &1005u64.to_ne_bytes());
        assert_eq!(&built[16..32], &[0x55; 16], "and so are the other bytes");
        assert_eq!(&built[32..], &1006u64.to_ne_bytes());
        // a zero handle is passed on as zero by a translator that keeps zero, and the size is exact
        let wrong = CK_MECHANISM { ulParameterLen: 32, ..m };
        assert_eq!(capture_mech(&wrong).unwrap_err(), CKR_MECHANISM_PARAM_INVALID);
    }
    set(&[]).unwrap();
}

#[test]
fn a_parameter_shaped_like_a_built_in_one() {
    let _g = serial();
    const H: u64 = 0x8000_0022;
    set(&[VendorMech { same_as: Some(NameOrNum::Name("CKM_AES_GCM".into())), ..entry(H) }]).unwrap();
    unsafe {
        let mut iv = [1u8; 12];
        let mut aad = *b"header";
        let mut gcm = CK_GCM_PARAMS {
            pIv: iv.as_mut_ptr(),
            ulIvLen: 12,
            ulIvBits: 96,
            pAAD: aad.as_mut_ptr(),
            ulAADLen: 6,
            ulTagBits: 128,
        };
        let plain = CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            pParameter: (&mut gcm as *mut CK_GCM_PARAMS).cast(),
            ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
        };
        let vendor = CK_MECHANISM { mechanism: H as CK_MECHANISM_TYPE, ..plain };
        let (a, b) = (capture_mech(&plain).unwrap(), capture_mech(&vendor).unwrap());
        assert_eq!(a.param, b.param, "the vendor mechanism's parameter is captured as GCM's is");
        // and rebuilt in the daemon's memory the same way
        let mut built = MechBuf::build(&b).unwrap();
        let g = &*((*built.as_mut_ptr()).pParameter as *const CK_GCM_PARAMS);
        assert_eq!((g.ulIvLen, g.ulAADLen, g.ulTagBits), (12, 6, 128));
        assert_eq!(std::slice::from_raw_parts(g.pAAD, 6), b"header");
    }
    set(&[]).unwrap();
}

#[test]
fn what_the_daemon_announces_is_what_the_client_installs() {
    let _g = serial();
    const H: u64 = 0x8000_0023;
    let list = vec![
        VendorMech { handle: true, ..entry(H) },
        VendorMech { length: Some(16), handles: vec![8], ..entry(H + 1) },
        VendorMech { same_as: Some(NameOrNum::Name("CKM_AES_GCM".into())), ..entry(H + 2) },
        VendorMech { max_length: Some(8), ..entry(H + 3) },
    ];
    let wire = p11_params::vendor::to_wire(&list, &[]).unwrap();
    assert_eq!(wire.0.len(), 4);
    // a client that has not been told refuses them, and accepts them once it has
    set(&[]).unwrap();
    assert!(!is_supported(H));
    p11_params::vendor::set_from_wire(&wire).unwrap();
    assert!(is_supported(H) && is_supported(H + 1) && is_supported(H + 2) && is_supported(H + 3));
    // an announcement that would not pass the local rules is refused whole
    let mut bad = wire.clone();
    bad.0[1].param = p11_wire::handshake::VendorParam::Handles { len: 16, offs: vec![12] };
    assert!(p11_params::vendor::set_from_wire(&bad).is_err());
    assert!(is_supported(H), "and changes nothing");
    set(&[]).unwrap();
}
