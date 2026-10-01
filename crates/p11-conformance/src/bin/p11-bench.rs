//! `p11-bench MODULE [SECONDS] [THREADS]`: how fast calls go through a module or a proxy.
//! The token must have user PIN 1234.

#![allow(
    clippy::undocumented_unsafe_blocks,
    unsafe_op_in_unsafe_fn,
    clippy::op_ref,
    clippy::unnecessary_to_owned,
    clippy::manual_c_str_literals
)]

use p11_conformance::Module;
use p11_types::*;
use std::ptr::null_mut;
use std::sync::Arc;
use std::time::{Duration, Instant};

type Op = Box<dyn Fn(&Module, CK_SESSION_HANDLE) -> CK_RV + Send + Sync>;

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().unwrap_or_else(|| {
        eprintln!("usage: p11-bench MODULE [SECONDS] [THREADS]");
        std::process::exit(2);
    });
    let secs: f64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(2.0);
    let threads: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(1);
    let m = Arc::new(Module::load(std::path::Path::new(&path)).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    }));
    unsafe {
        let mut init = CK_C_INITIALIZE_ARGS {
            CreateMutex: None,
            DestroyMutex: None,
            LockMutex: None,
            UnlockMutex: None,
            flags: CKF_OS_LOCKING_OK,
            pReserved: null_mut(),
        };
        assert_eq!((m.f.C_Initialize.unwrap())(&mut init as *mut _ as *mut _), CKR_OK);
        let mut n = 8;
        let mut slots = [0 as CK_SLOT_ID; 8];
        assert_eq!((m.f.C_GetSlotList.unwrap())(1, slots.as_mut_ptr(), &mut n), CKR_OK);
        let slot = slots[0];
        let s0 = open(&m, slot);
        let mut pin = *b"1234";
        assert_eq!((m.f.C_Login.unwrap())(s0, CKU_USER, pin.as_mut_ptr(), 4), CKR_OK);

        // an HMAC key with a known value, and an RSA key pair
        let cls = CKO_SECRET_KEY;
        let kt = CKK_GENERIC_SECRET;
        let val = [7u8; 32];
        let yes: CK_BBOOL = 1;
        let no: CK_BBOOL = 0;
        let attr =
            |ty, v: *const u8, l: usize| CK_ATTRIBUTE { type_: ty, pValue: v as *mut _, ulValueLen: l as CK_ULONG };
        let mut t = [
            attr(CKA_CLASS, &cls as *const _ as *const u8, 8),
            attr(CKA_KEY_TYPE, &kt as *const _ as *const u8, 8),
            attr(CKA_TOKEN, &no, 1),
            attr(CKA_SIGN, &yes, 1),
            attr(CKA_VALUE, val.as_ptr(), 32),
        ];
        let mut hk = 0;
        assert_eq!((m.f.C_CreateObject.unwrap())(s0, t.as_mut_ptr(), 5, &mut hk), CKR_OK);
        let mut rk = CK_MECHANISM { mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN, pParameter: null_mut(), ulParameterLen: 0 };
        let bits: CK_ULONG = 2048;
        let exp = [1u8, 0, 1];
        let mut pubt = [
            attr(CKA_MODULUS_BITS, &bits as *const _ as *const u8, 8),
            attr(CKA_PUBLIC_EXPONENT, exp.as_ptr(), 3),
            attr(CKA_TOKEN, &no, 1),
        ];
        let mut privt = [attr(CKA_SIGN, &yes, 1), attr(CKA_TOKEN, &no, 1)];
        let (mut pubk, mut privk) = (0, 0);
        assert_eq!(
            (m.f.C_GenerateKeyPair.unwrap())(
                s0,
                &mut rk,
                pubt.as_mut_ptr(),
                3,
                privt.as_mut_ptr(),
                2,
                &mut pubk,
                &mut privk
            ),
            CKR_OK
        );

        let data = Arc::new(vec![0x5au8; 1024]);
        let mut ops: Vec<(&str, Op)> = Vec::new();
        ops.push((
            "C_GetInfo",
            Box::new(|m, _| {
                let mut i: CK_INFO = std::mem::zeroed();
                (m.f.C_GetInfo.unwrap())(&mut i)
            }),
        ));
        ops.push((
            "C_GenerateRandom 32",
            Box::new(|m, s| {
                let mut b = [0u8; 32];
                (m.f.C_GenerateRandom.unwrap())(s, b.as_mut_ptr(), 32)
            }),
        ));
        let d = data.clone();
        ops.push((
            "SHA-256 of 1 KiB",
            Box::new(move |m, s| {
                let mut mech = CK_MECHANISM { mechanism: CKM_SHA256, pParameter: null_mut(), ulParameterLen: 0 };
                let mut out = [0u8; 32];
                let mut n: CK_ULONG = 32;
                let rv = (m.f.C_DigestInit.unwrap())(s, &mut mech);
                if rv != CKR_OK {
                    return rv;
                }
                (m.f.C_Digest.unwrap())(s, d.as_ptr() as *mut u8, d.len() as CK_ULONG, out.as_mut_ptr(), &mut n)
            }),
        ));
        let d = data.clone();
        ops.push((
            "HMAC-SHA256 of 1 KiB",
            Box::new(move |m, s| {
                let mut mech = CK_MECHANISM { mechanism: CKM_SHA256_HMAC, pParameter: null_mut(), ulParameterLen: 0 };
                let mut out = [0u8; 32];
                let mut n: CK_ULONG = 32;
                let rv = (m.f.C_SignInit.unwrap())(s, &mut mech, hk);
                if rv != CKR_OK {
                    return rv;
                }
                (m.f.C_Sign.unwrap())(s, d.as_ptr() as *mut u8, d.len() as CK_ULONG, out.as_mut_ptr(), &mut n)
            }),
        ));
        ops.push((
            "RSA-2048 sign",
            Box::new(move |m, s| {
                let mut mech =
                    CK_MECHANISM { mechanism: CKM_SHA256_RSA_PKCS, pParameter: null_mut(), ulParameterLen: 0 };
                let mut out = [0u8; 256];
                let mut n: CK_ULONG = 256;
                let mut msg = [1u8; 32];
                let rv = (m.f.C_SignInit.unwrap())(s, &mut mech, privk);
                if rv != CKR_OK {
                    return rv;
                }
                (m.f.C_Sign.unwrap())(s, msg.as_mut_ptr(), 32, out.as_mut_ptr(), &mut n)
            }),
        ));
        let ops = Arc::new(ops);

        println!(
            "{:<24} {:>10} {:>10} {:>10} {:>10}   ({threads} thread(s), {secs}s each)",
            "operation", "ops/s", "p50 us", "p99 us", "errors"
        );
        for (i, (name, _)) in ops.iter().enumerate() {
            let mut hs = Vec::new();
            let start = Instant::now();
            for _ in 0..threads {
                let (m, ops) = (m.clone(), ops.clone());
                hs.push(std::thread::spawn(move || {
                    let s = open(&m, slot);
                    let mut lat = Vec::new();
                    let mut errs = 0u64;
                    let end = Instant::now() + Duration::from_secs_f64(secs);
                    while Instant::now() < end {
                        let t = Instant::now();
                        if (ops[i].1)(&m, s) != CKR_OK {
                            errs += 1;
                        }
                        lat.push(t.elapsed());
                    }
                    (m.f.C_CloseSession.unwrap())(s);
                    (lat, errs)
                }));
            }
            let mut lat: Vec<Duration> = Vec::new();
            let mut errs = 0;
            for h in hs {
                let (l, e) = h.join().unwrap();
                lat.extend(l);
                errs += e;
            }
            let el = start.elapsed().as_secs_f64();
            lat.sort();
            let pct = |p: f64| lat[((lat.len() as f64 * p) as usize).min(lat.len() - 1)].as_secs_f64() * 1e6;
            println!(
                "{:<24} {:>10.0} {:>10.0} {:>10.0} {:>10}",
                name,
                lat.len() as f64 / el,
                pct(0.5),
                pct(0.99),
                errs
            );
        }
        (m.f.C_Finalize.unwrap())(null_mut());
    }
}

unsafe fn open(m: &Module, slot: CK_SLOT_ID) -> CK_SESSION_HANDLE {
    let mut h = 0;
    assert_eq!(
        (m.f.C_OpenSession.unwrap())(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, null_mut(), None, &mut h),
        CKR_OK
    );
    h
}
