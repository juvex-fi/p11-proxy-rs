//! Mechanism parameters through the whole path: a C structure captured on
//! the client, rebuilt in the daemon, filled in by a pretend module, read
//! back and applied to the caller's structure.
#![allow(clippy::undocumented_unsafe_blocks)]

use core::ffi::c_void;
use p11_params::mech::*;
use p11_types::*;
use p11_wire::structs::{MsgParam, MSG_DECRYPT, MSG_ENCRYPT};
use p11_wire::{from_slice, to_vec, Node};
use proptest::prelude::*;

fn mech<T>(m: CK_MECHANISM_TYPE, p: &mut T) -> CK_MECHANISM {
    CK_MECHANISM {
        mechanism: m,
        pParameter: p as *mut T as *mut c_void,
        ulParameterLen: core::mem::size_of::<T>() as CK_ULONG,
    }
}

fn bare(m: CK_MECHANISM_TYPE) -> CK_MECHANISM {
    CK_MECHANISM { mechanism: m, pParameter: core::ptr::null_mut(), ulParameterLen: 0 }
}

/// Send a mechanism through the wire encoding, as the real thing does.
fn over_the_wire(m: p11_wire::structs::Mech) -> p11_wire::structs::Mech {
    from_slice(&to_vec(&m)).unwrap()
}

/// The rebuilt structure, with a lifetime the borrow checker can't tie to `b` (a test convenience:
/// the memory lives as long as `b` does).
unsafe fn param<'a, T>(b: &mut MechBuf) -> &'a mut T {
    unsafe { &mut *((*b.as_mut_ptr()).pParameter as *mut T) }
}

#[test]
fn no_parameter_and_unknown_mechanisms() {
    unsafe {
        let mut m = bare(CKM_SHA256);
        let w = capture_mech(&m).unwrap();
        assert_eq!(w.param, None);
        // whatever a caller leaves in the parameter of a parameterless mechanism is ignored
        let mut junk = [1u8; 8];
        m.pParameter = junk.as_mut_ptr().cast();
        m.ulParameterLen = 8;
        assert_eq!(capture_mech(&m).unwrap().param, None);
        // unknown / unsupported
        assert_eq!(capture_mech(&bare(CKM_X3DH_INITIALIZE)).unwrap_err(), CKR_MECHANISM_INVALID);
        assert_eq!(capture_mech(core::ptr::null()).unwrap_err(), CKR_ARGUMENTS_BAD);
        assert!(!is_supported(CKM_X3DH_INITIALIZE as u64));
        assert!(is_supported(CKM_AES_GCM as u64) && is_supported(CKM_ML_DSA as u64));
    }
}

#[test]
fn flat_parameters_are_length_checked() {
    unsafe {
        let mut iv = [7u8; 16];
        let mut m = CK_MECHANISM { mechanism: CKM_AES_CBC, pParameter: iv.as_mut_ptr().cast(), ulParameterLen: 16 };
        let w = over_the_wire(capture_mech(&m).unwrap());
        assert_eq!(w.param, Some(Node::B(iv.to_vec())));
        let mut b = MechBuf::build(&w).unwrap();
        let got = &*b.as_mut_ptr();
        assert_eq!(got.ulParameterLen, 16);
        assert_eq!(core::slice::from_raw_parts(got.pParameter as *const u8, 16), &iv);
        assert!(b.extract_out().is_none());
        // wrong size
        m.ulParameterLen = 12;
        assert_eq!(capture_mech(&m).unwrap_err(), CKR_MECHANISM_PARAM_INVALID);
        // a hostile daemon-bound tree of the wrong size
        let mut evil = w.clone();
        evil.param = Some(Node::B(vec![0; 17]));
        assert_eq!(MechBuf::build(&evil).unwrap_err(), CKR_MECHANISM_PARAM_INVALID);
        evil.param = Some(Node::U(3));
        assert_eq!(MechBuf::build(&evil).unwrap_err(), CKR_MECHANISM_PARAM_INVALID);
        // NULL with a length
        m.pParameter = core::ptr::null_mut();
        m.ulParameterLen = 16;
        assert_eq!(capture_mech(&m).unwrap_err(), CKR_MECHANISM_PARAM_INVALID);
    }
}

#[test]
fn gcm_is_rebuilt_in_the_daemons_memory() {
    unsafe {
        let mut iv = *b"0123456789ab";
        let mut aad = *b"header";
        let mut p = CK_GCM_PARAMS {
            pIv: iv.as_mut_ptr(),
            ulIvLen: 12,
            ulIvBits: 96,
            pAAD: aad.as_mut_ptr(),
            ulAADLen: 6,
            ulTagBits: 128,
        };
        let m = mech(CKM_AES_GCM, &mut p);
        let w = over_the_wire(capture_mech(&m).unwrap());
        let mut b = MechBuf::build(&w).unwrap();
        let q: &mut CK_GCM_PARAMS = param(&mut b);
        // equal contents, different memory
        assert_eq!((q.ulIvLen, q.ulIvBits, q.ulAADLen, q.ulTagBits), (12, 96, 6, 128));
        assert_ne!(q.pIv, iv.as_mut_ptr());
        assert_ne!(q.pAAD, aad.as_mut_ptr());
        assert_eq!(core::slice::from_raw_parts(q.pIv, 12), &iv);
        assert_eq!(core::slice::from_raw_parts(q.pAAD, 6), &aad);
        assert!(b.extract_out().is_none());

        // NULL IV with a length is invalid on both ends
        let mut bad = p;
        bad.pIv = core::ptr::null_mut();
        let m = mech(CKM_AES_GCM, &mut bad);
        assert_eq!(capture_mech(&m).unwrap_err(), CKR_MECHANISM_PARAM_INVALID);
        // wrong structure size
        let mut m = mech(CKM_AES_GCM, &mut p);
        m.ulParameterLen -= 8;
        assert_eq!(capture_mech(&m).unwrap_err(), CKR_MECHANISM_PARAM_INVALID);
        // an IV longer than its member claims
        let mut w2 = w.clone();
        if let Some(Node::L(items)) = w2.param.as_mut() {
            items[0] = Node::B(vec![0; 13]);
        }
        assert_eq!(MechBuf::build(&w2).unwrap_err(), CKR_MECHANISM_PARAM_INVALID);
    }
}

#[test]
fn oaep_optional_source_and_aliases() {
    unsafe {
        let mut src = *b"label";
        let mut p = CK_RSA_PKCS_OAEP_PARAMS {
            hashAlg: CKM_SHA256,
            mgf: CKG_MGF1_SHA256,
            source: CKZ_DATA_SPECIFIED,
            pSourceData: src.as_mut_ptr().cast(),
            ulSourceDataLen: 5,
        };
        let m = mech(CKM_RSA_PKCS_OAEP, &mut p);
        let mut b = MechBuf::build(&over_the_wire(capture_mech(&m).unwrap())).unwrap();
        let q: &CK_RSA_PKCS_OAEP_PARAMS = param(&mut b);
        assert_eq!(core::slice::from_raw_parts(q.pSourceData as *const u8, 5), b"label");
        // no source data at all
        p.pSourceData = core::ptr::null_mut();
        p.ulSourceDataLen = 0;
        let m = mech(CKM_RSA_PKCS_OAEP, &mut p);
        let mut b = MechBuf::build(&over_the_wire(capture_mech(&m).unwrap())).unwrap();
        let q: &CK_RSA_PKCS_OAEP_PARAMS = param(&mut b);
        assert!(q.pSourceData.is_null());
    }
}

#[test]
fn object_handles_in_parameters_can_be_translated() {
    unsafe {
        let mut salt = *b"salt";
        let mut p = CK_HKDF_PARAMS {
            bExtract: 1,
            bExpand: 1,
            prfHashMechanism: CKM_SHA256,
            ulSaltType: CKF_HKDF_SALT_KEY,
            pSalt: salt.as_mut_ptr(),
            ulSaltLen: 4,
            hSaltKey: 42,
            pInfo: core::ptr::null_mut(),
            ulInfoLen: 0,
        };
        let m = mech(CKM_HKDF_DERIVE, &mut p);
        let mut w = over_the_wire(capture_mech(&m).unwrap());
        // the daemon maps client handles to the module's
        let mut seen = vec![];
        walk_handles(w.mechanism, w.param.as_mut().unwrap(), &mut |h| {
            seen.push(*h);
            *h += 1000;
        });
        assert_eq!(seen, vec![42]);
        let mut b = MechBuf::build(&w).unwrap();
        let q: &CK_HKDF_PARAMS = param(&mut b);
        assert_eq!(q.hSaltKey, 1042);

        // a flat handle
        let mut h: CK_OBJECT_HANDLE = 7;
        let m = mech(CKM_CONCATENATE_BASE_AND_KEY, &mut h);
        let mut w = over_the_wire(capture_mech(&m).unwrap());
        assert_eq!(w.param, Some(Node::U(7)));
        walk_handles(w.mechanism, w.param.as_mut().unwrap(), &mut |h| *h = 99);
        let mut b = MechBuf::build(&w).unwrap();
        let got = &*b.as_mut_ptr();
        assert_eq!((got.pParameter as *const CK_ULONG).read(), 99);
    }
}

#[test]
fn ssl3_master_returns_the_version() {
    unsafe {
        let mut cr = [1u8; 32];
        let mut sr = [2u8; 32];
        let mut ver = CK_VERSION { major: 0, minor: 0 };
        let mut p = CK_SSL3_MASTER_KEY_DERIVE_PARAMS {
            RandomInfo: CK_SSL3_RANDOM_DATA {
                pClientRandom: cr.as_mut_ptr(),
                ulClientRandomLen: 32,
                pServerRandom: sr.as_mut_ptr(),
                ulServerRandomLen: 32,
            },
            pVersion: &mut ver,
        };
        let m = mech(CKM_SSL3_MASTER_KEY_DERIVE, &mut p);
        let w = over_the_wire(capture_mech(&m).unwrap());
        let mut b = MechBuf::build(&w).unwrap();
        // the module writes the version it negotiated
        let q: &mut CK_SSL3_MASTER_KEY_DERIVE_PARAMS = param(&mut b);
        assert_eq!(core::slice::from_raw_parts(q.RandomInfo.pClientRandom, 32), &cr);
        *q.pVersion = CK_VERSION { major: 3, minor: 3 };
        let out = b.extract_out().expect("outputs");
        let out = from_slice::<Node>(&to_vec(&out)).unwrap();
        apply_mech_out(&Some(out), &m as *const _ as *mut _, CKR_DEVICE_ERROR as u64).unwrap();
        assert_eq!((ver.major, ver.minor), (0, 0), "nothing is applied when the call failed");
        let out = b.extract_out();
        apply_mech_out(&out, &m as *const _ as *mut _, CKR_OK as u64).unwrap();
        assert_eq!((ver.major, ver.minor), (3, 3));
    }
}

#[test]
fn tls_key_material_returns_handles_and_ivs() {
    unsafe {
        let mut cr = [1u8; 32];
        let mut sr = [2u8; 32];
        let mut civ = [0u8; 16];
        let mut siv = [0u8; 16];
        let mut out = CK_SSL3_KEY_MAT_OUT {
            hClientMacSecret: 0,
            hServerMacSecret: 0,
            hClientKey: 0,
            hServerKey: 0,
            pIVClient: civ.as_mut_ptr(),
            pIVServer: siv.as_mut_ptr(),
        };
        let mut p = CK_SSL3_KEY_MAT_PARAMS {
            ulMacSizeInBits: 256,
            ulKeySizeInBits: 128,
            ulIVSizeInBits: 128,
            bIsExport: 0,
            RandomInfo: CK_SSL3_RANDOM_DATA {
                pClientRandom: cr.as_mut_ptr(),
                ulClientRandomLen: 32,
                pServerRandom: sr.as_mut_ptr(),
                ulServerRandomLen: 32,
            },
            pReturnedKeyMaterial: &mut out,
        };
        let m = mech(CKM_SSL3_KEY_AND_MAC_DERIVE, &mut p);
        let w = over_the_wire(capture_mech(&m).unwrap());
        let mut b = MechBuf::build(&w).unwrap();
        let q: &mut CK_SSL3_KEY_MAT_PARAMS = param(&mut b);
        let o = &mut *q.pReturnedKeyMaterial;
        o.hClientMacSecret = 11;
        o.hServerMacSecret = 12;
        o.hClientKey = 13;
        o.hServerKey = 14;
        core::slice::from_raw_parts_mut(o.pIVClient, 16).copy_from_slice(&[0xaa; 16]);
        core::slice::from_raw_parts_mut(o.pIVServer, 16).copy_from_slice(&[0xbb; 16]);
        let mut res = b.extract_out().expect("outputs");
        // the daemon maps the module's handles to the client's
        walk_handles(CKM_SSL3_KEY_AND_MAC_DERIVE as u64, &mut res, &mut |h| *h += 100);
        let res = from_slice::<Node>(&to_vec(&res)).unwrap();
        apply_mech_out(&Some(res), &m as *const _ as *mut _, CKR_OK as u64).unwrap();
        assert_eq!((out.hClientMacSecret, out.hServerMacSecret, out.hClientKey, out.hServerKey), (111, 112, 113, 114));
        assert_eq!(civ, [0xaa; 16]);
        assert_eq!(siv, [0xbb; 16]);
    }
}

#[test]
fn a_hostile_reply_cannot_overrun_the_callers_buffers() {
    unsafe {
        let mut seed = [3u8; 8];
        let mut label = [4u8; 8];
        let mut outbuf = [0u8; 16];
        let mut outlen: CK_ULONG = 16;
        let mut p = CK_TLS_PRF_PARAMS {
            pSeed: seed.as_mut_ptr(),
            ulSeedLen: 8,
            pLabel: label.as_mut_ptr(),
            ulLabelLen: 8,
            pOutput: outbuf.as_mut_ptr(),
            pulOutputLen: &mut outlen,
        };
        let m = mech(CKM_TLS_PRF, &mut p);
        let w = over_the_wire(capture_mech(&m).unwrap());
        let mut b = MechBuf::build(&w).unwrap();
        let q: &mut CK_TLS_PRF_PARAMS = param(&mut b);
        *q.pulOutputLen = 10;
        core::slice::from_raw_parts_mut(q.pOutput, 10).copy_from_slice(&[9; 10]);
        let res = b.extract_out().unwrap();
        apply_mech_out(&Some(res.clone()), &m as *const _ as *mut _, CKR_OK as u64).unwrap();
        assert_eq!(outlen, 10);
        assert_eq!(&outbuf[..10], &[9; 10]);

        // the module claims more than the room it was given: caught in the daemon
        *q.pulOutputLen = 17;
        assert!(b.extract_out().is_none(), "an over-long result is dropped");

        // a forged reply with more bytes than the caller's buffer
        let mut forged = res.clone();
        if let Node::L(items) = &mut forged {
            items[4] = Node::B(vec![1; 20]);
        }
        outlen = 16;
        let before = outbuf;
        assert_eq!(
            apply_mech_out(&Some(forged), &m as *const _ as *mut _, CKR_OK as u64).unwrap_err(),
            CKR_DEVICE_ERROR
        );
        assert_eq!(outbuf, before);
        assert_eq!(outlen, 16, "a rejected reply leaves the caller's structure untouched");
        // wrong shape
        assert_eq!(
            apply_mech_out(&Some(Node::U(1)), &m as *const _ as *mut _, CKR_OK as u64).unwrap_err(),
            CKR_DEVICE_ERROR
        );
    }
}

#[test]
fn pbkd2_both_layouts() {
    unsafe {
        let mut salt = *b"saltsalt";
        let mut pw = *b"password";
        let mut p2 = CK_PKCS5_PBKD2_PARAMS2 {
            saltSource: CKZ_SALT_SPECIFIED,
            pSaltSourceData: salt.as_mut_ptr().cast(),
            ulSaltSourceDataLen: 8,
            iterations: 1000,
            prf: CKP_PKCS5_PBKD2_HMAC_SHA256,
            pPrfData: core::ptr::null_mut(),
            ulPrfDataLen: 0,
            pPassword: pw.as_mut_ptr(),
            ulPasswordLen: 8,
        };
        let m = mech(CKM_PKCS5_PBKD2, &mut p2);
        let w = over_the_wire(capture_mech(&m).unwrap());
        let Some(Node::L(v)) = &w.param else { panic!() };
        assert_eq!(v[0], Node::U(0));
        let mut b = MechBuf::build(&w).unwrap();
        let q: &CK_PKCS5_PBKD2_PARAMS2 = param(&mut b);
        assert_eq!(q.ulPasswordLen, 8);
        assert_eq!(core::slice::from_raw_parts(q.pPassword, 8), b"password");

        // the older layout: a pointer to the length
        let mut len: CK_ULONG = 8;
        let mut p1 = CK_PKCS5_PBKD2_PARAMS {
            saltSource: CKZ_SALT_SPECIFIED,
            pSaltSourceData: salt.as_mut_ptr().cast(),
            ulSaltSourceDataLen: 8,
            iterations: 1000,
            prf: CKP_PKCS5_PBKD2_HMAC_SHA256,
            pPrfData: core::ptr::null_mut(),
            ulPrfDataLen: 0,
            pPassword: pw.as_mut_ptr(),
            ulPasswordLen: &mut len,
        };
        let m = CK_MECHANISM {
            mechanism: CKM_PKCS5_PBKD2,
            pParameter: (&mut p1 as *mut CK_PKCS5_PBKD2_PARAMS).cast(),
            ulParameterLen: core::mem::size_of::<CK_PKCS5_PBKD2_PARAMS>() as CK_ULONG,
        };
        let w = over_the_wire(capture_mech(&m).unwrap());
        let Some(Node::L(v)) = &w.param else { panic!() };
        assert_eq!(v[0], Node::U(1));
        let mut b = MechBuf::build(&w).unwrap();
        let q: &CK_PKCS5_PBKD2_PARAMS = param(&mut b);
        assert_eq!(*q.ulPasswordLen, 8);
        assert_ne!(q.ulPasswordLen as *const CK_ULONG, &len as *const CK_ULONG);
    }
}

#[test]
fn sp800_kdf_arrays_templates_and_returned_keys() {
    unsafe {
        let mut label = *b"label";
        let mut data = [
            CK_PRF_DATA_PARAM { type_: CK_SP800_108_ITERATION_VARIABLE, pValue: core::ptr::null_mut(), ulValueLen: 0 },
            CK_PRF_DATA_PARAM { type_: CK_SP800_108_BYTE_ARRAY, pValue: label.as_mut_ptr().cast(), ulValueLen: 5 },
        ];
        let mut class: CK_ULONG = CKO_SECRET_KEY;
        let mut tpl = [CK_ATTRIBUTE { type_: CKA_CLASS, pValue: (&mut class as *mut CK_ULONG).cast(), ulValueLen: 8 }];
        let mut key_handle: CK_OBJECT_HANDLE = 0;
        let mut derived = [CK_DERIVED_KEY { pTemplate: tpl.as_mut_ptr(), ulAttributeCount: 1, phKey: &mut key_handle }];
        let mut p = CK_SP800_108_KDF_PARAMS {
            prfType: CKM_SHA256_HMAC,
            ulNumberOfDataParams: 2,
            pDataParams: data.as_mut_ptr(),
            ulAdditionalDerivedKeys: 1,
            pAdditionalDerivedKeys: derived.as_mut_ptr(),
        };
        let m = mech(CKM_SP800_108_COUNTER_KDF, &mut p);
        let w = over_the_wire(capture_mech(&m).unwrap());
        let mut b = MechBuf::build(&w).unwrap();
        let q: &mut CK_SP800_108_KDF_PARAMS = param(&mut b);
        assert_eq!(q.ulNumberOfDataParams, 2);
        let d1 = &*q.pDataParams.add(1);
        assert_eq!(core::slice::from_raw_parts(d1.pValue as *const u8, 5), b"label");
        let dk = &mut *q.pAdditionalDerivedKeys;
        assert_eq!(dk.ulAttributeCount, 1);
        assert_eq!((*dk.pTemplate).type_, CKA_CLASS);
        // the module returns the additional key's handle
        *dk.phKey = 77;
        let mut res = b.extract_out().unwrap();
        walk_handles(CKM_SP800_108_COUNTER_KDF as u64, &mut res, &mut |h| *h = 5);
        apply_mech_out(&Some(res), &m as *const _ as *mut _, CKR_OK as u64).unwrap();
        assert_eq!(key_handle, 5);
    }
}

#[test]
fn nested_mechanisms_and_strings() {
    unsafe {
        let mut iv = [5u8; 16];
        let mut inner = CK_MECHANISM { mechanism: CKM_AES_CBC, pParameter: iv.as_mut_ptr().cast(), ulParameterLen: 16 };
        let mut seed = *b"seed";
        let mut p = CK_KIP_PARAMS { pMechanism: &mut inner, hKey: 9, pSeed: seed.as_mut_ptr(), ulSeedLen: 4 };
        let m = mech(CKM_KIP_DERIVE, &mut p);
        let mut w = over_the_wire(capture_mech(&m).unwrap());
        let mut seen = vec![];
        walk_handles(w.mechanism, w.param.as_mut().unwrap(), &mut |h| seen.push(*h));
        assert_eq!(seen, vec![9]);
        let mut b = MechBuf::build(&w).unwrap();
        let q: &CK_KIP_PARAMS = param(&mut b);
        assert_eq!((*q.pMechanism).mechanism, CKM_AES_CBC);
        assert_eq!(core::slice::from_raw_parts((*q.pMechanism).pParameter as *const u8, 16), &iv);

        // a nested mechanism the proxy doesn't carry
        let mut bad_inner = bare(CKM_X3DH_INITIALIZE);
        let mut p2 = CK_KIP_PARAMS { pMechanism: &mut bad_inner, hKey: 9, pSeed: seed.as_mut_ptr(), ulSeedLen: 4 };
        let m = mech(CKM_KIP_DERIVE, &mut p2);
        assert_eq!(capture_mech(&m).unwrap_err(), CKR_MECHANISM_INVALID);
    }
}

#[test]
fn ml_dsa_context_is_optional() {
    unsafe {
        // none at all
        let w = capture_mech(&bare(CKM_ML_DSA)).unwrap();
        assert_eq!(w.param, None);
        let mut b = MechBuf::build(&w).unwrap();
        assert!((*b.as_mut_ptr()).pParameter.is_null());
        // with a context
        let mut ctx = *b"ctx";
        let mut p = CK_SIGN_ADDITIONAL_CONTEXT {
            hedgeVariant: CKH_HEDGE_REQUIRED,
            pContext: ctx.as_mut_ptr(),
            ulContextLen: 3,
        };
        let m = mech(CKM_ML_DSA, &mut p);
        let mut b = MechBuf::build(&over_the_wire(capture_mech(&m).unwrap())).unwrap();
        let q: &CK_SIGN_ADDITIONAL_CONTEXT = param(&mut b);
        assert_eq!(q.hedgeVariant, CKH_HEDGE_REQUIRED);
        assert_eq!(core::slice::from_raw_parts(q.pContext, 3), b"ctx");
        // too long a context
        let mut long = [0u8; 300];
        let mut p = CK_SIGN_ADDITIONAL_CONTEXT { hedgeVariant: 0, pContext: long.as_mut_ptr(), ulContextLen: 300 };
        let m = mech(CKM_ML_DSA, &mut p);
        assert_eq!(capture_mech(&m).unwrap_err(), CKR_MECHANISM_PARAM_INVALID);
        // the hashed variant
        let mut p = CK_HASH_SIGN_ADDITIONAL_CONTEXT {
            hedgeVariant: 0,
            pContext: ctx.as_mut_ptr(),
            ulContextLen: 3,
            hash: CKM_SHA256,
        };
        let m = mech(CKM_HASH_ML_DSA, &mut p);
        let mut b = MechBuf::build(&over_the_wire(capture_mech(&m).unwrap())).unwrap();
        let q: &CK_HASH_SIGN_ADDITIONAL_CONTEXT = param(&mut b);
        assert_eq!(q.hash, CKM_SHA256);
    }
}

#[test]
fn message_parameters_gcm_encrypt_and_decrypt() {
    unsafe {
        let mut iv = [0u8; 12];
        let mut tag = [0u8; 16];
        let mut p = CK_GCM_MESSAGE_PARAMS {
            pIv: iv.as_mut_ptr(),
            ulIvLen: 12,
            ulIvFixedBits: 0,
            ivGenerator: CKG_GENERATE_RANDOM,
            pTag: tag.as_mut_ptr(),
            ulTagBits: 128,
        };
        let len = core::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG;
        let w = capture_msg_param(CKM_AES_GCM as u64, MSG_ENCRYPT, (&mut p as *mut CK_GCM_MESSAGE_PARAMS).cast(), len)
            .unwrap();
        let w = from_slice::<MsgParam>(&to_vec(&w)).unwrap();
        let mut b = MsgBuf::build(&w).unwrap();
        assert_eq!(b.len(), len);
        // the module generates an IV and a tag
        let q = &mut *(b.as_mut_ptr() as *mut CK_GCM_MESSAGE_PARAMS);
        core::slice::from_raw_parts_mut(q.pIv, 12).copy_from_slice(&[0x5a; 12]);
        core::slice::from_raw_parts_mut(q.pTag, 16).copy_from_slice(&[0xa5; 16]);
        let out = b.extract_out();
        apply_msg_out(&out, (&mut p as *mut CK_GCM_MESSAGE_PARAMS).cast(), len, CKR_OK as u64).unwrap();
        assert_eq!(iv, [0x5a; 12]);
        assert_eq!(tag, [0xa5; 16]);

        // decrypt: the IV and tag are inputs, and nothing comes back
        let w = capture_msg_param(CKM_AES_GCM as u64, MSG_DECRYPT, (&mut p as *mut CK_GCM_MESSAGE_PARAMS).cast(), len)
            .unwrap();
        let b = MsgBuf::build(&w).unwrap();
        let q = &*(b.root_ptr() as *const CK_GCM_MESSAGE_PARAMS);
        assert_eq!(core::slice::from_raw_parts(q.pTag, 16), &[0xa5; 16]);
        assert!(b.extract_out().is_none());

        // no parameter at all
        let w = capture_msg_param(CKM_AES_GCM as u64, MSG_ENCRYPT, core::ptr::null(), 0).unwrap();
        let b = MsgBuf::build(&w).unwrap();
        assert!(b.is_empty());
        // a parameter for a mechanism that has none
        assert_eq!(
            capture_msg_param(CKM_SHA256 as u64, MSG_ENCRYPT, (&mut p as *mut CK_GCM_MESSAGE_PARAMS).cast(), len)
                .unwrap_err(),
            CKR_MECHANISM_PARAM_INVALID
        );
        // wrong size
        assert_eq!(
            capture_msg_param(CKM_AES_GCM as u64, MSG_ENCRYPT, (&mut p as *mut CK_GCM_MESSAGE_PARAMS).cast(), len - 8)
                .unwrap_err(),
            CKR_MECHANISM_PARAM_INVALID
        );
    }
}

// ---- arbitrary trees never crash the daemon side ----

fn arb_node() -> impl Strategy<Value = Node> {
    let leaf = prop_oneof![
        Just(Node::Absent),
        any::<u64>().prop_map(Node::U),
        proptest::collection::vec(any::<u8>(), 0..40).prop_map(Node::B),
    ];
    leaf.prop_recursive(4, 48, 6, |inner| proptest::collection::vec(inner, 0..7).prop_map(Node::L))
}

proptest! {
    #[test]
    fn hostile_trees_are_rejected_or_harmless(idx in 0usize..400, n in proptest::option::of(arb_node())) {
        // every mechanism the proxy knows: whatever a client sends, building never crashes,
        // and what is built can be read back
        let mechs: Vec<CK_MECHANISM_TYPE> = (0..0x8000u64).filter(|m| is_supported(*m)).collect();
        let mechs2: Vec<CK_MECHANISM_TYPE> = [CKM_AES_GCM, CKM_RSA_PKCS_OAEP, CKM_HKDF_DERIVE, CKM_SSL3_KEY_AND_MAC_DERIVE, CKM_TLS_PRF,
            CKM_PKCS5_PBKD2, CKM_SP800_108_COUNTER_KDF, CKM_KIP_DERIVE, CKM_CMS_SIG, CKM_SECURID, CKM_PBE_MD5_DES_CBC,
            CKM_ML_DSA, CKM_AES_XTS, CKM_CONCATENATE_BASE_AND_KEY, CKM_AES_CBC, CKM_WTLS_PRF, CKM_X9_42_MQV_DERIVE].to_vec();
        let all: Vec<_> = mechs.into_iter().chain(mechs2).collect();
        let m = all[idx % all.len()];
        let w = p11_wire::structs::Mech { mechanism: m as u64, param: n };
        if let Ok(mut b) = MechBuf::build(&w) {
            let _ = b.extract_out();
            let _ = b.as_mut_ptr();
        }
    }
}

#[test]
fn only_the_documented_families_are_refused() {
    // The C proxy carried every mechanism in the header except the X3DH and X2Ratchet
    // families (structures with byte buffers and no length member) and the obsolete
    // Skipjack, Baton, Juniper and GOST 28147 modes. This must stay true.
    let refused: Vec<&str> =
        p11_types::all_mechanisms().iter().filter(|(_, v)| !is_supported(*v as u64)).map(|(n, _)| *n).collect();
    for n in &refused {
        let ok = [
            "CKM_SKIPJACK_",
            "CKM_BATON_",
            "CKM_JUNIPER_",
            "CKM_GOST28147",
            "CKM_X3DH_",
            "CKM_X2RATCHET_",
            "CKM_VENDOR_DEFINED",
        ]
        .iter()
        .any(|p| n.starts_with(p));
        assert!(ok, "{n} is refused but is not in a documented family");
    }
    assert_eq!(refused.len(), 28);
    let mut values: Vec<CK_ULONG> = p11_types::all_mechanisms().iter().map(|(_, v)| *v).collect();
    values.sort();
    values.dedup();
    assert_eq!(values.iter().filter(|v| is_supported(**v as u64)).count(), 436, "distinct mechanism values carried");
    // and each family of parameters is represented
    for n in [
        "CKM_AES_GCM",
        "CKM_AES_CBC_ENCRYPT_DATA",
        "CKM_ARIA_CBC_ENCRYPT_DATA",
        "CKM_TLS12_KEY_AND_MAC_DERIVE",
        "CKM_SP800_108_FEEDBACK_KDF",
        "CKM_HASH_ML_DSA",
        "CKM_SLH_DSA",
    ] {
        assert!(is_supported(p11_types::mechanism_by_name(n).unwrap() as u64), "{n}");
    }
}

// ---- a module that overwrites what it was handed ----
//
// The daemon gives the module structures it built, and reads the answers back
// out of them. A module may overwrite any member, pointers and counts
// included (some modules repoint values into their own memory), so what comes back
// is followed only if it is still the daemon's own allocation.

#[test]
fn a_module_that_repoints_a_result_is_not_followed() {
    unsafe {
        let mut seed = [3u8; 8];
        let mut label = [4u8; 8];
        let mut outbuf = [0u8; 16];
        let mut outlen: CK_ULONG = 16;
        let mut p = CK_TLS_PRF_PARAMS {
            pSeed: seed.as_mut_ptr(),
            ulSeedLen: 8,
            pLabel: label.as_mut_ptr(),
            ulLabelLen: 8,
            pOutput: outbuf.as_mut_ptr(),
            pulOutputLen: &mut outlen,
        };
        let m = mech(CKM_TLS_PRF, &mut p);
        let w = over_the_wire(capture_mech(&m).unwrap());
        let mut foreign_bytes = [0xEEu8; 16];
        let mut foreign_len: CK_ULONG = 4;

        // the output buffer
        let mut b = MechBuf::build(&w).unwrap();
        let q: &mut CK_TLS_PRF_PARAMS = param(&mut b);
        *q.pulOutputLen = 4;
        q.pOutput = foreign_bytes.as_mut_ptr();
        assert!(b.extract_out().is_none(), "output buffer moved");

        // the pointer to its length
        let mut b = MechBuf::build(&w).unwrap();
        let q: &mut CK_TLS_PRF_PARAMS = param(&mut b);
        q.pulOutputLen = &mut foreign_len;
        assert!(b.extract_out().is_none(), "length pointer moved");
    }
}

#[test]
fn a_module_that_repoints_a_returned_structure_is_not_followed() {
    unsafe {
        let mut cr = [1u8; 32];
        let mut sr = [2u8; 32];
        let mut ver = CK_VERSION { major: 0, minor: 0 };
        let mut p = CK_SSL3_MASTER_KEY_DERIVE_PARAMS {
            RandomInfo: CK_SSL3_RANDOM_DATA {
                pClientRandom: cr.as_mut_ptr(),
                ulClientRandomLen: 32,
                pServerRandom: sr.as_mut_ptr(),
                ulServerRandomLen: 32,
            },
            pVersion: &mut ver,
        };
        let m = mech(CKM_SSL3_MASTER_KEY_DERIVE, &mut p);
        let w = over_the_wire(capture_mech(&m).unwrap());
        let mut b = MechBuf::build(&w).unwrap();
        let q: &mut CK_SSL3_MASTER_KEY_DERIVE_PARAMS = param(&mut b);
        let mut foreign = CK_VERSION { major: 9, minor: 9 };
        q.pVersion = &mut foreign;
        assert!(b.extract_out().is_none(), "version pointer moved");
    }
}

#[test]
fn a_module_that_moves_or_grows_an_array_is_not_followed() {
    unsafe {
        let mut label = *b"label";
        let mut data =
            [CK_PRF_DATA_PARAM { type_: CK_SP800_108_BYTE_ARRAY, pValue: label.as_mut_ptr().cast(), ulValueLen: 5 }];
        let mut class: CK_ULONG = CKO_SECRET_KEY;
        let mut tpl = [CK_ATTRIBUTE { type_: CKA_CLASS, pValue: (&mut class as *mut CK_ULONG).cast(), ulValueLen: 8 }];
        let mut key_handle: CK_OBJECT_HANDLE = 0;
        let mut derived = [CK_DERIVED_KEY { pTemplate: tpl.as_mut_ptr(), ulAttributeCount: 1, phKey: &mut key_handle }];
        let mut p = CK_SP800_108_KDF_PARAMS {
            prfType: CKM_SHA256_HMAC,
            ulNumberOfDataParams: 1,
            pDataParams: data.as_mut_ptr(),
            ulAdditionalDerivedKeys: 1,
            pAdditionalDerivedKeys: derived.as_mut_ptr(),
        };
        let m = mech(CKM_SP800_108_COUNTER_KDF, &mut p);
        let w = over_the_wire(capture_mech(&m).unwrap());

        // untouched: the returned handle comes back
        let mut b = MechBuf::build(&w).unwrap();
        let q: &mut CK_SP800_108_KDF_PARAMS = param(&mut b);
        *(*q.pAdditionalDerivedKeys).phKey = 77;
        assert!(b.extract_out().is_some());

        // more elements than the array holds: the read would run past it
        let mut b = MechBuf::build(&w).unwrap();
        let q: &mut CK_SP800_108_KDF_PARAMS = param(&mut b);
        q.ulAdditionalDerivedKeys = 1000;
        assert!(b.extract_out().is_none(), "array count grown");

        // the array moved
        let mut b = MechBuf::build(&w).unwrap();
        let q: &mut CK_SP800_108_KDF_PARAMS = param(&mut b);
        let mut foreign =
            [CK_DERIVED_KEY { pTemplate: core::ptr::null_mut(), ulAttributeCount: 0, phKey: &mut key_handle }];
        q.pAdditionalDerivedKeys = foreign.as_mut_ptr();
        assert!(b.extract_out().is_none(), "array moved");

        // the returned handle's pointer moved
        let mut b = MechBuf::build(&w).unwrap();
        let q: &mut CK_SP800_108_KDF_PARAMS = param(&mut b);
        let mut foreign_handle: CK_OBJECT_HANDLE = 5;
        (*q.pAdditionalDerivedKeys).phKey = &mut foreign_handle;
        assert!(b.extract_out().is_none(), "handle pointer moved");
    }
}
