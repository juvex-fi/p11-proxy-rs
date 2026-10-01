//! The PKCS#11 3.x entry points through the client, the daemon and the mock token.
#![allow(clippy::undocumented_unsafe_blocks, unsafe_op_in_unsafe_fn)]

use p11_daemon::{Limits, Policy, Rules, Server};
use p11_proxy::core::CoreConfig;
use p11_proxy::testing;
use p11_proxy::*;
use p11_testkit::mock::{Mock, USER_PIN};
use p11_testkit::raw::Loopback;
use p11_types::*;
use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::Arc;

const SLOT: CK_SLOT_ID = 7;

struct Env {
    _s: testing::Session,
    _mock: Arc<Mock>,
}

fn env() -> Env {
    let mock = Arc::new(Mock::new());
    let server = Arc::new(Server::new(mock.clone(), Policy::allow_all(Rules::default()), Limits::default()));
    let s = testing::install(Box::new(Loopback { server, identity: "t".into() }), CoreConfig::default()).unwrap();
    Env { _s: s, _mock: mock }
}

unsafe fn session() -> CK_SESSION_HANDLE {
    let mut s = 0;
    assert_eq!(C_OpenSession(SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION, null_mut(), None, &mut s), CKR_OK);
    s
}

unsafe fn login(s: CK_SESSION_HANDLE) {
    let mut pin = USER_PIN.to_vec();
    let mut user = *b"alice";
    let mut f32: *mut CK_INTERFACE = null_mut();
    assert_eq!(C_GetInterface(null_mut(), null_mut(), &mut f32, 0), CKR_OK);
    let l = &*((*f32).pFunctionList as *const CK_FUNCTION_LIST_3_2);
    assert_eq!(l.C_LoginUser.unwrap()(s, CKU_USER, pin.as_mut_ptr(), 4, user.as_mut_ptr(), 5), CKR_OK);
}

unsafe fn aes_key(s: CK_SESSION_HANDLE) -> CK_OBJECT_HANDLE {
    let mut mech = CK_MECHANISM { mechanism: CKM_AES_KEY_GEN, pParameter: null_mut(), ulParameterLen: 0 };
    let mut k = 0;
    assert_eq!(C_GenerateKey(s, &mut mech, null_mut(), 0, &mut k), CKR_OK);
    k
}

fn plain(m: CK_MECHANISM_TYPE) -> CK_MECHANISM {
    CK_MECHANISM { mechanism: m, pParameter: null_mut(), ulParameterLen: 0 }
}

unsafe fn get_value(s: CK_SESSION_HANDLE, o: CK_OBJECT_HANDLE) -> Vec<u8> {
    let mut a = [CK_ATTRIBUTE { type_: CKA_VALUE, pValue: null_mut(), ulValueLen: 0 }];
    assert_eq!(C_GetAttributeValue(s, o, a.as_mut_ptr(), 1), CKR_OK);
    let mut v = vec![0u8; a[0].ulValueLen as usize];
    a[0].pValue = v.as_mut_ptr().cast();
    assert_eq!(C_GetAttributeValue(s, o, a.as_mut_ptr(), 1), CKR_OK);
    v
}

fn l32() -> CK_FUNCTION_LIST_3_2 {
    unsafe {
        let mut f: *mut CK_INTERFACE = null_mut();
        assert_eq!(C_GetInterface(null_mut(), null_mut(), &mut f, 0), CKR_OK);
        *((*f).pFunctionList as *const CK_FUNCTION_LIST_3_2)
    }
}

#[test]
fn login_user_cancel_and_validation_flags() {
    let _e = env();
    unsafe {
        let s = session();
        let l = l32();
        let mut pin = USER_PIN.to_vec();
        let mut wrong = *b"bob";
        assert_eq!(l.C_LoginUser.unwrap()(s, CKU_USER, pin.as_mut_ptr(), 4, wrong.as_mut_ptr(), 3), CKR_PIN_INCORRECT);
        login(s);
        assert_eq!(l.C_SessionCancel.unwrap()(s, 0), CKR_OK);
        let mut flags = 0;
        assert_eq!(l.C_GetSessionValidationFlags.unwrap()(s, 3, &mut flags), CKR_OK);
        assert_eq!(flags, 0x53);
        assert_eq!(l.C_GetSessionValidationFlags.unwrap()(0xdead, 3, &mut flags), CKR_SESSION_HANDLE_INVALID);
    }
}

#[test]
fn async_functions() {
    let _e = env();
    unsafe {
        let s = session();
        login(s);
        let l = l32();
        let mut name = *b"C_SignInit\0";
        let mut id = 0;
        assert_eq!(l.C_AsyncGetID.unwrap()(s, name.as_mut_ptr(), &mut id), CKR_OK);
        assert_eq!(id, 7);
        let mut other = *b"C_Nothing\0";
        assert_eq!(l.C_AsyncGetID.unwrap()(s, other.as_mut_ptr(), &mut id), CKR_FUNCTION_NOT_SUPPORTED);
        let mut data = [0u8; 4];
        assert_eq!(l.C_AsyncJoin.unwrap()(s, name.as_mut_ptr(), id, data.as_mut_ptr(), 4), CKR_OK);
        assert_eq!(data, [0x5a, 0x5b, 0x58, 0x59]);
        assert_eq!(l.C_AsyncJoin.unwrap()(s, name.as_mut_ptr(), 99, data.as_mut_ptr(), 4), CKR_ARGUMENTS_BAD);

        // a result with a value buffer and object handles the client must be able to use
        let key = aes_key(s);
        let mut buf = [0u8; 32];
        let mut res =
            CK_ASYNC_DATA { ulVersion: 1, pValue: buf.as_mut_ptr(), ulValue: 32, hObject: 0, hAdditionalObject: 0 };
        assert_eq!(l.C_AsyncComplete.unwrap()(s, name.as_mut_ptr(), &mut res), CKR_OK);
        assert_eq!(&buf[..res.ulValue as usize], b"async-result");
        assert_eq!(res.hObject, key, "the module's object handle came back as the client's");
        // too small a buffer
        let mut small = [0u8; 4];
        let mut res =
            CK_ASYNC_DATA { ulVersion: 1, pValue: small.as_mut_ptr(), ulValue: 4, hObject: 0, hAdditionalObject: 0 };
        assert_eq!(l.C_AsyncComplete.unwrap()(s, name.as_mut_ptr(), &mut res), CKR_BUFFER_TOO_SMALL);
        assert_eq!(res.ulValue, 12);
    }
}

#[test]
fn kem_and_authenticated_wrapping() {
    let _e = env();
    unsafe {
        let s = session();
        login(s);
        let l = l32();
        let pubk = aes_key(s);
        let mut mech = plain(CKM_ML_KEM);
        let mut n: CK_ULONG = 0;
        let mut k1 = 0;
        assert_eq!(l.C_EncapsulateKey.unwrap()(s, &mut mech, pubk, null_mut(), 0, null_mut(), &mut n, &mut k1), CKR_OK);
        assert_eq!(n, 25);
        let mut ct = vec![0u8; n as usize];
        assert_eq!(
            l.C_EncapsulateKey.unwrap()(s, &mut mech, pubk, null_mut(), 0, ct.as_mut_ptr(), &mut n, &mut k1),
            CKR_OK
        );
        let mut k2 = 0;
        assert_eq!(l.C_DecapsulateKey.unwrap()(s, &mut mech, pubk, null_mut(), 0, ct.as_mut_ptr(), n, &mut k2), CKR_OK);
        assert_ne!(k1, 0);
        assert_eq!(get_value(s, k1), get_value(s, k2));
        // a key handle that isn't ours
        assert_eq!(
            l.C_EncapsulateKey.unwrap()(s, &mut mech, 0xbeef, null_mut(), 0, ct.as_mut_ptr(), &mut n, &mut k2),
            CKR_KEY_HANDLE_INVALID
        );

        // authenticated wrapping
        let wk = aes_key(s);
        let target = aes_key(s);
        let mut wm = plain(CKM_AES_KEY_WRAP);
        let mut aad = *b"context";
        let mut wn: CK_ULONG = 0;
        assert_eq!(
            l.C_WrapKeyAuthenticated.unwrap()(s, &mut wm, wk, target, aad.as_mut_ptr(), 7, null_mut(), &mut wn),
            CKR_OK
        );
        let mut wrapped = vec![0u8; wn as usize];
        assert_eq!(
            l.C_WrapKeyAuthenticated.unwrap()(
                s,
                &mut wm,
                wk,
                target,
                aad.as_mut_ptr(),
                7,
                wrapped.as_mut_ptr(),
                &mut wn
            ),
            CKR_OK
        );
        let mut back = 0;
        assert_eq!(
            l.C_UnwrapKeyAuthenticated.unwrap()(
                s,
                &mut wm,
                wk,
                wrapped.as_mut_ptr(),
                wn,
                null_mut(),
                0,
                aad.as_mut_ptr(),
                7,
                &mut back
            ),
            CKR_OK
        );
        assert_eq!(get_value(s, back), get_value(s, target));
        let mut bad_aad = *b"contexT";
        assert_eq!(
            l.C_UnwrapKeyAuthenticated.unwrap()(
                s,
                &mut wm,
                wk,
                wrapped.as_mut_ptr(),
                wn,
                null_mut(),
                0,
                bad_aad.as_mut_ptr(),
                7,
                &mut back
            ),
            CKR_WRAPPED_KEY_INVALID
        );
    }
}

#[test]
fn verify_with_the_signature_given_first() {
    let _e = env();
    unsafe {
        let s = session();
        login(s);
        let l = l32();
        let key = aes_key(s);
        let mut m = plain(CKM_SHA256_HMAC);
        let mut data = *b"the message";
        assert_eq!(C_SignInit(s, &mut m, key), CKR_OK);
        let mut sig = [0u8; 16];
        let mut sn: CK_ULONG = 16;
        assert_eq!(C_Sign(s, data.as_mut_ptr(), 11, sig.as_mut_ptr(), &mut sn), CKR_OK);

        assert_eq!(l.C_VerifySignatureInit.unwrap()(s, &mut m, key, sig.as_mut_ptr(), sn), CKR_OK);
        assert_eq!(l.C_VerifySignature.unwrap()(s, data.as_mut_ptr(), 11), CKR_OK);
        // in parts
        assert_eq!(l.C_VerifySignatureInit.unwrap()(s, &mut m, key, sig.as_mut_ptr(), sn), CKR_OK);
        assert_eq!(l.C_VerifySignatureUpdate.unwrap()(s, data.as_mut_ptr(), 4), CKR_OK);
        assert_eq!(l.C_VerifySignatureUpdate.unwrap()(s, data.as_mut_ptr().add(4), 7), CKR_OK);
        assert_eq!(l.C_VerifySignatureFinal.unwrap()(s), CKR_OK);
        // wrong data
        assert_eq!(l.C_VerifySignatureInit.unwrap()(s, &mut m, key, sig.as_mut_ptr(), sn), CKR_OK);
        data[0] ^= 1;
        assert_eq!(l.C_VerifySignature.unwrap()(s, data.as_mut_ptr(), 11), CKR_SIGNATURE_INVALID);
        assert_eq!(l.C_VerifySignature.unwrap()(s, data.as_mut_ptr(), 11), CKR_OPERATION_NOT_INITIALIZED);
    }
}

#[test]
fn message_based_sign_verify_and_encrypt() {
    let _e = env();
    unsafe {
        let s = session();
        login(s);
        let l = l32();
        let key = aes_key(s);
        let mut hm = plain(CKM_SHA256_HMAC);

        // signing several messages with one key
        assert_eq!(l.C_MessageSignInit.unwrap()(s, &mut hm, key), CKR_OK);
        let mut msg = *b"one";
        let mut sn: CK_ULONG = 0;
        assert_eq!(l.C_SignMessage.unwrap()(s, null_mut(), 0, msg.as_mut_ptr(), 3, null_mut(), &mut sn), CKR_OK);
        let mut sig = vec![0u8; sn as usize];
        assert_eq!(l.C_SignMessage.unwrap()(s, null_mut(), 0, msg.as_mut_ptr(), 3, sig.as_mut_ptr(), &mut sn), CKR_OK);
        assert_eq!(l.C_SignMessageBegin.unwrap()(s, null_mut(), 0), CKR_OK);
        let mut sig2 = vec![0u8; 16];
        let mut sn2: CK_ULONG = 16;
        assert_eq!(
            l.C_SignMessageNext.unwrap()(s, null_mut(), 0, msg.as_mut_ptr(), 3, sig2.as_mut_ptr(), &mut sn2),
            CKR_OK
        );
        assert_eq!(&sig2[..sn2 as usize], &sig[..]);
        assert_eq!(l.C_MessageSignFinal.unwrap()(s), CKR_OK);
        assert_eq!(l.C_MessageSignFinal.unwrap()(s), CKR_OPERATION_NOT_INITIALIZED);

        assert_eq!(l.C_MessageVerifyInit.unwrap()(s, &mut hm, key), CKR_OK);
        assert_eq!(l.C_VerifyMessage.unwrap()(s, null_mut(), 0, msg.as_mut_ptr(), 3, sig.as_mut_ptr(), sn), CKR_OK);
        assert_eq!(l.C_VerifyMessageBegin.unwrap()(s, null_mut(), 0), CKR_OK);
        assert_eq!(l.C_VerifyMessageNext.unwrap()(s, null_mut(), 0, msg.as_mut_ptr(), 3, sig.as_mut_ptr(), sn), CKR_OK);
        sig[0] ^= 1;
        assert_eq!(
            l.C_VerifyMessage.unwrap()(s, null_mut(), 0, msg.as_mut_ptr(), 3, sig.as_mut_ptr(), sn),
            CKR_SIGNATURE_INVALID
        );
        assert_eq!(l.C_MessageVerifyFinal.unwrap()(s), CKR_OK);
        // a parameter for a mechanism that takes none
        let mut junk = [0u8; 8];
        assert_eq!(l.C_MessageSignInit.unwrap()(s, &mut hm, key), CKR_OK);
        assert_eq!(
            l.C_SignMessage.unwrap()(s, junk.as_mut_ptr().cast(), 8, msg.as_mut_ptr(), 3, null_mut(), &mut sn),
            CKR_MECHANISM_PARAM_INVALID
        );
        assert_eq!(l.C_MessageSignFinal.unwrap()(s), CKR_OK);

        // AEAD: the IV and tag the module generates land in the caller's parameter
        let mut gcm = plain(CKM_AES_GCM);
        assert_eq!(l.C_MessageEncryptInit.unwrap()(s, &mut gcm, key), CKR_OK);
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
        let plen = std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG;
        let mut pt = *b"secret!";
        let mut ct = [0u8; 16];
        let mut cn: CK_ULONG = 16;
        assert_eq!(
            l.C_EncryptMessage.unwrap()(
                s,
                (&mut p as *mut CK_GCM_MESSAGE_PARAMS).cast::<c_void>(),
                plen,
                null_mut(),
                0,
                pt.as_mut_ptr(),
                7,
                ct.as_mut_ptr(),
                &mut cn
            ),
            CKR_OK
        );
        assert_eq!(&ct[..7], b"!terces");
        assert_eq!(iv, [0x11; 12]);
        assert_eq!(tag, [0xee; 16]);
        // streaming
        assert_eq!(
            l.C_EncryptMessageBegin.unwrap()(s, (&mut p as *mut CK_GCM_MESSAGE_PARAMS).cast(), plen, null_mut(), 0),
            CKR_OK
        );
        assert_eq!(iv, [0x22; 12]);
        let mut cn: CK_ULONG = 16;
        assert_eq!(
            l.C_EncryptMessageNext.unwrap()(
                s,
                (&mut p as *mut CK_GCM_MESSAGE_PARAMS).cast(),
                plen,
                pt.as_mut_ptr(),
                7,
                ct.as_mut_ptr(),
                &mut cn,
                CKF_END_OF_MESSAGE
            ),
            CKR_OK
        );
        assert_eq!(iv, [0x33; 12]);
        assert_eq!(l.C_MessageEncryptFinal.unwrap()(s), CKR_OK);
        // a parameter of the wrong size
        assert_eq!(l.C_MessageEncryptInit.unwrap()(s, &mut gcm, key), CKR_OK);
        assert_eq!(
            l.C_EncryptMessage.unwrap()(
                s,
                (&mut p as *mut CK_GCM_MESSAGE_PARAMS).cast(),
                plen - 8,
                null_mut(),
                0,
                pt.as_mut_ptr(),
                7,
                ct.as_mut_ptr(),
                &mut cn
            ),
            CKR_MECHANISM_PARAM_INVALID
        );
        assert_eq!(l.C_MessageEncryptFinal.unwrap()(s), CKR_OK);
        // and decryption
        assert_eq!(l.C_MessageDecryptInit.unwrap()(s, &mut gcm, key), CKR_OK);
        let mut out = [0u8; 16];
        let mut on: CK_ULONG = 16;
        let mut ctx = *b"!terces";
        assert_eq!(
            l.C_DecryptMessage.unwrap()(
                s,
                (&mut p as *mut CK_GCM_MESSAGE_PARAMS).cast(),
                plen,
                null_mut(),
                0,
                ctx.as_mut_ptr(),
                7,
                out.as_mut_ptr(),
                &mut on
            ),
            CKR_OK
        );
        assert_eq!(&out[..on as usize], b"secret!");
        assert_eq!(l.C_MessageDecryptFinal.unwrap()(s), CKR_OK);
        // messages without init
        assert_eq!(
            l.C_EncryptMessage.unwrap()(
                s,
                (&mut p as *mut CK_GCM_MESSAGE_PARAMS).cast(),
                plen,
                null_mut(),
                0,
                pt.as_mut_ptr(),
                7,
                ct.as_mut_ptr(),
                &mut cn
            ),
            CKR_OPERATION_NOT_INITIALIZED
        );
    }
}
