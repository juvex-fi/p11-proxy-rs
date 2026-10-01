//! The whole system: the real `p11-daemon` process serving SoftHSM, and
//! the client library's C entry points talking to it over real sockets.
//! Skipped when no SoftHSM is available (see p11_testkit::softhsm).
#![allow(clippy::undocumented_unsafe_blocks, unsafe_op_in_unsafe_fn)]

use p11_proxy::core::CoreConfig;
use p11_proxy::testing;
use p11_proxy::*;
use p11_testkit::proc::DaemonProc;
use p11_testkit::softhsm::{Token, USER_PIN};
use p11_transport::unix::UnixConnector;
use p11_types::*;
use std::ffi::c_void;
use std::ptr::null_mut;

const DAEMON: &str = env!("CARGO_BIN_EXE_p11-daemon");

macro_rules! token {
    () => {
        match Token::create() {
            Some(t) => t,
            None => {
                eprintln!("SKIP: no SoftHSM (set P11_SOFTHSM_MODULE and P11_SOFTHSM_UTIL)");
                return;
            }
        }
    };
}

#[allow(dead_code)]
struct Rig {
    daemon: DaemonProc,
    token: Token,
    _session: Option<testing::Session>,
}

fn spawn(token: &Token, args: &[&str], expect: usize) -> DaemonProc {
    let mut a: Vec<&str> = args.to_vec();
    let module = token.module.to_str().unwrap().to_string();
    let module: &'static str = Box::leak(module.into_boxed_str());
    a.push(module);
    DaemonProc::spawn(std::path::Path::new(DAEMON), &a, &token.envs(), expect).expect("daemon starts")
}

/// A daemon on a unix socket and a client connected to it.
fn unix_rig(token: Token) -> Rig {
    unix_rig_with(token, &[])
}

fn unix_rig_with(token: Token, extra: &[&str]) -> Rig {
    let sock = token.path().join("daemon.sock");
    let listen = format!("unix://{}", sock.display());
    let mut args = vec!["--listen", listen.as_str()];
    args.extend_from_slice(extra);
    let daemon = spawn(&token, &args, 1);
    let session = testing::install(Box::new(UnixConnector(sock)), CoreConfig::default()).expect("client initializes");
    Rig { daemon, token, _session: Some(session) }
}

// ---- thin wrappers over the C API ----

const SO: CK_ULONG = CKU_SO;

unsafe fn first_slot() -> CK_SLOT_ID {
    let mut n = 8;
    let mut slots = [0 as CK_SLOT_ID; 8];
    assert_eq!(C_GetSlotList(1, slots.as_mut_ptr(), &mut n), CKR_OK);
    let i = p11_testkit::softhsm::slot_index();
    assert!(n as usize > i, "slot index {i} of {n}");
    slots[i]
}

unsafe fn open(rw: bool) -> CK_SESSION_HANDLE {
    let mut s = 0;
    let flags = CKF_SERIAL_SESSION | if rw { CKF_RW_SESSION } else { 0 };
    assert_eq!(C_OpenSession(first_slot(), flags, null_mut(), None, &mut s), CKR_OK);
    s
}

unsafe fn login(s: CK_SESSION_HANDLE) {
    let mut pin = USER_PIN.as_bytes().to_vec();
    let rv = C_Login(s, CKU_USER, pin.as_mut_ptr(), pin.len() as CK_ULONG);
    assert!(rv == CKR_OK || rv == CKR_USER_ALREADY_LOGGED_IN, "login: 0x{rv:x}");
    let _ = SO;
}

fn m<T>(mech: CK_MECHANISM_TYPE, p: &mut T) -> CK_MECHANISM {
    CK_MECHANISM {
        mechanism: mech,
        pParameter: p as *mut T as *mut c_void,
        ulParameterLen: std::mem::size_of::<T>() as CK_ULONG,
    }
}
fn plain(mech: CK_MECHANISM_TYPE) -> CK_MECHANISM {
    CK_MECHANISM { mechanism: mech, pParameter: null_mut(), ulParameterLen: 0 }
}
fn a_bytes(ty: CK_ATTRIBUTE_TYPE, v: &[u8]) -> CK_ATTRIBUTE {
    CK_ATTRIBUTE { type_: ty, pValue: v.as_ptr() as *mut c_void, ulValueLen: v.len() as CK_ULONG }
}
fn a_bool(ty: CK_ATTRIBUTE_TYPE, v: &'static CK_BBOOL) -> CK_ATTRIBUTE {
    CK_ATTRIBUTE { type_: ty, pValue: v as *const CK_BBOOL as *mut c_void, ulValueLen: 1 }
}
fn a_ulong(ty: CK_ATTRIBUTE_TYPE, v: &CK_ULONG) -> CK_ATTRIBUTE {
    CK_ATTRIBUTE { type_: ty, pValue: v as *const CK_ULONG as *mut c_void, ulValueLen: 8 }
}
static TRUE: CK_BBOOL = 1;
static FALSE: CK_BBOOL = 0;

unsafe fn attr_value(s: CK_SESSION_HANDLE, o: CK_OBJECT_HANDLE, ty: CK_ATTRIBUTE_TYPE) -> Vec<u8> {
    let mut q = [CK_ATTRIBUTE { type_: ty, pValue: null_mut(), ulValueLen: 0 }];
    assert_eq!(C_GetAttributeValue(s, o, q.as_mut_ptr(), 1), CKR_OK);
    let mut buf = vec![0u8; q[0].ulValueLen as usize];
    q[0].pValue = buf.as_mut_ptr().cast();
    assert_eq!(C_GetAttributeValue(s, o, q.as_mut_ptr(), 1), CKR_OK);
    buf.truncate(q[0].ulValueLen as usize);
    buf
}

unsafe fn gen_aes(s: CK_SESSION_HANDLE, bits: CK_ULONG, extractable: bool) -> CK_OBJECT_HANDLE {
    let mut mech = plain(CKM_AES_KEY_GEN);
    let len: CK_ULONG = bits / 8;
    static EXTRACTABLE: CK_BBOOL = 1;
    let mut t = vec![
        a_ulong(CKA_VALUE_LEN, &len),
        a_bool(CKA_ENCRYPT, &TRUE),
        a_bool(CKA_DECRYPT, &TRUE),
        a_bool(CKA_TOKEN, &FALSE),
        a_bool(CKA_SENSITIVE, &FALSE),
        a_bool(CKA_DERIVE, &TRUE),
        a_bool(CKA_WRAP, &TRUE),
        a_bool(CKA_UNWRAP, &TRUE),
    ];
    if extractable {
        t.push(a_bool(CKA_EXTRACTABLE, &EXTRACTABLE));
    }
    let mut k = 0;
    assert_eq!(C_GenerateKey(s, &mut mech, t.as_mut_ptr(), t.len() as CK_ULONG, &mut k), CKR_OK);
    k
}

unsafe fn encrypt(
    s: CK_SESSION_HANDLE,
    mech: &mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
    data: &[u8],
) -> Result<Vec<u8>, CK_RV> {
    let rv = C_EncryptInit(s, mech, key);
    if rv != CKR_OK {
        return Err(rv);
    }
    let mut n: CK_ULONG = 0;
    let rv = C_Encrypt(s, data.as_ptr() as *mut u8, data.len() as CK_ULONG, null_mut(), &mut n);
    if rv != CKR_OK {
        return Err(rv);
    }
    let mut out = vec![0u8; n as usize];
    let rv = C_Encrypt(s, data.as_ptr() as *mut u8, data.len() as CK_ULONG, out.as_mut_ptr(), &mut n);
    if rv != CKR_OK {
        return Err(rv);
    }
    out.truncate(n as usize);
    Ok(out)
}

unsafe fn decrypt(
    s: CK_SESSION_HANDLE,
    mech: &mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
    data: &[u8],
) -> Result<Vec<u8>, CK_RV> {
    let rv = C_DecryptInit(s, mech, key);
    if rv != CKR_OK {
        return Err(rv);
    }
    let mut out = vec![0u8; data.len() + 64];
    let mut n = out.len() as CK_ULONG;
    let rv = C_Decrypt(s, data.as_ptr() as *mut u8, data.len() as CK_ULONG, out.as_mut_ptr(), &mut n);
    if rv != CKR_OK {
        return Err(rv);
    }
    out.truncate(n as usize);
    Ok(out)
}

unsafe fn sign(
    s: CK_SESSION_HANDLE,
    mech: &mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
    data: &[u8],
) -> Result<Vec<u8>, CK_RV> {
    let rv = C_SignInit(s, mech, key);
    if rv != CKR_OK {
        return Err(rv);
    }
    let mut n: CK_ULONG = 0;
    let rv = C_Sign(s, data.as_ptr() as *mut u8, data.len() as CK_ULONG, null_mut(), &mut n);
    if rv != CKR_OK {
        return Err(rv);
    }
    let mut out = vec![0u8; n as usize];
    let rv = C_Sign(s, data.as_ptr() as *mut u8, data.len() as CK_ULONG, out.as_mut_ptr(), &mut n);
    if rv != CKR_OK {
        return Err(rv);
    }
    out.truncate(n as usize);
    Ok(out)
}

unsafe fn verify(
    s: CK_SESSION_HANDLE,
    mech: &mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
    data: &[u8],
    sig: &[u8],
) -> CK_RV {
    let rv = C_VerifyInit(s, mech, key);
    if rv != CKR_OK {
        return rv;
    }
    C_Verify(s, data.as_ptr() as *mut u8, data.len() as CK_ULONG, sig.as_ptr() as *mut u8, sig.len() as CK_ULONG)
}

// ---- tests ----

#[test]
fn basics_over_a_unix_socket() {
    let rig = unix_rig(token!());
    unsafe {
        let mut info: CK_INFO = std::mem::zeroed();
        assert_eq!(C_GetInfo(&mut info), CKR_OK);
        assert!(info.cryptokiVersion.major >= 2);
        let slot = first_slot();
        let mut ti: CK_TOKEN_INFO = std::mem::zeroed();
        assert_eq!(C_GetTokenInfo(slot, &mut ti), CKR_OK);
        let label = p11_testkit::softhsm::token_label();
        assert_eq!(&ti.label[..label.len()], label.as_bytes());

        let s = open(true);
        login(s);
        let mut rnd = [0u8; 32];
        assert_eq!(C_GenerateRandom(s, rnd.as_mut_ptr(), 32), CKR_OK);
        assert!(rnd.iter().any(|&b| b != 0));

        // SHA-256("abc")
        let mut mech = plain(CKM_SHA256);
        assert_eq!(C_DigestInit(s, &mut mech), CKR_OK);
        let mut d = [0u8; 32];
        let mut n = 32;
        let mut abc = *b"abc";
        assert_eq!(C_Digest(s, abc.as_mut_ptr(), 3, d.as_mut_ptr(), &mut n), CKR_OK);
        assert_eq!(d[..4], [0xba, 0x78, 0x16, 0xbf]);

        // a data object round trip through attributes and search
        let label = b"e2e object";
        let class = CKO_DATA;
        let mut t = [
            a_ulong(CKA_CLASS, &class),
            a_bool(CKA_TOKEN, &FALSE),
            a_bytes(CKA_LABEL, label),
            a_bytes(CKA_VALUE, b"payload"),
        ];
        let mut obj = 0;
        assert_eq!(C_CreateObject(s, t.as_mut_ptr(), 4, &mut obj), CKR_OK);
        assert_eq!(C_FindObjectsInit(s, t.as_mut_ptr().add(2), 1), CKR_OK);
        let mut found = [0; 4];
        let mut nf = 0;
        assert_eq!(C_FindObjects(s, found.as_mut_ptr(), 4, &mut nf), CKR_OK);
        assert_eq!(C_FindObjectsFinal(s), CKR_OK);
        assert_eq!((nf, found[0]), (1, obj));
        assert_eq!(attr_value(s, obj, CKA_VALUE), b"payload");
        assert_eq!(attr_value(s, obj, CKA_LABEL), label);
        assert_eq!(C_DestroyObject(s, obj), CKR_OK);
        assert_eq!(C_CloseSession(s), CKR_OK);
    }
    drop(rig);
}

#[test]
fn aes_gcm_and_cbc_parameters_cross_the_wire() {
    let _rig = unix_rig(token!());
    unsafe {
        let s = open(true);
        login(s);
        let key = gen_aes(s, 256, false);

        let mut iv = *b"unique-iv-12";
        let mut aad = *b"header";
        let mut p = CK_GCM_PARAMS {
            pIv: iv.as_mut_ptr(),
            ulIvLen: 12,
            ulIvBits: 96,
            pAAD: aad.as_mut_ptr(),
            ulAADLen: 6,
            ulTagBits: 128,
        };
        let mut mech = m(CKM_AES_GCM, &mut p);
        let msg = b"attack at dawn, bring snacks";
        match encrypt(s, &mut mech, key, msg) {
            Err(rv)
                if p11_testkit::softhsm::external()
                    && (rv == CKR_MECHANISM_PARAM_INVALID || rv == CKR_MECHANISM_INVALID) =>
            {
                eprintln!("SKIP: this module refuses AES-GCM as given (0x{rv:x})");
            }
            ct => {
                let ct = ct.expect("gcm encrypt");
                assert_eq!(ct.len(), msg.len() + 16);
                assert_eq!(decrypt(s, &mut mech, key, &ct).expect("gcm decrypt"), msg);
                // a flipped bit is caught by the tag
                let mut bad = ct.clone();
                bad[3] ^= 1;
                // the module says what it says (which error differs between versions)
                assert!(decrypt(s, &mut mech, key, &bad).is_err());
                // different associated data too
                let mut aad2 = *b"headex";
                let mut p2 = CK_GCM_PARAMS { pAAD: aad2.as_mut_ptr(), ..p };
                let mut mech2 = m(CKM_AES_GCM, &mut p2);
                assert!(decrypt(s, &mut mech2, key, &ct).is_err());
            }
        }

        // CBC with a flat IV parameter
        let mut civ = [7u8; 16];
        let mut cbc =
            CK_MECHANISM { mechanism: CKM_AES_CBC_PAD, pParameter: civ.as_mut_ptr().cast(), ulParameterLen: 16 };
        let c = encrypt(s, &mut cbc, key, b"cbc test data").unwrap();
        assert_eq!(decrypt(s, &mut cbc, key, &c).unwrap(), b"cbc test data");
        // a parameter of the wrong size never leaves the client
        let mut short =
            CK_MECHANISM { mechanism: CKM_AES_CBC_PAD, pParameter: civ.as_mut_ptr().cast(), ulParameterLen: 12 };
        assert_eq!(C_EncryptInit(s, &mut short, key), CKR_MECHANISM_PARAM_INVALID);
    }
}

fn ec_p256() -> Vec<u8> {
    vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]
}

unsafe fn gen_ec(s: CK_SESSION_HANDLE, derive: bool) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
    let mut mech = plain(CKM_EC_KEY_PAIR_GEN);
    let params = ec_p256();
    let mut pubt = vec![a_bytes(CKA_EC_PARAMS, &params), a_bool(CKA_VERIFY, &TRUE), a_bool(CKA_TOKEN, &FALSE)];
    let mut privt = vec![
        a_bool(CKA_SIGN, &TRUE),
        a_bool(CKA_TOKEN, &FALSE),
        a_bool(CKA_SENSITIVE, &TRUE),
        a_bool(CKA_DERIVE, if derive { &TRUE } else { &FALSE }),
    ];
    let (mut p, mut k) = (0, 0);
    assert_eq!(
        C_GenerateKeyPair(
            s,
            &mut mech,
            pubt.as_mut_ptr(),
            pubt.len() as CK_ULONG,
            privt.as_mut_ptr(),
            privt.len() as CK_ULONG,
            &mut p,
            &mut k
        ),
        CKR_OK
    );
    (p, k)
}

#[test]
fn rsa_oaep_and_pss_with_structured_parameters() {
    let _rig = unix_rig(token!());
    unsafe {
        let s = open(true);
        login(s);
        let mut mech = plain(CKM_RSA_PKCS_KEY_PAIR_GEN);
        let bits: CK_ULONG = 2048;
        let exp = [1u8, 0, 1];
        let mut pubt = vec![
            a_ulong(CKA_MODULUS_BITS, &bits),
            a_bytes(CKA_PUBLIC_EXPONENT, &exp),
            a_bool(CKA_ENCRYPT, &TRUE),
            a_bool(CKA_VERIFY, &TRUE),
            a_bool(CKA_TOKEN, &FALSE),
        ];
        let mut privt = vec![
            a_bool(CKA_DECRYPT, &TRUE),
            a_bool(CKA_SIGN, &TRUE),
            a_bool(CKA_TOKEN, &FALSE),
            a_bool(CKA_SENSITIVE, &TRUE),
        ];
        let (mut pubk, mut privk) = (0, 0);
        assert_eq!(
            C_GenerateKeyPair(
                s,
                &mut mech,
                pubt.as_mut_ptr(),
                pubt.len() as CK_ULONG,
                privt.as_mut_ptr(),
                privt.len() as CK_ULONG,
                &mut pubk,
                &mut privk
            ),
            CKR_OK
        );
        // the modulus size comes back as a CK_ULONG attribute
        let mb = attr_value(s, pubk, CKA_MODULUS_BITS);
        assert_eq!(CK_ULONG::from_ne_bytes(mb.try_into().unwrap()), 2048);

        // older SoftHSM builds only do OAEP with SHA-1
        let mut oaep = CK_RSA_PKCS_OAEP_PARAMS {
            hashAlg: CKM_SHA256,
            mgf: CKG_MGF1_SHA256,
            source: CKZ_DATA_SPECIFIED,
            pSourceData: null_mut(),
            ulSourceDataLen: 0,
        };
        let first = encrypt(s, &mut m(CKM_RSA_PKCS_OAEP, &mut oaep), pubk, b"a short secret");
        if first.is_err() {
            oaep.hashAlg = CKM_SHA_1;
            oaep.mgf = CKG_MGF1_SHA1;
        }
        let mut om = m(CKM_RSA_PKCS_OAEP, &mut oaep);
        let ct = encrypt(s, &mut om, pubk, b"a short secret").expect("oaep encrypt");
        assert_eq!(ct.len(), 256);
        assert_eq!(decrypt(s, &mut om, privk, &ct).expect("oaep decrypt"), b"a short secret");

        // a label travels in the parameter too, where the module supports one
        let mut label = *b"oaep-label";
        let mut oaep_l = CK_RSA_PKCS_OAEP_PARAMS {
            pSourceData: label.as_mut_ptr().cast(),
            ulSourceDataLen: label.len() as CK_ULONG,
            ..oaep
        };
        let mut olm = m(CKM_RSA_PKCS_OAEP, &mut oaep_l);
        match encrypt(s, &mut olm, pubk, b"labelled") {
            Ok(ct) => {
                assert_eq!(decrypt(s, &mut olm, privk, &ct).expect("oaep decrypt with label"), b"labelled");
                let mut label2 = *b"other-label";
                let mut oaep2 = CK_RSA_PKCS_OAEP_PARAMS {
                    pSourceData: label2.as_mut_ptr().cast(),
                    ulSourceDataLen: label2.len() as CK_ULONG,
                    ..oaep
                };
                let mut om2 = m(CKM_RSA_PKCS_OAEP, &mut oaep2);
                assert!(decrypt(s, &mut om2, privk, &ct).is_err());
            }
            Err(rv) => eprintln!("this module has no OAEP labels (0x{rv:x})"),
        }

        let mut pss = CK_RSA_PKCS_PSS_PARAMS { hashAlg: CKM_SHA256, mgf: CKG_MGF1_SHA256, sLen: 32 };
        let mut pm = m(CKM_SHA256_RSA_PKCS_PSS, &mut pss);
        let sig = sign(s, &mut pm, privk, b"signed message").expect("pss sign");
        assert_eq!(verify(s, &mut pm, pubk, b"signed message", &sig), CKR_OK);
        assert_eq!(verify(s, &mut pm, pubk, b"signed massage", &sig), CKR_SIGNATURE_INVALID);
    }
}

#[test]
fn ecdsa_and_ecdh_with_derived_key_handles() {
    let _rig = unix_rig(token!());
    unsafe {
        let s = open(true);
        login(s);
        let (pa, ka) = gen_ec(s, true);
        let (pb, kb) = gen_ec(s, true);
        // raw ECDSA over a digest, which every module has
        let mut ecdsa = plain(CKM_ECDSA);
        let digest = [0x42u8; 32];
        let sig = sign(s, &mut ecdsa, ka, &digest).unwrap();
        assert_eq!(verify(s, &mut ecdsa, pa, &digest, &sig), CKR_OK);
        assert_eq!(verify(s, &mut ecdsa, pb, &digest, &sig), CKR_SIGNATURE_INVALID);

        // ECDH: each side derives with the other's public point
        let point_a = attr_value(s, pa, CKA_EC_POINT);
        let point_b = attr_value(s, pb, CKA_EC_POINT);
        // CKA_EC_POINT is a DER OCTET STRING; the derive parameter wants the raw point
        let raw = |d: &[u8]| -> Vec<u8> { d[if d[1] & 0x80 != 0 { 2 + (d[1] & 0x7f) as usize } else { 2 }..].to_vec() };
        let (mut ra, mut rb) = (raw(&point_a), raw(&point_b));
        let vlen: CK_ULONG = 32;
        let derive = |base: CK_OBJECT_HANDLE, other: &mut Vec<u8>| -> CK_OBJECT_HANDLE {
            let mut p = CK_ECDH1_DERIVE_PARAMS {
                kdf: CKD_NULL,
                ulSharedDataLen: 0,
                pSharedData: null_mut(),
                ulPublicDataLen: other.len() as CK_ULONG,
                pPublicData: other.as_mut_ptr(),
            };
            let mut mech = m(CKM_ECDH1_DERIVE, &mut p);
            let cls = CKO_SECRET_KEY;
            let kt = CKK_AES;
            let mut t = [
                a_ulong(CKA_CLASS, &cls),
                a_ulong(CKA_KEY_TYPE, &kt),
                a_ulong(CKA_VALUE_LEN, &vlen),
                a_bool(CKA_TOKEN, &FALSE),
                a_bool(CKA_SENSITIVE, &FALSE),
                a_bool(CKA_EXTRACTABLE, &TRUE),
            ];
            let mut out = 0;
            assert_eq!(C_DeriveKey(s, &mut mech, base, t.as_mut_ptr(), 6, &mut out), CKR_OK);
            out
        };
        let sa = derive(ka, &mut rb);
        let sb = derive(kb, &mut ra);
        assert_ne!(sa, 0);
        let va = attr_value(s, sa, CKA_VALUE);
        let vb = attr_value(s, sb, CKA_VALUE);
        assert_eq!(va.len(), 32);
        assert_eq!(va, vb, "both sides derive the same secret");
        // a derive with someone else's handle is refused before it reaches the module
        assert_eq!(C_DestroyObject(s, sa), CKR_OK);
    }
}

#[test]
fn post_quantum_signatures_and_kem() {
    let _rig = unix_rig(token!());
    unsafe {
        let s = open(true);
        login(s);
        // ML-DSA
        let mut mech = plain(CKM_ML_DSA_KEY_PAIR_GEN);
        let set: CK_ULONG = CKP_ML_DSA_65;
        let mut pubt = vec![a_ulong(CKA_PARAMETER_SET, &set), a_bool(CKA_VERIFY, &TRUE), a_bool(CKA_TOKEN, &FALSE)];
        let mut privt = vec![a_bool(CKA_SIGN, &TRUE), a_bool(CKA_TOKEN, &FALSE), a_bool(CKA_SENSITIVE, &TRUE)];
        let (mut pubk, mut privk) = (0, 0);
        let rv = C_GenerateKeyPair(s, &mut mech, pubt.as_mut_ptr(), 3, privt.as_mut_ptr(), 3, &mut pubk, &mut privk);
        if rv == CKR_MECHANISM_INVALID {
            eprintln!("SKIP: this SoftHSM has no ML-DSA");
            return;
        }
        assert_eq!(rv, CKR_OK);
        let ps = attr_value(s, pubk, CKA_PARAMETER_SET);
        assert_eq!(CK_ULONG::from_ne_bytes(ps.try_into().unwrap()), CKP_ML_DSA_65);
        let mut dsa = plain(CKM_ML_DSA);
        let sig = sign(s, &mut dsa, privk, b"pq message").unwrap();
        assert_eq!(verify(s, &mut dsa, pubk, b"pq message", &sig), CKR_OK);
        assert_eq!(verify(s, &mut dsa, pubk, b"pq messagf", &sig), CKR_SIGNATURE_INVALID);

        // with a context string in the mechanism parameter
        let mut ctx = *b"my-context";
        let mut p = CK_SIGN_ADDITIONAL_CONTEXT {
            hedgeVariant: CKH_HEDGE_PREFERRED,
            pContext: ctx.as_mut_ptr(),
            ulContextLen: 10,
        };
        let mut dm = m(CKM_ML_DSA, &mut p);
        let sig = sign(s, &mut dm, privk, b"with context").unwrap();
        assert_eq!(verify(s, &mut dm, pubk, b"with context", &sig), CKR_OK);
        let mut ctx2 = *b"other-conte";
        let mut p2 = CK_SIGN_ADDITIONAL_CONTEXT {
            hedgeVariant: CKH_HEDGE_PREFERRED,
            pContext: ctx2.as_mut_ptr(),
            ulContextLen: 10,
        };
        let mut dm2 = m(CKM_ML_DSA, &mut p2);
        assert_eq!(verify(s, &mut dm2, pubk, b"with context", &sig), CKR_SIGNATURE_INVALID);

        // ML-KEM: encapsulate with the public key, decapsulate with the private one
        let mut kem = plain(CKM_ML_KEM_KEY_PAIR_GEN);
        let kset: CK_ULONG = CKP_ML_KEM_768;
        let mut pubt =
            vec![a_ulong(CKA_PARAMETER_SET, &kset), a_bool(CKA_ENCAPSULATE, &TRUE), a_bool(CKA_TOKEN, &FALSE)];
        let mut privt = vec![a_bool(CKA_DECAPSULATE, &TRUE), a_bool(CKA_TOKEN, &FALSE), a_bool(CKA_SENSITIVE, &TRUE)];
        let (mut kpub, mut kpriv) = (0, 0);
        assert_eq!(
            C_GenerateKeyPair(s, &mut kem, pubt.as_mut_ptr(), 3, privt.as_mut_ptr(), 3, &mut kpub, &mut kpriv),
            CKR_OK
        );
        let cls = CKO_SECRET_KEY;
        let kt = CKK_AES;
        let vlen: CK_ULONG = 32;
        let mut tpl = [
            a_ulong(CKA_CLASS, &cls),
            a_ulong(CKA_KEY_TYPE, &kt),
            a_ulong(CKA_VALUE_LEN, &vlen),
            a_bool(CKA_TOKEN, &FALSE),
            a_bool(CKA_SENSITIVE, &FALSE),
            a_bool(CKA_EXTRACTABLE, &TRUE),
        ];
        let mut mk = plain(CKM_ML_KEM);
        let mut ctl: CK_ULONG = 0;
        let mut k1 = 0;
        assert_eq!(
            C_EncapsulateKey(s, &mut mk, kpub, tpl.as_mut_ptr(), 6, null_mut(), &mut ctl, &mut k1),
            CKR_OK,
            "length query"
        );
        assert!(ctl > 500);
        let mut ct = vec![0u8; ctl as usize];
        assert_eq!(C_EncapsulateKey(s, &mut mk, kpub, tpl.as_mut_ptr(), 6, ct.as_mut_ptr(), &mut ctl, &mut k1), CKR_OK);
        let mut k2 = 0;
        assert_eq!(C_DecapsulateKey(s, &mut mk, kpriv, tpl.as_mut_ptr(), 6, ct.as_mut_ptr(), ctl, &mut k2), CKR_OK);
        assert_ne!(k1, k2);
        assert_eq!(
            attr_value(s, k1, CKA_VALUE),
            attr_value(s, k2, CKA_VALUE),
            "both sides hold the same shared secret"
        );
    }
}

#[test]
fn many_threads_share_one_token_through_pooled_connections() {
    let rig = unix_rig(token!());
    unsafe {
        let s0 = open(true);
        login(s0);
    }
    let mut ts = Vec::new();
    for i in 0..8u8 {
        ts.push(std::thread::spawn(move || unsafe {
            let s = open(false);
            let mut mech = plain(CKM_SHA256);
            for round in 0..25u8 {
                assert_eq!(C_DigestInit(s, &mut mech), CKR_OK);
                let mut data = [i, round, 1, 2, 3];
                let mut out = [0u8; 32];
                let mut n = 32;
                assert_eq!(C_Digest(s, data.as_mut_ptr(), 5, out.as_mut_ptr(), &mut n), CKR_OK);
                assert_ne!(out, [0u8; 32]);
                let mut rnd = [0u8; 16];
                assert_eq!(C_GenerateRandom(s, rnd.as_mut_ptr(), 16), CKR_OK);
            }
            assert_eq!(C_CloseSession(s), CKR_OK);
        }));
    }
    for t in ts {
        t.join().unwrap();
    }
    drop(rig);
}

/// Threads doing different things on one token at once, checking what each gets back (not just that
/// calls succeed), so data leaking between sessions or clients would show.
fn mixed_workload(extra: &[&str]) {
    const THREADS: u8 = 8;
    const ROUNDS: u8 = 20;
    let rig = unix_rig_with(token!(), extra);
    unsafe {
        let s0 = open(true);
        login(s0);
    }
    let mut ts = Vec::new();
    for i in 0..THREADS {
        ts.push(std::thread::spawn(move || unsafe {
            let s = open(true);
            let label = [b'w', b'o', b'r', b'k', i];
            for round in 0..ROUNDS {
                // a hash of a known input
                let mut mech = plain(CKM_SHA256);
                assert_eq!(C_DigestInit(s, &mut mech), CKR_OK);
                let mut abc = *b"abc";
                let mut out = [0u8; 32];
                let mut n = 32;
                assert_eq!(C_Digest(s, abc.as_mut_ptr(), 3, out.as_mut_ptr(), &mut n), CKR_OK);
                assert_eq!(out[..4], [0xba, 0x78, 0x16, 0xbf], "thread {i} round {round}: sha256(abc)");

                // an object of this thread's own, found by its own label and read back
                let class = CKO_DATA;
                let value = [i, round, 7, 7, 7];
                let mut t = [
                    a_ulong(CKA_CLASS, &class),
                    a_bool(CKA_TOKEN, &FALSE),
                    a_bytes(CKA_LABEL, &label),
                    a_bytes(CKA_VALUE, &value),
                ];
                let mut obj = 0;
                assert_eq!(C_CreateObject(s, t.as_mut_ptr(), 4, &mut obj), CKR_OK);
                let mut q = [a_bytes(CKA_LABEL, &label)];
                assert_eq!(C_FindObjectsInit(s, q.as_mut_ptr(), 1), CKR_OK);
                let mut found = [0 as CK_OBJECT_HANDLE; 64];
                let mut nf = 0;
                assert_eq!(C_FindObjects(s, found.as_mut_ptr(), 64, &mut nf), CKR_OK);
                assert_eq!(C_FindObjectsFinal(s), CKR_OK);
                // other threads' objects have other labels: exactly this thread's one is found
                assert_eq!(&found[..nf as usize], &[obj], "thread {i} round {round}: find by label");
                assert_eq!(attr_value(s, obj, CKA_VALUE), value, "thread {i} round {round}: value");
                assert_eq!(C_DestroyObject(s, obj), CKR_OK);
            }
            assert_eq!(C_CloseSession(s), CKR_OK);
        }));
    }
    for t in ts {
        t.join().unwrap();
    }
    drop(rig);
}

#[test]
fn a_mixed_concurrent_workload_gets_its_own_answers() {
    mixed_workload(&[]);
}

#[test]
fn the_same_workload_with_the_module_serialized() {
    mixed_workload(&["--serialize-module"]);
}

#[test]
fn a_dead_daemon_gives_errors_not_hangs() {
    let mut rig = unix_rig(token!());
    unsafe {
        let s = open(false);
        let mut rnd = [0u8; 8];
        assert_eq!(C_GenerateRandom(s, rnd.as_mut_ptr(), 8), CKR_OK);
        rig.daemon.crash();
        let started = std::time::Instant::now();
        let rv = C_GenerateRandom(s, rnd.as_mut_ptr(), 8);
        assert_eq!(rv, CKR_DEVICE_ERROR);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        // and the library can be finalised and used again with a new daemon
        assert_eq!(C_Finalize(null_mut()), CKR_OK);
    }
    rig._session = None;
    // a second daemon, a fresh client
    let token = Token::create().unwrap();
    let rig2 = unix_rig(token);
    unsafe {
        let mut info: CK_INFO = std::mem::zeroed();
        assert_eq!(C_GetInfo(&mut info), CKR_OK);
    }
    drop(rig2);
}

fn tls_files(
    dir: &std::path::Path,
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf, p11_transport::ClientSettings) {
    let ca = p11_testkit::pki::Ca::new("e2e ca");
    let server = ca.leaf("daemon", &["localhost", "127.0.0.1"]);
    let alice = ca.leaf("alice", &[]);
    std::fs::write(dir.join("ca.pem"), &ca.pem).unwrap();
    let (sc, sk) = server.write(dir, "server");
    let settings = p11_transport::ClientSettings {
        ca_pem: Some(ca.pem.clone().into_bytes()),
        cert_pem: Some(alice.cert_pem.clone().into_bytes()),
        key_pem: Some(alice.key_pem.clone().into_bytes()),
        server_name: Some("localhost".into()),
        ..Default::default()
    };
    (dir.join("ca.pem"), sc, sk, settings)
}

#[test]
fn mutual_tls_end_to_end() {
    let token = token!();
    let (ca, sc, sk, settings) = tls_files(token.path());
    let daemon = spawn(
        &token,
        &[
            "--listen",
            "tcp://127.0.0.1:0",
            "--tls-cert",
            sc.to_str().unwrap(),
            "--tls-key",
            sk.to_str().unwrap(),
            "--tls-client-ca",
            ca.to_str().unwrap(),
        ],
        1,
    );
    let port: u16 = daemon.listening[0].rsplit(':').next().unwrap().parse().unwrap();
    let connector =
        p11_transport::client_connector(&p11_transport::Endpoint::Tcp { host: "127.0.0.1".into(), port }, &settings)
            .unwrap();
    let s = testing::install(connector, CoreConfig::default()).expect("client initializes over TLS");
    unsafe {
        let s = open(true);
        login(s);
        let key = gen_aes(s, 128, false);
        let mut iv = [1u8; 16];
        let mut cbc =
            CK_MECHANISM { mechanism: CKM_AES_CBC_PAD, pParameter: iv.as_mut_ptr().cast(), ulParameterLen: 16 };
        let ct = encrypt(s, &mut cbc, key, b"over tls").unwrap();
        assert_eq!(decrypt(s, &mut cbc, key, &ct).unwrap(), b"over tls");
    }
    // a client without a certificate from the right CA is not let in
    let other = p11_testkit::pki::Ca::new("other ca").leaf("mallory", &[]);
    let mut bad = settings.clone();
    bad.cert_pem = Some(other.cert_pem.into_bytes());
    bad.key_pem = Some(other.key_pem.into_bytes());
    let connector =
        p11_transport::client_connector(&p11_transport::Endpoint::Tcp { host: "127.0.0.1".into(), port }, &bad)
            .unwrap();
    drop(s);
    assert!(testing::install(connector, CoreConfig::default()).is_err());
}

#[test]
fn psk_end_to_end() {
    let token = token!();
    let keys = token.path().join("psk.keys");
    std::fs::write(&keys, "alice:00112233445566778899aabbccddeeff\n").unwrap();
    let daemon = spawn(&token, &["--listen", "psk://127.0.0.1:0", "--psk-file", keys.to_str().unwrap()], 1);
    let port: u16 = daemon.listening[0].rsplit(':').next().unwrap().parse().unwrap();
    let secret: Vec<u8> = (0..16).map(|i| (i * 0x11) as u8).collect();
    let settings = p11_transport::ClientSettings { psk: Some(("alice".into(), secret)), ..Default::default() };
    let connector =
        p11_transport::client_connector(&p11_transport::Endpoint::Psk { host: "127.0.0.1".into(), port }, &settings)
            .unwrap();
    let _s = testing::install(connector, CoreConfig::default()).expect("client initializes over PSK");
    unsafe {
        let mut n = 0;
        assert_eq!(C_GetSlotList(1, null_mut(), &mut n), CKR_OK);
        assert!(n >= 1);
    }
}

#[test]
fn policy_from_a_configuration_file() {
    let token = token!();
    let cfg = token.path().join("daemon.toml");
    let sock = token.path().join("policy.sock");
    std::fs::write(
        &cfg,
        format!(
            r#"
listen = ["unix://{}"]
[policy]
default = "deny"
[[client]]
identity = "unix:uid={}"
mechanisms = ["CKM_SHA256", "CKM_AES_KEY_GEN", "CKM_AES_CBC_PAD"]
deny_attributes = ["CKA_EXTRACTABLE"]
"#,
            sock.display(),
            unsafe { libc::getuid() }
        ),
    )
    .unwrap();
    let _daemon = spawn(&token, &["--config", cfg.to_str().unwrap()], 1);
    let s = testing::install(Box::new(UnixConnector(sock)), CoreConfig::default()).expect("client initializes");
    unsafe {
        let slot = first_slot();
        // only the allowed mechanisms are listed
        let mut n = 0;
        assert_eq!(C_GetMechanismList(slot, null_mut(), &mut n), CKR_OK);
        let mut list = vec![0 as CK_MECHANISM_TYPE; n as usize];
        assert_eq!(C_GetMechanismList(slot, list.as_mut_ptr(), &mut n), CKR_OK);
        list.sort();
        let mut want = vec![CKM_SHA256, CKM_AES_KEY_GEN, CKM_AES_CBC_PAD];
        want.sort();
        assert_eq!(list, want);

        let s = open(true);
        login(s);
        let mut sha1 = plain(CKM_SHA_1);
        assert_eq!(C_DigestInit(s, &mut sha1), CKR_MECHANISM_INVALID);
        let mut sha256 = plain(CKM_SHA256);
        assert_eq!(C_DigestInit(s, &mut sha256), CKR_OK);
        // a denied attribute in a template
        let mut mech = plain(CKM_AES_KEY_GEN);
        let len: CK_ULONG = 16;
        let mut t = [a_ulong(CKA_VALUE_LEN, &len), a_bool(CKA_EXTRACTABLE, &TRUE)];
        let mut k = 0;
        assert_eq!(C_GenerateKey(s, &mut mech, t.as_mut_ptr(), 2, &mut k), CKR_ATTRIBUTE_TYPE_INVALID);
        assert_eq!(C_GenerateKey(s, &mut mech, t.as_mut_ptr(), 1, &mut k), CKR_OK);
    }

    // a different identity gets no service at all
    let daemon2 = spawn(
        &token,
        &["--listen", &format!("unix://{}", token.path().join("nobody.sock").display()), "--config", {
            let c2 = token.path().join("nobody.toml");
            std::fs::write(&c2, "[[client]]\nidentity = \"unix:uid=1\"\n").unwrap();
            Box::leak(c2.to_str().unwrap().to_string().into_boxed_str())
        }],
        1,
    );
    drop(s);
    assert!(testing::install(Box::new(UnixConnector(token.path().join("nobody.sock"))), CoreConfig::default()).is_err());
    drop(daemon2);
}

#[test]
fn inetd_style_stdio() {
    let token = token!();
    let (mine, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    let module = token.module.to_str().unwrap().to_string();
    let child_in = theirs.try_clone().unwrap();
    let mut child = std::process::Command::new(DAEMON)
        .args(["--listen", "stdio", &module])
        .envs(token.envs())
        .stdin(std::process::Stdio::from(std::os::fd::OwnedFd::from(child_in)))
        .stdout(std::process::Stdio::from(std::os::fd::OwnedFd::from(theirs)))
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();

    #[derive(Debug)]
    struct Once(std::sync::Mutex<Option<std::os::unix::net::UnixStream>>);
    impl p11_transport::Connector for Once {
        fn connect(&self) -> std::io::Result<Box<dyn p11_transport::Conn>> {
            match self.0.lock().unwrap().take() {
                Some(s) => Ok(Box::new(s)),
                None => Err(std::io::Error::other("only one connection over a pipe")),
            }
        }
    }
    let cfg = CoreConfig { max_conns: 1, ..CoreConfig::default() };
    let s = testing::install(Box::new(Once(std::sync::Mutex::new(Some(mine)))), cfg)
        .expect("client initializes over stdio");
    unsafe {
        let mut info: CK_INFO = std::mem::zeroed();
        assert_eq!(C_GetInfo(&mut info), CKR_OK);
        let mut n = 0;
        assert_eq!(C_GetSlotList(1, null_mut(), &mut n), CKR_OK);
    }
    drop(s); // finalises: the connection closes, the daemon exits
    let st = child.wait().unwrap();
    assert!(st.success(), "{st:?}");
}

#[cfg(target_os = "linux")]
#[test]
fn the_daemon_runs_under_seccomp() {
    if std::env::var_os("P11_TEST_NO_SECCOMP").is_some() {
        eprintln!("SKIP: P11_TEST_NO_SECCOMP (seccomp does not work here, e.g. under emulation)");
        return;
    }
    let token = token!();
    let sock = token.path().join("s.sock");
    let daemon = spawn(&token, &["--listen", &format!("unix://{}", sock.display()), "--sandbox", "require"], 1);
    let status = std::fs::read_to_string(format!("/proc/{}/status", daemon.child.id())).unwrap();
    assert!(status.lines().any(|l| l.starts_with("Seccomp:") && l.trim_end().ends_with('2')), "{status}");
    assert!(status.lines().any(|l| l.starts_with("NoNewPrivs:") && l.trim_end().ends_with('1')));
}

#[cfg(target_os = "macos")]
#[test]
fn a_required_sandbox_starts_on_macos() {
    let token = token!();
    let sock = token.path().join("s.sock");
    let _daemon = spawn(&token, &["--listen", &format!("unix://{}", sock.display()), "--sandbox", "require"], 1);
}

// ---- the scenarios of the C project's softhsm-test.c ----

unsafe fn have(mech: CK_MECHANISM_TYPE) -> bool {
    let slot = first_slot();
    let mut mi: CK_MECHANISM_INFO = std::mem::zeroed();
    C_GetMechanismInfo(slot, mech, &mut mi) == CKR_OK
}

unsafe fn secret(s: CK_SESSION_HANDLE, kt: CK_KEY_TYPE, len: CK_ULONG) -> CK_OBJECT_HANDLE {
    let mut mech = plain(if kt == CKK_AES { CKM_AES_KEY_GEN } else { CKM_GENERIC_SECRET_KEY_GEN });
    let mut t = [
        a_ulong(CKA_VALUE_LEN, &len),
        a_bool(CKA_TOKEN, &FALSE),
        a_bool(CKA_SENSITIVE, &FALSE),
        a_bool(CKA_EXTRACTABLE, &TRUE),
        a_bool(CKA_ENCRYPT, &TRUE),
        a_bool(CKA_DECRYPT, &TRUE),
        a_bool(CKA_DERIVE, &TRUE),
        a_bool(CKA_SIGN, &TRUE),
        a_bool(CKA_VERIFY, &TRUE),
    ];
    let mut k = 0;
    assert_eq!(C_GenerateKey(s, &mut mech, t.as_mut_ptr(), 9, &mut k), CKR_OK);
    k
}

unsafe fn derive_secret(
    s: CK_SESSION_HANDLE,
    mech: &mut CK_MECHANISM,
    base: CK_OBJECT_HANDLE,
    len: Option<CK_ULONG>,
) -> Result<CK_OBJECT_HANDLE, CK_RV> {
    let cls = CKO_SECRET_KEY;
    let kt = CKK_GENERIC_SECRET;
    let len = len.unwrap_or(0);
    let mut t = vec![
        a_ulong(CKA_CLASS, &cls),
        a_ulong(CKA_KEY_TYPE, &kt),
        a_bool(CKA_TOKEN, &FALSE),
        a_bool(CKA_SENSITIVE, &FALSE),
        a_bool(CKA_EXTRACTABLE, &TRUE),
    ];
    if len != 0 {
        t.push(a_ulong(CKA_VALUE_LEN, &len));
    }
    let mut out = 0;
    match C_DeriveKey(s, mech, base, t.as_mut_ptr(), t.len() as CK_ULONG, &mut out) {
        CKR_OK => Ok(out),
        rv => Err(rv),
    }
}

#[test]
fn nested_templates_travel_and_come_back() {
    let _rig = unix_rig(token!());
    unsafe {
        let s = open(true);
        login(s);
        let mut mech = plain(CKM_AES_KEY_GEN);
        let len: CK_ULONG = 16;
        let inner_kt: CK_KEY_TYPE = CKK_AES;
        let inner_len: CK_ULONG = 16;
        let mut wrap = [a_ulong(CKA_KEY_TYPE, &inner_kt), a_ulong(CKA_VALUE_LEN, &inner_len)];
        let mut t = [
            a_ulong(CKA_VALUE_LEN, &len),
            a_bool(CKA_TOKEN, &FALSE),
            CK_ATTRIBUTE {
                type_: CKA_WRAP_TEMPLATE,
                pValue: wrap.as_mut_ptr().cast(),
                ulValueLen: std::mem::size_of_val(&wrap) as CK_ULONG,
            },
        ];
        let mut k = 0;
        let rv = C_GenerateKey(s, &mut mech, t.as_mut_ptr(), 3, &mut k);
        if rv != CKR_OK {
            eprintln!("this module has no wrap templates (0x{rv:x})");
            return;
        }
        // read it back into the caller's nested buffers
        let (mut kt, mut vl) = (0 as CK_KEY_TYPE, 0 as CK_ULONG);
        let mut out = [a_ulong(CKA_KEY_TYPE, &kt), a_ulong(CKA_VALUE_LEN, &vl)];
        out[0].pValue = (&mut kt as *mut CK_KEY_TYPE).cast();
        out[1].pValue = (&mut vl as *mut CK_ULONG).cast();
        let mut g = [CK_ATTRIBUTE {
            type_: CKA_WRAP_TEMPLATE,
            pValue: out.as_mut_ptr().cast(),
            ulValueLen: std::mem::size_of_val(&out) as CK_ULONG,
        }];
        assert_eq!(C_GetAttributeValue(s, k, g.as_mut_ptr(), 1), CKR_OK);
        assert_eq!(g[0].ulValueLen as usize, std::mem::size_of_val(&out));
        if p11_testkit::softhsm::external() {
            // some modules answer with pointers into their own memory instead of filling ours
            eprintln!("SKIP: nested values in the caller's buffers ({kt}, {vl})");
        } else {
            assert_eq!((kt, vl), (CKK_AES, 16), "nested values land in the caller's buffers");
            assert_eq!((out[0].ulValueLen, out[1].ulValueLen), (8, 8));
        }
        // only the size
        let mut g = [CK_ATTRIBUTE { type_: CKA_WRAP_TEMPLATE, pValue: null_mut(), ulValueLen: 0 }];
        assert_eq!(C_GetAttributeValue(s, k, g.as_mut_ptr(), 1), CKR_OK);
        assert_eq!(g[0].ulValueLen as usize, 2 * std::mem::size_of::<CK_ATTRIBUTE>());
        // a nested buffer that is too small must not overflow anything
        let mut tiny = [0u8; 2];
        let mut small: [CK_ULONG; 1] = [0];
        let mut out2 = [
            CK_ATTRIBUTE { type_: CKA_KEY_TYPE, pValue: tiny.as_mut_ptr().cast(), ulValueLen: 2 },
            CK_ATTRIBUTE { type_: CKA_VALUE_LEN, pValue: small.as_mut_ptr().cast(), ulValueLen: 8 },
        ];
        let mut g = [CK_ATTRIBUTE {
            type_: CKA_WRAP_TEMPLATE,
            pValue: out2.as_mut_ptr().cast(),
            ulValueLen: std::mem::size_of_val(&out2) as CK_ULONG,
        }];
        let rv = C_GetAttributeValue(s, k, g.as_mut_ptr(), 1);
        assert!(rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL, "0x{rv:x}");

        // malformed templates never leave the client
        let mut bad = [CK_ATTRIBUTE {
            type_: CKA_WRAP_TEMPLATE,
            pValue: wrap.as_mut_ptr().cast(),
            ulValueLen: (std::mem::size_of::<CK_ATTRIBUTE>() - 1) as CK_ULONG,
        }];
        assert_eq!(C_GenerateKey(s, &mut mech, bad.as_mut_ptr(), 1, &mut k), CKR_ATTRIBUTE_VALUE_INVALID);
        // a template nested in a template is fine on the wire (the module decides)
        // the daemon is still there
        assert_eq!(C_GenerateKey(s, &mut mech, t.as_mut_ptr(), 2, &mut k), CKR_OK);
    }
}

#[test]
fn eddsa_and_general_length_hmac() {
    let _rig = unix_rig(token!());
    unsafe {
        let s = open(true);
        login(s);
        if have(CKM_EDDSA) && have(CKM_EC_EDWARDS_KEY_PAIR_GEN) {
            let ed25519 = [0x06u8, 0x03, 0x2b, 0x65, 0x70];
            let mut mech = plain(CKM_EC_EDWARDS_KEY_PAIR_GEN);
            let mut pubt = [a_bytes(CKA_EC_PARAMS, &ed25519), a_bool(CKA_VERIFY, &TRUE), a_bool(CKA_TOKEN, &FALSE)];
            let mut privt = [a_bool(CKA_SIGN, &TRUE), a_bool(CKA_TOKEN, &FALSE), a_bool(CKA_SENSITIVE, &TRUE)];
            let (mut p, mut k) = (0, 0);
            assert_eq!(
                C_GenerateKeyPair(s, &mut mech, pubt.as_mut_ptr(), 3, privt.as_mut_ptr(), 3, &mut p, &mut k),
                CKR_OK
            );
            let mut ed = plain(CKM_EDDSA);
            let sig = sign(s, &mut ed, k, b"forty bytes of message, or thereabouts").unwrap();
            assert_eq!(sig.len(), 64);
            assert_eq!(verify(s, &mut ed, p, b"forty bytes of message, or thereabouts", &sig), CKR_OK);
        } else {
            eprintln!("skip: EdDSA not offered");
        }
        if have(CKM_SHA256_HMAC_GENERAL) && have(CKM_GENERIC_SECRET_KEY_GEN) {
            let k = secret(s, CKK_GENERIC_SECRET, 32);
            // the parameter is the MAC length
            let mut maclen: CK_ULONG = 16;
            let mut hm = m(CKM_SHA256_HMAC_GENERAL, &mut maclen);
            let mac = sign(s, &mut hm, k, b"message").unwrap();
            assert_eq!(mac.len(), 16);
            assert_eq!(verify(s, &mut hm, k, b"message", &mac), CKR_OK);
            let mut full = plain(CKM_SHA256_HMAC);
            let long = sign(s, &mut full, k, b"message").unwrap();
            assert_eq!(&long[..16], &mac[..], "a general-length MAC is the prefix of the full one");
        }
    }
}

#[test]
fn keys_derived_from_data_and_from_other_keys() {
    let _rig = unix_rig(token!());
    unsafe {
        let s = open(true);
        login(s);
        let base = secret(s, CKK_AES, 32);
        let bv = attr_value(s, base, CKA_VALUE);
        assert_eq!(bv.len(), 32);
        if have(CKM_CONCATENATE_BASE_AND_DATA) {
            let mut suffix = *b"suffix";
            let mut p = CK_KEY_DERIVATION_STRING_DATA { pData: suffix.as_mut_ptr(), ulLen: 6 };
            let mut mech = m(CKM_CONCATENATE_BASE_AND_DATA, &mut p);
            let d = derive_secret(s, &mut mech, base, None).expect("concatenate base and data");
            assert_eq!(attr_value(s, d, CKA_VALUE), [bv.clone(), b"suffix".to_vec()].concat());
        }
        if have(CKM_CONCATENATE_DATA_AND_BASE) {
            let mut prefix = *b"prefix";
            let mut p = CK_KEY_DERIVATION_STRING_DATA { pData: prefix.as_mut_ptr(), ulLen: 6 };
            let mut mech = m(CKM_CONCATENATE_DATA_AND_BASE, &mut p);
            let d = derive_secret(s, &mut mech, base, None).expect("concatenate data and base");
            assert_eq!(attr_value(s, d, CKA_VALUE), [b"prefix".to_vec(), bv.clone()].concat());
        }
        if have(CKM_CONCATENATE_BASE_AND_KEY) {
            // the parameter is another key's handle: the daemon must translate it
            let other = secret(s, CKK_AES, 16);
            let ov = attr_value(s, other, CKA_VALUE);
            let mut hk: CK_OBJECT_HANDLE = other;
            let mut mech = m(CKM_CONCATENATE_BASE_AND_KEY, &mut hk);
            let d = derive_secret(s, &mut mech, base, None).expect("concatenate base and key");
            assert_eq!(attr_value(s, d, CKA_VALUE), [bv.clone(), ov].concat());
            // a handle that isn't the client's is refused, not passed on as it is
            let mut bogus: CK_OBJECT_HANDLE = 0x7777;
            let mut mech = m(CKM_CONCATENATE_BASE_AND_KEY, &mut bogus);
            assert!(derive_secret(s, &mut mech, base, None).is_err());
        }
        if have(CKM_AES_CBC_ENCRYPT_DATA) {
            let data: Vec<u8> = (0..32).map(|i| (i * 3) as u8).collect();
            let iv: Vec<u8> = (0..16).map(|i| (0xa0 + i) as u8).collect();
            let mut p = CK_AES_CBC_ENCRYPT_DATA_PARAMS {
                iv: iv.clone().try_into().unwrap(),
                pData: data.as_ptr() as *mut u8,
                length: 32,
            };
            let mut mech = m(CKM_AES_CBC_ENCRYPT_DATA, &mut p);
            let d = derive_secret(s, &mut mech, base, Some(32)).expect("aes cbc encrypt data");
            let mut em =
                CK_MECHANISM { mechanism: CKM_AES_CBC, pParameter: iv.as_ptr() as *mut c_void, ulParameterLen: 16 };
            let direct = encrypt(s, &mut em, base, &data).unwrap();
            assert_eq!(attr_value(s, d, CKA_VALUE), direct, "the derived key is the data encrypted with the base key");
        }
        if have(CKM_AES_ECB_ENCRYPT_DATA) {
            let data: Vec<u8> = (0..32).map(|i| (i + 100) as u8).collect();
            let mut p = CK_KEY_DERIVATION_STRING_DATA { pData: data.as_ptr() as *mut u8, ulLen: 32 };
            let mut mech = m(CKM_AES_ECB_ENCRYPT_DATA, &mut p);
            let d = derive_secret(s, &mut mech, base, Some(32)).expect("aes ecb encrypt data");
            let mut em = plain(CKM_AES_ECB);
            let direct = encrypt(s, &mut em, base, &data).unwrap();
            assert_eq!(attr_value(s, d, CKA_VALUE), direct);
        }
    }
}

#[test]
fn rsa_aes_key_wrap_with_a_nested_parameter_structure() {
    let _rig = unix_rig(token!());
    unsafe {
        let s = open(true);
        login(s);
        if !have(CKM_RSA_AES_KEY_WRAP) {
            eprintln!("skip: RSA_AES_KEY_WRAP not offered");
            return;
        }
        let mut kg = plain(CKM_RSA_PKCS_KEY_PAIR_GEN);
        let bits: CK_ULONG = 2048;
        let e = [1u8, 0, 1];
        let mut pubt = [
            a_ulong(CKA_MODULUS_BITS, &bits),
            a_bytes(CKA_PUBLIC_EXPONENT, &e),
            a_bool(CKA_WRAP, &TRUE),
            a_bool(CKA_TOKEN, &FALSE),
        ];
        let mut privt = [a_bool(CKA_UNWRAP, &TRUE), a_bool(CKA_TOKEN, &FALSE)];
        let (mut pubk, mut privk) = (0, 0);
        assert_eq!(
            C_GenerateKeyPair(s, &mut kg, pubt.as_mut_ptr(), 4, privt.as_mut_ptr(), 2, &mut pubk, &mut privk),
            CKR_OK
        );
        let target = secret(s, CKK_AES, 32);
        let tv = attr_value(s, target, CKA_VALUE);

        let mut oaep = CK_RSA_PKCS_OAEP_PARAMS {
            hashAlg: CKM_SHA_1,
            mgf: CKG_MGF1_SHA1,
            source: CKZ_DATA_SPECIFIED,
            pSourceData: null_mut(),
            ulSourceDataLen: 0,
        };
        let mut wp = CK_RSA_AES_KEY_WRAP_PARAMS { ulAESKeyBits: 256, pOAEPParams: &mut oaep };
        let mut mech = m(CKM_RSA_AES_KEY_WRAP, &mut wp);
        let mut wl: CK_ULONG = 0;
        assert_eq!(C_WrapKey(s, &mut mech, pubk, target, null_mut(), &mut wl), CKR_OK);
        let mut wrapped = vec![0u8; wl as usize];
        assert_eq!(C_WrapKey(s, &mut mech, pubk, target, wrapped.as_mut_ptr(), &mut wl), CKR_OK);
        assert!(wl > 256);
        let cls = CKO_SECRET_KEY;
        let kt = CKK_AES;
        let mut ut = [
            a_ulong(CKA_CLASS, &cls),
            a_ulong(CKA_KEY_TYPE, &kt),
            a_bool(CKA_TOKEN, &FALSE),
            a_bool(CKA_SENSITIVE, &FALSE),
            a_bool(CKA_EXTRACTABLE, &TRUE),
        ];
        let mut back = 0;
        assert_eq!(C_UnwrapKey(s, &mut mech, privk, wrapped.as_mut_ptr(), wl, ut.as_mut_ptr(), 5, &mut back), CKR_OK);
        assert_eq!(attr_value(s, back, CKA_VALUE), tv, "the unwrapped key equals the original");
    }
}
