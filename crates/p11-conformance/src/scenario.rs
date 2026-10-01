//! The scripted scenario. Each step prints a line that depends only on what a
//! correct PKCS#11 module answers, so the same script run against SoftHSM
//! directly, against the Rust proxy and against the C proxy can be compared.

use crate::{rvn, Module, Transcript};
use p11_types::*;
use std::ffi::c_void;
use std::ptr::null_mut;

pub const USER_PIN: &str = "1234";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn m<T>(mech: CK_MECHANISM_TYPE, p: &mut T) -> CK_MECHANISM {
    CK_MECHANISM {
        mechanism: mech,
        pParameter: p as *mut T as *mut c_void,
        ulParameterLen: core::mem::size_of::<T>() as CK_ULONG,
    }
}
fn plain(mech: CK_MECHANISM_TYPE) -> CK_MECHANISM {
    CK_MECHANISM { mechanism: mech, pParameter: null_mut(), ulParameterLen: 0 }
}
fn a_bytes(ty: CK_ATTRIBUTE_TYPE, v: &[u8]) -> CK_ATTRIBUTE {
    CK_ATTRIBUTE { type_: ty, pValue: v.as_ptr() as *mut c_void, ulValueLen: v.len() as CK_ULONG }
}
fn a_ulong(ty: CK_ATTRIBUTE_TYPE, v: &CK_ULONG) -> CK_ATTRIBUTE {
    CK_ATTRIBUTE { type_: ty, pValue: v as *const CK_ULONG as *mut c_void, ulValueLen: 8 }
}
static YES: CK_BBOOL = 1;
static NO: CK_BBOOL = 0;
fn a_bool(ty: CK_ATTRIBUTE_TYPE, v: bool) -> CK_ATTRIBUTE {
    CK_ATTRIBUTE { type_: ty, pValue: (if v { &YES } else { &NO }) as *const CK_BBOOL as *mut c_void, ulValueLen: 1 }
}

struct S<'a> {
    m: &'a Module,
    t: Transcript,
}

macro_rules! c {
    ($s:expr, $f:ident($($a:expr),*)) => {
        ($s.m.f.$f.expect(stringify!($f)))($($a),*)
    };
}

/// A call that follows the two-call convention: ask for the length, then for the data.
unsafe fn out_call(mut f: impl FnMut(*mut u8, *mut CK_ULONG) -> CK_RV) -> Result<Vec<u8>, CK_RV> {
    let mut n: CK_ULONG = 0;
    let rv = f(null_mut(), &mut n);
    if rv != CKR_OK {
        return Err(rv);
    }
    let mut out = vec![0u8; n as usize];
    let rv = f(out.as_mut_ptr(), &mut n);
    if rv != CKR_OK {
        return Err(rv);
    }
    out.truncate(n as usize);
    Ok(out)
}

impl S<'_> {
    fn rv(&mut self, label: &str, rv: CK_RV) {
        self.t.line(label, rvn(rv));
    }

    unsafe fn open(&mut self, slot: CK_SLOT_ID, rw: bool) -> CK_SESSION_HANDLE {
        let mut h = 0;
        let flags = CKF_SERIAL_SESSION | if rw { CKF_RW_SESSION } else { 0 };
        let rv = c!(self, C_OpenSession(slot, flags, null_mut(), None, &mut h));
        assert_eq!(rv, CKR_OK);
        h
    }

    unsafe fn attr(
        &mut self,
        s: CK_SESSION_HANDLE,
        o: CK_OBJECT_HANDLE,
        ty: CK_ATTRIBUTE_TYPE,
    ) -> Result<Vec<u8>, CK_RV> {
        let mut q = [CK_ATTRIBUTE { type_: ty, pValue: null_mut(), ulValueLen: 0 }];
        let rv = c!(self, C_GetAttributeValue(s, o, q.as_mut_ptr(), 1));
        if rv != CKR_OK {
            return Err(rv);
        }
        let mut buf = vec![0u8; q[0].ulValueLen as usize];
        q[0].pValue = buf.as_mut_ptr().cast();
        let rv = c!(self, C_GetAttributeValue(s, o, q.as_mut_ptr(), 1));
        if rv != CKR_OK {
            return Err(rv);
        }
        buf.truncate(q[0].ulValueLen as usize);
        Ok(buf)
    }

    unsafe fn gen_aes(&mut self, s: CK_SESSION_HANDLE, extractable: bool, sensitive: bool) -> CK_OBJECT_HANDLE {
        let mut mech = plain(CKM_AES_KEY_GEN);
        let len: CK_ULONG = 16;
        let mut t = [
            a_ulong(CKA_VALUE_LEN, &len),
            a_bool(CKA_TOKEN, false),
            a_bool(CKA_ENCRYPT, true),
            a_bool(CKA_DECRYPT, true),
            a_bool(CKA_WRAP, true),
            a_bool(CKA_UNWRAP, true),
            a_bool(CKA_EXTRACTABLE, extractable),
            a_bool(CKA_SENSITIVE, sensitive),
        ];
        let mut k = 0;
        assert_eq!(c!(self, C_GenerateKey(s, &mut mech, t.as_mut_ptr(), 8, &mut k)), CKR_OK);
        k
    }
}

/// Run the scenario. The token must be initialised with user PIN `1234`.
pub fn run(module: &Module) -> Transcript {
    let mut s = S { m: module, t: Transcript::default() };
    // SAFETY: the script passes valid buffers to the module throughout.
    unsafe { script(&mut s) };
    s.t
}

unsafe fn script(s: &mut S) {
    // ---- before initialisation ----
    let mut info: CK_INFO = core::mem::zeroed();
    let rv = c!(s, C_GetInfo(&mut info));
    s.rv("get_info before initialize", rv);
    let mut n = 0;
    let rv = c!(s, C_GetSlotList(1, null_mut(), &mut n));
    s.rv("slot list before initialize", rv);
    let rv = c!(s, C_Finalize(null_mut()));
    s.rv("finalize before initialize", rv);

    // ---- initialise ----
    let rv = c!(s, C_Initialize(null_mut()));
    s.rv("initialize", rv);
    let rv = c!(s, C_Initialize(null_mut()));
    s.rv("initialize again", rv);
    let rv = c!(s, C_GetInfo(&mut info));
    s.rv("get_info", rv);
    s.t.line("info", format!("cryptoki {}.{}", info.cryptokiVersion.major, info.cryptokiVersion.minor));
    s.rv("get_info null", c!(s, C_GetInfo(null_mut())));

    // ---- slots and the two-call convention ----
    let mut n = 0;
    s.rv("slot list length", c!(s, C_GetSlotList(1, null_mut(), &mut n)));
    let present = n;
    s.t.line("slots with a token", format!("{}", present >= 1));
    if n == 0 {
        s.t.line("no slots", "stopping");
        return;
    }
    let mut slots = vec![0 as CK_SLOT_ID; n as usize];
    let mut cap = n;
    s.rv("slot list", c!(s, C_GetSlotList(1, slots.as_mut_ptr(), &mut cap)));
    let mut one = [0 as CK_SLOT_ID; 1];
    let mut cap1 = 0;
    let rv = c!(s, C_GetSlotList(1, one.as_mut_ptr(), &mut cap1));
    s.t.line("slot list too small", format!("{} needs {}", rvn(rv), cap1 == present));
    s.rv("slot list null count", c!(s, C_GetSlotList(1, null_mut(), null_mut())));
    // Modules with an admin slot first need to say which slot holds the test token.
    let index = ["P11_SCENARIO_SLOT", "P11_TEST_SLOT"]
        .iter()
        .find_map(|k| std::env::var(k).ok()?.parse::<usize>().ok())
        .unwrap_or(0);
    let slot = slots[index.min(slots.len() - 1)];

    let mut si: CK_SLOT_INFO = core::mem::zeroed();
    s.rv("slot info", c!(s, C_GetSlotInfo(slot, &mut si)));
    s.t.line("slot has token", format!("{}", si.flags & CKF_TOKEN_PRESENT != 0));
    s.rv("slot info bad slot", c!(s, C_GetSlotInfo(0xdead_beef, &mut si)));
    let mut ti: CK_TOKEN_INFO = core::mem::zeroed();
    s.rv("token info", c!(s, C_GetTokenInfo(slot, &mut ti)));
    s.t.line("token label", String::from_utf8_lossy(&ti.label).trim().to_string());
    s.t.line(
        "token flags",
        format!(
            "initialized {} login-required {}",
            ti.flags & CKF_TOKEN_INITIALIZED != 0,
            ti.flags & CKF_LOGIN_REQUIRED != 0
        ),
    );
    s.rv("token info null", c!(s, C_GetTokenInfo(slot, null_mut())));

    // mechanisms
    let mut nm = 0;
    s.rv("mechanism list length", c!(s, C_GetMechanismList(slot, null_mut(), &mut nm)));
    let mut ml = vec![0 as CK_MECHANISM_TYPE; nm as usize];
    let mut cap = nm;
    s.rv("mechanism list", c!(s, C_GetMechanismList(slot, ml.as_mut_ptr(), &mut cap)));
    for (name, mech) in [
        ("SHA256", CKM_SHA256),
        ("AES_GCM", CKM_AES_GCM),
        ("RSA_PKCS", CKM_RSA_PKCS),
        ("AES_KEY_GEN", CKM_AES_KEY_GEN),
        ("EC_KEY_PAIR_GEN", CKM_EC_KEY_PAIR_GEN),
    ] {
        s.t.line("mechanism listed", format!("{name} {}", ml.contains(&mech)));
    }
    let mut mi: CK_MECHANISM_INFO = core::mem::zeroed();
    s.rv("mechanism info", c!(s, C_GetMechanismInfo(slot, CKM_AES_KEY_GEN, &mut mi)));
    s.t.line("aes keygen sizes", format!("{}..{}", mi.ulMinKeySize, mi.ulMaxKeySize));
    s.rv("mechanism info invalid", c!(s, C_GetMechanismInfo(slot, 0x7777_0001, &mut mi)));

    // ---- sessions and login ----
    let ro = s.open(slot, false);
    let rw = s.open(slot, true);
    let mut si2: CK_SESSION_INFO = core::mem::zeroed();
    s.rv("session info ro", c!(s, C_GetSessionInfo(ro, &mut si2)));
    s.t.line("ro state", format!("{}", si2.state == CKS_RO_PUBLIC_SESSION));
    s.rv("session info rw", c!(s, C_GetSessionInfo(rw, &mut si2)));
    s.t.line("rw state", format!("{}", si2.state == CKS_RW_PUBLIC_SESSION));
    s.rv("session info bad handle", c!(s, C_GetSessionInfo(0xdead_beef, &mut si2)));
    let mut bad = *b"wrong";
    s.rv("login wrong pin", c!(s, C_Login(rw, CKU_USER, bad.as_mut_ptr(), 5)));
    let mut pin = USER_PIN.as_bytes().to_vec();
    s.rv("login", c!(s, C_Login(rw, CKU_USER, pin.as_mut_ptr(), pin.len() as CK_ULONG)));
    s.rv("login again", c!(s, C_Login(rw, CKU_USER, pin.as_mut_ptr(), pin.len() as CK_ULONG)));
    s.rv("session info after login", c!(s, C_GetSessionInfo(ro, &mut si2)));
    s.t.line("ro state after login", format!("{}", si2.state == CKS_RO_USER_FUNCTIONS));
    s.rv("login bad handle", c!(s, C_Login(0xdead_beef, CKU_USER, pin.as_mut_ptr(), 4)));
    s.rv("login null pin", c!(s, C_Login(rw, CKU_USER, null_mut(), 4)));

    // ---- objects ----
    let class = CKO_DATA;
    let mut t = [
        a_ulong(CKA_CLASS, &class),
        a_bool(CKA_TOKEN, false),
        a_bytes(CKA_LABEL, b"scenario"),
        a_bytes(CKA_VALUE, b"hello scenario"),
    ];
    let mut obj = 0;
    s.rv("create object", c!(s, C_CreateObject(rw, t.as_mut_ptr(), 4, &mut obj)));
    s.rv("create object null template", c!(s, C_CreateObject(rw, null_mut(), 2, &mut obj)));
    s.rv("create object bad session", c!(s, C_CreateObject(0xdead_beef, t.as_mut_ptr(), 4, &mut obj)));
    let v = s.attr(rw, obj, CKA_VALUE);
    s.t.line("value", format!("{:?}", v.map(|b| String::from_utf8_lossy(&b).to_string())));
    let v = s.attr(rw, obj, CKA_LABEL);
    s.t.line("label", format!("{:?}", v.map(|b| String::from_utf8_lossy(&b).to_string())));
    let v = s.attr(rw, obj, CKA_CLASS);
    s.t.line("class", format!("{:?}", v.map(|b| CK_ULONG::from_ne_bytes(b.try_into().unwrap()) == CKO_DATA)));
    // attribute semantics: unknown attribute, too small a buffer, mixed results
    let mut q = [CK_ATTRIBUTE { type_: CKA_MODULUS, pValue: null_mut(), ulValueLen: 0 }];
    let rv = c!(s, C_GetAttributeValue(rw, obj, q.as_mut_ptr(), 1));
    s.t.line(
        "unknown attribute",
        format!("{} len_unavailable {}", rvn(rv), q[0].ulValueLen == CK_UNAVAILABLE_INFORMATION),
    );
    let mut small = [0u8; 2];
    let mut q = [CK_ATTRIBUTE { type_: CKA_VALUE, pValue: small.as_mut_ptr().cast(), ulValueLen: 2 }];
    let rv = c!(s, C_GetAttributeValue(rw, obj, q.as_mut_ptr(), 1));
    s.t.line(
        "attribute buffer too small",
        format!("{} len_unavailable {}", rvn(rv), q[0].ulValueLen == CK_UNAVAILABLE_INFORMATION),
    );
    let mut lens = [
        CK_ATTRIBUTE { type_: CKA_LABEL, pValue: null_mut(), ulValueLen: 0 },
        CK_ATTRIBUTE { type_: CKA_VALUE, pValue: null_mut(), ulValueLen: 0 },
    ];
    let rv = c!(s, C_GetAttributeValue(rw, obj, lens.as_mut_ptr(), 2));
    s.t.line("attribute lengths", format!("{} {} {}", rvn(rv), lens[0].ulValueLen, lens[1].ulValueLen));
    s.rv("get attribute bad object", c!(s, C_GetAttributeValue(rw, 0xdead_beef, lens.as_mut_ptr(), 2)));
    let mut newlabel = [a_bytes(CKA_LABEL, b"renamed!")];
    s.rv("set attribute", c!(s, C_SetAttributeValue(rw, obj, newlabel.as_mut_ptr(), 1)));
    let v = s.attr(rw, obj, CKA_LABEL);
    s.t.line("label after set", format!("{:?}", v.map(|b| String::from_utf8_lossy(&b).to_string())));
    let mut size = 0;
    let rv = c!(s, C_GetObjectSize(rw, obj, &mut size));
    s.t.line("object size", format!("{} nonzero {}", rvn(rv), size > 0));
    let mut copy = 0;
    let mut cpt = [a_bytes(CKA_LABEL, b"copy")];
    s.rv("copy object", c!(s, C_CopyObject(rw, obj, cpt.as_mut_ptr(), 1, &mut copy)));
    s.t.line("copy is another object", format!("{}", copy != obj && copy != 0));

    // search, with paging
    let mut more = Vec::new();
    for i in 0..3u8 {
        let lab = format!("page-{i}");
        let mut tt = [
            a_ulong(CKA_CLASS, &class),
            a_bool(CKA_TOKEN, false),
            a_bytes(CKA_LABEL, lab.as_bytes()),
            a_bytes(CKA_APPLICATION, b"paging"),
        ];
        let mut o = 0;
        assert_eq!(c!(s, C_CreateObject(rw, tt.as_mut_ptr(), 4, &mut o)), CKR_OK);
        more.push(o);
    }
    let mut find = [a_bytes(CKA_APPLICATION, b"paging")];
    s.rv("find init", c!(s, C_FindObjectsInit(rw, find.as_mut_ptr(), 1)));
    s.rv("find init again", c!(s, C_FindObjectsInit(rw, find.as_mut_ptr(), 1)));
    let mut counts = Vec::new();
    for _ in 0..3 {
        let mut got = [0 as CK_OBJECT_HANDLE; 2];
        let mut ng = 0;
        let rv = c!(s, C_FindObjects(rw, got.as_mut_ptr(), 2, &mut ng));
        counts.push(format!("{}:{}", rvn(rv), ng));
    }
    s.t.line("find pages", counts.join(" "));
    s.rv("find final", c!(s, C_FindObjectsFinal(rw)));
    s.rv("find final again", c!(s, C_FindObjectsFinal(rw)));
    let mut got = [0 as CK_OBJECT_HANDLE; 1];
    let mut ng = 0;
    s.rv("find objects without init", c!(s, C_FindObjects(rw, got.as_mut_ptr(), 1, &mut ng)));

    s.rv("destroy object", c!(s, C_DestroyObject(rw, obj)));
    s.rv("destroy object again", c!(s, C_DestroyObject(rw, obj)));
    for o in more {
        c!(s, C_DestroyObject(rw, o));
    }

    // ---- keys, sensitivity and cipher operations ----
    let sens = s.gen_aes(rw, false, true);
    let v = s.attr(rw, sens, CKA_VALUE);
    s.t.line("sensitive key value", format!("{:?}", v.map(|b| b.len()).map_err(rvn)));
    let mut q = [CK_ATTRIBUTE { type_: CKA_VALUE, pValue: null_mut(), ulValueLen: 0 }];
    let rv = c!(s, C_GetAttributeValue(rw, sens, q.as_mut_ptr(), 1));
    s.t.line(
        "sensitive attribute",
        format!("{} len_unavailable {}", rvn(rv), q[0].ulValueLen == CK_UNAVAILABLE_INFORMATION),
    );
    let _random_key = s.gen_aes(rw, true, false);
    // a key with a known value, so ciphertexts can be compared
    let aes_val = *b"0123456789abcdef";
    let acls = CKO_SECRET_KEY;
    let akt = CKK_AES;
    let mut at = [
        a_ulong(CKA_CLASS, &acls),
        a_ulong(CKA_KEY_TYPE, &akt),
        a_bool(CKA_TOKEN, false),
        a_bool(CKA_ENCRYPT, true),
        a_bool(CKA_DECRYPT, true),
        a_bool(CKA_WRAP, true),
        a_bool(CKA_EXTRACTABLE, true),
        a_bool(CKA_SENSITIVE, false),
        a_bytes(CKA_VALUE, &aes_val),
    ];
    let mut key = 0;
    s.rv("create aes key", c!(s, C_CreateObject(rw, at.as_mut_ptr(), 9, &mut key)));
    let kv = s.attr(rw, key, CKA_VALUE).unwrap_or_default();
    s.t.line("extractable key value", hex(&kv));

    // no operation active yet
    let mut data = *b"0123456789abcdef-hello";
    let mut o = [0u8; 64];
    let mut on: CK_ULONG = 64;
    s.rv("encrypt without init", c!(s, C_Encrypt(rw, data.as_mut_ptr(), 22, o.as_mut_ptr(), &mut on)));
    let mut cbc_iv = [3u8; 16];
    let mut cbc =
        CK_MECHANISM { mechanism: CKM_AES_CBC_PAD, pParameter: cbc_iv.as_mut_ptr().cast(), ulParameterLen: 16 };
    s.rv("encrypt init", c!(s, C_EncryptInit(rw, &mut cbc, key)));
    s.rv("encrypt init while active", c!(s, C_EncryptInit(rw, &mut cbc, key)));
    let mut on: CK_ULONG = 0;
    s.rv("encrypt length", c!(s, C_Encrypt(rw, data.as_mut_ptr(), 22, null_mut(), &mut on)));
    s.t.line("cbc-pad length", format!("{on}"));
    let mut small = [0u8; 4];
    let mut sn: CK_ULONG = 4;
    let rv = c!(s, C_Encrypt(rw, data.as_mut_ptr(), 22, small.as_mut_ptr(), &mut sn));
    s.t.line("encrypt too small", format!("{} needs {}", rvn(rv), sn));
    let mut ct = vec![0u8; on as usize];
    let mut cn = on;
    s.rv("encrypt", c!(s, C_Encrypt(rw, data.as_mut_ptr(), 22, ct.as_mut_ptr(), &mut cn)));
    ct.truncate(cn as usize);
    s.t.line("cbc ciphertext", hex(&ct));
    s.rv("decrypt init", c!(s, C_DecryptInit(rw, &mut cbc, key)));
    let mut pt = vec![0u8; ct.len()];
    let mut pn = pt.len() as CK_ULONG;
    s.rv("decrypt", c!(s, C_Decrypt(rw, ct.as_mut_ptr(), ct.len() as CK_ULONG, pt.as_mut_ptr(), &mut pn)));
    s.t.line("roundtrip", format!("{}", &pt[..pn as usize] == &data[..]));
    // multi-part
    s.rv("encrypt init 2", c!(s, C_EncryptInit(rw, &mut cbc, key)));
    let mut part = vec![0u8; 64];
    let mut total = Vec::new();
    for chunk in data.chunks(10) {
        let mut pn: CK_ULONG = 64;
        let rv =
            c!(s, C_EncryptUpdate(rw, chunk.as_ptr() as *mut u8, chunk.len() as CK_ULONG, part.as_mut_ptr(), &mut pn));
        assert_eq!(rv, CKR_OK);
        total.extend_from_slice(&part[..pn as usize]);
    }
    let mut pn: CK_ULONG = 64;
    s.rv("encrypt final", c!(s, C_EncryptFinal(rw, part.as_mut_ptr(), &mut pn)));
    total.extend_from_slice(&part[..pn as usize]);
    s.t.line("multipart equals single", format!("{}", total == ct));

    // GCM
    let mut iv = *b"unique-iv-12";
    let mut aad = *b"hdr";
    let mut gp = CK_GCM_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: 12,
        ulIvBits: 96,
        pAAD: aad.as_mut_ptr(),
        ulAADLen: 3,
        ulTagBits: 128,
    };
    let mut gm = m(CKM_AES_GCM, &mut gp);
    s.rv("gcm init", c!(s, C_EncryptInit(rw, &mut gm, key)));
    let gct = out_call(|p, n| c!(s, C_Encrypt(rw, data.as_mut_ptr(), 22, p, n)));
    s.t.line("gcm ciphertext", format!("{:?}", gct.as_ref().map(|c| hex(c))));
    if let Ok(mut gct) = gct {
        s.rv("gcm decrypt init", c!(s, C_DecryptInit(rw, &mut gm, key)));
        let mut gpt = vec![0u8; gct.len()];
        let mut gn = gpt.len() as CK_ULONG;
        s.rv("gcm decrypt", c!(s, C_Decrypt(rw, gct.as_mut_ptr(), gct.len() as CK_ULONG, gpt.as_mut_ptr(), &mut gn)));
        gct[0] ^= 1;
        s.rv("gcm decrypt init 2", c!(s, C_DecryptInit(rw, &mut gm, key)));
        let mut gn = gpt.len() as CK_ULONG;
        let rv = c!(s, C_Decrypt(rw, gct.as_mut_ptr(), gct.len() as CK_ULONG, gpt.as_mut_ptr(), &mut gn));
        s.t.line("gcm tampered", format!("fails {}", rv != CKR_OK));
    }
    // a parameter of the wrong size never reaches the module
    let mut short =
        CK_MECHANISM { mechanism: CKM_AES_CBC_PAD, pParameter: cbc_iv.as_mut_ptr().cast(), ulParameterLen: 8 };
    let rv = c!(s, C_EncryptInit(rw, &mut short, key));
    s.t.line("cbc wrong iv size", format!("fails {}", rv != CKR_OK));
    s.rv("encrypt invalid mechanism", c!(s, C_EncryptInit(rw, &mut plain(0x7777_0002), key)));
    s.rv("encrypt null mechanism", c!(s, C_EncryptInit(rw, null_mut(), key)));
    s.rv("encrypt bad key", c!(s, C_EncryptInit(rw, &mut cbc, 0xdead_beef)));

    // ---- digest ----
    let mut sha = plain(CKM_SHA256);
    s.rv("digest init", c!(s, C_DigestInit(rw, &mut sha)));
    let mut abc = *b"abc";
    let d = out_call(|p, n| c!(s, C_Digest(rw, abc.as_mut_ptr(), 3, p, n)));
    s.t.line("sha256(abc)", format!("{:?}", d.map(|d| hex(&d))));
    s.rv("digest init 2", c!(s, C_DigestInit(rw, &mut sha)));
    s.rv("digest update", c!(s, C_DigestUpdate(rw, abc.as_mut_ptr(), 3)));
    s.rv("digest key", c!(s, C_DigestKey(rw, key)));
    let d = out_call(|p, n| c!(s, C_DigestFinal(rw, p, n)));
    s.t.line("digest with key fails or works", format!("{}", d.is_ok() || d.is_err()));
    s.rv("digest without init", c!(s, C_DigestUpdate(rw, abc.as_mut_ptr(), 3)));

    // ---- signatures ----
    let hclass = CKO_SECRET_KEY;
    let hkt = CKK_GENERIC_SECRET;
    let hkey = [0x0bu8; 20];
    let mut ht = [
        a_ulong(CKA_CLASS, &hclass),
        a_ulong(CKA_KEY_TYPE, &hkt),
        a_bool(CKA_TOKEN, false),
        a_bool(CKA_SIGN, true),
        a_bool(CKA_VERIFY, true),
        a_bytes(CKA_VALUE, &hkey),
    ];
    let mut hk = 0;
    s.rv("create hmac key", c!(s, C_CreateObject(rw, ht.as_mut_ptr(), 6, &mut hk)));
    let mut hm = plain(CKM_SHA256_HMAC);
    s.rv("sign init", c!(s, C_SignInit(rw, &mut hm, hk)));
    let mut msg = *b"Hi There";
    let sig = out_call(|p, n| c!(s, C_Sign(rw, msg.as_mut_ptr(), 8, p, n)));
    s.t.line("hmac-sha256", format!("{:?}", sig.as_ref().map(|d| hex(d))));
    if let Ok(mut sig) = sig {
        s.rv("verify init", c!(s, C_VerifyInit(rw, &mut hm, hk)));
        s.rv("verify", c!(s, C_Verify(rw, msg.as_mut_ptr(), 8, sig.as_mut_ptr(), sig.len() as CK_ULONG)));
        sig[0] ^= 1;
        s.rv("verify init 2", c!(s, C_VerifyInit(rw, &mut hm, hk)));
        s.rv("verify tampered", c!(s, C_Verify(rw, msg.as_mut_ptr(), 8, sig.as_mut_ptr(), sig.len() as CK_ULONG)));
    }
    s.rv("sign multipart init", c!(s, C_SignInit(rw, &mut hm, hk)));
    s.rv("sign update", c!(s, C_SignUpdate(rw, msg.as_mut_ptr(), 4)));
    s.rv("sign update 2", c!(s, C_SignUpdate(rw, msg.as_mut_ptr().add(4), 4)));
    let sig2 = out_call(|p, n| c!(s, C_SignFinal(rw, p, n)));
    s.t.line("multipart hmac", format!("{:?}", sig2.map(|d| hex(&d))));

    // RSA: keygen, PKCS#1 sign/verify, PSS with parameters, OAEP with parameters
    let mut rmech = plain(CKM_RSA_PKCS_KEY_PAIR_GEN);
    let bits: CK_ULONG = 2048;
    let exp = [1u8, 0, 1];
    let mut pubt = [
        a_ulong(CKA_MODULUS_BITS, &bits),
        a_bytes(CKA_PUBLIC_EXPONENT, &exp),
        a_bool(CKA_ENCRYPT, true),
        a_bool(CKA_VERIFY, true),
        a_bool(CKA_TOKEN, false),
    ];
    let mut privt =
        [a_bool(CKA_DECRYPT, true), a_bool(CKA_SIGN, true), a_bool(CKA_TOKEN, false), a_bool(CKA_SENSITIVE, true)];
    let (mut pubk, mut privk) = (0, 0);
    s.rv(
        "rsa keygen",
        c!(s, C_GenerateKeyPair(rw, &mut rmech, pubt.as_mut_ptr(), 5, privt.as_mut_ptr(), 4, &mut pubk, &mut privk)),
    );
    let mb = s.attr(rw, pubk, CKA_MODULUS_BITS);
    s.t.line("modulus bits", format!("{:?}", mb.map(|b| CK_ULONG::from_ne_bytes(b.try_into().unwrap()))));
    let mut rs = plain(CKM_SHA256_RSA_PKCS);
    s.rv("rsa sign init", c!(s, C_SignInit(rw, &mut rs, privk)));
    let rsig = out_call(|p, n| c!(s, C_Sign(rw, msg.as_mut_ptr(), 8, p, n)));
    s.t.line("rsa signature length", format!("{:?}", rsig.as_ref().map(|d| d.len())));
    if let Ok(mut rsig) = rsig {
        s.rv("rsa verify init", c!(s, C_VerifyInit(rw, &mut rs, pubk)));
        s.rv("rsa verify", c!(s, C_Verify(rw, msg.as_mut_ptr(), 8, rsig.as_mut_ptr(), rsig.len() as CK_ULONG)));
        s.rv("rsa verify init 2", c!(s, C_VerifyInit(rw, &mut rs, pubk)));
        rsig[10] ^= 1;
        s.rv(
            "rsa verify tampered",
            c!(s, C_Verify(rw, msg.as_mut_ptr(), 8, rsig.as_mut_ptr(), rsig.len() as CK_ULONG)),
        );
    }
    s.rv("sign with the public key", c!(s, C_SignInit(rw, &mut rs, pubk)));
    let mut pss = CK_RSA_PKCS_PSS_PARAMS { hashAlg: CKM_SHA256, mgf: CKG_MGF1_SHA256, sLen: 32 };
    let mut pm = m(CKM_SHA256_RSA_PKCS_PSS, &mut pss);
    s.rv("pss sign init", c!(s, C_SignInit(rw, &mut pm, privk)));
    let psig = out_call(|p, n| c!(s, C_Sign(rw, msg.as_mut_ptr(), 8, p, n)));
    if let Ok(mut psig) = psig {
        s.rv("pss verify init", c!(s, C_VerifyInit(rw, &mut pm, pubk)));
        s.rv("pss verify", c!(s, C_Verify(rw, msg.as_mut_ptr(), 8, psig.as_mut_ptr(), psig.len() as CK_ULONG)));
    }
    // OAEP: SHA-1 works on every SoftHSM
    let mut oaep = CK_RSA_PKCS_OAEP_PARAMS {
        hashAlg: CKM_SHA_1,
        mgf: CKG_MGF1_SHA1,
        source: CKZ_DATA_SPECIFIED,
        pSourceData: null_mut(),
        ulSourceDataLen: 0,
    };
    let mut om = m(CKM_RSA_PKCS_OAEP, &mut oaep);
    s.rv("oaep init", c!(s, C_EncryptInit(rw, &mut om, pubk)));
    let oct = out_call(|p, n| c!(s, C_Encrypt(rw, msg.as_mut_ptr(), 8, p, n)));
    if let Ok(mut oct) = oct {
        s.t.line("oaep length", format!("{}", oct.len()));
        s.rv("oaep decrypt init", c!(s, C_DecryptInit(rw, &mut om, privk)));
        let mut op = vec![0u8; 256];
        let mut opn: CK_ULONG = 256;
        s.rv("oaep decrypt", c!(s, C_Decrypt(rw, oct.as_mut_ptr(), oct.len() as CK_ULONG, op.as_mut_ptr(), &mut opn)));
        s.t.line("oaep roundtrip", format!("{}", &op[..opn as usize] == &msg[..]));
    }

    // EC: ECDH agreement between two key pairs, through returned handles
    let ecp = [0x06u8, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    let mut ecm = plain(CKM_EC_KEY_PAIR_GEN);
    let mut gen_ec = |s: &mut S| -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
        let mut pt = [a_bytes(CKA_EC_PARAMS, &ecp), a_bool(CKA_VERIFY, true), a_bool(CKA_TOKEN, false)];
        let mut vt =
            [a_bool(CKA_SIGN, true), a_bool(CKA_DERIVE, true), a_bool(CKA_TOKEN, false), a_bool(CKA_SENSITIVE, true)];
        let (mut p, mut k) = (0, 0);
        let rv = c!(s, C_GenerateKeyPair(rw, &mut ecm, pt.as_mut_ptr(), 3, vt.as_mut_ptr(), 4, &mut p, &mut k));
        assert_eq!(rv, CKR_OK);
        (p, k)
    };
    let (pa, ka) = gen_ec(s);
    let (pb, kb) = gen_ec(s);
    let raw = |d: Vec<u8>| -> Vec<u8> { d[if d[1] & 0x80 != 0 { 2 + (d[1] & 0x7f) as usize } else { 2 }..].to_vec() };
    let mut pta = raw(s.attr(rw, pa, CKA_EC_POINT).unwrap());
    let mut ptb = raw(s.attr(rw, pb, CKA_EC_POINT).unwrap());
    let vlen: CK_ULONG = 32;
    let derive = |s: &mut S, base: CK_OBJECT_HANDLE, other: &mut Vec<u8>| -> CK_OBJECT_HANDLE {
        let mut p = CK_ECDH1_DERIVE_PARAMS {
            kdf: CKD_NULL,
            ulSharedDataLen: 0,
            pSharedData: null_mut(),
            ulPublicDataLen: other.len() as CK_ULONG,
            pPublicData: other.as_mut_ptr(),
        };
        let mut dm = m(CKM_ECDH1_DERIVE, &mut p);
        let cls = CKO_SECRET_KEY;
        let kt = CKK_AES;
        let mut t = [
            a_ulong(CKA_CLASS, &cls),
            a_ulong(CKA_KEY_TYPE, &kt),
            a_ulong(CKA_VALUE_LEN, &vlen),
            a_bool(CKA_TOKEN, false),
            a_bool(CKA_SENSITIVE, false),
            a_bool(CKA_EXTRACTABLE, true),
        ];
        let mut out = 0;
        let rv = c!(s, C_DeriveKey(rw, &mut dm, base, t.as_mut_ptr(), 6, &mut out));
        s.rv("ecdh derive", rv);
        out
    };
    let da = derive(s, ka, &mut ptb);
    let db = derive(s, kb, &mut pta);
    let (va, vb) = (s.attr(rw, da, CKA_VALUE), s.attr(rw, db, CKA_VALUE));
    s.t.line("ecdh agreement", format!("{}", va.is_ok() && va == vb));

    // key wrapping
    let wrapping = s.gen_aes(rw, true, false);
    let mut wm = plain(CKM_AES_KEY_WRAP);
    let wrapped = out_call(|p, n| c!(s, C_WrapKey(rw, &mut wm, wrapping, key, p, n)));
    s.t.line("wrapped length", format!("{:?}", wrapped.as_ref().map(|w| w.len())));
    if let Ok(mut w) = wrapped {
        let wcls = CKO_SECRET_KEY;
        let wkt = CKK_AES;
        let mut ut = [
            a_ulong(CKA_CLASS, &wcls),
            a_ulong(CKA_KEY_TYPE, &wkt),
            a_bool(CKA_TOKEN, false),
            a_bool(CKA_EXTRACTABLE, true),
            a_bool(CKA_SENSITIVE, false),
        ];
        let mut un = 0;
        s.rv(
            "unwrap",
            c!(s, C_UnwrapKey(rw, &mut wm, wrapping, w.as_mut_ptr(), w.len() as CK_ULONG, ut.as_mut_ptr(), 5, &mut un)),
        );
        let uv = s.attr(rw, un, CKA_VALUE);
        s.t.line("unwrapped equals original", format!("{}", uv.as_ref().ok() == Some(&kv)));
    }

    // ---- nested templates, EdDSA, general-length MACs, keys derived from data ----
    {
        let mut wmech = plain(CKM_AES_KEY_GEN);
        let l: CK_ULONG = 16;
        let ikt: CK_KEY_TYPE = CKK_AES;
        let ilen: CK_ULONG = 16;
        let mut wrap = [a_ulong(CKA_KEY_TYPE, &ikt), a_ulong(CKA_VALUE_LEN, &ilen)];
        let mut t = [
            a_ulong(CKA_VALUE_LEN, &l),
            a_bool(CKA_TOKEN, false),
            CK_ATTRIBUTE {
                type_: CKA_WRAP_TEMPLATE,
                pValue: wrap.as_mut_ptr().cast(),
                ulValueLen: core::mem::size_of_val(&wrap) as CK_ULONG,
            },
        ];
        let mut k = 0;
        let rv = c!(s, C_GenerateKey(rw, &mut wmech, t.as_mut_ptr(), 3, &mut k));
        s.rv("key with a wrap template", rv);
        if rv == CKR_OK {
            let (mut kt, mut vl) = (0 as CK_KEY_TYPE, 0 as CK_ULONG);
            let mut out = [
                CK_ATTRIBUTE { type_: CKA_KEY_TYPE, pValue: (&mut kt as *mut CK_KEY_TYPE).cast(), ulValueLen: 8 },
                CK_ATTRIBUTE { type_: CKA_VALUE_LEN, pValue: (&mut vl as *mut CK_ULONG).cast(), ulValueLen: 8 },
            ];
            let mut g = [CK_ATTRIBUTE {
                type_: CKA_WRAP_TEMPLATE,
                pValue: out.as_mut_ptr().cast(),
                ulValueLen: core::mem::size_of_val(&out) as CK_ULONG,
            }];
            let rv = c!(s, C_GetAttributeValue(rw, k, g.as_mut_ptr(), 1));
            s.t.line(
                "wrap template read back",
                format!("{} len {} values {}/{}", rvn(rv), g[0].ulValueLen, kt == CKK_AES, vl),
            );
            let mut q = [CK_ATTRIBUTE { type_: CKA_WRAP_TEMPLATE, pValue: null_mut(), ulValueLen: 0 }];
            let rv = c!(s, C_GetAttributeValue(rw, k, q.as_mut_ptr(), 1));
            s.t.line("wrap template size", format!("{} {}", rvn(rv), q[0].ulValueLen));
        }
        let mut bad = [CK_ATTRIBUTE { type_: CKA_WRAP_TEMPLATE, pValue: wrap.as_mut_ptr().cast(), ulValueLen: 5 }];
        let mut kk = 0;
        s.rv("template of a bad size", c!(s, C_GenerateKey(rw, &mut wmech, bad.as_mut_ptr(), 1, &mut kk)));
    }
    {
        let ed25519 = [0x06u8, 0x03, 0x2b, 0x65, 0x70];
        let mut mech = plain(CKM_EC_EDWARDS_KEY_PAIR_GEN);
        let mut pt = [a_bytes(CKA_EC_PARAMS, &ed25519), a_bool(CKA_VERIFY, true), a_bool(CKA_TOKEN, false)];
        let mut vt = [a_bool(CKA_SIGN, true), a_bool(CKA_TOKEN, false), a_bool(CKA_SENSITIVE, true)];
        let (mut p, mut k) = (0, 0);
        let rv = c!(s, C_GenerateKeyPair(rw, &mut mech, pt.as_mut_ptr(), 3, vt.as_mut_ptr(), 3, &mut p, &mut k));
        s.rv("ed25519 keygen", rv);
        if rv == CKR_OK {
            let mut ed = plain(CKM_EDDSA);
            s.rv("eddsa sign init", c!(s, C_SignInit(rw, &mut ed, k)));
            let sig = out_call(|p, n| c!(s, C_Sign(rw, msg.as_mut_ptr(), 8, p, n)));
            s.t.line("eddsa signature length", format!("{:?}", sig.as_ref().map(|d| d.len())));
            if let Ok(mut sig) = sig {
                s.rv("eddsa verify init", c!(s, C_VerifyInit(rw, &mut ed, p)));
                s.rv("eddsa verify", c!(s, C_Verify(rw, msg.as_mut_ptr(), 8, sig.as_mut_ptr(), sig.len() as CK_ULONG)));
            }
        }
        // general-length HMAC: the parameter is the MAC length, the key has a known value
        let mut maclen: CK_ULONG = 16;
        let mut hg = m(CKM_SHA256_HMAC_GENERAL, &mut maclen);
        s.rv("general hmac init", c!(s, C_SignInit(rw, &mut hg, hk)));
        let mac = out_call(|p, n| c!(s, C_Sign(rw, msg.as_mut_ptr(), 8, p, n)));
        s.t.line("general hmac", format!("{:?}", mac.map(|d| hex(&d))));
    }
    {
        // derived keys: the base has a known value, so the result can be compared
        let base_val = *b"0123456789abcdef0123456789ABCDEF";
        let cls = CKO_SECRET_KEY;
        let akt = CKK_AES;
        let mut bt = [
            a_ulong(CKA_CLASS, &cls),
            a_ulong(CKA_KEY_TYPE, &akt),
            a_bool(CKA_TOKEN, false),
            a_bool(CKA_DERIVE, true),
            a_bool(CKA_ENCRYPT, true),
            a_bool(CKA_EXTRACTABLE, true),
            a_bool(CKA_SENSITIVE, false),
            a_bytes(CKA_VALUE, &base_val),
        ];
        let mut base = 0;
        s.rv("create derive base key", c!(s, C_CreateObject(rw, bt.as_mut_ptr(), 8, &mut base)));
        let derive = |s: &mut S, name: &str, mech: &mut CK_MECHANISM, len: Option<CK_ULONG>| -> Option<Vec<u8>> {
            let gk = CKK_GENERIC_SECRET;
            let l = len.unwrap_or(0);
            let mut t = vec![
                a_ulong(CKA_CLASS, &cls),
                a_ulong(CKA_KEY_TYPE, &gk),
                a_bool(CKA_TOKEN, false),
                a_bool(CKA_SENSITIVE, false),
                a_bool(CKA_EXTRACTABLE, true),
            ];
            if l != 0 {
                t.push(a_ulong(CKA_VALUE_LEN, &l));
            }
            let mut out = 0;
            let rv = c!(s, C_DeriveKey(rw, mech, base, t.as_mut_ptr(), t.len() as CK_ULONG, &mut out));
            s.t.line(name, rvn(rv));
            (rv == CKR_OK).then(|| s.attr(rw, out, CKA_VALUE).unwrap_or_default())
        };
        let mut suffix = *b"suffix";
        let mut sp = CK_KEY_DERIVATION_STRING_DATA { pData: suffix.as_mut_ptr(), ulLen: 6 };
        let mut cm = m(CKM_CONCATENATE_BASE_AND_DATA, &mut sp);
        let v = derive(s, "concatenate base and data", &mut cm, None);
        s.t.line("  value", format!("{:?}", v.map(|d| hex(&d))));
        let mut cm = m(CKM_CONCATENATE_DATA_AND_BASE, &mut sp);
        let v = derive(s, "concatenate data and base", &mut cm, None);
        s.t.line("  value", format!("{:?}", v.map(|d| hex(&d))));
        // the parameter is another key's handle
        let mut other: CK_OBJECT_HANDLE = key;
        let mut cm = m(CKM_CONCATENATE_BASE_AND_KEY, &mut other);
        let v = derive(s, "concatenate base and key", &mut cm, None);
        s.t.line("  value", format!("{:?}", v.map(|d| hex(&d))));
        // an IV inside the structure and a pointer
        let data: Vec<u8> = (0..32).map(|i| (i * 3) as u8).collect();
        let iv: [u8; 16] = core::array::from_fn(|i| 0xa0 + i as u8);
        let mut cp = CK_AES_CBC_ENCRYPT_DATA_PARAMS { iv, pData: data.as_ptr() as *mut u8, length: 32 };
        let mut cm = m(CKM_AES_CBC_ENCRYPT_DATA, &mut cp);
        let v = derive(s, "aes cbc encrypt data", &mut cm, Some(32));
        s.t.line("  value", format!("{:?}", v.map(|d| hex(&d))));
        let mut ep = CK_KEY_DERIVATION_STRING_DATA { pData: data.as_ptr() as *mut u8, ulLen: 32 };
        let mut em = m(CKM_AES_ECB_ENCRYPT_DATA, &mut ep);
        let v = derive(s, "aes ecb encrypt data", &mut em, Some(32));
        s.t.line("  value", format!("{:?}", v.map(|d| hex(&d))));
        // a mechanism the module does not have
        let mut nm = plain(0x7777_0003);
        s.rv("derive with an unknown mechanism", c!(s, C_DeriveKey(rw, &mut nm, base, null_mut(), 0, &mut 0)));
    }
    {
        // RSA-AES key wrap: the parameter points at an OAEP structure
        let mut oaep = CK_RSA_PKCS_OAEP_PARAMS {
            hashAlg: CKM_SHA_1,
            mgf: CKG_MGF1_SHA1,
            source: CKZ_DATA_SPECIFIED,
            pSourceData: null_mut(),
            ulSourceDataLen: 0,
        };
        let mut wp = CK_RSA_AES_KEY_WRAP_PARAMS { ulAESKeyBits: 256, pOAEPParams: &mut oaep };
        let mut wm = m(CKM_RSA_AES_KEY_WRAP, &mut wp);
        let mut wl: CK_ULONG = 0;
        let rv = c!(s, C_WrapKey(rw, &mut wm, pubk, key, null_mut(), &mut wl));
        s.rv("rsa-aes wrap length", rv);
        if rv == CKR_OK {
            let mut wrapped = vec![0u8; wl as usize];
            s.rv("rsa-aes wrap", c!(s, C_WrapKey(rw, &mut wm, pubk, key, wrapped.as_mut_ptr(), &mut wl)));
            s.t.line("rsa-aes wrapped length", format!("{}", wl > 256));
            let cls = CKO_SECRET_KEY;
            let akt = CKK_AES;
            let mut ut = [
                a_ulong(CKA_CLASS, &cls),
                a_ulong(CKA_KEY_TYPE, &akt),
                a_bool(CKA_TOKEN, false),
                a_bool(CKA_SENSITIVE, false),
                a_bool(CKA_EXTRACTABLE, true),
            ];
            let mut back = 0;
            s.rv(
                "rsa-aes unwrap",
                c!(s, C_UnwrapKey(rw, &mut wm, privk, wrapped.as_mut_ptr(), wl, ut.as_mut_ptr(), 5, &mut back)),
            );
            let bv = s.attr(rw, back, CKA_VALUE);
            s.t.line("rsa-aes unwrapped equals the original", format!("{}", bv.as_ref().ok() == Some(&kv)));
        }
    }

    // ---- randomness ----
    let mut rnd = [0u8; 32];
    s.rv("random", c!(s, C_GenerateRandom(rw, rnd.as_mut_ptr(), 32)));
    s.t.line("random not zero", format!("{}", rnd.iter().any(|&b| b != 0)));
    s.rv("random null", c!(s, C_GenerateRandom(rw, null_mut(), 32)));
    let mut seed = [1u8; 8];
    let rv = c!(s, C_SeedRandom(rw, seed.as_mut_ptr(), 8));
    s.t.line(
        "seed random",
        if rv == CKR_OK || rv == CKR_RANDOM_SEED_NOT_SUPPORTED { "ok or unsupported".to_string() } else { rvn(rv) },
    );

    // ---- post-quantum, where the module has it ----
    let mut dm = plain(CKM_ML_DSA_KEY_PAIR_GEN);
    let set: CK_ULONG = CKP_ML_DSA_65;
    let mut dpt = [a_ulong(CKA_PARAMETER_SET, &set), a_bool(CKA_VERIFY, true), a_bool(CKA_TOKEN, false)];
    let mut dvt = [a_bool(CKA_SIGN, true), a_bool(CKA_TOKEN, false), a_bool(CKA_SENSITIVE, true)];
    let (mut dp, mut dk) = (0, 0);
    let rv = c!(s, C_GenerateKeyPair(rw, &mut dm, dpt.as_mut_ptr(), 3, dvt.as_mut_ptr(), 3, &mut dp, &mut dk));
    if rv == CKR_OK {
        let mut ctx = *b"scenario-ctx";
        let mut cp = CK_SIGN_ADDITIONAL_CONTEXT {
            hedgeVariant: CKH_HEDGE_PREFERRED,
            pContext: ctx.as_mut_ptr(),
            ulContextLen: 12,
        };
        let mut sm = m(CKM_ML_DSA, &mut cp);
        s.rv("ml-dsa sign init", c!(s, C_SignInit(rw, &mut sm, dk)));
        let ds = out_call(|p, n| c!(s, C_Sign(rw, msg.as_mut_ptr(), 8, p, n)));
        if let Ok(mut ds) = ds {
            s.rv("ml-dsa verify init", c!(s, C_VerifyInit(rw, &mut sm, dp)));
            s.rv("ml-dsa verify", c!(s, C_Verify(rw, msg.as_mut_ptr(), 8, ds.as_mut_ptr(), ds.len() as CK_ULONG)));
            let mut ctx2 = *b"other-ctx!!!";
            let mut cp2 = CK_SIGN_ADDITIONAL_CONTEXT {
                hedgeVariant: CKH_HEDGE_PREFERRED,
                pContext: ctx2.as_mut_ptr(),
                ulContextLen: 12,
            };
            let mut sm2 = m(CKM_ML_DSA, &mut cp2);
            s.rv("ml-dsa verify init 2", c!(s, C_VerifyInit(rw, &mut sm2, dp)));
            s.rv(
                "ml-dsa verify other context",
                c!(s, C_Verify(rw, msg.as_mut_ptr(), 8, ds.as_mut_ptr(), ds.len() as CK_ULONG)),
            );
        }
    } else {
        s.t.line("ml-dsa", "not available");
    }

    // ---- 3.x entry points ----
    // (a proxy always offers the 3.x function list, whatever the module behind it speaks, so
    // "has the entry points" is asked of the module: does it answer C_LoginUser?)
    let f32 = s.m.f32.filter(|f| {
        let probe = s.open(slot, false);
        let rv = (f.C_LoginUser.unwrap())(probe, CKU_USER, null_mut(), 0, null_mut(), 0);
        c!(s, C_CloseSession(probe));
        rv != CKR_FUNCTION_NOT_SUPPORTED
    });
    if f32.is_none() {
        s.t.line("3.x calls", "not supported");
    }
    if let Some(f32) = f32 {
        let mut mech = plain(CKM_ML_KEM_KEY_PAIR_GEN);
        let kset: CK_ULONG = CKP_ML_KEM_768;
        let mut pt = [a_ulong(CKA_PARAMETER_SET, &kset), a_bool(CKA_ENCAPSULATE, true), a_bool(CKA_TOKEN, false)];
        let mut vt = [a_bool(CKA_DECAPSULATE, true), a_bool(CKA_TOKEN, false), a_bool(CKA_SENSITIVE, true)];
        let (mut kp, mut kk) = (0, 0);
        if c!(s, C_GenerateKeyPair(rw, &mut mech, pt.as_mut_ptr(), 3, vt.as_mut_ptr(), 3, &mut kp, &mut kk)) == CKR_OK {
            let cls = CKO_SECRET_KEY;
            let kt = CKK_AES;
            let l: CK_ULONG = 32;
            let mut tpl = [
                a_ulong(CKA_CLASS, &cls),
                a_ulong(CKA_KEY_TYPE, &kt),
                a_ulong(CKA_VALUE_LEN, &l),
                a_bool(CKA_TOKEN, false),
                a_bool(CKA_SENSITIVE, false),
                a_bool(CKA_EXTRACTABLE, true),
            ];
            let mut km = plain(CKM_ML_KEM);
            let mut ctn: CK_ULONG = 0;
            let mut k1 = 0;
            let rv =
                (f32.C_EncapsulateKey.unwrap())(rw, &mut km, kp, tpl.as_mut_ptr(), 6, null_mut(), &mut ctn, &mut k1);
            s.rv("encapsulate length", rv);
            let mut ct = vec![0u8; ctn as usize];
            s.rv(
                "encapsulate",
                (f32.C_EncapsulateKey.unwrap())(
                    rw,
                    &mut km,
                    kp,
                    tpl.as_mut_ptr(),
                    6,
                    ct.as_mut_ptr(),
                    &mut ctn,
                    &mut k1,
                ),
            );
            let mut k2 = 0;
            s.rv(
                "decapsulate",
                (f32.C_DecapsulateKey.unwrap())(rw, &mut km, kk, tpl.as_mut_ptr(), 6, ct.as_mut_ptr(), ctn, &mut k2),
            );
            let (v1, v2) = (s.attr(rw, k1, CKA_VALUE), s.attr(rw, k2, CKA_VALUE));
            s.t.line("kem shared secret agrees", format!("{}", v1.is_ok() && v1 == v2));
        } else {
            s.t.line("ml-kem", "not available");
        }
        let mut pin2 = USER_PIN.as_bytes().to_vec();
        let ss = s.open(slot, false);
        // login as the user again in a new session: already logged in on the token
        let rv = (f32.C_LoginUser.unwrap())(ss, CKU_USER, pin2.as_mut_ptr(), pin2.len() as CK_ULONG, null_mut(), 0);
        s.rv("login user (3.0)", rv);
        s.rv("session cancel", (f32.C_SessionCancel.unwrap())(ss, 0));
        c!(s, C_CloseSession(ss));
    }

    // ---- session lifecycle and finalisation ----
    s.rv("logout", c!(s, C_Logout(rw)));
    s.rv("logout again", c!(s, C_Logout(rw)));
    s.rv("close session", c!(s, C_CloseSession(ro)));
    s.rv("close session again", c!(s, C_CloseSession(ro)));
    s.rv("use closed session", c!(s, C_GetSessionInfo(ro, &mut si2)));
    s.rv("close all sessions", c!(s, C_CloseAllSessions(slot)));
    s.rv("use after close all", c!(s, C_GetSessionInfo(rw, &mut si2)));
    s.rv("finalize", c!(s, C_Finalize(null_mut())));
    s.rv("finalize again", c!(s, C_Finalize(null_mut())));
    s.rv("get_info after finalize", c!(s, C_GetInfo(&mut info)));
}
