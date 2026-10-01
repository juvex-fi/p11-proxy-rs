//! The descriptors of the structures that carry mechanism parameters.
//!
//! Ported from the C proxy's tables and checked against the bindgen types:
//! every member is named through `offset_of!`. The tests below verify that
//! each length and count refers to a scalar member and that every offset
//! fits its structure.
#![allow(clippy::all)]

use crate::desc::*;
use core::mem::{offset_of, size_of};
use p11_types::*;

macro_rules! o {
    ($t:ty, $m:ident) => {
        offset_of!($t, $m)
    };
}
static GCM_MSG_FIELDS: [Field; 6] = [
    buf_io(o!(CK_GCM_MESSAGE_PARAMS, pIv), Len::Field(1), false, MSG),
    ulong(o!(CK_GCM_MESSAGE_PARAMS, ulIvLen)),
    ulong(o!(CK_GCM_MESSAGE_PARAMS, ulIvFixedBits)),
    ulong(o!(CK_GCM_MESSAGE_PARAMS, ivGenerator)),
    buf_io(o!(CK_GCM_MESSAGE_PARAMS, pTag), Len::Field(5), true, MSG),
    ulong(o!(CK_GCM_MESSAGE_PARAMS, ulTagBits)),
];
static CCM_MSG_FIELDS: [Field; 7] = [
    ulong(o!(CK_CCM_MESSAGE_PARAMS, ulDataLen)),
    buf_io(o!(CK_CCM_MESSAGE_PARAMS, pNonce), Len::Field(2), false, MSG),
    ulong(o!(CK_CCM_MESSAGE_PARAMS, ulNonceLen)),
    ulong(o!(CK_CCM_MESSAGE_PARAMS, ulNonceFixedBits)),
    ulong(o!(CK_CCM_MESSAGE_PARAMS, nonceGenerator)),
    buf_io(o!(CK_CCM_MESSAGE_PARAMS, pMAC), Len::Field(6), false, MSG),
    ulong(o!(CK_CCM_MESSAGE_PARAMS, ulMACLen)),
];
static CHACHA_MSG_FIELDS: [Field; 3] = [
    buf_io(o!(CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS, pNonce), Len::Field(1), false, MSG),
    ulong(o!(CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS, ulNonceLen)),
    buf_io(o!(CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS, pTag), Len::Fixed(16), false, MSG),
];
static GCM_FIELDS: [Field; 6] = [
    buf(o!(CK_GCM_PARAMS, pIv), Len::Field(1), MECH),
    ulong(o!(CK_GCM_PARAMS, ulIvLen)),
    ulong(o!(CK_GCM_PARAMS, ulIvBits)),
    buf(o!(CK_GCM_PARAMS, pAAD), Len::Field(4), MECH),
    ulong(o!(CK_GCM_PARAMS, ulAADLen)),
    ulong(o!(CK_GCM_PARAMS, ulTagBits)),
];
static CCM_FIELDS: [Field; 6] = [
    ulong(o!(CK_CCM_PARAMS, ulDataLen)),
    buf(o!(CK_CCM_PARAMS, pNonce), Len::Field(2), MECH),
    ulong(o!(CK_CCM_PARAMS, ulNonceLen)),
    buf(o!(CK_CCM_PARAMS, pAAD), Len::Field(4), MECH),
    ulong(o!(CK_CCM_PARAMS, ulAADLen)),
    ulong(o!(CK_CCM_PARAMS, ulMACLen)),
];
static CHACHA_FIELDS: [Field; 4] = [
    buf(o!(CK_SALSA20_CHACHA20_POLY1305_PARAMS, pNonce), Len::Field(1), MECH),
    ulong(o!(CK_SALSA20_CHACHA20_POLY1305_PARAMS, ulNonceLen)),
    buf(o!(CK_SALSA20_CHACHA20_POLY1305_PARAMS, pAAD), Len::Field(3), MECH),
    ulong(o!(CK_SALSA20_CHACHA20_POLY1305_PARAMS, ulAADLen)),
];
static OAEP_FIELDS: [Field; 5] = [
    ulong(o!(CK_RSA_PKCS_OAEP_PARAMS, hashAlg)),
    ulong(o!(CK_RSA_PKCS_OAEP_PARAMS, mgf)),
    ulong(o!(CK_RSA_PKCS_OAEP_PARAMS, source)),
    buf(o!(CK_RSA_PKCS_OAEP_PARAMS, pSourceData), Len::Field(4), MECH),
    ulong(o!(CK_RSA_PKCS_OAEP_PARAMS, ulSourceDataLen)),
];
static ECDH1_FIELDS: [Field; 5] = [
    ulong(o!(CK_ECDH1_DERIVE_PARAMS, kdf)),
    ulong(o!(CK_ECDH1_DERIVE_PARAMS, ulSharedDataLen)),
    buf(o!(CK_ECDH1_DERIVE_PARAMS, pSharedData), Len::Field(1), MECH),
    ulong(o!(CK_ECDH1_DERIVE_PARAMS, ulPublicDataLen)),
    buf(o!(CK_ECDH1_DERIVE_PARAMS, pPublicData), Len::Field(3), MECH),
];
static ECDH_WRAP_FIELDS: [Field; 4] = [
    ulong(o!(CK_ECDH_AES_KEY_WRAP_PARAMS, ulAESKeyBits)),
    ulong(o!(CK_ECDH_AES_KEY_WRAP_PARAMS, kdf)),
    ulong(o!(CK_ECDH_AES_KEY_WRAP_PARAMS, ulSharedDataLen)),
    buf(o!(CK_ECDH_AES_KEY_WRAP_PARAMS, pSharedData), Len::Field(2), MECH),
];
static HKDF_FIELDS: [Field; 9] = [
    boolean(o!(CK_HKDF_PARAMS, bExtract)),
    boolean(o!(CK_HKDF_PARAMS, bExpand)),
    ulong(o!(CK_HKDF_PARAMS, prfHashMechanism)),
    ulong(o!(CK_HKDF_PARAMS, ulSaltType)),
    buf(o!(CK_HKDF_PARAMS, pSalt), Len::Field(5), MECH),
    ulong(o!(CK_HKDF_PARAMS, ulSaltLen)),
    handle(o!(CK_HKDF_PARAMS, hSaltKey)),
    buf(o!(CK_HKDF_PARAMS, pInfo), Len::Field(8), MECH),
    ulong(o!(CK_HKDF_PARAMS, ulInfoLen)),
];
static EDDSA_FIELDS: [Field; 3] = [
    boolean(o!(CK_EDDSA_PARAMS, phFlag)),
    ulong(o!(CK_EDDSA_PARAMS, ulContextDataLen)),
    buf(o!(CK_EDDSA_PARAMS, pContextData), Len::Field(1), MECH),
];
static CHACHA20_FIELDS: [Field; 4] = [
    buf_bits(o!(CK_CHACHA20_PARAMS, pBlockCounter), Len::Field(1), MECH),
    ulong(o!(CK_CHACHA20_PARAMS, blockCounterBits)),
    buf_bits(o!(CK_CHACHA20_PARAMS, pNonce), Len::Field(3), MECH),
    ulong(o!(CK_CHACHA20_PARAMS, ulNonceBits)),
];
static SALSA20_FIELDS: [Field; 3] = [
    buf(o!(CK_SALSA20_PARAMS, pBlockCounter), Len::Fixed(8), MECH),
    buf_bits(o!(CK_SALSA20_PARAMS, pNonce), Len::Field(2), MECH),
    ulong(o!(CK_SALSA20_PARAMS, ulNonceBits)),
];
static STRDATA_FIELDS: [Field; 2] = [
    buf(o!(CK_KEY_DERIVATION_STRING_DATA, pData), Len::Field(1), MECH),
    ulong(o!(CK_KEY_DERIVATION_STRING_DATA, ulLen)),
];
static AES_CBC_DATA_FIELDS: [Field; 3] = [
    inline(o!(CK_AES_CBC_ENCRYPT_DATA_PARAMS, iv), 16),
    buf(o!(CK_AES_CBC_ENCRYPT_DATA_PARAMS, pData), Len::Field(2), MECH),
    ulong(o!(CK_AES_CBC_ENCRYPT_DATA_PARAMS, length)),
];
static DES_CBC_DATA_FIELDS: [Field; 3] = [
    inline(o!(CK_DES_CBC_ENCRYPT_DATA_PARAMS, iv), 8),
    buf(o!(CK_DES_CBC_ENCRYPT_DATA_PARAMS, pData), Len::Field(2), MECH),
    ulong(o!(CK_DES_CBC_ENCRYPT_DATA_PARAMS, length)),
];
static DSA_GEN_FIELDS: [Field; 4] = [
    ulong(o!(CK_DSA_PARAMETER_GEN_PARAM, hash)),
    buf(o!(CK_DSA_PARAMETER_GEN_PARAM, pSeed), Len::Field(2), MECH),
    ulong(o!(CK_DSA_PARAMETER_GEN_PARAM, ulSeedLen)),
    ulong(o!(CK_DSA_PARAMETER_GEN_PARAM, ulIndex)),
];
static IKE2_PRF_PLUS_FIELDS: [Field; 5] = [
    ulong(o!(CK_IKE2_PRF_PLUS_DERIVE_PARAMS, prfMechanism)),
    boolean(o!(CK_IKE2_PRF_PLUS_DERIVE_PARAMS, bHasSeedKey)),
    handle(o!(CK_IKE2_PRF_PLUS_DERIVE_PARAMS, hSeedKey)),
    buf(o!(CK_IKE2_PRF_PLUS_DERIVE_PARAMS, pSeedData), Len::Field(4), MECH),
    ulong(o!(CK_IKE2_PRF_PLUS_DERIVE_PARAMS, ulSeedDataLen)),
];
static IKE_PRF_FIELDS: [Field; 8] = [
    ulong(o!(CK_IKE_PRF_DERIVE_PARAMS, prfMechanism)),
    boolean(o!(CK_IKE_PRF_DERIVE_PARAMS, bDataAsKey)),
    boolean(o!(CK_IKE_PRF_DERIVE_PARAMS, bRekey)),
    buf(o!(CK_IKE_PRF_DERIVE_PARAMS, pNi), Len::Field(4), MECH),
    ulong(o!(CK_IKE_PRF_DERIVE_PARAMS, ulNiLen)),
    buf(o!(CK_IKE_PRF_DERIVE_PARAMS, pNr), Len::Field(6), MECH),
    ulong(o!(CK_IKE_PRF_DERIVE_PARAMS, ulNrLen)),
    handle(o!(CK_IKE_PRF_DERIVE_PARAMS, hNewKey)),
];
static IKE1_PRF_FIELDS: [Field; 9] = [
    ulong(o!(CK_IKE1_PRF_DERIVE_PARAMS, prfMechanism)),
    boolean(o!(CK_IKE1_PRF_DERIVE_PARAMS, bHasPrevKey)),
    handle(o!(CK_IKE1_PRF_DERIVE_PARAMS, hKeygxy)),
    handle(o!(CK_IKE1_PRF_DERIVE_PARAMS, hPrevKey)),
    buf(o!(CK_IKE1_PRF_DERIVE_PARAMS, pCKYi), Len::Field(5), MECH),
    ulong(o!(CK_IKE1_PRF_DERIVE_PARAMS, ulCKYiLen)),
    buf(o!(CK_IKE1_PRF_DERIVE_PARAMS, pCKYr), Len::Field(7), MECH),
    ulong(o!(CK_IKE1_PRF_DERIVE_PARAMS, ulCKYrLen)),
    byte(o!(CK_IKE1_PRF_DERIVE_PARAMS, keyNumber)),
];
static IKE1_EXT_FIELDS: [Field; 5] = [
    ulong(o!(CK_IKE1_EXTENDED_DERIVE_PARAMS, prfMechanism)),
    boolean(o!(CK_IKE1_EXTENDED_DERIVE_PARAMS, bHasKeygxy)),
    handle(o!(CK_IKE1_EXTENDED_DERIVE_PARAMS, hKeygxy)),
    buf(o!(CK_IKE1_EXTENDED_DERIVE_PARAMS, pExtraData), Len::Field(4), MECH),
    ulong(o!(CK_IKE1_EXTENDED_DERIVE_PARAMS, ulExtraDataLen)),
];
static X942_DH1_FIELDS: [Field; 5] = [
    ulong(o!(CK_X9_42_DH1_DERIVE_PARAMS, kdf)),
    ulong(o!(CK_X9_42_DH1_DERIVE_PARAMS, ulOtherInfoLen)),
    buf(o!(CK_X9_42_DH1_DERIVE_PARAMS, pOtherInfo), Len::Field(1), MECH),
    ulong(o!(CK_X9_42_DH1_DERIVE_PARAMS, ulPublicDataLen)),
    buf(o!(CK_X9_42_DH1_DERIVE_PARAMS, pPublicData), Len::Field(3), MECH),
];
static X942_DH2_FIELDS: [Field; 9] = [
    ulong(o!(CK_X9_42_DH2_DERIVE_PARAMS, kdf)),
    ulong(o!(CK_X9_42_DH2_DERIVE_PARAMS, ulOtherInfoLen)),
    buf(o!(CK_X9_42_DH2_DERIVE_PARAMS, pOtherInfo), Len::Field(1), MECH),
    ulong(o!(CK_X9_42_DH2_DERIVE_PARAMS, ulPublicDataLen)),
    buf(o!(CK_X9_42_DH2_DERIVE_PARAMS, pPublicData), Len::Field(3), MECH),
    ulong(o!(CK_X9_42_DH2_DERIVE_PARAMS, ulPrivateDataLen)),
    handle(o!(CK_X9_42_DH2_DERIVE_PARAMS, hPrivateData)),
    ulong(o!(CK_X9_42_DH2_DERIVE_PARAMS, ulPublicDataLen2)),
    buf(o!(CK_X9_42_DH2_DERIVE_PARAMS, pPublicData2), Len::Field(7), MECH),
];
static X942_MQV_FIELDS: [Field; 10] = [
    ulong(o!(CK_X9_42_MQV_DERIVE_PARAMS, kdf)),
    ulong(o!(CK_X9_42_MQV_DERIVE_PARAMS, ulOtherInfoLen)),
    buf(o!(CK_X9_42_MQV_DERIVE_PARAMS, pOtherInfo), Len::Field(1), MECH),
    ulong(o!(CK_X9_42_MQV_DERIVE_PARAMS, ulPublicDataLen)),
    buf(o!(CK_X9_42_MQV_DERIVE_PARAMS, pPublicData), Len::Field(3), MECH),
    ulong(o!(CK_X9_42_MQV_DERIVE_PARAMS, ulPrivateDataLen)),
    handle(o!(CK_X9_42_MQV_DERIVE_PARAMS, hPrivateData)),
    ulong(o!(CK_X9_42_MQV_DERIVE_PARAMS, ulPublicDataLen2)),
    buf(o!(CK_X9_42_MQV_DERIVE_PARAMS, pPublicData2), Len::Field(7), MECH),
    handle(o!(CK_X9_42_MQV_DERIVE_PARAMS, publicKey)),
];
static ECMQV_FIELDS: [Field; 10] = [
    ulong(o!(CK_ECMQV_DERIVE_PARAMS, kdf)),
    ulong(o!(CK_ECMQV_DERIVE_PARAMS, ulSharedDataLen)),
    buf(o!(CK_ECMQV_DERIVE_PARAMS, pSharedData), Len::Field(1), MECH),
    ulong(o!(CK_ECMQV_DERIVE_PARAMS, ulPublicDataLen)),
    buf(o!(CK_ECMQV_DERIVE_PARAMS, pPublicData), Len::Field(3), MECH),
    ulong(o!(CK_ECMQV_DERIVE_PARAMS, ulPrivateDataLen)),
    handle(o!(CK_ECMQV_DERIVE_PARAMS, hPrivateData)),
    ulong(o!(CK_ECMQV_DERIVE_PARAMS, ulPublicDataLen2)),
    buf(o!(CK_ECMQV_DERIVE_PARAMS, pPublicData2), Len::Field(7), MECH),
    handle(o!(CK_ECMQV_DERIVE_PARAMS, publicKey)),
];
static KEA_FIELDS: [Field; 6] = [
    boolean(o!(CK_KEA_DERIVE_PARAMS, isSender)),
    ulong(o!(CK_KEA_DERIVE_PARAMS, ulRandomLen)),
    buf(o!(CK_KEA_DERIVE_PARAMS, pRandomA), Len::Field(1), MECH),
    buf(o!(CK_KEA_DERIVE_PARAMS, pRandomB), Len::Field(1), MECH),
    ulong(o!(CK_KEA_DERIVE_PARAMS, ulPublicDataLen)),
    buf(o!(CK_KEA_DERIVE_PARAMS, pPublicData), Len::Field(4), MECH),
];
static RC5_CBC_FIELDS: [Field; 4] = [
    ulong(o!(CK_RC5_CBC_PARAMS, ulWordsize)),
    ulong(o!(CK_RC5_CBC_PARAMS, ulRounds)),
    buf(o!(CK_RC5_CBC_PARAMS, pIv), Len::Field(3), MECH),
    ulong(o!(CK_RC5_CBC_PARAMS, ulIvLen)),
];
static GOST_DERIVE_FIELDS: [Field; 5] = [
    ulong(o!(CK_GOSTR3410_DERIVE_PARAMS, kdf)),
    buf(o!(CK_GOSTR3410_DERIVE_PARAMS, pPublicData), Len::Field(2), MECH),
    ulong(o!(CK_GOSTR3410_DERIVE_PARAMS, ulPublicDataLen)),
    buf(o!(CK_GOSTR3410_DERIVE_PARAMS, pUKM), Len::Field(4), MECH),
    ulong(o!(CK_GOSTR3410_DERIVE_PARAMS, ulUKMLen)),
];
static GOST_WRAP_FIELDS: [Field; 5] = [
    buf(o!(CK_GOSTR3410_KEY_WRAP_PARAMS, pWrapOID), Len::Field(1), MECH),
    ulong(o!(CK_GOSTR3410_KEY_WRAP_PARAMS, ulWrapOIDLen)),
    buf(o!(CK_GOSTR3410_KEY_WRAP_PARAMS, pUKM), Len::Field(3), MECH),
    ulong(o!(CK_GOSTR3410_KEY_WRAP_PARAMS, ulUKMLen)),
    handle(o!(CK_GOSTR3410_KEY_WRAP_PARAMS, hKey)),
];
static SET_OAEP_FIELDS: [Field; 3] = [
    byte(o!(CK_KEY_WRAP_SET_OAEP_PARAMS, bBC)),
    buf(o!(CK_KEY_WRAP_SET_OAEP_PARAMS, pX), Len::Field(2), MECH),
    ulong(o!(CK_KEY_WRAP_SET_OAEP_PARAMS, ulXLen)),
];
static OTP_PARAM_FIELDS: [Field; 3] = [
    ulong(o!(CK_OTP_PARAM, type_)),
    buf(o!(CK_OTP_PARAM, pValue), Len::Field(2), MECH),
    ulong(o!(CK_OTP_PARAM, ulValueLen)),
];
pub static OTP_PARAM: Desc =
    Desc { name: "CK_OTP_PARAM", size: size_of::<CK_OTP_PARAM>(), phases: MECH, fields: &OTP_PARAM_FIELDS };
static OTP_FIELDS: [Field; 2] = [array(o!(CK_OTP_PARAMS, pParams), &OTP_PARAM, 1), ulong(o!(CK_OTP_PARAMS, ulCount))];
static KIP_FIELDS: [Field; 4] = [
    mech_ptr(o!(CK_KIP_PARAMS, pMechanism)),
    handle(o!(CK_KIP_PARAMS, hKey)),
    buf(o!(CK_KIP_PARAMS, pSeed), Len::Field(3), MECH),
    ulong(o!(CK_KIP_PARAMS, ulSeedLen)),
];
static CMS_SIG_FIELDS: [Field; 8] = [
    handle(o!(CK_CMS_SIG_PARAMS, certificateHandle)),
    mech_ptr(o!(CK_CMS_SIG_PARAMS, pSigningMechanism)),
    mech_ptr(o!(CK_CMS_SIG_PARAMS, pDigestMechanism)),
    cstr(o!(CK_CMS_SIG_PARAMS, pContentType)),
    buf(o!(CK_CMS_SIG_PARAMS, pRequestedAttributes), Len::Field(5), MECH),
    ulong(o!(CK_CMS_SIG_PARAMS, ulRequestedAttributesLen)),
    buf(o!(CK_CMS_SIG_PARAMS, pRequiredAttributes), Len::Field(7), MECH),
    ulong(o!(CK_CMS_SIG_PARAMS, ulRequiredAttributesLen)),
];
static RANDOM_FIELDS: [Field; 4] = [
    buf(o!(CK_SSL3_RANDOM_DATA, pClientRandom), Len::Field(1), MECH),
    ulong(o!(CK_SSL3_RANDOM_DATA, ulClientRandomLen)),
    buf(o!(CK_SSL3_RANDOM_DATA, pServerRandom), Len::Field(3), MECH),
    ulong(o!(CK_SSL3_RANDOM_DATA, ulServerRandomLen)),
];
pub static RANDOM: Desc =
    Desc { name: "CK_SSL3_RANDOM_DATA", size: size_of::<CK_SSL3_RANDOM_DATA>(), phases: MECH, fields: &RANDOM_FIELDS };
static SSL3_MASTER_FIELDS: [Field; 2] = [
    embedded(o!(CK_SSL3_MASTER_KEY_DERIVE_PARAMS, RandomInfo), &RANDOM),
    buf_io(o!(CK_SSL3_MASTER_KEY_DERIVE_PARAMS, pVersion), Len::Fixed(size_of::<CK_VERSION>() as u32), false, MECH),
];
static TLS12_MASTER_FIELDS: [Field; 3] = [
    embedded(o!(CK_TLS12_MASTER_KEY_DERIVE_PARAMS, RandomInfo), &RANDOM),
    buf_io(o!(CK_TLS12_MASTER_KEY_DERIVE_PARAMS, pVersion), Len::Fixed(size_of::<CK_VERSION>() as u32), false, MECH),
    ulong(o!(CK_TLS12_MASTER_KEY_DERIVE_PARAMS, prfHashMechanism)),
];
static TLS12_EXT_MASTER_FIELDS: [Field; 4] = [
    ulong(o!(CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS, prfHashMechanism)),
    buf(o!(CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS, pSessionHash), Len::Field(2), MECH),
    ulong(o!(CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS, ulSessionHashLen)),
    buf_io(
        o!(CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS, pVersion),
        Len::Fixed(size_of::<CK_VERSION>() as u32),
        false,
        MECH,
    ),
];
static SSL3_KEY_OUT_FIELDS: [Field; 6] = [
    handle_out(o!(CK_SSL3_KEY_MAT_OUT, hClientMacSecret)),
    handle_out(o!(CK_SSL3_KEY_MAT_OUT, hServerMacSecret)),
    handle_out(o!(CK_SSL3_KEY_MAT_OUT, hClientKey)),
    handle_out(o!(CK_SSL3_KEY_MAT_OUT, hServerKey)),
    buf_out(o!(CK_SSL3_KEY_MAT_OUT, pIVClient), Len::Parent(2), true),
    buf_out(o!(CK_SSL3_KEY_MAT_OUT, pIVServer), Len::Parent(2), true),
];
pub static SSL3_KEY_OUT: Desc = Desc {
    name: "CK_SSL3_KEY_MAT_OUT",
    size: size_of::<CK_SSL3_KEY_MAT_OUT>(),
    phases: MECH,
    fields: &SSL3_KEY_OUT_FIELDS,
};
static SSL3_KEY_MAT_FIELDS: [Field; 6] = [
    ulong(o!(CK_SSL3_KEY_MAT_PARAMS, ulMacSizeInBits)),
    ulong(o!(CK_SSL3_KEY_MAT_PARAMS, ulKeySizeInBits)),
    ulong(o!(CK_SSL3_KEY_MAT_PARAMS, ulIVSizeInBits)),
    boolean(o!(CK_SSL3_KEY_MAT_PARAMS, bIsExport)),
    embedded(o!(CK_SSL3_KEY_MAT_PARAMS, RandomInfo), &RANDOM),
    structure(o!(CK_SSL3_KEY_MAT_PARAMS, pReturnedKeyMaterial), &SSL3_KEY_OUT),
];
static TLS12_KEY_MAT_FIELDS: [Field; 7] = [
    ulong(o!(CK_TLS12_KEY_MAT_PARAMS, ulMacSizeInBits)),
    ulong(o!(CK_TLS12_KEY_MAT_PARAMS, ulKeySizeInBits)),
    ulong(o!(CK_TLS12_KEY_MAT_PARAMS, ulIVSizeInBits)),
    boolean(o!(CK_TLS12_KEY_MAT_PARAMS, bIsExport)),
    embedded(o!(CK_TLS12_KEY_MAT_PARAMS, RandomInfo), &RANDOM),
    structure(o!(CK_TLS12_KEY_MAT_PARAMS, pReturnedKeyMaterial), &SSL3_KEY_OUT),
    ulong(o!(CK_TLS12_KEY_MAT_PARAMS, prfHashMechanism)),
];
static TLS_PRF_FIELDS: [Field; 6] = [
    buf(o!(CK_TLS_PRF_PARAMS, pSeed), Len::Field(1), MECH),
    ulong(o!(CK_TLS_PRF_PARAMS, ulSeedLen)),
    buf(o!(CK_TLS_PRF_PARAMS, pLabel), Len::Field(3), MECH),
    ulong(o!(CK_TLS_PRF_PARAMS, ulLabelLen)),
    buf_out(o!(CK_TLS_PRF_PARAMS, pOutput), Len::Field(5), false),
    ulong_ptr(o!(CK_TLS_PRF_PARAMS, pulOutputLen), MECH, true),
];
static TLS_KDF_FIELDS: [Field; 6] = [
    ulong(o!(CK_TLS_KDF_PARAMS, prfMechanism)),
    buf(o!(CK_TLS_KDF_PARAMS, pLabel), Len::Field(2), MECH),
    ulong(o!(CK_TLS_KDF_PARAMS, ulLabelLength)),
    embedded(o!(CK_TLS_KDF_PARAMS, RandomInfo), &RANDOM),
    buf(o!(CK_TLS_KDF_PARAMS, pContextData), Len::Field(5), MECH),
    ulong(o!(CK_TLS_KDF_PARAMS, ulContextDataLength)),
];
static WTLS_MASTER_FIELDS: [Field; 3] = [
    ulong(o!(CK_WTLS_MASTER_KEY_DERIVE_PARAMS, DigestMechanism)),
    embedded(o!(CK_WTLS_MASTER_KEY_DERIVE_PARAMS, RandomInfo), &RANDOM),
    buf_io(o!(CK_WTLS_MASTER_KEY_DERIVE_PARAMS, pVersion), Len::Fixed(1), false, MECH),
];
static WTLS_PRF_FIELDS: [Field; 7] = [
    ulong(o!(CK_WTLS_PRF_PARAMS, DigestMechanism)),
    buf(o!(CK_WTLS_PRF_PARAMS, pSeed), Len::Field(2), MECH),
    ulong(o!(CK_WTLS_PRF_PARAMS, ulSeedLen)),
    buf(o!(CK_WTLS_PRF_PARAMS, pLabel), Len::Field(4), MECH),
    ulong(o!(CK_WTLS_PRF_PARAMS, ulLabelLen)),
    buf_out(o!(CK_WTLS_PRF_PARAMS, pOutput), Len::Field(6), false),
    ulong_ptr(o!(CK_WTLS_PRF_PARAMS, pulOutputLen), MECH, true),
];
static WTLS_KEY_OUT_FIELDS: [Field; 3] = [
    handle_out(o!(CK_WTLS_KEY_MAT_OUT, hMacSecret)),
    handle_out(o!(CK_WTLS_KEY_MAT_OUT, hKey)),
    buf_out(o!(CK_WTLS_KEY_MAT_OUT, pIV), Len::Parent(3), true),
];
pub static WTLS_KEY_OUT: Desc = Desc {
    name: "CK_WTLS_KEY_MAT_OUT",
    size: size_of::<CK_WTLS_KEY_MAT_OUT>(),
    phases: MECH,
    fields: &WTLS_KEY_OUT_FIELDS,
};
static WTLS_KEY_MAT_FIELDS: [Field; 8] = [
    ulong(o!(CK_WTLS_KEY_MAT_PARAMS, DigestMechanism)),
    ulong(o!(CK_WTLS_KEY_MAT_PARAMS, ulMacSizeInBits)),
    ulong(o!(CK_WTLS_KEY_MAT_PARAMS, ulKeySizeInBits)),
    ulong(o!(CK_WTLS_KEY_MAT_PARAMS, ulIVSizeInBits)),
    ulong(o!(CK_WTLS_KEY_MAT_PARAMS, ulSequenceNumber)),
    boolean(o!(CK_WTLS_KEY_MAT_PARAMS, bIsExport)),
    embedded(o!(CK_WTLS_KEY_MAT_PARAMS, RandomInfo), &RANDOM),
    structure(o!(CK_WTLS_KEY_MAT_PARAMS, pReturnedKeyMaterial), &WTLS_KEY_OUT),
];
static PBE_FIELDS: [Field; 6] = [
    buf_out(o!(CK_PBE_PARAMS, pInitVector), Len::Fixed(8), false),
    buf(o!(CK_PBE_PARAMS, pPassword), Len::Field(2), MECH),
    ulong(o!(CK_PBE_PARAMS, ulPasswordLen)),
    buf(o!(CK_PBE_PARAMS, pSalt), Len::Field(4), MECH),
    ulong(o!(CK_PBE_PARAMS, ulSaltLen)),
    ulong(o!(CK_PBE_PARAMS, ulIteration)),
];
static PBKD2_2_FIELDS: [Field; 9] = [
    ulong(o!(CK_PKCS5_PBKD2_PARAMS2, saltSource)),
    buf(o!(CK_PKCS5_PBKD2_PARAMS2, pSaltSourceData), Len::Field(2), MECH),
    ulong(o!(CK_PKCS5_PBKD2_PARAMS2, ulSaltSourceDataLen)),
    ulong(o!(CK_PKCS5_PBKD2_PARAMS2, iterations)),
    ulong(o!(CK_PKCS5_PBKD2_PARAMS2, prf)),
    buf(o!(CK_PKCS5_PBKD2_PARAMS2, pPrfData), Len::Field(6), MECH),
    ulong(o!(CK_PKCS5_PBKD2_PARAMS2, ulPrfDataLen)),
    buf(o!(CK_PKCS5_PBKD2_PARAMS2, pPassword), Len::Field(8), MECH),
    ulong(o!(CK_PKCS5_PBKD2_PARAMS2, ulPasswordLen)),
];
static PBKD2_FIELDS: [Field; 9] = [
    ulong(o!(CK_PKCS5_PBKD2_PARAMS, saltSource)),
    buf(o!(CK_PKCS5_PBKD2_PARAMS, pSaltSourceData), Len::Field(2), MECH),
    ulong(o!(CK_PKCS5_PBKD2_PARAMS, ulSaltSourceDataLen)),
    ulong(o!(CK_PKCS5_PBKD2_PARAMS, iterations)),
    ulong(o!(CK_PKCS5_PBKD2_PARAMS, prf)),
    buf(o!(CK_PKCS5_PBKD2_PARAMS, pPrfData), Len::Field(6), MECH),
    ulong(o!(CK_PKCS5_PBKD2_PARAMS, ulPrfDataLen)),
    buf(o!(CK_PKCS5_PBKD2_PARAMS, pPassword), Len::Field(8), MECH),
    ulong_ptr(o!(CK_PKCS5_PBKD2_PARAMS, ulPasswordLen), MECH, false),
];
static PRF_DATA_FIELDS: [Field; 3] = [
    ulong(o!(CK_PRF_DATA_PARAM, type_)),
    buf(o!(CK_PRF_DATA_PARAM, pValue), Len::Field(2), MECH),
    ulong(o!(CK_PRF_DATA_PARAM, ulValueLen)),
];
pub static PRF_DATA: Desc =
    Desc { name: "CK_PRF_DATA_PARAM", size: size_of::<CK_PRF_DATA_PARAM>(), phases: MECH, fields: &PRF_DATA_FIELDS };
static DERIVED_KEY_FIELDS: [Field; 3] = [
    attrs(o!(CK_DERIVED_KEY, pTemplate), 1),
    ulong(o!(CK_DERIVED_KEY, ulAttributeCount)),
    handle_ptr(o!(CK_DERIVED_KEY, phKey)),
];
pub static DERIVED_KEY: Desc =
    Desc { name: "CK_DERIVED_KEY", size: size_of::<CK_DERIVED_KEY>(), phases: MECH, fields: &DERIVED_KEY_FIELDS };
static SP800_FIELDS: [Field; 5] = [
    ulong(o!(CK_SP800_108_KDF_PARAMS, prfType)),
    ulong(o!(CK_SP800_108_KDF_PARAMS, ulNumberOfDataParams)),
    array(o!(CK_SP800_108_KDF_PARAMS, pDataParams), &PRF_DATA, 1),
    ulong(o!(CK_SP800_108_KDF_PARAMS, ulAdditionalDerivedKeys)),
    array(o!(CK_SP800_108_KDF_PARAMS, pAdditionalDerivedKeys), &DERIVED_KEY, 3),
];
static SP800_FB_FIELDS: [Field; 7] = [
    ulong(o!(CK_SP800_108_FEEDBACK_KDF_PARAMS, prfType)),
    ulong(o!(CK_SP800_108_FEEDBACK_KDF_PARAMS, ulNumberOfDataParams)),
    array(o!(CK_SP800_108_FEEDBACK_KDF_PARAMS, pDataParams), &PRF_DATA, 1),
    ulong(o!(CK_SP800_108_FEEDBACK_KDF_PARAMS, ulIVLen)),
    buf(o!(CK_SP800_108_FEEDBACK_KDF_PARAMS, pIV), Len::Field(3), MECH),
    ulong(o!(CK_SP800_108_FEEDBACK_KDF_PARAMS, ulAdditionalDerivedKeys)),
    array(o!(CK_SP800_108_FEEDBACK_KDF_PARAMS, pAdditionalDerivedKeys), &DERIVED_KEY, 5),
];
pub static OAEP: Desc = Desc {
    name: "CK_RSA_PKCS_OAEP_PARAMS",
    size: size_of::<CK_RSA_PKCS_OAEP_PARAMS>(),
    phases: MECH,
    fields: &OAEP_FIELDS,
};
static RSA_AES_WRAP_FIELDS: [Field; 2] = [
    ulong(o!(CK_RSA_AES_KEY_WRAP_PARAMS, ulAESKeyBits)),
    structure(o!(CK_RSA_AES_KEY_WRAP_PARAMS, pOAEPParams), &OAEP),
];
pub static GCM_MSG: Desc = Desc {
    name: "CK_GCM_MESSAGE_PARAMS",
    size: size_of::<CK_GCM_MESSAGE_PARAMS>(),
    phases: MSG,
    fields: &GCM_MSG_FIELDS,
};
pub static CCM_MSG: Desc = Desc {
    name: "CK_CCM_MESSAGE_PARAMS",
    size: size_of::<CK_CCM_MESSAGE_PARAMS>(),
    phases: MSG,
    fields: &CCM_MSG_FIELDS,
};
pub static CHACHA_MSG: Desc = Desc {
    name: "CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS",
    size: size_of::<CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS>(),
    phases: MSG,
    fields: &CHACHA_MSG_FIELDS,
};
pub static GCM: Desc =
    Desc { name: "CK_GCM_PARAMS", size: size_of::<CK_GCM_PARAMS>(), phases: MECH, fields: &GCM_FIELDS };
pub static CCM: Desc =
    Desc { name: "CK_CCM_PARAMS", size: size_of::<CK_CCM_PARAMS>(), phases: MECH, fields: &CCM_FIELDS };
pub static CHACHA: Desc = Desc {
    name: "CK_SALSA20_CHACHA20_POLY1305_PARAMS",
    size: size_of::<CK_SALSA20_CHACHA20_POLY1305_PARAMS>(),
    phases: MECH,
    fields: &CHACHA_FIELDS,
};
pub static ECDH1: Desc = Desc {
    name: "CK_ECDH1_DERIVE_PARAMS",
    size: size_of::<CK_ECDH1_DERIVE_PARAMS>(),
    phases: MECH,
    fields: &ECDH1_FIELDS,
};
pub static ECDH_WRAP: Desc = Desc {
    name: "CK_ECDH_AES_KEY_WRAP_PARAMS",
    size: size_of::<CK_ECDH_AES_KEY_WRAP_PARAMS>(),
    phases: MECH,
    fields: &ECDH_WRAP_FIELDS,
};
pub static HKDF: Desc =
    Desc { name: "CK_HKDF_PARAMS", size: size_of::<CK_HKDF_PARAMS>(), phases: MECH, fields: &HKDF_FIELDS };
pub static EDDSA: Desc =
    Desc { name: "CK_EDDSA_PARAMS", size: size_of::<CK_EDDSA_PARAMS>(), phases: MECH, fields: &EDDSA_FIELDS };
pub static CHACHA20: Desc =
    Desc { name: "CK_CHACHA20_PARAMS", size: size_of::<CK_CHACHA20_PARAMS>(), phases: MECH, fields: &CHACHA20_FIELDS };
pub static SALSA20: Desc =
    Desc { name: "CK_SALSA20_PARAMS", size: size_of::<CK_SALSA20_PARAMS>(), phases: MECH, fields: &SALSA20_FIELDS };
pub static STRDATA: Desc = Desc {
    name: "CK_KEY_DERIVATION_STRING_DATA",
    size: size_of::<CK_KEY_DERIVATION_STRING_DATA>(),
    phases: MECH,
    fields: &STRDATA_FIELDS,
};
pub static AES_CBC_DATA: Desc = Desc {
    name: "CK_AES_CBC_ENCRYPT_DATA_PARAMS",
    size: size_of::<CK_AES_CBC_ENCRYPT_DATA_PARAMS>(),
    phases: MECH,
    fields: &AES_CBC_DATA_FIELDS,
};
pub static DES_CBC_DATA: Desc = Desc {
    name: "CK_DES_CBC_ENCRYPT_DATA_PARAMS",
    size: size_of::<CK_DES_CBC_ENCRYPT_DATA_PARAMS>(),
    phases: MECH,
    fields: &DES_CBC_DATA_FIELDS,
};
pub static RSA_AES_WRAP: Desc = Desc {
    name: "CK_RSA_AES_KEY_WRAP_PARAMS",
    size: size_of::<CK_RSA_AES_KEY_WRAP_PARAMS>(),
    phases: MECH,
    fields: &RSA_AES_WRAP_FIELDS,
};
pub static DSA_GEN: Desc = Desc {
    name: "CK_DSA_PARAMETER_GEN_PARAM",
    size: size_of::<CK_DSA_PARAMETER_GEN_PARAM>(),
    phases: MECH,
    fields: &DSA_GEN_FIELDS,
};
pub static IKE2_PRF_PLUS: Desc = Desc {
    name: "CK_IKE2_PRF_PLUS_DERIVE_PARAMS",
    size: size_of::<CK_IKE2_PRF_PLUS_DERIVE_PARAMS>(),
    phases: MECH,
    fields: &IKE2_PRF_PLUS_FIELDS,
};
pub static IKE_PRF: Desc = Desc {
    name: "CK_IKE_PRF_DERIVE_PARAMS",
    size: size_of::<CK_IKE_PRF_DERIVE_PARAMS>(),
    phases: MECH,
    fields: &IKE_PRF_FIELDS,
};
pub static IKE1_PRF: Desc = Desc {
    name: "CK_IKE1_PRF_DERIVE_PARAMS",
    size: size_of::<CK_IKE1_PRF_DERIVE_PARAMS>(),
    phases: MECH,
    fields: &IKE1_PRF_FIELDS,
};
pub static IKE1_EXT: Desc = Desc {
    name: "CK_IKE1_EXTENDED_DERIVE_PARAMS",
    size: size_of::<CK_IKE1_EXTENDED_DERIVE_PARAMS>(),
    phases: MECH,
    fields: &IKE1_EXT_FIELDS,
};
pub static X942_DH1: Desc = Desc {
    name: "CK_X9_42_DH1_DERIVE_PARAMS",
    size: size_of::<CK_X9_42_DH1_DERIVE_PARAMS>(),
    phases: MECH,
    fields: &X942_DH1_FIELDS,
};
pub static X942_DH2: Desc = Desc {
    name: "CK_X9_42_DH2_DERIVE_PARAMS",
    size: size_of::<CK_X9_42_DH2_DERIVE_PARAMS>(),
    phases: MECH,
    fields: &X942_DH2_FIELDS,
};
pub static X942_MQV: Desc = Desc {
    name: "CK_X9_42_MQV_DERIVE_PARAMS",
    size: size_of::<CK_X9_42_MQV_DERIVE_PARAMS>(),
    phases: MECH,
    fields: &X942_MQV_FIELDS,
};
pub static ECMQV: Desc = Desc {
    name: "CK_ECMQV_DERIVE_PARAMS",
    size: size_of::<CK_ECMQV_DERIVE_PARAMS>(),
    phases: MECH,
    fields: &ECMQV_FIELDS,
};
pub static KEA: Desc =
    Desc { name: "CK_KEA_DERIVE_PARAMS", size: size_of::<CK_KEA_DERIVE_PARAMS>(), phases: MECH, fields: &KEA_FIELDS };
pub static RC5_CBC: Desc =
    Desc { name: "CK_RC5_CBC_PARAMS", size: size_of::<CK_RC5_CBC_PARAMS>(), phases: MECH, fields: &RC5_CBC_FIELDS };
pub static GOST_DERIVE: Desc = Desc {
    name: "CK_GOSTR3410_DERIVE_PARAMS",
    size: size_of::<CK_GOSTR3410_DERIVE_PARAMS>(),
    phases: MECH,
    fields: &GOST_DERIVE_FIELDS,
};
pub static GOST_WRAP: Desc = Desc {
    name: "CK_GOSTR3410_KEY_WRAP_PARAMS",
    size: size_of::<CK_GOSTR3410_KEY_WRAP_PARAMS>(),
    phases: MECH,
    fields: &GOST_WRAP_FIELDS,
};
pub static SET_OAEP: Desc = Desc {
    name: "CK_KEY_WRAP_SET_OAEP_PARAMS",
    size: size_of::<CK_KEY_WRAP_SET_OAEP_PARAMS>(),
    phases: MECH,
    fields: &SET_OAEP_FIELDS,
};
pub static OTP: Desc =
    Desc { name: "CK_OTP_PARAMS", size: size_of::<CK_OTP_PARAMS>(), phases: MECH, fields: &OTP_FIELDS };
pub static KIP: Desc =
    Desc { name: "CK_KIP_PARAMS", size: size_of::<CK_KIP_PARAMS>(), phases: MECH, fields: &KIP_FIELDS };
pub static CMS_SIG: Desc =
    Desc { name: "CK_CMS_SIG_PARAMS", size: size_of::<CK_CMS_SIG_PARAMS>(), phases: MECH, fields: &CMS_SIG_FIELDS };
pub static TLS_KDF: Desc =
    Desc { name: "CK_TLS_KDF_PARAMS", size: size_of::<CK_TLS_KDF_PARAMS>(), phases: MECH, fields: &TLS_KDF_FIELDS };
pub static SSL3_MASTER: Desc = Desc {
    name: "CK_SSL3_MASTER_KEY_DERIVE_PARAMS",
    size: size_of::<CK_SSL3_MASTER_KEY_DERIVE_PARAMS>(),
    phases: MECH,
    fields: &SSL3_MASTER_FIELDS,
};
pub static TLS12_MASTER: Desc = Desc {
    name: "CK_TLS12_MASTER_KEY_DERIVE_PARAMS",
    size: size_of::<CK_TLS12_MASTER_KEY_DERIVE_PARAMS>(),
    phases: MECH,
    fields: &TLS12_MASTER_FIELDS,
};
pub static TLS12_EXT_MASTER: Desc = Desc {
    name: "CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS",
    size: size_of::<CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS>(),
    phases: MECH,
    fields: &TLS12_EXT_MASTER_FIELDS,
};
pub static SSL3_KEY_MAT: Desc = Desc {
    name: "CK_SSL3_KEY_MAT_PARAMS",
    size: size_of::<CK_SSL3_KEY_MAT_PARAMS>(),
    phases: MECH,
    fields: &SSL3_KEY_MAT_FIELDS,
};
pub static TLS12_KEY_MAT: Desc = Desc {
    name: "CK_TLS12_KEY_MAT_PARAMS",
    size: size_of::<CK_TLS12_KEY_MAT_PARAMS>(),
    phases: MECH,
    fields: &TLS12_KEY_MAT_FIELDS,
};
pub static TLS_PRF: Desc =
    Desc { name: "CK_TLS_PRF_PARAMS", size: size_of::<CK_TLS_PRF_PARAMS>(), phases: MECH, fields: &TLS_PRF_FIELDS };
pub static WTLS_MASTER: Desc = Desc {
    name: "CK_WTLS_MASTER_KEY_DERIVE_PARAMS",
    size: size_of::<CK_WTLS_MASTER_KEY_DERIVE_PARAMS>(),
    phases: MECH,
    fields: &WTLS_MASTER_FIELDS,
};
pub static WTLS_PRF: Desc =
    Desc { name: "CK_WTLS_PRF_PARAMS", size: size_of::<CK_WTLS_PRF_PARAMS>(), phases: MECH, fields: &WTLS_PRF_FIELDS };
pub static WTLS_KEY_MAT: Desc = Desc {
    name: "CK_WTLS_KEY_MAT_PARAMS",
    size: size_of::<CK_WTLS_KEY_MAT_PARAMS>(),
    phases: MECH,
    fields: &WTLS_KEY_MAT_FIELDS,
};
pub static PBE: Desc =
    Desc { name: "CK_PBE_PARAMS", size: size_of::<CK_PBE_PARAMS>(), phases: MECH, fields: &PBE_FIELDS };
pub static PBKD2_2: Desc = Desc {
    name: "CK_PKCS5_PBKD2_PARAMS2",
    size: size_of::<CK_PKCS5_PBKD2_PARAMS2>(),
    phases: MECH,
    fields: &PBKD2_2_FIELDS,
};
pub static PBKD2: Desc = Desc {
    name: "CK_PKCS5_PBKD2_PARAMS",
    size: size_of::<CK_PKCS5_PBKD2_PARAMS>(),
    phases: MECH,
    fields: &PBKD2_FIELDS,
};
pub static SP800: Desc = Desc {
    name: "CK_SP800_108_KDF_PARAMS",
    size: size_of::<CK_SP800_108_KDF_PARAMS>(),
    phases: MECH,
    fields: &SP800_FIELDS,
};
pub static SP800_FB: Desc = Desc {
    name: "CK_SP800_108_FEEDBACK_KDF_PARAMS",
    size: size_of::<CK_SP800_108_FEEDBACK_KDF_PARAMS>(),
    phases: MECH,
    fields: &SP800_FB_FIELDS,
};

// The optional additional context of ML-DSA and SLH-DSA signatures. The
// context string is limited to 255 bytes by the standards.
static SIGN_CTX_FIELDS: [Field; 3] = [
    ulong(o!(CK_SIGN_ADDITIONAL_CONTEXT, hedgeVariant)),
    buf_max(o!(CK_SIGN_ADDITIONAL_CONTEXT, pContext), Len::Field(2), 255),
    ulong(o!(CK_SIGN_ADDITIONAL_CONTEXT, ulContextLen)),
];
pub static SIGN_CTX: Desc = Desc {
    name: "CK_SIGN_ADDITIONAL_CONTEXT",
    size: size_of::<CK_SIGN_ADDITIONAL_CONTEXT>(),
    phases: MECH,
    fields: &SIGN_CTX_FIELDS,
};

static HASH_SIGN_CTX_FIELDS: [Field; 4] = [
    ulong(o!(CK_HASH_SIGN_ADDITIONAL_CONTEXT, hedgeVariant)),
    buf_max(o!(CK_HASH_SIGN_ADDITIONAL_CONTEXT, pContext), Len::Field(2), 255),
    ulong(o!(CK_HASH_SIGN_ADDITIONAL_CONTEXT, ulContextLen)),
    ulong(o!(CK_HASH_SIGN_ADDITIONAL_CONTEXT, hash)),
];
pub static HASH_SIGN_CTX: Desc = Desc {
    name: "CK_HASH_SIGN_ADDITIONAL_CONTEXT",
    size: size_of::<CK_HASH_SIGN_ADDITIONAL_CONTEXT>(),
    phases: MECH,
    fields: &HASH_SIGN_CTX_FIELDS,
};

/// `CK_AES_XTS_PARAMS`: the tweak key handle, then the 16-byte tweak. The
/// header of this build doesn't define it, so the layout is spelled out.
#[repr(C)]
#[derive(Debug)]
pub struct AesXtsParams {
    pub h_tweak_key: CK_OBJECT_HANDLE,
    pub cb: [u8; 16],
}
static XTS_FIELDS: [Field; 2] = [handle(o!(AesXtsParams, h_tweak_key)), inline(o!(AesXtsParams, cb), 16)];
pub static XTS: Desc =
    Desc { name: "CK_AES_XTS_PARAMS", size: size_of::<AesXtsParams>(), phases: MECH, fields: &XTS_FIELDS };

/// Every descriptor, for the consistency tests.
pub static ALL_DESCS: &[&Desc] = &[
    &OTP_PARAM,
    &RANDOM,
    &SSL3_KEY_OUT,
    &WTLS_KEY_OUT,
    &PRF_DATA,
    &DERIVED_KEY,
    &OAEP,
    &GCM_MSG,
    &CCM_MSG,
    &CHACHA_MSG,
    &GCM,
    &CCM,
    &CHACHA,
    &ECDH1,
    &ECDH_WRAP,
    &HKDF,
    &EDDSA,
    &CHACHA20,
    &SALSA20,
    &STRDATA,
    &AES_CBC_DATA,
    &DES_CBC_DATA,
    &RSA_AES_WRAP,
    &DSA_GEN,
    &IKE2_PRF_PLUS,
    &IKE_PRF,
    &IKE1_PRF,
    &IKE1_EXT,
    &X942_DH1,
    &X942_DH2,
    &X942_MQV,
    &ECMQV,
    &KEA,
    &RC5_CBC,
    &GOST_DERIVE,
    &GOST_WRAP,
    &SET_OAEP,
    &OTP,
    &KIP,
    &CMS_SIG,
    &TLS_KDF,
    &SSL3_MASTER,
    &TLS12_MASTER,
    &TLS12_EXT_MASTER,
    &SSL3_KEY_MAT,
    &TLS12_KEY_MAT,
    &TLS_PRF,
    &WTLS_MASTER,
    &WTLS_PRF,
    &WTLS_KEY_MAT,
    &PBE,
    &PBKD2_2,
    &PBKD2,
    &SP800,
    &SP800_FB,
    &SIGN_CTX,
    &HASH_SIGN_CTX,
    &XTS,
];

#[cfg(test)]
mod tests {
    use super::*;

    fn check_len(d: &Desc, l: &Len, parent: Option<&Desc>) {
        let (dd, i) = match l {
            Len::Field(i) => (d, *i),
            Len::Parent(i) => match parent {
                Some(p) => (p, *i),
                None => return, // checked where the descriptor is embedded
            },
            Len::Fixed(_) => return,
        };
        let f = dd.fields.get(i as usize).unwrap_or_else(|| panic!("{}: length index {i} out of range", d.name));
        assert!(
            matches!(f.kind, Kind::Ulong | Kind::Bool | Kind::Byte | Kind::UlongPtr),
            "{}: length member {i} is not a scalar",
            d.name
        );
    }

    fn check(d: &Desc, parent: Option<&Desc>) {
        assert!(d.size > 0, "{}", d.name);
        for f in d.fields {
            assert!(f.off < d.size, "{}: offset {} outside the structure", d.name, f.off);
            match f.kind {
                Kind::Bytes { len, .. } => check_len(d, &len, parent),
                Kind::Array { desc, count } => {
                    check_len(d, &Len::Field(count), None);
                    check(desc, Some(d));
                }
                Kind::Attrs { count } => check_len(d, &Len::Field(count), None),
                Kind::Struct(s) | Kind::Embedded(s) => check(s, Some(d)),
                _ => {}
            }
        }
    }

    #[test]
    fn descriptors_are_consistent() {
        for d in ALL_DESCS {
            check(d, None);
        }
        assert!(ALL_DESCS.len() >= 50);
    }
}
