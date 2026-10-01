// Generated from the C proxy's mechanism lists; see tools/gen_mechtab.py in the repository history.
// Which mechanisms the proxy can carry, and how each one's parameter travels.
#![allow(unreachable_patterns, clippy::all)]
use crate::desc::{Flat, Spec};
use crate::descs as d;
use core::mem::size_of;
use p11_types::*;

/// How the parameter of `m` travels, or `None` if the proxy doesn't carry `m`.
pub fn spec(m: CK_ULONG) -> Option<Spec> {
    Some(match m {
        CKM_CONCATENATE_BASE_AND_KEY => Spec::FlatHandle,
        CKM_AES_XTS => Spec::Xts,
        CKM_PKCS5_PBKD2 => Spec::Pbkd2,
        // (the ARIA, Camellia and SEED structures have the layout of the AES one)
        CKM_AES_CBC_ENCRYPT_DATA
        | CKM_ARIA_CBC_ENCRYPT_DATA
        | CKM_CAMELLIA_CBC_ENCRYPT_DATA
        | CKM_SEED_CBC_ENCRYPT_DATA => Spec::Struct(&d::AES_CBC_DATA),
        CKM_RSA_PKCS_PSS
        | CKM_SHA1_RSA_PKCS_PSS
        | CKM_SHA224_RSA_PKCS_PSS
        | CKM_SHA256_RSA_PKCS_PSS
        | CKM_SHA384_RSA_PKCS_PSS
        | CKM_SHA512_RSA_PKCS_PSS
        | CKM_SHA3_224_RSA_PKCS_PSS
        | CKM_SHA3_256_RSA_PKCS_PSS
        | CKM_SHA3_384_RSA_PKCS_PSS
        | CKM_SHA3_512_RSA_PKCS_PSS => Spec::Flat(Flat::Exact(size_of::<CK_RSA_PKCS_PSS_PARAMS>())),
        CKM_AES_CBC | CKM_AES_CBC_PAD | CKM_AES_CTS | CKM_AES_OFB | CKM_AES_CFB128 | CKM_AES_CFB64 | CKM_AES_CFB8
        | CKM_AES_CFB1 | CKM_ARIA_CBC | CKM_ARIA_CBC_PAD | CKM_CAMELLIA_CBC | CKM_CAMELLIA_CBC_PAD | CKM_SEED_CBC
        | CKM_SEED_CBC_PAD | CKM_TWOFISH_CBC | CKM_TWOFISH_CBC_PAD => Spec::Flat(Flat::Exact(16)),
        CKM_DES_CBC | CKM_DES_CBC_PAD | CKM_DES3_CBC | CKM_DES3_CBC_PAD | CKM_DES_CFB64 | CKM_DES_CFB8
        | CKM_DES_OFB64 | CKM_DES_OFB8 | CKM_BLOWFISH_CBC | CKM_BLOWFISH_CBC_PAD | CKM_CAST_CBC | CKM_CAST_CBC_PAD
        | CKM_CAST3_CBC | CKM_CAST3_CBC_PAD | CKM_CAST5_CBC | CKM_CAST5_CBC_PAD | CKM_IDEA_CBC | CKM_IDEA_CBC_PAD
        | CKM_CDMF_CBC | CKM_CDMF_CBC_PAD => Spec::Flat(Flat::Exact(8)),
        CKM_AES_CTR | CKM_CAMELLIA_CTR => Spec::Flat(Flat::Exact(size_of::<CK_AES_CTR_PARAMS>())),
        CKM_AES_KEY_WRAP => Spec::Flat(Flat::Exact(8)),
        CKM_AES_KEY_WRAP_PAD | CKM_AES_KEY_WRAP_KWP | CKM_AES_KEY_WRAP_PKCS7 => Spec::Flat(Flat::Either(4, 8)),
        CKM_MD2_HMAC_GENERAL
        | CKM_MD5_HMAC_GENERAL
        | CKM_SHA_1_HMAC_GENERAL
        | CKM_SHA224_HMAC_GENERAL
        | CKM_SHA256_HMAC_GENERAL
        | CKM_SHA384_HMAC_GENERAL
        | CKM_SHA512_HMAC_GENERAL
        | CKM_SHA512_224_HMAC_GENERAL
        | CKM_SHA512_256_HMAC_GENERAL
        | CKM_SHA3_224_HMAC_GENERAL
        | CKM_SHA3_256_HMAC_GENERAL
        | CKM_SHA3_384_HMAC_GENERAL
        | CKM_SHA3_512_HMAC_GENERAL
        | CKM_RIPEMD128_HMAC_GENERAL
        | CKM_RIPEMD160_HMAC_GENERAL
        | CKM_BLAKE2B_160_HMAC_GENERAL
        | CKM_BLAKE2B_256_HMAC_GENERAL
        | CKM_BLAKE2B_384_HMAC_GENERAL
        | CKM_BLAKE2B_512_HMAC_GENERAL
        | CKM_AES_MAC_GENERAL
        | CKM_AES_CMAC_GENERAL
        | CKM_DES_MAC_GENERAL
        | CKM_DES3_MAC_GENERAL
        | CKM_DES3_CMAC_GENERAL
        | CKM_ARIA_MAC_GENERAL
        | CKM_CAMELLIA_MAC_GENERAL
        | CKM_SEED_MAC_GENERAL
        | CKM_CAST_MAC_GENERAL
        | CKM_CAST3_MAC_GENERAL
        | CKM_CAST5_MAC_GENERAL
        | CKM_IDEA_MAC_GENERAL
        | CKM_CDMF_MAC_GENERAL
        | CKM_EXTRACT_KEY_FROM_KEY
        | CKM_RC2_ECB
        | CKM_RC2_MAC
        | CKM_SSL3_MD5_MAC
        | CKM_SSL3_SHA1_MAC => Spec::Flat(Flat::Exact(size_of::<CK_ULONG>())),
        CKM_TLS_MAC | CKM_TLS12_MAC => Spec::Flat(Flat::Exact(size_of::<CK_TLS_MAC_PARAMS>())),
        CKM_TLS10_MAC_CLIENT
        | CKM_TLS10_MAC_SERVER
        | CKM_SHA512_T
        | CKM_SHA512_T_HMAC
        | CKM_SHA512_T_HMAC_GENERAL
        | CKM_SHA512_T_KEY_DERIVATION
        | CKM_SHA512_T_KEY_GEN => Spec::Flat(Flat::Exact(size_of::<CK_ULONG>())),
        CKM_XEDDSA => Spec::Flat(Flat::Exact(size_of::<CK_XEDDSA_PARAMS>())),
        CKM_WTLS_PRE_MASTER_KEY_GEN => Spec::Flat(Flat::Exact(1)),
        CKM_RC5_MAC_GENERAL => Spec::Flat(Flat::Exact(size_of::<CK_RC5_MAC_GENERAL_PARAMS>())),
        CKM_RC5_ECB | CKM_RC5_MAC => Spec::Flat(Flat::Exact(size_of::<CK_RC5_PARAMS>())),
        CKM_RC2_CBC | CKM_RC2_CBC_PAD => Spec::Flat(Flat::Exact(size_of::<CK_RC2_CBC_PARAMS>())),
        CKM_RC2_MAC_GENERAL => Spec::Flat(Flat::Exact(size_of::<CK_RC2_MAC_GENERAL_PARAMS>())),
        CKM_SSL3_PRE_MASTER_KEY_GEN | CKM_TLS_PRE_MASTER_KEY_GEN => Spec::Flat(Flat::Exact(size_of::<CK_VERSION>())),
        CKM_DH_PKCS_DERIVE => Spec::Flat(Flat::Any(4096)),
        CKM_AES_GCM | CKM_AES_GMAC => Spec::Struct(&d::GCM),
        CKM_AES_CCM => Spec::Struct(&d::CCM),
        CKM_CHACHA20_POLY1305 | CKM_SALSA20_POLY1305 => Spec::Struct(&d::CHACHA),
        CKM_RSA_PKCS_OAEP => Spec::Struct(&d::OAEP),
        CKM_ECDH1_DERIVE | CKM_ECDH1_COFACTOR_DERIVE => Spec::Struct(&d::ECDH1),
        CKM_ECDH_AES_KEY_WRAP | CKM_ECDH_COF_AES_KEY_WRAP | CKM_ECDH_X_AES_KEY_WRAP => Spec::Struct(&d::ECDH_WRAP),
        CKM_HKDF_DERIVE | CKM_HKDF_DATA => Spec::Struct(&d::HKDF),
        CKM_EDDSA => Spec::Struct(&d::EDDSA),
        CKM_CHACHA20 => Spec::Struct(&d::CHACHA20),
        CKM_SALSA20 => Spec::Struct(&d::SALSA20),
        CKM_CONCATENATE_BASE_AND_DATA
        | CKM_CONCATENATE_DATA_AND_BASE
        | CKM_XOR_BASE_AND_DATA
        | CKM_AES_ECB_ENCRYPT_DATA
        | CKM_DES_ECB_ENCRYPT_DATA
        | CKM_DES3_ECB_ENCRYPT_DATA
        | CKM_ARIA_ECB_ENCRYPT_DATA
        | CKM_CAMELLIA_ECB_ENCRYPT_DATA
        | CKM_SEED_ECB_ENCRYPT_DATA => Spec::Struct(&d::STRDATA),
        CKM_DES_CBC_ENCRYPT_DATA | CKM_DES3_CBC_ENCRYPT_DATA => Spec::Struct(&d::DES_CBC_DATA),
        CKM_RSA_AES_KEY_WRAP => Spec::Struct(&d::RSA_AES_WRAP),
        CKM_DSA_FIPS_G_GEN | CKM_DSA_PROBABILISTIC_PARAMETER_GEN | CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN => {
            Spec::Struct(&d::DSA_GEN)
        }
        CKM_IKE2_PRF_PLUS_DERIVE => Spec::Struct(&d::IKE2_PRF_PLUS),
        CKM_IKE_PRF_DERIVE => Spec::Struct(&d::IKE_PRF),
        CKM_IKE1_PRF_DERIVE => Spec::Struct(&d::IKE1_PRF),
        CKM_IKE1_EXTENDED_DERIVE => Spec::Struct(&d::IKE1_EXT),
        CKM_X9_42_DH_DERIVE => Spec::Struct(&d::X942_DH1),
        CKM_X9_42_DH_HYBRID_DERIVE => Spec::Struct(&d::X942_DH2),
        CKM_X9_42_MQV_DERIVE => Spec::Struct(&d::X942_MQV),
        CKM_ECMQV_DERIVE => Spec::Struct(&d::ECMQV),
        CKM_KEA_DERIVE | CKM_KEA_KEY_DERIVE => Spec::Struct(&d::KEA),
        CKM_RC5_CBC | CKM_RC5_CBC_PAD => Spec::Struct(&d::RC5_CBC),
        CKM_GOSTR3410_DERIVE => Spec::Struct(&d::GOST_DERIVE),
        CKM_GOSTR3410_KEY_WRAP => Spec::Struct(&d::GOST_WRAP),
        CKM_KEY_WRAP_SET_OAEP => Spec::Struct(&d::SET_OAEP),
        CKM_SECURID | CKM_SECURID_KEY_GEN | CKM_HOTP | CKM_HOTP_KEY_GEN | CKM_ACTI | CKM_ACTI_KEY_GEN => {
            Spec::Struct(&d::OTP)
        }
        CKM_KIP_DERIVE | CKM_KIP_WRAP | CKM_KIP_MAC => Spec::Struct(&d::KIP),
        CKM_CMS_SIG => Spec::Struct(&d::CMS_SIG),
        CKM_TLS_KDF | CKM_TLS12_KDF => Spec::Struct(&d::TLS_KDF),
        CKM_SSL3_MASTER_KEY_DERIVE
        | CKM_SSL3_MASTER_KEY_DERIVE_DH
        | CKM_TLS_MASTER_KEY_DERIVE
        | CKM_TLS_MASTER_KEY_DERIVE_DH => Spec::Struct(&d::SSL3_MASTER),
        CKM_TLS12_MASTER_KEY_DERIVE | CKM_TLS12_MASTER_KEY_DERIVE_DH => Spec::Struct(&d::TLS12_MASTER),
        CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE | CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH => {
            Spec::Struct(&d::TLS12_EXT_MASTER)
        }
        CKM_SSL3_KEY_AND_MAC_DERIVE | CKM_TLS_KEY_AND_MAC_DERIVE => Spec::Struct(&d::SSL3_KEY_MAT),
        CKM_TLS12_KEY_AND_MAC_DERIVE | CKM_TLS12_KEY_SAFE_DERIVE => Spec::Struct(&d::TLS12_KEY_MAT),
        CKM_TLS_PRF => Spec::Struct(&d::TLS_PRF),
        CKM_WTLS_MASTER_KEY_DERIVE | CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC => Spec::Struct(&d::WTLS_MASTER),
        CKM_WTLS_PRF => Spec::Struct(&d::WTLS_PRF),
        CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE | CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE => Spec::Struct(&d::WTLS_KEY_MAT),
        CKM_PBE_MD2_DES_CBC
        | CKM_PBE_MD5_DES_CBC
        | CKM_PBE_MD5_CAST_CBC
        | CKM_PBE_MD5_CAST3_CBC
        | CKM_PBE_MD5_CAST5_CBC
        | CKM_PBE_SHA1_CAST5_CBC
        | CKM_PBE_SHA1_RC4_128
        | CKM_PBE_SHA1_RC4_40
        | CKM_PBE_SHA1_DES3_EDE_CBC
        | CKM_PBE_SHA1_DES2_EDE_CBC
        | CKM_PBE_SHA1_RC2_128_CBC
        | CKM_PBE_SHA1_RC2_40_CBC
        | CKM_PBA_SHA1_WITH_SHA1_HMAC => Spec::Struct(&d::PBE),
        CKM_SP800_108_COUNTER_KDF | CKM_SP800_108_DOUBLE_PIPELINE_KDF => Spec::Struct(&d::SP800),
        CKM_SP800_108_FEEDBACK_KDF => Spec::Struct(&d::SP800_FB),
        CKM_HASH_ML_DSA | CKM_HASH_SLH_DSA => Spec::OptStruct(&d::HASH_SIGN_CTX),
        CKM_ML_DSA
        | CKM_HASH_ML_DSA_SHA224
        | CKM_HASH_ML_DSA_SHA256
        | CKM_HASH_ML_DSA_SHA384
        | CKM_HASH_ML_DSA_SHA512
        | CKM_HASH_ML_DSA_SHA3_224
        | CKM_HASH_ML_DSA_SHA3_256
        | CKM_HASH_ML_DSA_SHA3_384
        | CKM_HASH_ML_DSA_SHA3_512
        | CKM_HASH_ML_DSA_SHAKE128
        | CKM_HASH_ML_DSA_SHAKE256
        | CKM_SLH_DSA
        | CKM_HASH_SLH_DSA_SHA224
        | CKM_HASH_SLH_DSA_SHA256
        | CKM_HASH_SLH_DSA_SHA384
        | CKM_HASH_SLH_DSA_SHA512
        | CKM_HASH_SLH_DSA_SHA3_224
        | CKM_HASH_SLH_DSA_SHA3_256
        | CKM_HASH_SLH_DSA_SHA3_384
        | CKM_HASH_SLH_DSA_SHA3_512
        | CKM_HASH_SLH_DSA_SHAKE128
        | CKM_HASH_SLH_DSA_SHAKE256 => Spec::OptStruct(&d::SIGN_CTX),
        CKM_RSA_PKCS_KEY_PAIR_GEN
        | CKM_RSA_X9_31_KEY_PAIR_GEN
        | CKM_RSA_PKCS
        | CKM_RSA_9796
        | CKM_RSA_X_509
        | CKM_RSA_X9_31
        | CKM_MD2_RSA_PKCS
        | CKM_MD5_RSA_PKCS
        | CKM_SHA1_RSA_PKCS
        | CKM_SHA256_RSA_PKCS
        | CKM_SHA384_RSA_PKCS
        | CKM_SHA512_RSA_PKCS
        | CKM_RIPEMD128_RSA_PKCS
        | CKM_RIPEMD160_RSA_PKCS
        | CKM_SHA1_RSA_X9_31
        | CKM_DSA_KEY_PAIR_GEN
        | CKM_DSA_PARAMETER_GEN
        | CKM_DSA
        | CKM_DSA_SHA1
        | CKM_FORTEZZA_TIMESTAMP
        | CKM_EC_KEY_PAIR_GEN
        | CKM_ECDSA
        | CKM_ECDSA_SHA1
        | CKM_DH_PKCS_KEY_PAIR_GEN
        | CKM_DH_PKCS_PARAMETER_GEN
        | CKM_X9_42_DH_KEY_PAIR_GEN
        | CKM_X9_42_DH_PARAMETER_GEN
        | CKM_KEA_KEY_PAIR_GEN
        | CKM_GENERIC_SECRET_KEY_GEN
        | CKM_RC2_KEY_GEN
        | CKM_RC4_KEY_GEN
        | CKM_RC4
        | CKM_RC5_KEY_GEN
        | CKM_AES_KEY_GEN
        | CKM_AES_ECB
        | CKM_AES_MAC
        | CKM_DES_KEY_GEN
        | CKM_DES2_KEY_GEN
        | CKM_DES3_KEY_GEN
        | CKM_CDMF_KEY_GEN
        | CKM_CAST_KEY_GEN
        | CKM_CAST3_KEY_GEN
        | CKM_CAST128_KEY_GEN
        | CKM_IDEA_KEY_GEN
        | CKM_SKIPJACK_KEY_GEN
        | CKM_BATON_KEY_GEN
        | CKM_JUNIPER_KEY_GEN
        | CKM_DES_ECB
        | CKM_DES3_ECB
        | CKM_CDMF_ECB
        | CKM_CAST_ECB
        | CKM_CAST3_ECB
        | CKM_CAST128_ECB
        | CKM_IDEA_ECB
        | CKM_DES_MAC
        | CKM_DES3_MAC
        | CKM_CDMF_MAC
        | CKM_CAST_MAC
        | CKM_CAST3_MAC
        | CKM_IDEA_MAC
        | CKM_SKIPJACK_WRAP
        | CKM_BATON_WRAP
        | CKM_JUNIPER_WRAP
        | CKM_MD2
        | CKM_MD2_HMAC
        | CKM_MD5
        | CKM_MD5_HMAC
        | CKM_SHA_1
        | CKM_SHA_1_HMAC
        | CKM_SHA256
        | CKM_SHA256_HMAC
        | CKM_SHA384
        | CKM_SHA384_HMAC
        | CKM_SHA512
        | CKM_SHA512_HMAC
        | CKM_FASTHASH
        | CKM_RIPEMD128
        | CKM_RIPEMD128_HMAC
        | CKM_RIPEMD160
        | CKM_RIPEMD160_HMAC
        | CKM_KEY_WRAP_LYNKS
        | CKM_AES_CMAC
        | CKM_SHA224
        | CKM_SHA224_HMAC
        | CKM_SHA224_RSA_PKCS
        | CKM_SHA3_224
        | CKM_SHA3_224_HMAC
        | CKM_SHA3_256
        | CKM_SHA3_256_HMAC
        | CKM_SHA3_384
        | CKM_SHA3_384_HMAC
        | CKM_SHA3_512
        | CKM_SHA3_512_HMAC
        | CKM_EC_EDWARDS_KEY_PAIR_GEN
        | CKM_EC_MONTGOMERY_KEY_PAIR_GEN
        | CKM_ML_KEM_KEY_PAIR_GEN
        | CKM_ML_KEM
        | CKM_ML_DSA_KEY_PAIR_GEN
        | CKM_SLH_DSA_KEY_PAIR_GEN
        | CKM_HSS_KEY_PAIR_GEN
        | CKM_HSS
        | CKM_XMSS_KEY_PAIR_GEN
        | CKM_XMSSMT_KEY_PAIR_GEN
        | CKM_XMSS
        | CKM_XMSSMT
        | CKM_ECDSA_SHA224
        | CKM_ECDSA_SHA256
        | CKM_ECDSA_SHA384
        | CKM_ECDSA_SHA512
        | CKM_ECDSA_SHA3_224
        | CKM_ECDSA_SHA3_256
        | CKM_ECDSA_SHA3_384
        | CKM_ECDSA_SHA3_512
        | CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS
        | CKM_DSA_SHA224
        | CKM_DSA_SHA256
        | CKM_DSA_SHA384
        | CKM_DSA_SHA512
        | CKM_DSA_SHA3_224
        | CKM_DSA_SHA3_256
        | CKM_DSA_SHA3_384
        | CKM_DSA_SHA3_512
        | CKM_SHA3_224_RSA_PKCS
        | CKM_SHA3_256_RSA_PKCS
        | CKM_SHA3_384_RSA_PKCS
        | CKM_SHA3_512_RSA_PKCS
        | CKM_SHA512_224
        | CKM_SHA512_256
        | CKM_SHA512_224_HMAC
        | CKM_SHA512_256_HMAC
        | CKM_SHA224_KEY_GEN
        | CKM_SHA256_KEY_GEN
        | CKM_SHA384_KEY_GEN
        | CKM_SHA512_KEY_GEN
        | CKM_SHA512_224_KEY_GEN
        | CKM_SHA512_256_KEY_GEN
        | CKM_SHA3_224_KEY_GEN
        | CKM_SHA3_256_KEY_GEN
        | CKM_SHA3_384_KEY_GEN
        | CKM_SHA3_512_KEY_GEN
        | CKM_SHA224_KEY_DERIVATION
        | CKM_SHA256_KEY_DERIVATION
        | CKM_SHA384_KEY_DERIVATION
        | CKM_SHA512_KEY_DERIVATION
        | CKM_SHA512_224_KEY_DERIVATION
        | CKM_SHA512_256_KEY_DERIVATION
        | CKM_SHA3_224_KEY_DERIVATION
        | CKM_SHA3_256_KEY_DERIVATION
        | CKM_SHA3_384_KEY_DERIVATION
        | CKM_SHA3_512_KEY_DERIVATION
        | CKM_SHAKE_128_KEY_DERIVATION
        | CKM_SHAKE_256_KEY_DERIVATION
        | CKM_MD2_KEY_DERIVATION
        | CKM_MD5_KEY_DERIVATION
        | CKM_BLAKE2B_160
        | CKM_BLAKE2B_256
        | CKM_BLAKE2B_384
        | CKM_BLAKE2B_512
        | CKM_BLAKE2B_160_HMAC
        | CKM_BLAKE2B_256_HMAC
        | CKM_BLAKE2B_384_HMAC
        | CKM_BLAKE2B_512_HMAC
        | CKM_BLAKE2B_160_KEY_GEN
        | CKM_BLAKE2B_256_KEY_GEN
        | CKM_BLAKE2B_384_KEY_GEN
        | CKM_BLAKE2B_512_KEY_GEN
        | CKM_BLAKE2B_160_KEY_DERIVE
        | CKM_BLAKE2B_256_KEY_DERIVE
        | CKM_BLAKE2B_384_KEY_DERIVE
        | CKM_BLAKE2B_512_KEY_DERIVE
        | CKM_HKDF_KEY_GEN
        | CKM_POLY1305
        | CKM_POLY1305_KEY_GEN
        | CKM_CHACHA20_KEY_GEN
        | CKM_SALSA20_KEY_GEN
        | CKM_AES_XTS_KEY_GEN
        | CKM_AES_XCBC_MAC
        | CKM_AES_XCBC_MAC_96
        | CKM_DES3_CMAC
        | CKM_ARIA_MAC
        | CKM_CAMELLIA_MAC
        | CKM_SEED_MAC
        | CKM_CAST5_MAC
        | CKM_ARIA_ECB
        | CKM_ARIA_KEY_GEN
        | CKM_CAMELLIA_ECB
        | CKM_CAMELLIA_KEY_GEN
        | CKM_SEED_ECB
        | CKM_SEED_KEY_GEN
        | CKM_TWOFISH_KEY_GEN
        | CKM_BLOWFISH_KEY_GEN
        | CKM_PUB_KEY_FROM_PRIV_KEY
        | CKM_NULL
        | CKM_RSA_PKCS_TPM_1_1
        | CKM_RSA_PKCS_OAEP_TPM_1_1
        | CKM_GOSTR3410
        | CKM_GOSTR3410_KEY_PAIR_GEN
        | CKM_GOSTR3410_WITH_GOSTR3411
        | CKM_GOSTR3411
        | CKM_GOSTR3411_HMAC
        | CKM_GOST28147_KEY_GEN
        | CKM_GOST28147_ECB
        | CKM_SHA1_KEY_DERIVATION
        | CKM_SHA_1_KEY_GEN => Spec::NoParam,
        _ => return None,
    })
}
