//
// rust-nss/pkcs11t.rs
//
// Primitive cryptographic types.
//
// Copyright (c) 2012 Mozilla Foundation
//

use libc::c_ulong;

type CK_ULONG = c_ulong;

// Attribute types

type CK_ATTRIBUTE_TYPE = CK_ULONG;

// FIXME: This is a botch, but it's waiting on newtype'd structs with the correct alignment.
type CKAttributeType = CK_ATTRIBUTE_TYPE;

/* The CKF_ARRAY_ATTRIBUTE flag identifies an attribute which
   consists of an array of values. */
const CKF_ARRAY_ATTRIBUTE: CKAttributeType = 0x40000000;

/* The following attribute types are defined: */
const CKA_CLASS: CKAttributeType = 0x00000000;
const CKA_TOKEN: CKAttributeType = 0x00000001;
const CKA_PRIVATE: CKAttributeType = 0x00000002;
const CKA_LABEL: CKAttributeType = 0x00000003;
const CKA_APPLICATION: CKAttributeType = 0x00000010;
const CKA_VALUE: CKAttributeType = 0x00000011;

/* CKA_OBJECT_ID is new for v2.10 */
const CKA_OBJECT_ID: CKAttributeType = 0x00000012;

const CKA_CERTIFICATE_TYPE: CKAttributeType = 0x00000080;
const CKA_ISSUER: CKAttributeType = 0x00000081;
const CKA_SERIAL_NUMBER: CKAttributeType = 0x00000082;

/* CKA_AC_ISSUER, CKA_OWNER, and CKA_ATTR_TYPES are new
 * for v2.10 */
const CKA_AC_ISSUER: CKAttributeType = 0x00000083;
const CKA_OWNER: CKAttributeType = 0x00000084;
const CKA_ATTR_TYPES: CKAttributeType = 0x00000085;

/* CKA_TRUSTED is new for v2.11 */
const CKA_TRUSTED: CKAttributeType = 0x00000086;

/* CKA_CERTIFICATE_CATEGORY ...
 * CKA_CHECK_VALUE are new for v2.20 */
const CKA_CERTIFICATE_CATEGORY: CKAttributeType = 0x00000087;
const CKA_JAVA_MIDP_SECURITY_DOMAIN: CKAttributeType = 0x00000088;
const CKA_URL: CKAttributeType = 0x00000089;
const CKA_HASH_OF_SUBJECT_PUBLIC_KEY: CKAttributeType = 0x0000008A;
const CKA_HASH_OF_ISSUER_PUBLIC_KEY: CKAttributeType = 0x0000008B;
const CKA_CHECK_VALUE: CKAttributeType = 0x00000090;

const CKA_KEY_TYPE: CKAttributeType = 0x00000100;
const CKA_SUBJECT: CKAttributeType = 0x00000101;
const CKA_ID: CKAttributeType = 0x00000102;
const CKA_SENSITIVE: CKAttributeType = 0x00000103;
const CKA_ENCRYPT: CKAttributeType = 0x00000104;
const CKA_DECRYPT: CKAttributeType = 0x00000105;
const CKA_WRAP: CKAttributeType = 0x00000106;
const CKA_UNWRAP: CKAttributeType = 0x00000107;
const CKA_SIGN: CKAttributeType = 0x00000108;
const CKA_SIGN_RECOVER: CKAttributeType = 0x00000109;
const CKA_VERIFY: CKAttributeType = 0x0000010A;
const CKA_VERIFY_RECOVER: CKAttributeType = 0x0000010B;
const CKA_DERIVE: CKAttributeType = 0x0000010C;
const CKA_START_DATE: CKAttributeType = 0x00000110;
const CKA_END_DATE: CKAttributeType = 0x00000111;
const CKA_MODULUS: CKAttributeType = 0x00000120;
const CKA_MODULUS_BITS: CKAttributeType = 0x00000121;
const CKA_PUBLIC_EXPONENT: CKAttributeType = 0x00000122;
const CKA_PRIVATE_EXPONENT: CKAttributeType = 0x00000123;
const CKA_PRIME_1: CKAttributeType = 0x00000124;
const CKA_PRIME_2: CKAttributeType = 0x00000125;
const CKA_EXPONENT_1: CKAttributeType = 0x00000126;
const CKA_EXPONENT_2: CKAttributeType = 0x00000127;
const CKA_COEFFICIENT: CKAttributeType = 0x00000128;
const CKA_PRIME: CKAttributeType = 0x00000130;
const CKA_SUBPRIME: CKAttributeType = 0x00000131;
const CKA_BASE: CKAttributeType = 0x00000132;

/* CKA_PRIME_BITS and CKA_SUB_PRIME_BITS are new for v2.11 */
const CKA_PRIME_BITS: CKAttributeType = 0x00000133;
const CKA_SUBPRIME_BITS: CKAttributeType = 0x00000134;
const CKA_SUB_PRIME_BITS: CKAttributeType = CKA_SUBPRIME_BITS;
/* (To retain backwards-compatibility) */

const CKA_VALUE_BITS: CKAttributeType = 0x00000160;
const CKA_VALUE_LEN: CKAttributeType = 0x00000161;

/* CKA_EXTRACTABLE, CKA_LOCAL, CKA_NEVER_EXTRACTABLE,
 * CKA_ALWAYS_SENSITIVE, CKA_MODIFIABLE, CKA_ECDSA_PARAMS,
 * and CKA_EC_POINT are new for v2.0 */
const CKA_EXTRACTABLE: CKAttributeType = 0x00000162;
const CKA_LOCAL: CKAttributeType = 0x00000163;
const CKA_NEVER_EXTRACTABLE: CKAttributeType = 0x00000164;
const CKA_ALWAYS_SENSITIVE: CKAttributeType = 0x00000165;

/* CKA_KEY_GEN_MECHANISM is new for v2.11 */
const CKA_KEY_GEN_MECHANISM: CKAttributeType = 0x00000166;

const CKA_MODIFIABLE: CKAttributeType = 0x00000170;

/* CKA_ECDSA_PARAMS is deprecated in v2.11,
 * CKA_EC_PARAMS is preferred. */
const CKA_ECDSA_PARAMS: CKAttributeType = 0x00000180;
const CKA_EC_PARAMS: CKAttributeType = 0x00000180;

const CKA_EC_POINT: CKAttributeType = 0x00000181;

/* CKA_SECONDARY_AUTH, CKA_AUTH_PIN_FLAGS,
 * are new for v2.10. Deprecated in v2.11 and onwards. */
const CKA_SECONDARY_AUTH: CKAttributeType = 0x00000200;
const CKA_AUTH_PIN_FLAGS: CKAttributeType = 0x00000201;

/* CKA_ALWAYS_AUTHENTICATE ...
 * CKA_UNWRAP_TEMPLATE are new for v2.20 */
const CKA_ALWAYS_AUTHENTICATE: CKAttributeType = 0x00000202;

const CKA_WRAP_WITH_TRUSTED: CKAttributeType = 0x00000210;
const CKA_WRAP_TEMPLATE: CKAttributeType = (CKF_ARRAY_ATTRIBUTE|0x00000211);
const CKA_UNWRAP_TEMPLATE: CKAttributeType = (CKF_ARRAY_ATTRIBUTE|0x00000212);

/* CKA_HW_FEATURE_TYPE, CKA_RESET_ON_INIT, and CKA_HAS_RESET
 * are new for v2.10 */
const CKA_HW_FEATURE_TYPE: CKAttributeType = 0x00000300;
const CKA_RESET_ON_INIT: CKAttributeType = 0x00000301;
const CKA_HAS_RESET: CKAttributeType = 0x00000302;

/* The following attributes are new for v2.20 */
const CKA_PIXEL_X: CKAttributeType = 0x00000400;
const CKA_PIXEL_Y: CKAttributeType = 0x00000401;
const CKA_RESOLUTION: CKAttributeType = 0x00000402;
const CKA_CHAR_ROWS: CKAttributeType = 0x00000403;
const CKA_CHAR_COLUMNS: CKAttributeType = 0x00000404;
const CKA_COLOR: CKAttributeType = 0x00000405;
const CKA_BITS_PER_PIXEL: CKAttributeType = 0x00000406;
const CKA_CHAR_SETS: CKAttributeType = 0x00000480;
const CKA_ENCODING_METHODS: CKAttributeType = 0x00000481;
const CKA_MIME_TYPES: CKAttributeType = 0x00000482;
const CKA_MECHANISM_TYPE: CKAttributeType = 0x00000500;
const CKA_REQUIRED_CMS_ATTRIBUTES: CKAttributeType = 0x00000501;
const CKA_DEFAULT_CMS_ATTRIBUTES: CKAttributeType = 0x00000502;
const CKA_SUPPORTED_CMS_ATTRIBUTES: CKAttributeType = 0x00000503;
const CKA_ALLOWED_MECHANISMS: CKAttributeType = (CKF_ARRAY_ATTRIBUTE|0x00000600);

const CKA_VENDOR_DEFINED: CKAttributeType = 0x80000000;

// Mechanism types

type CK_MECHANISM_TYPE = CK_ULONG;

// FIXME: This is a botch, but it's waiting on newtype'd structs with the correct alignment.
type CKMechanismType = CK_MECHANISM_TYPE;

/* the following mechanism types are defined: */
const CKM_RSA_PKCS_KEY_PAIR_GEN: CKMechanismType = 0x00000000;
const CKM_RSA_PKCS: CKMechanismType = 0x00000001;
const CKM_RSA_9796: CKMechanismType = 0x00000002;
const CKM_RSA_X_509: CKMechanismType = 0x00000003;

/* CKM_MD2_RSA_PKCS, CKM_MD5_RSA_PKCS, and CKM_SHA1_RSA_PKCS
 * are new for v2.0.  They are mechanisms which hash and sign */
const CKM_MD2_RSA_PKCS: CKMechanismType = 0x00000004;
const CKM_MD5_RSA_PKCS: CKMechanismType = 0x00000005;
const CKM_SHA1_RSA_PKCS: CKMechanismType = 0x00000006;

/* CKM_RIPEMD128_RSA_PKCS, CKM_RIPEMD160_RSA_PKCS, and
 * CKM_RSA_PKCS_OAEP are new for v2.10 */
const CKM_RIPEMD128_RSA_PKCS: CKMechanismType = 0x00000007;
const CKM_RIPEMD160_RSA_PKCS: CKMechanismType = 0x00000008;
const CKM_RSA_PKCS_OAEP: CKMechanismType = 0x00000009;

/* CKM_RSA_X9_31_KEY_PAIR_GEN, CKM_RSA_X9_31, CKM_SHA1_RSA_X9_31,
 * CKM_RSA_PKCS_PSS, and CKM_SHA1_RSA_PKCS_PSS are new for v2.11 */
const CKM_RSA_X9_31_KEY_PAIR_GEN: CKMechanismType = 0x0000000A;
const CKM_RSA_X9_31: CKMechanismType = 0x0000000B;
const CKM_SHA1_RSA_X9_31: CKMechanismType = 0x0000000C;
const CKM_RSA_PKCS_PSS: CKMechanismType = 0x0000000D;
const CKM_SHA1_RSA_PKCS_PSS: CKMechanismType = 0x0000000E;

const CKM_DSA_KEY_PAIR_GEN: CKMechanismType = 0x00000010;
const CKM_DSA: CKMechanismType = 0x00000011;
const CKM_DSA_SHA1: CKMechanismType = 0x00000012;
const CKM_DH_PKCS_KEY_PAIR_GEN: CKMechanismType = 0x00000020;
const CKM_DH_PKCS_DERIVE: CKMechanismType = 0x00000021;

/* CKM_X9_42_DH_KEY_PAIR_GEN, CKM_X9_42_DH_DERIVE,
 * CKM_X9_42_DH_HYBRID_DERIVE, and CKM_X9_42_MQV_DERIVE are new for
 * v2.11 */
const CKM_X9_42_DH_KEY_PAIR_GEN: CKMechanismType = 0x00000030;
const CKM_X9_42_DH_DERIVE: CKMechanismType = 0x00000031;
const CKM_X9_42_DH_HYBRID_DERIVE: CKMechanismType = 0x00000032;
const CKM_X9_42_MQV_DERIVE: CKMechanismType = 0x00000033;

/* CKM_SHA256/384/512 are new for v2.20 */
const CKM_SHA256_RSA_PKCS: CKMechanismType = 0x00000040;
const CKM_SHA384_RSA_PKCS: CKMechanismType = 0x00000041;
const CKM_SHA512_RSA_PKCS: CKMechanismType = 0x00000042;
const CKM_SHA256_RSA_PKCS_PSS: CKMechanismType = 0x00000043;
const CKM_SHA384_RSA_PKCS_PSS: CKMechanismType = 0x00000044;
const CKM_SHA512_RSA_PKCS_PSS: CKMechanismType = 0x00000045;

/* CKM_SHA224 new for v2.20 amendment 3 */
const CKM_SHA224_RSA_PKCS: CKMechanismType = 0x00000046;
const CKM_SHA224_RSA_PKCS_PSS: CKMechanismType = 0x00000047;

const CKM_RC2_KEY_GEN: CKMechanismType = 0x00000100;
const CKM_RC2_ECB: CKMechanismType = 0x00000101;
const CKM_RC2_CBC: CKMechanismType = 0x00000102;
const CKM_RC2_MAC: CKMechanismType = 0x00000103;

/* CKM_RC2_MAC_GENERAL and CKM_RC2_CBC_PAD are new for v2.0 */
const CKM_RC2_MAC_GENERAL: CKMechanismType = 0x00000104;
const CKM_RC2_CBC_PAD: CKMechanismType = 0x00000105;

const CKM_RC4_KEY_GEN: CKMechanismType = 0x00000110;
const CKM_RC4: CKMechanismType = 0x00000111;
const CKM_DES_KEY_GEN: CKMechanismType = 0x00000120;
const CKM_DES_ECB: CKMechanismType = 0x00000121;
const CKM_DES_CBC: CKMechanismType = 0x00000122;
const CKM_DES_MAC: CKMechanismType = 0x00000123;

/* CKM_DES_MAC_GENERAL and CKM_DES_CBC_PAD are new for v2.0 */
const CKM_DES_MAC_GENERAL: CKMechanismType = 0x00000124;
const CKM_DES_CBC_PAD: CKMechanismType = 0x00000125;

const CKM_DES2_KEY_GEN: CKMechanismType = 0x00000130;
const CKM_DES3_KEY_GEN: CKMechanismType = 0x00000131;
const CKM_DES3_ECB: CKMechanismType = 0x00000132;
const CKM_DES3_CBC: CKMechanismType = 0x00000133;
const CKM_DES3_MAC: CKMechanismType = 0x00000134;

/* CKM_DES3_MAC_GENERAL, CKM_DES3_CBC_PAD, CKM_CDMF_KEY_GEN,
 * CKM_CDMF_ECB, CKM_CDMF_CBC, CKM_CDMF_MAC,
 * CKM_CDMF_MAC_GENERAL, and CKM_CDMF_CBC_PAD are new for v2.0 */
const CKM_DES3_MAC_GENERAL: CKMechanismType = 0x00000135;
const CKM_DES3_CBC_PAD: CKMechanismType = 0x00000136;
const CKM_CDMF_KEY_GEN: CKMechanismType = 0x00000140;
const CKM_CDMF_ECB: CKMechanismType = 0x00000141;
const CKM_CDMF_CBC: CKMechanismType = 0x00000142;
const CKM_CDMF_MAC: CKMechanismType = 0x00000143;
const CKM_CDMF_MAC_GENERAL: CKMechanismType = 0x00000144;
const CKM_CDMF_CBC_PAD: CKMechanismType = 0x00000145;

/* the following four DES mechanisms are new for v2.20 */
const CKM_DES_OFB64: CKMechanismType = 0x00000150;
const CKM_DES_OFB8: CKMechanismType = 0x00000151;
const CKM_DES_CFB64: CKMechanismType = 0x00000152;
const CKM_DES_CFB8: CKMechanismType = 0x00000153;

const CKM_MD2: CKMechanismType = 0x00000200;

/* CKM_MD2_HMAC and CKM_MD2_HMAC_GENERAL are new for v2.0 */
const CKM_MD2_HMAC: CKMechanismType = 0x00000201;
const CKM_MD2_HMAC_GENERAL: CKMechanismType = 0x00000202;

const CKM_MD5: CKMechanismType = 0x00000210;

/* CKM_MD5_HMAC and CKM_MD5_HMAC_GENERAL are new for v2.0 */
const CKM_MD5_HMAC: CKMechanismType = 0x00000211;
const CKM_MD5_HMAC_GENERAL: CKMechanismType = 0x00000212;

const CKM_SHA_1: CKMechanismType = 0x00000220;

/* CKM_SHA_1_HMAC and CKM_SHA_1_HMAC_GENERAL are new for v2.0 */
const CKM_SHA_1_HMAC: CKMechanismType = 0x00000221;
const CKM_SHA_1_HMAC_GENERAL: CKMechanismType = 0x00000222;

/* CKM_RIPEMD128, CKM_RIPEMD128_HMAC,
 * CKM_RIPEMD128_HMAC_GENERAL, CKM_RIPEMD160, CKM_RIPEMD160_HMAC,
 * and CKM_RIPEMD160_HMAC_GENERAL are new for v2.10 */
const CKM_RIPEMD128: CKMechanismType = 0x00000230;
const CKM_RIPEMD128_HMAC: CKMechanismType = 0x00000231;
const CKM_RIPEMD128_HMAC_GENERAL: CKMechanismType = 0x00000232;
const CKM_RIPEMD160: CKMechanismType = 0x00000240;
const CKM_RIPEMD160_HMAC: CKMechanismType = 0x00000241;
const CKM_RIPEMD160_HMAC_GENERAL: CKMechanismType = 0x00000242;

/* CKM_SHA256/384/512 are new for v2.20 */
const CKM_SHA256: CKMechanismType = 0x00000250;
const CKM_SHA256_HMAC: CKMechanismType = 0x00000251;
const CKM_SHA256_HMAC_GENERAL: CKMechanismType = 0x00000252;
const CKM_SHA384: CKMechanismType = 0x00000260;
const CKM_SHA384_HMAC: CKMechanismType = 0x00000261;
const CKM_SHA384_HMAC_GENERAL: CKMechanismType = 0x00000262;
const CKM_SHA512: CKMechanismType = 0x00000270;
const CKM_SHA512_HMAC: CKMechanismType = 0x00000271;
const CKM_SHA512_HMAC_GENERAL: CKMechanismType = 0x00000272;

/* CKM_SHA224 new for v2.20 amendment 3 */
const CKM_SHA224: CKMechanismType = 0x00000255;
const CKM_SHA224_HMAC: CKMechanismType = 0x00000256;
const CKM_SHA224_HMAC_GENERAL: CKMechanismType = 0x00000257;

/* All of the following mechanisms are new for v2.0 */
/* Note that CAST128 and CAST5 are the same algorithm */
const CKM_CAST_KEY_GEN: CKMechanismType = 0x00000300;
const CKM_CAST_ECB: CKMechanismType = 0x00000301;
const CKM_CAST_CBC: CKMechanismType = 0x00000302;
const CKM_CAST_MAC: CKMechanismType = 0x00000303;
const CKM_CAST_MAC_GENERAL: CKMechanismType = 0x00000304;
const CKM_CAST_CBC_PAD: CKMechanismType = 0x00000305;
const CKM_CAST3_KEY_GEN: CKMechanismType = 0x00000310;
const CKM_CAST3_ECB: CKMechanismType = 0x00000311;
const CKM_CAST3_CBC: CKMechanismType = 0x00000312;
const CKM_CAST3_MAC: CKMechanismType = 0x00000313;
const CKM_CAST3_MAC_GENERAL: CKMechanismType = 0x00000314;
const CKM_CAST3_CBC_PAD: CKMechanismType = 0x00000315;
const CKM_CAST5_KEY_GEN: CKMechanismType = 0x00000320;
const CKM_CAST128_KEY_GEN: CKMechanismType = 0x00000320;
const CKM_CAST5_ECB: CKMechanismType = 0x00000321;
const CKM_CAST128_ECB: CKMechanismType = 0x00000321;
const CKM_CAST5_CBC: CKMechanismType = 0x00000322;
const CKM_CAST128_CBC: CKMechanismType = 0x00000322;
const CKM_CAST5_MAC: CKMechanismType = 0x00000323;
const CKM_CAST128_MAC: CKMechanismType = 0x00000323;
const CKM_CAST5_MAC_GENERAL: CKMechanismType = 0x00000324;
const CKM_CAST128_MAC_GENERAL: CKMechanismType = 0x00000324;
const CKM_CAST5_CBC_PAD: CKMechanismType = 0x00000325;
const CKM_CAST128_CBC_PAD: CKMechanismType = 0x00000325;
const CKM_RC5_KEY_GEN: CKMechanismType = 0x00000330;
const CKM_RC5_ECB: CKMechanismType = 0x00000331;
const CKM_RC5_CBC: CKMechanismType = 0x00000332;
const CKM_RC5_MAC: CKMechanismType = 0x00000333;
const CKM_RC5_MAC_GENERAL: CKMechanismType = 0x00000334;
const CKM_RC5_CBC_PAD: CKMechanismType = 0x00000335;
const CKM_IDEA_KEY_GEN: CKMechanismType = 0x00000340;
const CKM_IDEA_ECB: CKMechanismType = 0x00000341;
const CKM_IDEA_CBC: CKMechanismType = 0x00000342;
const CKM_IDEA_MAC: CKMechanismType = 0x00000343;
const CKM_IDEA_MAC_GENERAL: CKMechanismType = 0x00000344;
const CKM_IDEA_CBC_PAD: CKMechanismType = 0x00000345;
const CKM_GENERIC_SECRET_KEY_GEN: CKMechanismType = 0x00000350;
const CKM_CONCATENATE_BASE_AND_KEY: CKMechanismType = 0x00000360;
const CKM_CONCATENATE_BASE_AND_DATA: CKMechanismType = 0x00000362;
const CKM_CONCATENATE_DATA_AND_BASE: CKMechanismType = 0x00000363;
const CKM_XOR_BASE_AND_DATA: CKMechanismType = 0x00000364;
const CKM_EXTRACT_KEY_FROM_KEY: CKMechanismType = 0x00000365;
const CKM_SSL3_PRE_MASTER_KEY_GEN: CKMechanismType = 0x00000370;
const CKM_SSL3_MASTER_KEY_DERIVE: CKMechanismType = 0x00000371;
const CKM_SSL3_KEY_AND_MAC_DERIVE: CKMechanismType = 0x00000372;

/* CKM_SSL3_MASTER_KEY_DERIVE_DH, CKM_TLS_PRE_MASTER_KEY_GEN,
 * CKM_TLS_MASTER_KEY_DERIVE, CKM_TLS_KEY_AND_MAC_DERIVE, and
 * CKM_TLS_MASTER_KEY_DERIVE_DH are new for v2.11 */
const CKM_SSL3_MASTER_KEY_DERIVE_DH: CKMechanismType = 0x00000373;
const CKM_TLS_PRE_MASTER_KEY_GEN: CKMechanismType = 0x00000374;
const CKM_TLS_MASTER_KEY_DERIVE: CKMechanismType = 0x00000375;
const CKM_TLS_KEY_AND_MAC_DERIVE: CKMechanismType = 0x00000376;
const CKM_TLS_MASTER_KEY_DERIVE_DH: CKMechanismType = 0x00000377;

/* CKM_TLS_PRF is new for v2.20 */
const CKM_TLS_PRF: CKMechanismType = 0x00000378;

const CKM_SSL3_MD5_MAC: CKMechanismType = 0x00000380;
const CKM_SSL3_SHA1_MAC: CKMechanismType = 0x00000381;
const CKM_MD5_KEY_DERIVATION: CKMechanismType = 0x00000390;
const CKM_MD2_KEY_DERIVATION: CKMechanismType = 0x00000391;
const CKM_SHA1_KEY_DERIVATION: CKMechanismType = 0x00000392;

/* CKM_SHA256/384/512 are new for v2.20 */
const CKM_SHA256_KEY_DERIVATION: CKMechanismType = 0x00000393;
const CKM_SHA384_KEY_DERIVATION: CKMechanismType = 0x00000394;
const CKM_SHA512_KEY_DERIVATION: CKMechanismType = 0x00000395;

/* CKM_SHA224 new for v2.20 amendment 3 */
const CKM_SHA224_KEY_DERIVATION: CKMechanismType = 0x00000396;

const CKM_PBE_MD2_DES_CBC: CKMechanismType = 0x000003A0;
const CKM_PBE_MD5_DES_CBC: CKMechanismType = 0x000003A1;
const CKM_PBE_MD5_CAST_CBC: CKMechanismType = 0x000003A2;
const CKM_PBE_MD5_CAST3_CBC: CKMechanismType = 0x000003A3;
const CKM_PBE_MD5_CAST5_CBC: CKMechanismType = 0x000003A4;
const CKM_PBE_MD5_CAST128_CBC: CKMechanismType = 0x000003A4;
const CKM_PBE_SHA1_CAST5_CBC: CKMechanismType = 0x000003A5;
const CKM_PBE_SHA1_CAST128_CBC: CKMechanismType = 0x000003A5;
const CKM_PBE_SHA1_RC4_128: CKMechanismType = 0x000003A6;
const CKM_PBE_SHA1_RC4_40: CKMechanismType = 0x000003A7;
const CKM_PBE_SHA1_DES3_EDE_CBC: CKMechanismType = 0x000003A8;
const CKM_PBE_SHA1_DES2_EDE_CBC: CKMechanismType = 0x000003A9;
const CKM_PBE_SHA1_RC2_128_CBC: CKMechanismType = 0x000003AA;
const CKM_PBE_SHA1_RC2_40_CBC: CKMechanismType = 0x000003AB;

/* CKM_PKCS5_PBKD2 is new for v2.10 */
const CKM_PKCS5_PBKD2: CKMechanismType = 0x000003B0;

const CKM_PBA_SHA1_WITH_SHA1_HMAC: CKMechanismType = 0x000003C0;

/* WTLS mechanisms are new for v2.20 */
const CKM_WTLS_PRE_MASTER_KEY_GEN: CKMechanismType = 0x000003D0;
const CKM_WTLS_MASTER_KEY_DERIVE: CKMechanismType = 0x000003D1;
const CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC: CKMechanismType = 0x000003D2;
const CKM_WTLS_PRF: CKMechanismType = 0x000003D3;
const CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE: CKMechanismType = 0x000003D4;
const CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE: CKMechanismType = 0x000003D5;

const CKM_KEY_WRAP_LYNKS: CKMechanismType = 0x00000400;
const CKM_KEY_WRAP_SET_OAEP: CKMechanismType = 0x00000401;

/* CKM_CMS_SIG is new for v2.20 */
const CKM_CMS_SIG: CKMechanismType = 0x00000500;

/* Fortezza mechanisms */
const CKM_SKIPJACK_KEY_GEN: CKMechanismType = 0x00001000;
const CKM_SKIPJACK_ECB64: CKMechanismType = 0x00001001;
const CKM_SKIPJACK_CBC64: CKMechanismType = 0x00001002;
const CKM_SKIPJACK_OFB64: CKMechanismType = 0x00001003;
const CKM_SKIPJACK_CFB64: CKMechanismType = 0x00001004;
const CKM_SKIPJACK_CFB32: CKMechanismType = 0x00001005;
const CKM_SKIPJACK_CFB16: CKMechanismType = 0x00001006;
const CKM_SKIPJACK_CFB8: CKMechanismType = 0x00001007;
const CKM_SKIPJACK_WRAP: CKMechanismType = 0x00001008;
const CKM_SKIPJACK_PRIVATE_WRAP: CKMechanismType = 0x00001009;
const CKM_SKIPJACK_RELAYX: CKMechanismType = 0x0000100a;
const CKM_KEA_KEY_PAIR_GEN: CKMechanismType = 0x00001010;
const CKM_KEA_KEY_DERIVE: CKMechanismType = 0x00001011;
const CKM_FORTEZZA_TIMESTAMP: CKMechanismType = 0x00001020;
const CKM_BATON_KEY_GEN: CKMechanismType = 0x00001030;
const CKM_BATON_ECB128: CKMechanismType = 0x00001031;
const CKM_BATON_ECB96: CKMechanismType = 0x00001032;
const CKM_BATON_CBC128: CKMechanismType = 0x00001033;
const CKM_BATON_COUNTER: CKMechanismType = 0x00001034;
const CKM_BATON_SHUFFLE: CKMechanismType = 0x00001035;
const CKM_BATON_WRAP: CKMechanismType = 0x00001036;

/* CKM_ECDSA_KEY_PAIR_GEN is deprecated in v2.11,
 * CKM_EC_KEY_PAIR_GEN is preferred */
const CKM_ECDSA_KEY_PAIR_GEN: CKMechanismType = 0x00001040;
const CKM_EC_KEY_PAIR_GEN: CKMechanismType = 0x00001040;

const CKM_ECDSA: CKMechanismType = 0x00001041;
const CKM_ECDSA_SHA1: CKMechanismType = 0x00001042;

/* CKM_ECDH1_DERIVE, CKM_ECDH1_COFACTOR_DERIVE, and CKM_ECMQV_DERIVE
 * are new for v2.11 */
const CKM_ECDH1_DERIVE: CKMechanismType = 0x00001050;
const CKM_ECDH1_COFACTOR_DERIVE: CKMechanismType = 0x00001051;
const CKM_ECMQV_DERIVE: CKMechanismType = 0x00001052;

const CKM_JUNIPER_KEY_GEN: CKMechanismType = 0x00001060;
const CKM_JUNIPER_ECB128: CKMechanismType = 0x00001061;
const CKM_JUNIPER_CBC128: CKMechanismType = 0x00001062;
const CKM_JUNIPER_COUNTER: CKMechanismType = 0x00001063;
const CKM_JUNIPER_SHUFFLE: CKMechanismType = 0x00001064;
const CKM_JUNIPER_WRAP: CKMechanismType = 0x00001065;
const CKM_FASTHASH: CKMechanismType = 0x00001070;

/* CKM_AES_KEY_GEN, CKM_AES_ECB, CKM_AES_CBC, CKM_AES_MAC,
 * CKM_AES_MAC_GENERAL, CKM_AES_CBC_PAD, CKM_DSA_PARAMETER_GEN,
 * CKM_DH_PKCS_PARAMETER_GEN, and CKM_X9_42_DH_PARAMETER_GEN are
 * new for v2.11 */
const CKM_AES_KEY_GEN: CKMechanismType = 0x00001080;
const CKM_AES_ECB: CKMechanismType = 0x00001081;
const CKM_AES_CBC: CKMechanismType = 0x00001082;
const CKM_AES_MAC: CKMechanismType = 0x00001083;
const CKM_AES_MAC_GENERAL: CKMechanismType = 0x00001084;
const CKM_AES_CBC_PAD: CKMechanismType = 0x00001085;

/* BlowFish and TwoFish are new for v2.20 */
const CKM_BLOWFISH_KEY_GEN: CKMechanismType = 0x00001090;
const CKM_BLOWFISH_CBC: CKMechanismType = 0x00001091;
const CKM_TWOFISH_KEY_GEN: CKMechanismType = 0x00001092;
const CKM_TWOFISH_CBC: CKMechanismType = 0x00001093;

/* Camellia is proposed for v2.20 Amendment 3 */
const CKM_CAMELLIA_KEY_GEN: CKMechanismType = 0x00000550;
const CKM_CAMELLIA_ECB: CKMechanismType = 0x00000551;
const CKM_CAMELLIA_CBC: CKMechanismType = 0x00000552;
const CKM_CAMELLIA_MAC: CKMechanismType = 0x00000553;
const CKM_CAMELLIA_MAC_GENERAL: CKMechanismType = 0x00000554;
const CKM_CAMELLIA_CBC_PAD: CKMechanismType = 0x00000555;
const CKM_CAMELLIA_ECB_ENCRYPT_DATA: CKMechanismType = 0x00000556;
const CKM_CAMELLIA_CBC_ENCRYPT_DATA: CKMechanismType = 0x00000557;

const CKM_SEED_KEY_GEN: CKMechanismType = 0x00000650;    
const CKM_SEED_ECB: CKMechanismType = 0x00000651;
const CKM_SEED_CBC: CKMechanismType = 0x00000652;
const CKM_SEED_MAC: CKMechanismType = 0x00000653;
const CKM_SEED_MAC_GENERAL: CKMechanismType = 0x00000654;
const CKM_SEED_CBC_PAD: CKMechanismType = 0x00000655;
const CKM_SEED_ECB_ENCRYPT_DATA: CKMechanismType = 0x00000656;
const CKM_SEED_CBC_ENCRYPT_DATA: CKMechanismType = 0x00000657;

/* CKM_xxx_ENCRYPT_DATA mechanisms are new for v2.20 */
const CKM_DES_ECB_ENCRYPT_DATA: CKMechanismType = 0x00001100;
const CKM_DES_CBC_ENCRYPT_DATA: CKMechanismType = 0x00001101;
const CKM_DES3_ECB_ENCRYPT_DATA: CKMechanismType = 0x00001102;
const CKM_DES3_CBC_ENCRYPT_DATA: CKMechanismType = 0x00001103;
const CKM_AES_ECB_ENCRYPT_DATA: CKMechanismType = 0x00001104;
const CKM_AES_CBC_ENCRYPT_DATA: CKMechanismType = 0x00001105;

const CKM_DSA_PARAMETER_GEN: CKMechanismType = 0x00002000;
const CKM_DH_PKCS_PARAMETER_GEN: CKMechanismType = 0x00002001;
const CKM_X9_42_DH_PARAMETER_GEN: CKMechanismType = 0x00002002;

const CKM_VENDOR_DEFINED: CKMechanismType = 0x80000000;

