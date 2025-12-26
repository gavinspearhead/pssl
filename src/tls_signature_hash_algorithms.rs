use serde::{Deserialize, Serialize};
use std::fmt::Display;
use strum_macros::{EnumIter, EnumString, FromRepr, IntoStaticStr};

#[derive(
    EnumIter,
    EnumString,
    FromRepr,
    IntoStaticStr,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Default,
    Serialize,
    Deserialize,
    PartialOrd,
    Ord,
)]
#[repr(u16)]
pub enum TlsSignatureScheme {
    // --- Legacy (TLS 1.2) algorithms ---
    #[default]
    Unknown = 0x0000,
    RsaPkcs1Sha1 = 0x0201,
    EcdsaSha1 = 0x0203,

    // --- SHA-2 based (TLS 1.2) ---
    RsaPkcs1Sha256 = 0x0401,
    EcdsaSecp256r1Sha256 = 0x0403,
    RsaPkcs1Sha384 = 0x0501,
    EcdsaSecp384r1Sha384 = 0x0503,
    RsaPkcs1Sha512 = 0x0601,
    EcdsaSecp521r1Sha512 = 0x0603,
    RsaPkcs1Sha384Legacy = 0x0520,
    RsaPkcs1Sha512Legacy = 0x0620,
    EccsiSha256 = 0x0704,
    IsoIbs1 = 0x0705,
    IsoIbs2 = 0x0706,
    IsoChineseIbs = 0x0707,
    Gostr34102012256a = 0x0709,
    Gostr34102012256b = 0x070A,
    Gostr34102012256c = 0x070B,
    Gostr34102012256d = 0x070C,
    Gostr34102012512a = 0x070D,
    Gostr34102012512b = 0x070E,
    Gostr34102012512c = 0x070f,
    EcdsaBrainpoolP256r1tls13Sha256 = 0x081a,
    EcdsaBrainpoolP384r1tls13Sha384 = 0x081b,
    EcdsaBrainpoolP512r1tls13Sha512 = 0x081c,
    Mldsa44 = 0x0904,
    Mldsa65 = 0x0905,
    Mldsa87 = 0x0906,

    SlhdsaSha2128s = 0x0911,
    SlhdsaSha2128f = 0x0912,
    SlhdsaSha2192s = 0x0913,
    SlhdsaSha2192f = 0x0914,
    SlhdsaSha2256s = 0x0915,
    SlhdsaSha2256f = 0x0916,

    SlhdsaShake128s = 0x917,
    SlhdsaShake128f = 0x918,
    SlhdsaShake192s = 0x919,
    SlhdsaShake192f = 0x91a,
    SlhdsaShake256s = 0x91b,
    SlhdsaShake256f = 0x91c,

    // --- RSASSA-PSS (RFC 8446 / TLS 1.3) ---
    RsaPssRsaeSha256 = 0x0804,
    RsaPssRsaeSha384 = 0x0805,
    RsaPssRsaeSha512 = 0x0806,
    RsaPssPssSha256 = 0x0809,
    RsaPssPssSha384 = 0x080A,
    RsaPssPssSha512 = 0x080B,

    // --- EdDSA (RFC 8422 / RFC 8446) ---
    Ed25519 = 0x0807,
    Ed448 = 0x0808,

    // --- SM2 (RFC 8998) ---
    Sm2sigSm3 = 0x0708,

    // --- RSASSA-PKCS1 with MD5/SHA-1 (obsolete / deprecated) ---
    RsaPkcs1Md5Sha1 = 0x0101,

    // --- Post-Quantum / Hybrid (drafts, experimental use only) ---
    // Hybrid PQC key exchange with classical signature algorithms
    // Defined in drafts like draft-ietf-tls-hybrid-design, draft-tls-wiggers-pqtls-hybrid
    RsaPkcs1Sha256Kyber768Draft00 = 0xFE00,
    EcdsaSecp256r1Sha256Kyber768Draft00 = 0xFE01,
    RsaPssRsaeSha256Kyber768Draft00 = 0xFE02,
    Ed25519Kyber768Draft00 = 0xFE03,
    Ed448Kyber768Draft00 = 0xFE04,

    // (Optional placeholders for future PQC)
    Dilithium2 = 0xFE30,
    Dilithium3 = 0xFE31,
    Falcon512 = 0xFE32,
    Falcon1024 = 0xFE33,
}

impl TlsSignatureScheme {
    pub fn from_u16(id: u16) -> Option<Self> {
        Self::from_repr(id)
    }

    pub fn to_u16(self) -> u16 {
        self as u16
    }

    pub fn as_str(self) -> &'static str {
        self.into()
    }
}
impl Display for TlsSignatureScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
