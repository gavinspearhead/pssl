use crate::ssl_helper::is_grease;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::fmt::Display;
use strum_macros::{EnumIter, EnumString, FromRepr, IntoStaticStr};
use tracing::debug;

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
pub enum TlsSignatureSchemeValue {
    // --- Legacy (TLS 1.2) algorithms ---
    #[default]
    Unknown = 0x0000,
    RsaPkcs1Sha1 = 0x0201,
    EcdsaSha1 = 0x0203,
    DsaSha1 = 0x0202,
    RsaPkcs1Sha224 = 0x301,
    DsaSha224 = 0x0302,
    EcdsaSha224 = 0x303,
    DsaSha256 = 0x0402,
    DsaSha384 = 0x0502,
    DsaSha512 = 0x0602,
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
#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub enum TlsSignatureScheme {
    Known(TlsSignatureSchemeValue),
    Unknown(u16),
    Grease,
}

impl Serialize for TlsSignatureScheme {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let value: Cow<'static, str> = match self {
            TlsSignatureScheme::Known(known) => Cow::Borrowed(known.into()),
            TlsSignatureScheme::Unknown(unknown) => Cow::Owned(format!("Unknown ({unknown:x})")),
            TlsSignatureScheme::Grease => Cow::Borrowed("Grease"),
        };
        value.serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for TlsSignatureScheme {
    fn deserialize<D>(deserializer: D) -> Result<TlsSignatureScheme, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s == "Grease" {
            return Ok(TlsSignatureScheme::Grease);
        }

        if let Ok(known) = s.parse::<TlsSignatureSchemeValue>() {
            return Ok(TlsSignatureScheme::Known(known));
        }

        if s.starts_with("Unknown (") && s.ends_with(')') {
            let hex_part = &s[9..s.len() - 1];
            debug!("{hex_part}");
            if let Ok(id) = u16::from_str_radix(hex_part, 16) {
                return Ok(TlsSignatureScheme::Unknown(id));
            }
        }

        Ok(TlsSignatureScheme::Unknown(0))
    }
}

impl Default for TlsSignatureScheme {
    #[inline]
    fn default() -> Self {
        TlsSignatureScheme::Known(TlsSignatureSchemeValue::Unknown)
    }
}

impl TlsSignatureScheme {
    #[must_use]
    pub fn from_u16(id: u16) -> Self {
        if is_grease(id) {
            TlsSignatureScheme::Grease
        } else {
            match TlsSignatureSchemeValue::from_repr(id) {
                Some(known) => TlsSignatureScheme::Known(known),
                None => TlsSignatureScheme::Unknown(id),
            }
        }
    }

    #[must_use]
    pub fn to_u16(self) -> u16 {
        match self {
            TlsSignatureScheme::Known(known) => known as u16,
            TlsSignatureScheme::Unknown(unknown) => unknown,
            TlsSignatureScheme::Grease => 0x0a0a,
        }
    }

    #[must_use]
    pub fn as_str(self) -> String {
        match self {
            TlsSignatureScheme::Known(known) => Cow::Borrowed(known.into()),
            TlsSignatureScheme::Unknown(val) => Cow::Owned(format!("Unknown ({val:x})")),
            TlsSignatureScheme::Grease => Cow::Borrowed("Grease"),
        }
        .into_owned()
    }
}
impl Display for TlsSignatureScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
