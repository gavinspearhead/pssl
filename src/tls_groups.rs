use crate::tls_groups::TlsSupportedGroup::Known;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use strum_macros::{EnumIter, EnumString, FromRepr, IntoStaticStr};
use crate::ssl_helper::is_grease;

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
    Ord,
    PartialOrd,
    Serialize,
    Deserialize,
)]
#[repr(u16)]
pub enum TlsSupportedGroupValue {
    // Elliptic Curve Groups (RFC 4492, RFC 8422, RFC 7919, RFC 8446)
    #[default]
    Unknown = 0x0000,
    Sect163K1 = 0x0001,
    Sect163R1 = 0x0002,
    Sect163R2 = 0x0003,
    Sect193R1 = 0x0004,
    Sect193R2 = 0x0005,
    Sect233K1 = 0x0006,
    Sect233R1 = 0x0007,
    Sect239K1 = 0x0008,
    Sect283K1 = 0x0009,
    Sect283R1 = 0x000A,
    Sect409K1 = 0x000B,
    Sect409R1 = 0x000C,
    Sect571K1 = 0x000D,
    Sect571R1 = 0x000E,
    Secp160K1 = 0x000F,
    Secp160R1 = 0x0010,
    Secp160R2 = 0x0011,
    Secp192K1 = 0x0012,
    Secp192R1 = 0x0013,
    Secp224K1 = 0x0014,
    Secp224R1 = 0x0015,
    Secp256K1 = 0x0016,
    Secp256R1 = 0x0017,
    Secp384R1 = 0x0018,
    Secp521R1 = 0x0019,

    // RFC 7027: Brainpool Curves
    BrainpoolP256R1 = 0x001A,
    BrainpoolP384R1 = 0x001B,
    BrainpoolP512R1 = 0x001C,
    // RFC 8734: Brainpool Curves for TLS 1.3
    BrainpoolP256r1tls13 = 0x001f,
    BrainpoolP384r1tls13 = 0x0020,
    BrainpoolP512r1tls13 = 0x0021,
    GC256A = 34,
    GC256B = 35,
    GC256C = 36,
    GC256D = 37,
    GC512A = 38,
    GC512B = 39,
    GC512C = 40,
    CurveSM2 = 41,
    Ffdhe2048 = 256,
    Ffdhe3072 = 257,
    Ffdhe4096 = 258,
    Ffdhe6144 = 259,
    Ffdhe8192 = 260,

    // RFC 8422, RFC 8446
    X25519 = 0x001D,
    X448 = 0x001E,

    MLKEM512 = 512,
    MLKEM768 = 513,
    MLKEM1024 = 514,
    SecP256r1MLKEM768 = 4587,
    X25519MLKEM768 = 4588,
    SecP384r1MLKEM1024 = 4589,
    CurveSM2MLKEM768 = 4590,
    X25519Kyber768Draft00 = 25497,
    SecP256r1Kyber768Draft00 = 25498,
    ArbitraryExplicitPrimeCurves = 65281,
    ArbitraryExplicitChar2Curves = 65282,
}
#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub enum TlsSupportedGroup {
    Known(TlsSupportedGroupValue),
    Unknown(u16),
    Grease
}

impl Serialize for TlsSupportedGroup {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let value: Cow<'static, str> = match self {
            TlsSupportedGroup::Known(known) => Cow::Borrowed(known.into()),
            TlsSupportedGroup::Unknown(unknown) => Cow::Owned(format!("Unknown ({unknown:x})")),
            TlsSupportedGroup::Grease => Cow::Borrowed("Grease"),
        };
        value.serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for TlsSupportedGroup {
    fn deserialize<D>(deserializer: D) -> Result<TlsSupportedGroup, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<'de, str>::deserialize(deserializer)?;

        if s == "Grease" {
            return Ok(TlsSupportedGroup::Grease);
        }

        // Try to parse as a known variant name
        if let Ok(value) = TlsSupportedGroupValue::try_from(s.as_ref()) {
            return Ok(TlsSupportedGroup::Known(value));
        }

        // Handle "Unknown (hex)" format
        if s.starts_with("Unknown (") && s.ends_with(')') {
            let hex_part = &s[9..s.len() - 1];
            if let Ok(id) = u16::from_str_radix(hex_part, 16) {
                return Ok(TlsSupportedGroup::from_u16(id).unwrap_or(TlsSupportedGroup::Unknown(id)));
            }
        }

        // Fallback or error
        Ok(TlsSupportedGroup::Unknown(0))
    }
}


impl Default for TlsSupportedGroup {
    fn default() -> Self {
        TlsSupportedGroup::Unknown(0)
    }
}

impl TlsSupportedGroup {
    #[must_use] 
    pub fn from_u16(id: u16) -> Option<Self> {
        if is_grease(id) {
            Some(TlsSupportedGroup::Grease)
        } else {
            match TlsSupportedGroupValue::from_repr(id) {
                Some(known) => Some(TlsSupportedGroup::Known(known)),
                None => Some(TlsSupportedGroup::Unknown(id)),
            }
        }
    }
    #[must_use] 
    pub fn to_u16(self) -> u16 {
        match self {
            Known(known) => known as u16,
            TlsSupportedGroup::Unknown(unknown) => unknown,
            TlsSupportedGroup::Grease => 0x0a0a,
        }
    }

    #[inline]
    #[must_use] 
    pub fn to_str(self) -> Cow<'static, str> {
        match self {
            Known(known) => Cow::Borrowed(known.into()),
            TlsSupportedGroup::Unknown(val) => Cow::Owned(format!("Unknown ({val:x})")),
            TlsSupportedGroup::Grease => Cow::Borrowed("Grease"),
        }
    }

    #[must_use] 
    pub fn as_str(self) -> String {
        self.to_str().into_owned()
    }
}

impl std::fmt::Display for TlsSupportedGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_str())
    }
}
