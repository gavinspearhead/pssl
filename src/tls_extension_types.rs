use crate::ssl_helper::is_grease;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::fmt::Display;
use std::str::FromStr;
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
    Ord,
    PartialOrd,
    Serialize,
    Deserialize,
)]
#[repr(u16)]
pub enum TlsExtensionTypeValue {
    ServerNameIndication = 0, // SNI
    MaxFragmentLength = 1,
    ClientCertificateUrl = 2,
    TrustedCaKeys = 3,
    TruncatedHmac = 4,
    StatusRequest = 5, // OCSP stapling
    UserMapping = 6,
    ClientAuthz = 7,
    ServerAuthz = 8,
    CertType = 9,
    SupportedGroups = 10, // formerly elliptic_curves
    EcPointFormats = 11,
    Srp = 12,
    SignatureAlgorithms = 13,
    UseSrtp = 14,
    Heartbeat = 15,
    ApplicationLayerProtocolNegotiation = 16, // ALPN
    StatusRequestv2 = 17,
    SignedCertificateTimestamp = 18, // Certificate Transparency
    ClientCertificateType = 19,
    ServerCertificateType = 20,
    Padding = 21,
    EncryptThenMac = 22,
    ExtendedMasterSecret = 23,
    TokenBinding = 24,
    CachedInfo = 25,
    TlsLts = 26,
    CompressCertificate = 27,
    RecordSizeLimit = 28,
    PwdProtect = 29,
    PwdClear = 30,
    PasswordSalt = 31,
    TicketPinning = 32,
    TlsCertWithExternPsk = 33,
    DelegatedCredentials = 34,
    SessionTicket = 35,
    TLMSP = 36,
    TLMSPProxying = 37,
    TLMSPDelegate = 38,
    SupportedEktCiphers = 39,

    PreSharedKey = 41,
    EarlyData = 42,
    SupportedVersions = 43,
    Cookie = 44,
    PskKeyExchangeModes = 45,
    CertificateAuthorities = 47,
    OidFilters = 48,
    PostHandshakeAuth = 49,
    SignatureAlgorithmsCert = 50,
    KeyShare = 51,
    TransparencyInfo = 52,
    ConnectionId_deprecated = 53,
    ConnectionId = 54,
    ExternalIdHash = 55,
    ExternalIdSignature = 56,
    QuicTransportParameters = 57,
    TicketRequest = 58,
    DnsSecChain = 59,
    SequenceNumberEncryptionAlgorithms = 60,
    RRC = 61,
    TlsFlags = 62,
    EchOuterExtensions = 64768,
    EncryptedClientHello = 65037,
    RenegotiationInfo = 65281,

    #[default]
    Unknown = 0xFFFF,
}
#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash, PartialOrd, Ord)]

pub enum TlsExtensionType {
    Grease,
    Known(TlsExtensionTypeValue),
    Unknown(u16),
}

impl Default for TlsExtensionType {
    fn default() -> Self {
        TlsExtensionType::Unknown(0xFFFF)
    }
}

impl TlsExtensionType {
    #[must_use]
    pub fn from_u16(id: u16) -> Self {
        if is_grease(id) {
            TlsExtensionType::Grease
        } else {
            match TlsExtensionTypeValue::from_repr(id) {
                Some(known) => TlsExtensionType::Known(known),
                None => TlsExtensionType::Unknown(id),
            }
        }
    }
    #[must_use]
    pub fn to_u16(&self) -> u16 {
        match self {
            TlsExtensionType::Grease => 0x0a0a,
            TlsExtensionType::Unknown(unknown) => *unknown,
            TlsExtensionType::Known(known) => *known as u16,
        }
    }
    #[must_use]
    pub fn as_str(self) -> String {
        match self {
            TlsExtensionType::Grease => Cow::Owned("Grease".to_owned()),
            TlsExtensionType::Known(known) => Cow::Borrowed(known.into()),
            TlsExtensionType::Unknown(val) => Cow::Owned(format!("Unknown ({val:x})")),
        }
        .into_owned()
    }
}

impl Display for TlsExtensionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Serialize for TlsExtensionType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let value: Cow<'static, str> = match self {
            TlsExtensionType::Grease => Cow::Borrowed("Grease"),
            TlsExtensionType::Known(known) => Cow::Borrowed(known.into()),
            TlsExtensionType::Unknown(unknown) => Cow::Owned(format!("Unknown ({unknown:x})")),
        };
        value.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TlsExtensionType {
    fn deserialize<D>(deserializer: D) -> Result<TlsExtensionType, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        if s == "Grease" {
            return Ok(TlsExtensionType::Grease);
        }

        if let Some(caps) = s.strip_prefix("Unknown (") {
            if let Some(hex_val) = caps.strip_suffix(')') {
                if let Ok(id) = u16::from_str_radix(hex_val, 16) {
                    return Ok(TlsExtensionType::Unknown(id));
                }
            }
        }

        // Attempt to parse the name back to TlsCipherSuiteValue using strum
        match TlsExtensionTypeValue::from_str(&s) {
            Ok(known) => Ok(TlsExtensionType::Known(known)),
            Err(_) => Err(serde::de::Error::custom(format!(
                "Invalid TLS Cipher Suite string: {s}"
            ))),
        }
    }
}
