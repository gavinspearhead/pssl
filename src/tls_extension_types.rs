use std::borrow::Cow;
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
    Ord,
    PartialOrd,
    Serialize,
    Deserialize,
)]
#[repr(u16)]
pub enum TlsExtensionTypeValue {
    // RFC 3546 / RFC 4366 / RFC 6066
    ServerNameIndication = 0, // SNI
    MaxFragmentLength = 1,
    ClientCertificateUrl = 2,
    TrustedCaKeys = 3,
    TruncatedHmac = 4,
    StatusRequest = 5, // OCSP stapling

    // RFC 4681 / RFC 5878
    UserMapping = 6,

    // RFC 4492
    SupportedGroups = 10, // formerly elliptic_curves
    EcPointFormats = 11,

    // RFC 5054
    Srp = 12,

    // RFC 5246 / RFC 8446
    SignatureAlgorithms = 13,
    UseSrtp = 14,
    Heartbeat = 15,

    // RFC 5077
    SessionTicket = 35,

    // RFC 7627
    ExtendedMasterSecret = 23,

    // RFC 7250
    CachedInfo = 25,

    // RFC 7366
    EncryptThenMac = 22,

    // RFC 7924
    RecordSizeLimit = 28,

    // RFC 7685
    Padding = 21,

    // RFC 7301
    ApplicationLayerProtocolNegotiation = 16, // ALPN

    // RFC 5746
    RenegotiationInfo = 65281,

    // RFC 6962
    SignedCertificateTimestamp = 18, // Certificate Transparency

    // RFC 8446 (TLS 1.3)
    SupportedVersions = 43,
    Cookie = 44,
    PskKeyExchangeModes = 45,
    CertificateAuthorities = 47,
    OidFilters = 48,
    PostHandshakeAuth = 49,
    SignatureAlgorithmsCert = 50,
    KeyShare = 51,

    // RFC 8471
    PreSharedKey = 41,

    // RFC 8701
    EarlyData = 42,

    // RFC 8879
    CompressCertificate = 27,

    // RFC 8773
    DelegatedCredentials = 34,

    // RFC 8449

    // RFC 9325
    EncryptedClientHello = 65037,

    // QUIC / RFC 9001
    QuicTransportParameters = 57,

    // RFC 9146
    ConnectionId = 54,

    // Catch-all
    #[default]
    Unknown = 0xFFFF,
}
#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash, PartialOrd, Ord)]

pub enum TlsExtensionType {
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
    pub fn from_u16(id: u16) -> Option<Self> {
        match TlsExtensionTypeValue::from_repr(id) {
            Some(known) => Some(TlsExtensionType::Known(known)),
            None => Some(TlsExtensionType::Unknown(id)),
        }
    }
    #[must_use] 
    pub fn to_u16(&self) -> u16 {
        match self {
           TlsExtensionType::Unknown(unknown) => *unknown,
            TlsExtensionType::Known(known)=> *known as u16,
        }
    }
    #[must_use] 
    pub fn as_str(self) -> String {
        match self {
            TlsExtensionType::Known(known) => Cow::Borrowed(known.into()),
            TlsExtensionType::Unknown(val) => Cow::Owned(format!("Unknown ({val:x})")),
        }.into_owned()
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
        let id = u16::deserialize(deserializer)?;
        Ok(TlsExtensionType::from_u16(id).unwrap_or(TlsExtensionType::Unknown(id)))
    }
}
