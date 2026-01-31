use strum_macros::{EnumIter, EnumString};

#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString, EnumIter)]
#[repr(u16)]
pub enum TlsHandshakeType {
    ClientHello = 1,         // 1
    ServerHello = 2,         // 2
    NewSessionTicket = 4,    // 4
    Certificate = 11,        // 11
    ServerKeyExchange = 12,  // 12 (TLS 1.2)
    CertificateRequest = 13, // 13
    ServerHelloDone = 14,    // 14
    CertificateVerify = 15,  // 15
    ClientKeyExchange = 16,  // 16
    Finished = 20,           // 20
    CertificateStatus = 22,  // 22
    KeyUpdate = 24,          // 24
    Unknown(u8),
}

impl TlsHandshakeType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::ClientHello,
            2 => Self::ServerHello,
            4 => Self::NewSessionTicket,
            11 => Self::Certificate,
            12 => Self::ServerKeyExchange,
            13 => Self::CertificateRequest,
            14 => Self::ServerHelloDone,
            15 => Self::CertificateVerify,
            16 => Self::ClientKeyExchange,
            20 => Self::Finished,
            22 => Self::CertificateStatus,
            24 => Self::KeyUpdate,
            other => Self::Unknown(other),
        }
    }
}
