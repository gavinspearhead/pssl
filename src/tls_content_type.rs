#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsRecordContentType {
    ChangeCipherSpec,
    Alert,
    Handshake,
    ApplicationData,
    Heartbeat,
    Tls12Cid,
    Ack,
    ReturnRoutabilityCheck,
    Unknown(u8),
}

impl From<u8> for TlsRecordContentType {
    fn from(v: u8) -> Self {
        match v {
            20 => Self::ChangeCipherSpec,
            21 => Self::Alert,
            22 => Self::Handshake,
            23 => Self::ApplicationData,
            24 => Self::Heartbeat,
            25 => Self::Tls12Cid,
            26 => Self::Ack,
            27 => Self::ReturnRoutabilityCheck,
            other => Self::Unknown(other),
        }
    }
}
