use std::{error::Error, fmt};

use strum_macros::{EnumIter, IntoStaticStr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, IntoStaticStr)]
pub(crate) enum ParseErrorType {
    Invalid_UDP_Header,
    Invalid_TCP_Header,
    Invalid_IPv6_Header,
    Invalid_IPv4_Header,
    Invalid_TCP_Packet,
    Invalid_UDP_Packet,
    Invalid_IP_Version,
    Packet_Too_Small,
    Unknown_Packet_Type,
    Unknown_Link_Type,
    Unknown_Frame_Type,
    Invalid_packet_index,
    Invalid_timestamp,
    Unknown_Protocol,
    Unknown_Address_Family,
    Invalid_Resource_Record,
    Invalid_Parameter,
    Invalid_Domain_name,
    Invalid_TLS_Packet,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Parse_error {
    error_type: ParseErrorType,
    error_str: String,
    value: String,
}

impl Parse_error {
    pub(crate) fn new(err_t: ParseErrorType, val: &str) -> Parse_error {
        let s = match err_t {
            ParseErrorType::Invalid_UDP_Header => "Invalid UDP Header",
            ParseErrorType::Invalid_TCP_Header => "Invalid TCP Header",
            ParseErrorType::Invalid_TCP_Packet => "Invalid TCP Packet",
            ParseErrorType::Invalid_UDP_Packet => "Invalid UDP Packet",
            ParseErrorType::Invalid_IPv6_Header => "Invalid IPv6 Header",
            ParseErrorType::Invalid_IPv4_Header => "Invalid IPv4 Header",
            ParseErrorType::Invalid_IP_Version => "Invalid IP Version",
            ParseErrorType::Packet_Too_Small => "Packet Too Small",
            ParseErrorType::Unknown_Packet_Type => "Unknown Packet Type",
            ParseErrorType::Unknown_Link_Type => "Unknown Link Type",
            ParseErrorType::Unknown_Protocol => "Unknown protocol",
            ParseErrorType::Unknown_Frame_Type => "Unknown Frame Type",
            ParseErrorType::Unknown_Address_Family => "Unknown Address Family",
            ParseErrorType::Invalid_packet_index => "Invalid packet index",
            ParseErrorType::Invalid_timestamp => "Invalid timestamp",
            ParseErrorType::Invalid_Resource_Record => "Invalid resource record",
            ParseErrorType::Invalid_TLS_Packet => "Invalid TLS packet",
            ParseErrorType::Invalid_Parameter => "Invalid Parameter",
            ParseErrorType::Invalid_Domain_name => "Invalid domain name",
        };
        Parse_error {
            error_type: err_t,
            error_str: s.to_owned(),
            value: val.to_string(),
        }
    }
}

impl fmt::Display for Parse_error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {}", self.error_str, self.value)
    }
}

impl Error for Parse_error {
    fn description(&self) -> &str {
        &self.error_str
    }
}
