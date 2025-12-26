use crate::errors::ParseErrorType::{Invalid_TLS_Packet, Invalid_packet_index};
use crate::errors::Parse_error;
use byteorder::{BigEndian, ByteOrder};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::RangeBounds;

pub(crate) fn ssl_parse_slice<T>(packet: &[u8], range: T) -> Result<&[u8], Parse_error>
where
    T: RangeBounds<usize>,
{
    let start = match range.start_bound() {
        std::ops::Bound::Included(&s) => s,
        std::ops::Bound::Excluded(&s) => s + 1,
        std::ops::Bound::Unbounded => 0,
    };

    let end = match range.end_bound() {
        std::ops::Bound::Included(&e) => e + 1,
        std::ops::Bound::Excluded(&e) => e,
        std::ops::Bound::Unbounded => packet.len(),
    };

    if start <= end && end <= packet.len() {
        Ok(&packet[start..end])
    } else {
        Err(Parse_error::new(Invalid_packet_index, " {start}..{end}"))
    }
}

pub(crate) fn parse_ssl_str(rdata: &[u8]) -> Result<String, Parse_error> {
    if let Ok(x) = std::str::from_utf8(rdata) {
        Ok(x.to_owned())
    } else {
        Err(Parse_error::new(Invalid_TLS_Packet, ""))
    }
}

pub(crate) fn ssl_read_u64(packet: &[u8], offset: usize) -> Result<u64, Parse_error> {
    let Some(r) = packet.get(offset..offset + 8) else {
        return Err(Parse_error::new(Invalid_packet_index, &offset.to_string()));
    };
    let val = BigEndian::read_u64(r);
    Ok(val)
}

pub(crate) fn ssl_read_u24(packet: &[u8], offset: usize) -> Result<u32, Parse_error> {
    let Some(r) = packet.get(offset..offset + 3) else {
        return Err(Parse_error::new(Invalid_packet_index, &offset.to_string()));
    };
    let val = BigEndian::read_u24(r);
    Ok(val)
}

pub(crate) fn ssl_read_u16(packet: &[u8], offset: usize) -> Result<u16, Parse_error> {
    let Some(r) = packet.get(offset..offset + 2) else {
        return Err(Parse_error::new(Invalid_packet_index, &offset.to_string()));
    };
    let val = BigEndian::read_u16(r);
    Ok(val)
}

pub(crate) fn ssl_read_u8(packet: &[u8], offset: usize) -> Result<u8, Parse_error> {
    let Some(r) = packet.get(offset) else {
        return Err(Parse_error::new(Invalid_packet_index, &offset.to_string()));
    };
    Ok(*r)
}

pub(crate) fn ssl_read_u32(packet: &[u8], offset: usize) -> Result<u32, Parse_error> {
    let Some(r) = packet.get(offset..offset + 4) else {
        return Err(Parse_error::new(Invalid_packet_index, &offset.to_string()));
    };
    let val = BigEndian::read_u32(r);
    Ok(val)
}

pub(crate) fn base32hex_encode(input: &[u8]) -> String {
    static BASE32HEX_NOPAD: data_encoding::Encoding = data_encoding::BASE32HEX_NOPAD;
    let mut output = String::new();
    let mut enc = BASE32HEX_NOPAD.new_encoder(&mut output);
    enc.append(input);
    enc.finalize();
    output
}

pub(crate) fn parse_ipv4(data: &[u8]) -> Result<IpAddr, Parse_error> {
    let r: [u8; 4] = match data.try_into() {
        Ok(x) => x,
        Err(_) => {
            return Err(Parse_error::new(Invalid_TLS_Packet, ""));
        }
    };
    let addr = Ipv4Addr::from(r);
    Ok(IpAddr::V4(addr))
}

pub(crate) fn parse_ipv6(data: &[u8]) -> Result<IpAddr, Parse_error> {
    let r: [u8; 16] = match data.try_into() {
        Ok(x) => x,
        Err(_) => {
            return Err(Parse_error::new(Invalid_TLS_Packet, ""));
        }
    };
    let addr = Ipv6Addr::from(r);
    Ok(IpAddr::V6(addr))
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        str::FromStr,
    };

    use crate::ssl_helper::{ssl_read_u16, ssl_read_u32, ssl_read_u64, ssl_read_u8};

    use super::{parse_ipv4, parse_ipv6};

    #[test]
    fn test_parse_ipv4() {
        assert_eq!(
            parse_ipv4(&[192, 168, 178, 254]).unwrap(),
            Ipv4Addr::from_str("192.168.178.254").unwrap()
        );
        assert_eq!(
            parse_ipv4(&[130, 89, 1, 1]).unwrap(),
            Ipv4Addr::from_str("130.89.1.1").unwrap()
        );
        assert!(parse_ipv4(&[130, 89, 1]).is_err());
        assert!(parse_ipv4(&[89, 1]).is_err());
    }
    #[test]
    fn test_parse_ipv6() {
        assert_eq!(
            parse_ipv6(&[
                0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1a, 0xc0, 0x4d, 0xff, 0xfe, 0xaf, 0x86,
                0x31
            ])
            .unwrap(),
            Ipv6Addr::from_str("fe80:0:0:0:1ac0:4dff:feaf:8631").unwrap()
        );
        assert!(parse_ipv6(&[
            0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1a, 0xc0, 0x4d, 0xff, 0xfe, 0xaf, 0x86, 0x31
        ])
        .is_err());
        assert!(
            parse_ipv6(&[0x0, 0x0, 0x0, 0x1a, 0xc0, 0x4d, 0xff, 0xfe, 0xaf, 0x86, 0x31]).is_err()
        );
    }

    #[test]
    fn test_dns_read_u32() {
        assert_eq!(
            ssl_read_u32(&[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe], 0).unwrap(),
            0xdeadbeef
        );
        assert_eq!(
            ssl_read_u32(&[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe], 4).unwrap(),
            0xcafebabe
        );
        assert!(ssl_read_u32(&[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe], 7).is_err());
    }
    #[test]
    fn test_dns_read_u16() {
        assert_eq!(
            ssl_read_u16(&[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe], 2).unwrap(),
            0xbeef
        );
        assert_eq!(
            ssl_read_u16(&[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe], 4).unwrap(),
            0xcafe
        );
        assert!(ssl_read_u16(&[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe], 7).is_err());
    }
    #[test]
    fn test_dns_read_u8() {
        assert_eq!(
            ssl_read_u8(&[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe], 2).unwrap(),
            0xbe
        );
        assert_eq!(
            ssl_read_u8(&[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe], 5).unwrap(),
            0xfe
        );
        assert!(ssl_read_u8(&[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe], 8).is_err());
    }
    #[test]
    fn test_dns_read_u64() {
        assert_eq!(
            ssl_read_u64(
                &[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x12, 0x23, 0x45, 0x67],
                2
            )
            .unwrap(),
            0xbeefcafebabe1223
        );
        assert_eq!(
            ssl_read_u64(
                &[
                    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x12, 0x23, 0x45, 0x67, 0x89,
                    0xaa
                ],
                5
            )
            .unwrap(),
            0xfebabe1223456789
        );
        assert!(ssl_read_u64(
            &[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x12, 0x23, 0x45, 0x67, 0x89, 0xaa],
            15
        )
        .is_err());
    }
}

pub fn join_u16(list: &[u16]) -> String {
    list.iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

// Helper to join u7 lists with '-'
pub fn join_u8(list: &[u8]) -> String {
    list.iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-")
}
/// Helper: compute SHA-256 of a string, then take the first 12 hex characters (for example)
pub fn truncated_hash_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    // take first 6 or 8 hex characters as the fingerprint component
    hex::encode(&result)[..12].to_string()
}
