use crate::ssl_helper::{filter_grease, is_grease, join_u16, join_u8, truncated_hash_hex};
use crate::TLS_Protocol;
use std::fmt::Write;

fn first_and_last(s: &str) -> String {
    let mut chars = s.chars();

    // Get the first character
    let Some(first) = chars.next() else {
        return String::new();
    };

    // Get the last character (if it exists)
    match chars.next_back() {
        Some(last) => format!("{first}{last}"),
        None => first.to_string(), // Only one character existed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_first_and_last_empty() {
        assert_eq!(first_and_last(""), "");
    }

    #[test]
    fn test_first_and_last_single_char() {
        assert_eq!(first_and_last("h"), "h");
        assert_eq!(first_and_last("z"), "z");
    }

    #[test]
    fn test_first_and_last_two_chars() {
        assert_eq!(first_and_last("hi"), "hi");
    }

    #[test]
    fn test_first_and_last_multiple_chars() {
        assert_eq!(first_and_last("hello"), "ho");
        assert_eq!(first_and_last("rustacean"), "rn");
    }

    #[test]
    fn test_first_and_last_unicode() {
        // Testing with multi-byte characters
        assert_eq!(first_and_last("🦀"), "🦀");
        assert_eq!(first_and_last("🚀rust🦀"), "🚀🦀");
    }
}
/// Check if a byte is ASCII alphanumeric per JA4 rules
#[inline]
fn is_ascii_alnum(b: u8) -> bool {
    matches!(b,
        b'0'..=b'9' |
        b'A'..=b'Z' |
        b'a'..=b'z'
    )
}

/// Normalize the first ALPN identifier into a JA4 2-character token
///
/// Input: raw ALPN string
/// Output: String with 2 chars,
#[must_use]
pub fn ja4_normalize_alpn(alpn: &[u8]) -> String {
    // Must have at least:
    // - 2 bytes ProtocolNameList length
    // - 1 byte ProtocolName length
    if alpn.is_empty() {
        return "00".into();
    }
    let first = *alpn.first().unwrap_or(&b'0');
    let last = *alpn.last().unwrap_or(&b'0');

    let out = if is_ascii_alnum(first) && is_ascii_alnum(last) {
        // ASCII fast path
        let mut s = String::with_capacity(2);
        s.push(first as char);
        s.push(last as char);
        s
    } else {
        let to_hex = |b: u8| -> char {
            match b {
                0..=9 => (b + b'0') as char,
                _ => (b - 10 + b'a') as char,
            }
        };
        let mut s = String::with_capacity(2);
        s.push(to_hex(first >> 4)); // High nibble of first
        s.push(to_hex(last & 0x0F)); // Low nibble of last
        s
    };

    out
}

#[cfg(test)]
mod tests_alpns {
    use super::*;

    #[test]
    fn test_ja4_normalize_alpn() {
        assert_eq!(ja4_normalize_alpn(&[0xAB]), ("ab"));
        assert_eq!(ja4_normalize_alpn(&[0xAB, 0xCD]), ("ad"));
        assert_eq!(ja4_normalize_alpn(&[0x30, 0xAB]), ("3b"));
        assert_eq!(ja4_normalize_alpn(&[0x30, 0x31, 0xAB, 0xCD]), ("3d"));
        assert_eq!(ja4_normalize_alpn(&[0x30, 0xAB, 0xCD, 0x31]), ("01"));
        assert_eq!(ja4_normalize_alpn(&[b'h', b'2']), ("h2"));
        assert_eq!(ja4_normalize_alpn(&[b'h', b'.', b'2']), ("h2"));
        assert_eq!(ja4_normalize_alpn(&[]), ("00"));
        assert_eq!(
            ja4_normalize_alpn(&[0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31]),
            ("h1")
        );
    }
}
#[must_use]
pub fn compute_ja4_client_fingerprint(
    protocol: TLS_Protocol,
    ciphers: &[u16],
    exts: &[u16],
    version: u16,
    alpn: &[String],
    sni_present: bool,
    sig_list: &[u16],
) -> String {
    // Sort lists to normalize (per JA4 recommendation)
    let mut ja4_string = String::new();
    ja4_string.push(if protocol == TLS_Protocol::TLS {
        't'
    } else if protocol == TLS_Protocol::DTLS {
        'd'
    } else {
        'q'
    });
    match version {
        0x0303 => ja4_string.push_str("12"),
        0x0304 => ja4_string.push_str("13"),
        0x0302 => ja4_string.push_str("11"),
        0x0301 => ja4_string.push_str("10"),
        0x3000 => ja4_string.push_str("s3"),
        0x0002 => ja4_string.push_str("s2"),
        0xfeff => ja4_string.push_str("d1"),
        0xfefd => ja4_string.push_str("d2"),
        0xfefc => ja4_string.push_str("d3"),
        _ => ja4_string.push_str("00"),
    }
    if sni_present {
        ja4_string.push('d');
    } else {
        ja4_string.push('i');
    }
    let mut filtered_ciphers: Vec<u16> = ciphers
        .iter()
        .filter(|&&v| !is_grease(v))
        .copied()
        .collect();
    let mut filtered_exts: Vec<u16> = exts.iter().filter(|&&v| !is_grease(v)).copied().collect();
    let _ = write!(ja4_string, "{:02}", filtered_ciphers.len().min(99));
    let _ = write!(ja4_string, "{:02}", filtered_exts.len().min(99));

    ja4_string.push_str(&ja4_normalize_alpn(
        alpn.first().unwrap_or(&String::new()).as_bytes(),
    ));
    filtered_ciphers.sort_unstable();
    filtered_exts.sort_unstable();
    let sigs = sig_list.to_vec();

    let cipher_list_str = filtered_ciphers
        .iter()
        .map(|v| format!("{v:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let cipher_hash = truncated_hash_hex(&cipher_list_str);

    let ext_list_str = filtered_exts
        .iter()
        // ignore SNI  and ALPN
        .filter(|v| **v != 0 && **v != 0x0010)
        .map(|v| format!("{v:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let sig_list_str = sigs
        .iter()
        .filter(|v| !is_grease(**v))
        .map(|v| format!("{v:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let ext_hash = truncated_hash_hex(&format!("{}_{}", &ext_list_str, sig_list_str));
    //debug!("JA4C {}", sig_list_str);

    ja4_string.push('_');
    ja4_string.push_str(&cipher_hash);
    ja4_string.push('_');
    ja4_string.push_str(&ext_hash);
    //debug!("JA4 :{:x?}", ja4_string);
    ja4_string
}

#[must_use]
pub fn compute_ja4_server_fingerprint(
    protocol: TLS_Protocol,
    cipher: u16,
    exts: &[u16],
    version: u16,
    alpn: &str,
) -> String {
    // Sort lists to normalize (per JA4 recommendation)
    let mut ja4_string = String::new();
    ja4_string.push(if protocol == TLS_Protocol::TLS {
        't'
    } else if protocol == TLS_Protocol::DTLS {
        'd'
    } else {
        'q'
    });
    match version {
        0x0304 => ja4_string.push_str("13"),
        0x0303 => ja4_string.push_str("12"),
        0x0302 => ja4_string.push_str("11"),
        0x0301 => ja4_string.push_str("10"),
        0x3000 => ja4_string.push_str("s3"),
        0x0002 => ja4_string.push_str("s2"),
        0xfeff => ja4_string.push_str("d1"),
        0xfefd => ja4_string.push_str("d2"),
        0xfefc => ja4_string.push_str("d3"),
        _ => ja4_string.push_str("00"),
    }
    let mut filtered_exts: Vec<u16> = exts.iter().filter(|&&v| !is_grease(v)).copied().collect();
    let _ = write!(ja4_string, "{:02}", filtered_exts.len().min(99));
    let _ = write!(
        ja4_string,
        "{:02}",
        first_and_last(if alpn.is_empty() { "00" } else { alpn })
    );
    let _ = write!(ja4_string, "_{cipher:04x}");
    //debug!( "JA4S -- {} {} {} {:x}", ja4_string, version, exts.len(), cipher );
    filtered_exts.sort_unstable();

    let ext_list_str = filtered_exts
        .iter()
        .filter(|v| **v != 0 && **v != 0x0010)
        .map(|v| format!("{v:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let ext_hash = truncated_hash_hex(&ext_list_str);
    //debug!("JA4S : '{}_{}'", ja4_string, ext_list_str);

    ja4_string.push('_');
    ja4_string.push_str(&ext_hash);

    ja4_string
}

#[must_use]
pub fn compute_ja3_client_fingerprint(
    client_hello_version: u16,
    cipher_list: &[u16],
    ext_list: &[u16],
    group_list: &[u16],
    point_list: &[u8],
) -> String {
    let ja3_string = format!(
        "{},{},{},{},{}",
        client_hello_version,
        join_u16(&filter_grease(cipher_list)),
        join_u16(&filter_grease(ext_list)),
        join_u16(&filter_grease(group_list)),
        join_u8(point_list),
    );
    //debug!("JA3C: {}", ja3_string);
    format!("{:x}", md5::compute(ja3_string.as_bytes()))
}

#[must_use]
pub fn compute_ja3_server_fingerprint(
    server_hello_version: u16,
    cipher: u16,
    ext_list: &[u16],
) -> String {
    let ja3s_string = format!(
        "{},{},{}",
        server_hello_version,
        cipher,
        join_u16(&filter_grease(ext_list)),
    );
    //debug!("JA3S: {}", ja3s_string);
    let ja3s_hash = format!("{:x}", md5::compute(ja3s_string.as_bytes()));
    ja3s_hash
}
