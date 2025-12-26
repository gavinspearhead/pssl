use crate::ssl_helper::{join_u16, join_u8, truncated_hash_hex};
use crate::TLS_Protocol;
use tracing::debug;

fn first_and_last(s: &str) -> String {
    let mut chars = s.chars();

    // Get the first character
    let first = match chars.next() {
        Some(c) => c,
        None => return String::new(), // Handle empty string
    };

    // Get the last character (if it exists)
    match chars.next_back() {
        Some(last) => format!("{}{}", first, last),
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
    ja4_string.push(if protocol == TLS_Protocol::TCP {
        't'
    } else {
        'q'
    });
    match version {
        0x0303 => ja4_string.push_str("12"),
        0x0304 => ja4_string.push_str("13"),
        0x0302 => ja4_string.push_str("11"),
        0x0301 => ja4_string.push_str("10"),
        _ => {}
    }
    if sni_present {
        ja4_string.push('d');
    } else {
        ja4_string.push('i');
    }
    ja4_string.push_str(&format!("{}", ciphers.len()));
    ja4_string.push_str(&format!("{}", exts.len()));
    if alpn.is_empty() {
        ja4_string.push_str("00")
    } else {
        ja4_string.push_str(&first_and_last(&alpn[0]));
    }

    let mut ciphers = ciphers.to_vec();
    ciphers.sort_unstable();
    let mut exts = exts.to_vec();
    exts.sort_unstable();
    let sigs = sig_list.to_vec();

    let cipher_list_str = ciphers
        .iter()
        .map(|v| format!("{:04x}", v))
        .collect::<Vec<_>>()
        .join(",");
    let cipher_hash = truncated_hash_hex(&cipher_list_str);

    let ext_list_str = exts
        .iter()
        .filter(|v| **v != 0)
        .map(|v| format!("{:04x}", v))
        .collect::<Vec<_>>()
        .join(",");
    let sig_list_str = sigs
        .iter()
        .map(|v| format!("{:04x}", v))
        .collect::<Vec<_>>()
        .join(",");
    let ext_hash = truncated_hash_hex(&format!("{}_{}", &ext_list_str, sig_list_str));
    debug!("JA4C:  {}", sig_list_str);

    ja4_string.push('_');
    ja4_string.push_str(&cipher_hash);
    ja4_string.push('_');
    ja4_string.push_str(&ext_hash);
    //debug!("JA4 :{:x?}", ja4_string);
    ja4_string
}

pub fn compute_ja4_server_fingerprint(
    protocol: TLS_Protocol,
    cipher: u16,
    exts: &[u16],
    version: u16,
    alpn: &str,
) -> String {
    // Sort lists to normalize (per JA4 recommendation)
    let mut ja4_string = String::new();
    ja4_string.push(if protocol == TLS_Protocol::TCP {
        't'
    } else {
        'q'
    });
    match version {
        0x0304 => ja4_string.push_str("13"),
        0x0303 => ja4_string.push_str("12"),
        0x0302 => ja4_string.push_str("11"),
        0x0301 => ja4_string.push_str("10"),
        _ => (),
    }
    ja4_string.push_str(&format!("{:02}", exts.len()));
    ja4_string.push_str(&format!(
        "{}",
        first_and_last(if !alpn.is_empty() { alpn } else { "00" })
    ));

    ja4_string.push('_');
    ja4_string.push_str(&format!("{:04x}", cipher));
    //debug!( "JA4S -- {} {} {} {:x}", ja4_string, version, exts.len(), cipher );
    let mut exts = exts.to_vec();
    exts.sort_unstable();

    let ext_list_str = exts
        .iter()
        .filter(|v| **v != 0)
        .map(|v| format!("{:04x}", v))
        .collect::<Vec<_>>()
        .join(",");
    let ext_hash = truncated_hash_hex(format!("{}", &ext_list_str).as_str());
    debug!("JA4S : '{}_{}'", ja4_string, ext_list_str);

    ja4_string.push('_');
    ja4_string.push_str(&ext_hash);

    ja4_string
}

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
        join_u16(&cipher_list),
        join_u16(&ext_list),
        join_u16(&group_list),
        join_u8(&point_list),
    );
    debug!("JA3C: {}", ja3_string);
    let ja3_hash = format!("{:x}", md5::compute(ja3_string.as_bytes()));
    ja3_hash
}

pub fn compute_ja3_server_fingerprint(
    server_hello_version: u16,
    cipher: u16,
    ext_list: &[u16],
) -> String {
    let ja3s_string = format!(
        "{},{},{}",
        server_hello_version,
        cipher,
        join_u16(&ext_list),
    );
    debug!("JA3S: {}", ja3s_string);
    let ja3s_hash = format!("{:x}", md5::compute(ja3s_string.as_bytes()));
    ja3s_hash
}
