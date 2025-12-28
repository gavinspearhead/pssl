use ::hkdf::Hkdf;
use sha2::Sha256;

use crate::config::Config;
use crate::errors::{ParseErrorType, Parse_error};
use crate::ja4::{
    compute_ja3_client_fingerprint, compute_ja3_server_fingerprint, compute_ja4_client_fingerprint,
    compute_ja4_server_fingerprint,
};
use crate::packet_info::{Packet_Info_List, Packet_info};
use crate::ssl_helper::{
    parse_ssl_str, ssl_parse_slice, ssl_read_u16, ssl_read_u24, ssl_read_u32, ssl_read_u8,
};
use crate::statistics::Statistics;
use crate::tls_cipher_suites::TlsCipherSuite;
use crate::tls_extension_types::TlsExtensionType;
use crate::tls_extension_types::TlsExtensionType::{
    ApplicationLayerProtocolNegotiation, EcPointFormats, EncryptedClientHello, KeyShare,
    PreSharedKey, PskKeyExchangeModes, RecordSizeLimit, RenegotiationInfo, ServerNameIndication,
    SessionTicket, SignatureAlgorithms, SupportedGroups, SupportedVersions,
};
pub use crate::tls_groups::TlsSupportedGroup;
use crate::tls_signature_hash_algorithms::TlsSignatureScheme;
use crate::TLS_Protocol;
use aes::Aes128;
use aes_gcm::aead::Aead;
use aes_gcm::{AeadInPlace, Aes128Gcm};
use chrono::{DateTime, Utc};
use cipher::generic_array::GenericArray;
use cipher::{BlockEncrypt, KeyInit};
use std::collections::hash_map::Entry;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::debug;

#[inline]
fn is_grease(val: u16) -> bool {
    val & 0x0a0a == 0x0a0a
}

fn parse_sni_extension(data: &[u8], tls_data: &mut TlsExtensionData) -> Result<(), Box<dyn Error>> {
    // The ServerNameList is at least 2 bytes (the list length)

    let list_len = ssl_read_u16(data, 0)? as usize;
    // Ensure the data provided matches the internal list length

    let mut cursor = 2;
    let end = 2 + list_len;

    while cursor + 3 <= end {
        let sni_type = ssl_read_u8(data, cursor)?;
        let sni_len = ssl_read_u16(data, cursor + 1)? as usize;
        cursor += 3;

        if sni_type == 0 {
            let name_bytes = ssl_parse_slice(data, cursor..cursor + sni_len)?;
            tls_data.sni = parse_ssl_str(name_bytes)?;
            // Usually, we stop at the first host_name
            break;
        } else {
            debug!("Unknown SNI type: {}", sni_type);
            cursor += sni_len;
        }
    }

    Ok(())
}

fn parse_supported_groups_extension(
    data: &[u8],
    tls_data: &mut TlsExtensionData,
    statistics: &mut Statistics,
) -> Result<(), Box<dyn Error>> {
    let groups_len = ssl_read_u16(data, 0)?;
    if groups_len % 2 != 0 {
        return Err(Parse_error::new(
            ParseErrorType::Invalid_TLS_Packet,
            &format!("group len not even {groups_len}"),
        )
        .into());
    }
    let groups_count = groups_len / 2;

    let mut gr_offset = 2;
    for _i in 0..groups_count {
        let group_id = ssl_read_u16(data, gr_offset)?;
        gr_offset += 2;
        if is_grease(group_id) {
            continue;
        }
        tls_data.group_list.push(group_id);
        *statistics
            .client_curves
            .entry(TlsSupportedGroup::from_u16(group_id).unwrap_or_default())
            .or_insert(0) += 1;
        // debug!("Group {group_id:x}");
    }
    Ok(())
}

fn parse_signature_algorithms_extension(
    data: &[u8],
    tls_data: &mut TlsExtensionData,
    statistics: &mut Statistics,
) -> Result<(), Box<dyn Error>> {
    let sigs_len = ssl_read_u16(data, 0)?;
    if sigs_len % 2 != 0 {
        return Err(Parse_error::new(
            ParseErrorType::Invalid_TLS_Packet,
            &format!("group len not even {sigs_len}"),
        )
        .into());
    }
    let mut sig_offset = 2;
    let sigs_count = sigs_len / 2;
    for _i in 0..sigs_count {
        let sig_alg = ssl_read_u16(data, sig_offset)?;
        sig_offset += 2;
        if is_grease(sig_alg) {
            continue;
        }
        tls_data.sig_list.push(sig_alg);
        let scheme = TlsSignatureScheme::from_u16(sig_alg).unwrap_or_default();
        *statistics
            .client_signature_algorithms
            .entry(scheme)
            .or_insert(0) += 1;
    }
    Ok(())
}

fn parse_ec_point_formats_extension(
    data: &[u8],
    tls_data: &mut TlsExtensionData,
) -> Result<(), Box<dyn Error>> {
    let format_len = ssl_read_u8(data, 0)?;
    let mut pnt_offset = 1;
    for _i in 0..format_len {
        let ec_point_format = ssl_read_u8(data, pnt_offset)?;
        tls_data.point_list.push(ec_point_format);
        pnt_offset += 1;
    }
    Ok(())
}

fn parse_key_share_extension(
    data: &[u8],
    is_client: bool,
    tls_data: &mut TlsExtensionData,
    statistics: &mut Statistics,
) -> Result<(), Box<dyn Error>> {
    if is_client {
        let key_share_len = ssl_read_u16(data, 0)?;
        let mut gr_offset = 2;
        while gr_offset < 2 + key_share_len as usize {
            let group = ssl_read_u16(data, gr_offset)?;
            let key_len = ssl_read_u16(data, gr_offset + 2)?;
            gr_offset += 4;
            if !is_grease(group) {
                *statistics
                    .client_pk_curves
                    .entry(TlsSupportedGroup::from_u16(group).unwrap_or_default())
                    .or_insert(0) += 1;
                debug!("client group: {}", group);
                let _key = ssl_parse_slice(data, gr_offset..gr_offset + key_len as usize)?;
            }
            gr_offset += key_len as usize;
        }
    } else {
        let group = ssl_read_u16(data, 0)?;
        let key_len = ssl_read_u16(data, 2)?;
        tls_data.key = ssl_parse_slice(data, 4..4 + key_len as usize)?.to_vec();
        tls_data.group_list.push(group);
        *statistics
            .curves
            .entry(TlsSupportedGroup::from_u16(group).unwrap_or_default())
            .or_insert(0) += 1;
    }
    Ok(())
}

fn parse_alpn_extension(
    data: &[u8],
    tls_data: &mut TlsExtensionData,
    statistics: &mut Statistics,
) -> Result<(), Box<dyn Error>> {
    let alpn_len = ssl_read_u16(data, 0)?;
    let mut gr_offset = 2;
    while gr_offset < 2 + alpn_len as usize {
        let str_len = ssl_read_u8(data, gr_offset)?;
        if str_len == 0 {
            return Err(Parse_error::new(
                ParseErrorType::Invalid_TLS_Packet,
                &"str_len is 0".to_string(),
            )
            .into());
        }
        gr_offset += 1;
        let alpn = parse_ssl_str(ssl_parse_slice(
            data,
            gr_offset..str_len as usize + gr_offset,
        )?)?;
        gr_offset += str_len as usize;
        *statistics.alpns.entry(alpn.clone()).or_insert(0) += 1;
        tls_data.alpn_list.push(alpn);
    }
    Ok(())
}

fn parse_supported_versions_extension(
    data: &[u8],
    is_client: bool,
    tls_data: &mut TlsExtensionData,
    statistics: &mut Statistics,
) -> Result<(), Box<dyn Error>> {
    if !is_client {
        let ver = ssl_read_u16(data, 0)?;
        tls_data.highest_version = ver;
        *statistics.tls_versions.entry(ver).or_insert(0) += 1;
    } else {
        let version_len = ssl_read_u8(data, 0)?;
        if version_len % 2 != 0 {
            return Err(Parse_error::new(
                ParseErrorType::Invalid_TLS_Packet,
                &format!("versions len not even {version_len}"),
            )
            .into());
        }
        let mut gr_offset = 1;
        for _i in 0..version_len / 2 {
            let ver = ssl_read_u16(data, gr_offset)?;
            gr_offset += 2;
            if is_grease(ver) {
                continue;
            }
            *statistics.client_tls_versions.entry(ver).or_insert(0) += 1;
            if ver > tls_data.highest_version {
                tls_data.highest_version = ver;
            }
        }
    }
    Ok(())
}

#[derive(Default, Clone, Debug, PartialEq, Eq, Hash)]
pub struct TlsExtensionData {
    pub ext_list: Vec<u16>,
    pub group_list: Vec<u16>,
    pub point_list: Vec<u8>,
    pub alpn_list: Vec<String>,
    pub sni: String,
    pub highest_version: u16,
    pub sig_list: Vec<u16>,
    pub key: Vec<u8>,
}

fn parse_extension(
    extension_data: &[u8],
    is_client: bool,
    statistics: &mut Statistics,
) -> Result<TlsExtensionData, Box<dyn Error>> {
    let mut offset = 0;
    let mut tls_extension_data = TlsExtensionData::default();
    while offset < extension_data.len() {
        let ext_type_val = ssl_read_u16(extension_data, offset)?;
        let ext_type = TlsExtensionType::from_u16(ext_type_val).unwrap_or_default();
        let ext_len = ssl_read_u16(extension_data, offset + 2)? as usize;

        if is_grease(ext_type_val) {
            debug!("ext type: GREASE value {:x}", ext_type_val);
        } else {
            let stats_entry = if is_client {
                statistics.client_extensions.entry(ext_type)
            } else {
                statistics.server_extensions.entry(ext_type)
            };
            *stats_entry.or_insert(0) += 1;
            tls_extension_data.ext_list.push(ext_type_val);
        }

        if ext_len > 0 {
            let data = ssl_parse_slice(extension_data, offset + 4..offset + 4 + ext_len)?;
            match ext_type {
                ServerNameIndication => parse_sni_extension(data, &mut tls_extension_data)?,
                SupportedGroups => {
                    parse_supported_groups_extension(data, &mut tls_extension_data, statistics)?
                }
                SignatureAlgorithms => {
                    parse_signature_algorithms_extension(data, &mut tls_extension_data, statistics)?
                }
                EcPointFormats => parse_ec_point_formats_extension(data, &mut tls_extension_data)?,
                KeyShare => {
                    parse_key_share_extension(data, is_client, &mut tls_extension_data, statistics)?
                }
                ApplicationLayerProtocolNegotiation => {
                    parse_alpn_extension(data, &mut tls_extension_data, statistics)?
                }
                SupportedVersions => parse_supported_versions_extension(
                    data,
                    is_client,
                    &mut tls_extension_data,
                    statistics,
                )?,
                EncryptedClientHello | PskKeyExchangeModes | RecordSizeLimit | SessionTicket
                | PreSharedKey | RenegotiationInfo => {}
                _ => {}
            }
        }
        offset += 4 + ext_len;
    }
    Ok(tls_extension_data)
}

fn parse_server_hello(
    packet_info: &mut Packet_info,
    packet: &[u8],
    statistics: &mut Statistics,
) -> Result<usize, Box<dyn Error>> {
    let mut offset = 0;
    //debug!("SH length {}", packet.len());
    let server_hello_version = ssl_read_u16(packet, offset)?;
    //debug!("SH version {:x}", server_hello_version);
    offset += 2;

    let _random = ssl_parse_slice(packet, offset..offset + 32)?;
    offset += 32;
    //debug!("random:{:x?}", random);
    let session_id_len = ssl_read_u8(packet, offset)?;
    offset += 1;
    //debug!("session id len:{}", session_id_len);
    let _session_id = ssl_parse_slice(packet, offset..offset + session_id_len as usize)?;
    offset += session_id_len as usize;
    //  debug!("session id :{:x?}", session_id);
    packet_info.tls_server.cipher =
        TlsCipherSuite::from_u16(ssl_read_u16(packet, offset)?).unwrap_or_default();
    offset += 2;

    //debug!("cipher suite: {}", packet_info.tls_server.cipher.as_str());
    let _compression = ssl_read_u8(packet, offset)?;
    offset += 1;
    //debug!("compression: {}", compression);
    let extension_len = ssl_read_u16(packet, offset)?;
    //debug!("extension len:{}", extension_len);
    offset += 2;
    let tls_extension_data = parse_extension(
        ssl_parse_slice(packet, offset..offset + extension_len as usize)?,
        false,
        statistics,
    )?;
    if tls_extension_data.highest_version > 0 {
        packet_info.tls_server.version = tls_extension_data.highest_version;
    } else {
        packet_info.tls_server.version = server_hello_version;
    }
    packet_info.tls_server.group = tls_extension_data
        .group_list
        .first()
        .map(|g| TlsSupportedGroup::from_u16(*g).unwrap_or_default())
        .unwrap_or_default();
    packet_info.tls_server.alpn = tls_extension_data
        .alpn_list
        .first()
        .map(|s| s.as_str())
        .unwrap_or("")
        .to_string();
    let ja3s_hash = compute_ja3_server_fingerprint(
        server_hello_version,
        packet_info.tls_server.cipher.to_u16(),
        &tls_extension_data.ext_list,
    );
    packet_info.tls_server.ja3s = ja3s_hash;
    packet_info.tls_server.ja4s = compute_ja4_server_fingerprint(
        packet_info.protocol,
        packet_info.tls_server.cipher.to_u16(),
        &tls_extension_data.ext_list,
        tls_extension_data.highest_version,
        &packet_info.tls_server.alpn,
    );

    offset += extension_len as usize;
    Ok(offset)
}

fn parse_client_hello(
    packet_info: &mut Packet_info,
    packet: &[u8],
    statistics: &mut Statistics,
) -> Result<usize, Box<dyn Error>> {
    let mut offset = 0;
    let client_hello_version = ssl_read_u16(packet, offset)?;
    offset += 2;

    //debug!("CH length:{}", packet.len());
    //debug!("CH version:{:x}", client_hello_version);
    let _random = ssl_parse_slice(packet, offset..offset + 32)?;
    offset += 32;
    //debug!("random:{:x?}", random);
    let session_id_len = ssl_read_u8(packet, offset)?;
    offset += 1;
    //debug!("session id len:{}", session_id_len);
    let _session_id = ssl_parse_slice(packet, offset..offset + session_id_len as usize)?;
    offset += session_id_len as usize;
    //debug!("session id :{:x?}", session_id);
    let cipher_suite_len = ssl_read_u16(packet, offset)?;
    //debug!("ciphersuite length:{}", cipher_suite_len);
    offset += 2;
    let mut cipher_list = Vec::new();
    for _i in 0..cipher_suite_len / 2 {
        let cs = ssl_read_u16(packet, offset)?;
        cipher_list.push(cs);
        let cs = TlsCipherSuite::from_u16(cs).unwrap_or_default();
        packet_info.tls_client.ciphers.push(cs);
        *statistics.client_ciphers.entry(cs).or_insert(0) += 1;
        //debug!("cipher: {:}", cs.as_str());
        offset += 2;
    }
    let compression_methods_len = ssl_read_u8(packet, offset)?;
    //debug!("compression methods len:{}", compression_methods_len);
    offset += 1;
    for _i in 0..compression_methods_len {
        let _cm = ssl_read_u8(packet, offset)?;
        //debug!("compression method: {}", cm);
        offset += 1;
    }
    let extension_len = ssl_read_u16(packet, offset)?;
    //debug!("extension len:{}", extension_len);
    offset += 2;

    let tls_extension_data = parse_extension(
        ssl_parse_slice(packet, offset..offset + extension_len as usize)?,
        true,
        statistics,
    )?;
    //debug!("Sig list: {:x?}", sig_list);

    offset += extension_len as usize;

    let ja4_string = compute_ja4_client_fingerprint(
        packet_info.protocol,
        &cipher_list,
        &tls_extension_data.ext_list,
        tls_extension_data.highest_version,
        &tls_extension_data.alpn_list,
        !tls_extension_data.sni.is_empty(),
        &tls_extension_data.sig_list,
    );

    packet_info.tls_client.sni = tls_extension_data.sni.clone();
    packet_info.tls_client.ja3c = compute_ja3_client_fingerprint(
        client_hello_version,
        &cipher_list,
        &tls_extension_data.ext_list,
        &tls_extension_data.group_list,
        &tls_extension_data.point_list,
    );
    packet_info.tls_client.ja4c = ja4_string.clone();
    packet_info.tls_client.alpns = tls_extension_data.alpn_list.to_vec();
    packet_info.tls_client.versions = vec![packet_info.tls_server.version];
    packet_info.tls_client.signature_algorithms = tls_extension_data
        .sig_list
        .iter()
        .map(|v| TlsSignatureScheme::from_u16(*v).unwrap_or_default())
        .collect::<Vec<_>>();
    packet_info.tls_client.groups = tls_extension_data
        .group_list
        .iter()
        .map(|v| TlsSupportedGroup::from_u16(*v).unwrap_or_default())
        .collect();
    /*  debug!("cipherlist: {:?} ", cipher_list);
    debug!("ext list: {:?} ", ext_list);
    debug!("grouplist: {:?} ", group_list);
    debug!("pointlist: {:?} ", point_list);
    debug!("alpn list: {:?} ", alpn_list);
    debug!("sni: {:?} ", sni);
    debug!("version: {:?}", client_hello_version);
    debug!("JA3: {} --", &ja3_string);
    debug!("JA3 hash: {}", hash);
    debug!("JA4: {} --", &ja4_string);*/
    Ok(offset)
}

fn parse_tls_handshake(
    packet: &[u8],
    packet_info: &mut Packet_info,
    statistics: &mut Statistics,
) -> Result<(), Box<dyn Error>> {
    let mut offset = 0;
    let len = packet.len();
    while offset < len {
        // handshake
        let handshake_type = ssl_read_u8(packet, offset)?;
        let length = ssl_read_u24(packet, offset + 1)?;
        //debug!("handshake type:{} length {} {}", handshake_type, length, offset) ;
        if handshake_type == 1 {
            // debug!("client hello {source_ip} {dest_ip} {sp} {dp}");
            parse_client_hello(
                packet_info,
                ssl_parse_slice(packet, offset + 4..offset + 4 + length as usize)?,
                statistics,
            )?;
        } else if handshake_type == 2 {
            //            debug!( "server hello {source_ip} {dest_ip} {sp} {dp}", source_ip = packet_info.s_addr, dest_ip = packet_info.d_addr, sp = packet_info.sp, dp = packet_info.dp );
            parse_server_hello(
                packet_info,
                ssl_parse_slice(packet, offset + 4..offset + 4 + length as usize)?,
                statistics,
            )?;
        } else if handshake_type == 22 {
            debug!(
                "Content Type: certificate status {source_ip} {dest_ip} {sp} {dp}",
                source_ip = packet_info.s_addr,
                dest_ip = packet_info.d_addr,
                sp = packet_info.sp,
                dp = packet_info.dp
            );
        } else if handshake_type == 11 {
            debug!("certificate");
        } else if handshake_type == 13 {
            debug!("certificate request");
        } else if handshake_type == 15 {
            debug!("certificate verify");
        } else if handshake_type == 15 {
            debug!("client certificate request");
        } else if handshake_type == 20 {
            debug!("finished");
        } else if handshake_type == 24 {
            debug!("key update");
        } else if handshake_type == 4 {
            debug!("new session ticket");
        } else if handshake_type == 14 {
            debug!("server hello done");
        } else if handshake_type == 16 {
            debug!("client key exchange");
        } else if handshake_type == 12 {
            // key exchange // TLS 1.2 only
            debug!("Server key exchange");
            //            debug!( "Content Type: key exchange {source_ip} {dest_ip} {sp} {dp}", source_ip = packet_info.s_addr, dest_ip = packet_info.d_addr, sp = packet_info.sp, dp = packet_info.dp );
            parse_key_exchange(packet_info, packet, offset + 1)?;
        } else {
            return Err(Parse_error::new(
                ParseErrorType::Invalid_TLS_Packet,
                &format!("handshake type {handshake_type}"),
            )
            .into());
        }
        offset += 4 + length as usize;
    }
    Ok(())
}

fn parse_ssl(
    packet: &[u8],
    packet_info: &mut Packet_info,
    statistics: &mut Statistics,
) -> Result<(), Box<dyn Error>> {
    //debug!("{:?}", &packet);
    let mut offset = 0;
    while offset < packet.len() {
        let content_type = ssl_read_u8(packet, offset)?;
        // debug!("offset {} content type {} ", offset, content_type);
        let _tls_version = ssl_read_u16(packet, offset + 1)?;
        let tls_length = ssl_read_u16(packet, offset + 3)?;
        // debug!("Version:{:x} length:{}", tls_version, tls_length);
        if content_type == 22 {
            parse_tls_handshake(
                ssl_parse_slice(packet, offset + 5..offset + 5 + tls_length as usize)?,
                packet_info,
                statistics,
            )?;
        } else if content_type == 23 {
            //            debug!("Content Type: application data {content_type} {source_ip} {dest_ip} {sp} {dp}", source_ip = packet_info.s_addr, dest_ip = packet_info.d_addr, sp = packet_info.sp, dp = packet_info.dp );
            // stop parsing
            return Ok(());
        } else if content_type == 20 {
            // change cipher spec
            //            debug!("Content Type: change cipher spec {content_type} {source_ip} {dest_ip} {sp} {dp}", source_ip = packet_info.s_addr, dest_ip = packet_info.d_addr, sp = packet_info.sp, dp = packet_info.dp );
            // stop parsing
            return Ok(());
        } else if content_type == 21 {
            //   debug!("Content Type: alert");
        } else if content_type == 24 {
            //   debug!("Content Type: heartbeat");
        } else if content_type == 25 {
            //    debug!("Content Type: tls12_cid");
        } else if content_type == 26 {
            //   debug!("Content Type: ack");
        } else if content_type == 27 {
            //   debug!("Content Type: return_routability_check");
        } else {
            return Err(Parse_error::new(
                ParseErrorType::Invalid_TLS_Packet,
                &format!("Content type: {}", content_type),
            )
            .into());
        }
        offset += 5 + tls_length as usize;
    }
    Ok(())
}

fn parse_key_exchange(
    packet_info: &mut Packet_info,
    packet: &[u8],
    offset_in: usize,
) -> Result<(), Box<dyn Error>> {
    let mut offset = offset_in;
    // Length of the KeyExchange message
    let _len = ssl_read_u24(packet, offset)?;
    offset += 3;

    let cipher_name = packet_info.tls_server.cipher.as_str();

    if cipher_name.contains("ECDHE") {
        parse_ecdhe_params(packet_info, packet, &mut offset)?;
    } else if cipher_name.contains("DHE") {
        parse_dhe_params(packet_info, packet, &mut offset)?;
    }

    Ok(())
}

fn parse_ecdhe_params(
    packet_info: &mut Packet_info,
    packet: &[u8],
    offset: &mut usize,
) -> Result<(), Box<dyn Error>> {
    let curve_type = ssl_read_u8(packet, *offset)?;
    *offset += 1;

    if curve_type != 3 {
        // Only named_curve (3) is supported.
        return Err(Parse_error::new(
            ParseErrorType::Invalid_TLS_Packet,
            &format!("Unsupported curve type: {curve_type}"),
        )
        .into());
    }

    let curve = ssl_read_u16(packet, *offset)?;
    *offset += 2;
    packet_info.tls_server.group = TlsSupportedGroup::from_u16(curve).unwrap_or_default();

    let pubkey_len = ssl_read_u8(packet, *offset)? as usize;
    *offset += 1;

    packet_info.tls_server.pubkey =
        ssl_parse_slice(packet, *offset..*offset + pubkey_len)?.to_vec();
    *offset += pubkey_len;

    Ok(())
}

fn parse_dhe_params(
    packet_info: &mut Packet_info,
    packet: &[u8],
    offset: &mut usize,
) -> Result<(), Box<dyn Error>> {
    let p_len = ssl_read_u16(packet, *offset)? as usize;
    *offset += 2;
    let p = ssl_parse_slice(packet, *offset..*offset + p_len)?;
    *offset += p_len;

    let g_len = ssl_read_u16(packet, *offset)? as usize;
    *offset += 2;
    let g = ssl_parse_slice(packet, *offset..*offset + g_len)?;
    *offset += g_len;

    let pubkey_len = ssl_read_u16(packet, *offset)? as usize;
    *offset += 2;
    let pubkey = ssl_parse_slice(packet, *offset..*offset + pubkey_len)?;
    *offset += pubkey_len;

    let sig_alg = ssl_read_u16(packet, *offset)?;
    *offset += 2;
    packet_info.tls_server.signature_algorithm =
        TlsSignatureScheme::from_u16(sig_alg).unwrap_or_default();

    let sig_len = ssl_read_u16(packet, *offset)? as usize;
    *offset += 2;
    let sig = ssl_parse_slice(packet, *offset..*offset + sig_len)?;
    *offset += sig_len;

    debug!(
        "DHE Params - P: {:x?}, G: {:x?}, PK: {:x?}, Sig: {:x?}",
        p, g, pubkey, sig
    );
    Ok(())
}

const SYN_FLAG: u16 = 2;
const FIN_FLAG: u16 = 1;
const RESET_FLAG: u16 = 4;
fn parse_tcp(
    packet: &[u8],
    packet_info_list: &mut Packet_Info_List,
    config: &Config,
    ts: DateTime<Utc>,
    source_ip: &IpAddr,
    dest_ip: &IpAddr,
    statistics: &mut Statistics,
) -> Result<(), Box<dyn Error>> {
    const MIN_TCP_HEADER_LEN: usize = 20;
    if packet.len() < MIN_TCP_HEADER_LEN {
        return Err(Parse_error::new(ParseErrorType::Invalid_TCP_Header, "LEN < 20").into());
    }

    let src_port = ssl_read_u16(packet, 0)?;
    let dst_port = ssl_read_u16(packet, 2)?;
    let seq_nr = ssl_read_u32(packet, 4)?;

    // Header length is the high 4 bits of byte 12, multiplied by 4
    let header_len = (ssl_read_u8(packet, 12)? >> 4) as usize * 4;
    let flags = ssl_read_u16(packet, 12)? & 0x0fff;

    if packet.len() < header_len {
        return Ok(());
    }

    if flags & SYN_FLAG != 0 {
        return handle_syn_packet(
            packet_info_list,
            config,
            ts,
            seq_nr,
            src_port,
            dst_port,
            source_ip,
            dest_ip,
        );
    }

    if flags & (FIN_FLAG | RESET_FLAG) != 0 {
        handle_fin_packet(
            packet_info_list,
            config,
            src_port,
            dst_port,
            source_ip,
            dest_ip,
            statistics,
        )?;
    } else {
        let data = ssl_parse_slice(packet, header_len..)?;
        if !data.is_empty() {
            if config.ports.contains(&src_port) {
                handle_server_data(
                    packet_info_list,
                    seq_nr,
                    data,
                    src_port,
                    dst_port,
                    source_ip,
                    dest_ip,
                    statistics,
                )?;
            } else if config.ports.contains(&dst_port) {
                handle_client_data(
                    packet_info_list,
                    seq_nr,
                    data,
                    src_port,
                    dst_port,
                    source_ip,
                    dest_ip,
                    statistics,
                )?;
            }
        }
    }

    Ok(())
}

fn handle_syn_packet(
    packet_info_list: &mut Packet_Info_List,
    config: &Config,
    ts: DateTime<Utc>,
    seqnr: u32,
    sp: u16,
    dp: u16,
    source_ip: &IpAddr,
    dest_ip: &IpAddr,
) -> Result<(), Box<dyn Error>> {
    let (client_ip, server_ip, client_port, server_port, is_server_msg) =
        if config.ports.contains(&dp) {
            (source_ip, dest_ip, sp, dp, false)
        } else if config.ports.contains(&sp) {
            (dest_ip, source_ip, dp, sp, true)
        } else {
            return Ok(());
        };
    let packet_info = packet_info_list
        .packets
        .entry((
            client_ip.clone(),
            server_ip.clone(),
            client_port,
            server_port,
        ))
        .or_insert_with(|| {
            Packet_info::new(
                ts,
                client_port,
                server_port,
                client_ip.clone(),
                server_ip.clone(),
                &TLS_Protocol::TCP,
            )
        });

    if is_server_msg {
        packet_info.tls_server.initial_seqnr = seqnr + 1;
    } else {
        packet_info.tls_client.initial_seqnr = seqnr + 1;
    }
    Ok(())
}

fn handle_fin_packet(
    packet_info_list: &mut Packet_Info_List,
    config: &Config,
    sp: u16,
    dp: u16,
    source_ip: &IpAddr,
    dest_ip: &IpAddr,
    statistics: &mut Statistics,
) -> Result<(), Box<dyn Error>> {
    //debug!("FIN or RESET packet {source_ip} {dest_ip} {sp} {dp}");
    let key = if config.ports.contains(&sp) {
        (dest_ip.clone(), source_ip.clone(), dp, sp)
    } else {
        (source_ip.clone(), dest_ip.clone(), sp, dp)
    };
    if let Entry::Occupied(mut p) = packet_info_list.packets.entry(key) {
        let packet_data = p.get_mut();
        //        debug!( "setting done for ({source_ip},{dest_ip},{sp},{dp}) {:?}", packet_data );
        finalize_server(packet_data, statistics)?;
        finalize_client(packet_data, statistics)?;
    }
    Ok(())
}

fn finalize_client(p: &mut Packet_info, statistics: &mut Statistics) -> Result<(), Box<dyn Error>> {
    if !p.tls_client.done && p.tls_client.data.len() > 0 {
        let client_data = p.tls_client.data.clone();
        parse_ssl(&client_data, p, statistics)?;
        p.tls_client.data.clear();
    }
    p.tls_client.initial_seqnr = 0;
    p.tls_client.done = true;
    Ok(())
}

fn finalize_server(p: &mut Packet_info, statistics: &mut Statistics) -> Result<(), Box<dyn Error>> {
    if !p.tls_server.done && p.tls_server.data.len() > 0 {
        let server_data = p.tls_server.data.clone();
        parse_ssl(&server_data, p, statistics)?;
        p.tls_server.data.clear();
    }
    p.tls_server.initial_seqnr = 0;
    p.tls_server.done = true;
    Ok(())
}
fn handle_server_data(
    packet_info_list: &mut Packet_Info_List,
    seqnr: u32,
    data: &[u8],
    sp: u16,
    dp: u16,
    source_ip: &IpAddr,
    dest_ip: &IpAddr,
    statistics: &mut Statistics,
) -> Result<(), Box<dyn Error>> {
    let key = (dest_ip.clone(), source_ip.clone(), dp, sp);

    let packet = match packet_info_list.packets.get_mut(&key) {
        Some(p) => p,
        None => return Ok(()),
    };

    let initial_seqnr = packet.tls_server.initial_seqnr;
    if initial_seqnr == 0 {
        return Ok(());
    }

    let offset = seqnr.wrapping_sub(initial_seqnr) as usize;
    if offset >= 50000 {
        debug!("offset too big {} seqnr {} ", offset, seqnr);
        return Ok(());
    }

    // Buffer management and data ingestion
    let server_data = &mut packet.tls_server.data;
    let end_index = offset + data.len();
    if server_data.len() < end_index {
        server_data.resize(end_index, 0);
    }
    server_data[offset..end_index].copy_from_slice(data);

    packet.tls_server.packet_count += 1;

    if packet.tls_server.packet_count >= 4 {
        return finalize_server(packet, statistics);
    }

    Ok(())
}

fn handle_client_data(
    packet_info_list: &mut Packet_Info_List,
    seqnr: u32,
    data: &[u8],
    sp: u16,
    dp: u16,
    source_ip: &IpAddr,
    dest_ip: &IpAddr,
    statistics: &mut Statistics,
) -> Result<(), Box<dyn Error>> {
    let key = (source_ip.clone(), dest_ip.clone(), sp, dp);
    let mut entry = match packet_info_list.packets.entry(key) {
        Entry::Occupied(e) => e,
        Entry::Vacant(_) => return Ok(()),
    };

    let v = entry.get_mut();
    let client = &mut v.tls_client;

    if client.initial_seqnr == 0 {
        return Ok(());
    }

    let offset = seqnr.wrapping_sub(client.initial_seqnr) as usize;
    if offset > 25000 {
        debug!(
            "offset too big {} seqnr {} {} {} ",
            offset, seqnr, client.initial_seqnr, v.tls_server.initial_seqnr
        );
        return Ok(());
    }

    client.data.resize(offset + data.len(), 0);
    client.data[offset..offset + data.len()].copy_from_slice(data);
    client.packet_count += 1;

    if client.packet_count >= 4 {
        return finalize_client(v, statistics);
    }

    Ok(())
}

fn parse_udp(
    packet: &mut [u8],
    packet_info_list: &mut Packet_Info_List,
    config: &Config,
    ts: DateTime<Utc>,
    source_ip: &IpAddr,
    dest_ip: &IpAddr,
    statistics: &mut Statistics,
) -> Result<(), Box<dyn Error>> {
    if packet.len() < 8 {
        return Err(Parse_error::new(ParseErrorType::Invalid_UDP_Header, "packet len < 8").into());
    }
    let sp = ssl_read_u16(packet, 0)?;
    let dp = ssl_read_u16(packet, 2)?;
    let _len = ssl_read_u16(packet, 4)?;
    let _checksum = ssl_read_u16(packet, 6)?;
    //    debug!( "UDP sp: {} dp:{} len:{} checksum:{:x}", sp, dp, len, checksum );
    // packet_info.set_dest_port(dp);
    ////packet_info.set_source_port(sp);
    //    packet_info.set_data_len(u32::from(len) - 8);

    // TODO need to handle DTLS
    if config.ports.contains(&dp) || config.ports.contains(&sp) {
        //parse_ssl(packet, packet_info_list, ts, source_ip, dest_ip, sp, dp)
        let mut data = ssl_parse_slice(packet, 8..)?.to_vec();
        parse_quic(
            &mut data,
            config,
            packet_info_list,
            ts,
            source_ip,
            dest_ip,
            sp,
            dp,
            statistics,
        )
    } else {
        Err(Parse_error::new(
            ParseErrorType::Invalid_TLS_Packet,
            &format!("UDP {dp} {sp}"),
        )
        .into())
    }
}

const QUIC_V1_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

fn hkdf_expand_label(secret: &[u8], label: &str, length: usize) -> Result<Vec<u8>, Parse_error> {
    let hk = Hkdf::<Sha256>::from_prk(secret).map_err(|_| {
        Parse_error::new(ParseErrorType::Invalid_TLS_Packet, "Invalid PRK length for SHA256")
    })?;
    // 1. Build the "tls13 " prefixed label
    let full_label = format!("tls13 {}", label);

    // 2. Construct the 'info' byte sequence:
    // [2 bytes: length] [1 byte: label_length] [label] [1 byte: 0x00 (context length)]
    let mut info = Vec::new();
    info.extend_from_slice(&(length as u16).to_be_bytes()); // Output length (big-endian)
    info.push(full_label.len() as u8); // Label length
    info.extend_from_slice(full_label.as_bytes()); // The label itself
    info.push(0); // Context length (always 0)

    let mut okm = vec![0u8; length];
    hk.expand(&info, &mut okm).map_err(|_| {
        Parse_error::new(ParseErrorType::Invalid_TLS_Packet, "HKDF expansion failed")
    })?;
    Ok(okm)
}


pub fn calculate_initial_secret(salt: &[u8], cid: &[u8]) -> Vec<u8> {
    // HKDF-Extract returns (PseudoRandomKey, HkdfObj)
    // The PseudoRandomKey is our initial_secret.
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), cid);

    // Convert the output to a Vec for easy handling
    prk.to_vec()
}
fn derive_initial_secret(dcid: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>>  {
    let initial_secret = calculate_initial_secret(&QUIC_V1_SALT, &dcid);

    let client_secret = hkdf_expand_label(&initial_secret, "client in", 32)?;
    let server_secret = hkdf_expand_label(&initial_secret, "server in", 32)?;

    Ok((client_secret, server_secret))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_quic_initial_secret_derivation() {
        // This is the CID used in the RFC test vector
        let cid: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

        // 2. Expected output provided by you (and RFC 9001)
        let expected_hex = "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44";

        // 3. Calculate the secret
        let secret = calculate_initial_secret(&QUIC_V1_SALT, &cid);

        // 4. Verification
        let result_hex = hex::encode(secret);
        assert_eq!(result_hex, expected_hex);
        println!("Success! Calculated Secret: {}", result_hex);
    }
    #[test]
    fn test_rfc9001_appendix_a_initial_secrets() {
        // Initial secret test vectors from RFC 9001, Appendix A.1
        let dcid = hex::decode("8394c8f03e515708").unwrap();

        let (client_secret, server_secret) = derive_initial_secret(&dcid).unwrap();

        // Expected Initial Secret (extracted intermediate value from RFC)
        // initial_secret = HKDF-Extract(salt, dcid)
        // RFC value: 7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44

        // Expected Client Initial Secret
        // RFC value: c00cf151ca5be075ed0ebfb5c803ad3f5196a0bb2ed13875691459a499801295
        let expected_client = "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea";
        assert_eq!(hex::encode(client_secret), expected_client);

        // Expected Server Initial Secret
        // RFC value: d0ed82005c7448d5d1451000b0f75143003b57084531818d360814917a126742
        let expected_server = "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b";
        assert_eq!(hex::encode(server_secret), expected_server);
    }

    #[test]
    fn test_rfc9001_appendix_a2_client_initial_keys() {
        // RFC 9001 Appendix A.2 - Client Initial packet protection keys
        let client_secret =
            hex::decode("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
                .unwrap();
        let keys = derive_packet_keys(&client_secret).unwrap();

        // Expected values from RFC 9001 A.2
        assert_eq!(hex::encode(keys.key), "1f369613dd76d5467730efcbe3b1a22d");
        assert_eq!(hex::encode(keys.iv), "fa044b2f42a3fd3b46fb255c");
        assert_eq!(hex::encode(keys.hp), "9f50449e04a0e810283a1e9933adedd2");
    }

    #[test]
    fn test_rfc9001_appendix_a2_server_initial_keys() {
        // RFC 9001 Appendix A.2 - Server Initial packet protection keys
        let server_secret =
            hex::decode("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")
                .unwrap();
        let keys = derive_packet_keys(&server_secret).unwrap();

        // Expected values from RFC 9001 A.2
        assert_eq!(hex::encode(keys.key), "cf3a5331653c364c88f0f379b6067e37");
        assert_eq!(hex::encode(keys.iv), "0ac1493ca1905853b0bba03e");
        assert_eq!(hex::encode(keys.hp), "c206b8d9b9f0f37644430b490eeaa314");
    }
}
struct PacketKeys {
    hp: [u8; 16],
    key: [u8; 16],
    iv: [u8; 12],
}

fn derive_packet_keys(secret: &[u8]) -> Result<PacketKeys, Parse_error> {
    Ok(PacketKeys {
        hp: hkdf_expand_label(secret, "quic hp", 16)?
            .try_into()
            .map_err(|_| {
                Parse_error::new(ParseErrorType::Invalid_TLS_Packet, "QUIC HP key size mismatch")
            })?,
        key: hkdf_expand_label(secret, "quic key", 16)?
            .try_into()
            .map_err(|_| {
                Parse_error::new(ParseErrorType::Invalid_TLS_Packet, "QUCI key size mismatch")
            })?,
        iv: hkdf_expand_label(secret, "quic iv", 12)?
            .try_into()
            .map_err(|_| {
                Parse_error::new(ParseErrorType::Invalid_TLS_Packet, "QUIC IV size mismatch")
            })?,
    })
}

/// Removes QUIC header protection in-place
///
/// `packet` = full QUIC packet buffer
/// `pn_offset` = offset of packet number field
/// `hp_key` = header protection key (16 bytes for AES-128)
pub fn remove_header_protection(
    packet: &mut [u8],
    pn_offset: usize,
    hp_key: &[u8; 16],
) -> Result<usize, Box<dyn Error>> {
    // Sample is always 16 bytes starting 4 bytes after PN start
    let sample_offset = pn_offset + 4;
    let sample = ssl_parse_slice(packet, sample_offset..sample_offset + 16)?;

    // Encrypt sample with AES-ECB
    let cipher = Aes128::new(GenericArray::from_slice(hp_key));
    let mut block = GenericArray::clone_from_slice(sample);
    cipher.encrypt_block(&mut block);

    let mask = block.as_slice();

    // Long header: mask lower 4 bits of the first byte
    packet[0] ^= mask[0] & 0x0f;

    // Packet number length is encoded in low 2 bits
    let pn_len = (packet[0] & 0x03) as usize + 1;
    if packet.len() < pn_offset + pn_len {
        return Err(Parse_error::new(
            ParseErrorType::Invalid_TLS_Packet,
            &format!("Packet too short {:x}", packet.len()),
        )
        .into());
    }

    // Unmask packet number bytes
    for i in 0..pn_len {
        packet[pn_offset + i] ^= mask[1 + i];
    }

    Ok(pn_len)
}

fn parse_varint(buf: &[u8], offset: usize) -> Result<(u64, usize), Parse_error> {
    let remaining = buf.get(offset..).ok_or_else(|| {
        Parse_error::new(
            ParseErrorType::Invalid_TLS_Packet,
            &format!(
                "Offset {} out of bounds for buffer length {}",
                offset,
                buf.len()
            ),
        )
    })?;

    if remaining.is_empty() {
        return Err(Parse_error::new(
            ParseErrorType::Invalid_TLS_Packet,
            &format!("Empty buffer at offset {}", offset),
        )
        .into());
    }

    let first = remaining[0];
    let len = match first >> 6 {
        0b00 => 1,
        0b01 => 2,
        0b10 => 4,
        0b11 => 8,
        _ => unreachable!(),
    };

    if remaining.len() < len {
        return Err(Parse_error::new(
            ParseErrorType::Invalid_TLS_Packet,
            &format!(
                "Packet too short: expected {} bytes, got {}",
                len,
                remaining.len()
            ),
        )
        .into());
    }

    let mut value = (first & 0x3f) as u64;
    for i in 1..len {
        value = (value << 8) | remaining[i] as u64;
    }

    Ok((value, len))
}
fn decrypt_quic_payload(
    aead_key: &[u8],
    iv: &[u8],
    packet_number: u64,
    ciphertext: &mut [u8],
    aad: &[u8],
) -> Result<usize, Box<dyn Error>> {
    if aead_key.len() != 16 || iv.len() != 12 {
        return Err(Parse_error::new(
            ParseErrorType::Invalid_TLS_Packet,
            &format!( "Mismatch IV and AAD length {} {} ", aead_key.len(), iv.len() )).into());
    }

   // debug!("payload: {:x?} {}", &ciphertext[0..4], ciphertext.len());
    let cipher = Aes128Gcm::new(GenericArray::from_slice(aead_key));

    // compute nonce = IV ⊕ packet_number
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(iv);
    let pn_bytes = packet_number.to_be_bytes(); // 8 bytes
    // XOR last 8 bytes of IV with packet number
    for i in 0..8 {
        nonce_bytes[4 + i] ^= pn_bytes[i];
    }
    let nonce = GenericArray::from_slice(&nonce_bytes);
    let tag_pos = ciphertext.len().saturating_sub(16);
    let (data, tag) = ciphertext.split_at_mut(tag_pos);
    let tag = aes_gcm::Tag::from_slice(tag);
    cipher.decrypt_in_place_detached( nonce, aad, data, tag).map_err(|_| Parse_error::new(ParseErrorType::Invalid_TLS_Packet, "Decryption failed"))?;
    Ok(ciphertext.len().saturating_sub(16))

}


#[inline]
fn skip_varint(buf: &[u8], pos: usize) -> Option<usize> {
    let first = *buf.get(pos)?;
    let len = match first >> 6 {
        0b00 => 1,
        0b01 => 2,
        0b10 => 4,
        0b11 => 8,
        _ => unreachable!(),
    };
    if pos + len > buf.len() {
        None
    } else {
        Some(len)
    }
}

fn parse_ack_frame(buf: &[u8], pos_in: usize) -> Result<usize, Parse_error> {
    let mut pos = pos_in;
    let (_, len) = parse_varint(buf, pos)?;
    pos += len;
    let (_, len) = parse_varint(buf, pos)?;
    pos += len;
    let (range_count, len) = parse_varint(buf, pos)?;
    pos += len;
    let (_, len) = parse_varint(buf, pos)?;
    pos += len;
    if range_count > (buf.len().saturating_sub(pos) as u64 / 2) {
        return Err(Parse_error::new(ParseErrorType::Invalid_TLS_Packet, "Invalid range count: exceeds remaining buffer capacity").into());
    }
    for _ in 0..range_count as usize {
        // Gap
        pos += skip_varint(buf, pos).ok_or_else(|| Parse_error::new(ParseErrorType::Invalid_TLS_Packet, "ACK Gap"))?;
        // Length
        pos += skip_varint(buf, pos).ok_or_else(|| Parse_error::new(ParseErrorType::Invalid_TLS_Packet, "ACK Range Len"))?;
    }
    Ok(pos - pos_in)
}

fn process_quic_handshake_data(
    is_client: bool,
    packet_info: &mut Packet_info,
    statistics: &mut Statistics,
) -> Result<(), Box<dyn Error>> {
    if is_client {
        packet_info.tls_client.done = true;
        let mut client_data = packet_info.tls_client.data.clone();
        if !client_data.is_empty() {
            parse_tls_handshake(&mut client_data, packet_info, statistics)?;
        }
    } else {
        packet_info.tls_server.done = true;
        let mut server_data = packet_info.tls_server.data.clone();
        if !server_data.is_empty() {
            parse_tls_handshake(&mut server_data, packet_info, statistics)?;
        }
    }
    Ok(())
}

fn ssl_read_packet_number(
    packet: &[u8],
    offset: usize,
    pn_len: usize,
) -> Result<u32, Parse_error> {
    match pn_len {
        1 => Ok(ssl_read_u8(packet, offset)? as u32),
        2 => Ok(ssl_read_u16(packet, offset)? as u32),
        3 => Ok(ssl_read_u24(packet, offset)?),
        4 => Ok(ssl_read_u32(packet, offset)?),
        _ => Err(Parse_error::new(
            ParseErrorType::Invalid_TLS_Packet,
            &format!("Packet number length {pn_len}"),
        )
        .into()),
    }
}


const MAX_HANDSHAKE_SIZE: u64 = 30000;

fn parse_crypto_frame(
    packet_payload: &[u8],
    mut crypto_offset: usize,
    is_client: bool,
    packet_info: &mut Packet_info,
    frame_type: u64,
) -> Result<usize, Box<dyn Error>> {
    let start_offset = crypto_offset;
   // debug!("Crypto frame");
    let (offset, len) = parse_varint(packet_payload, crypto_offset)?;
    crypto_offset += len;
    let (length, len) = parse_varint(packet_payload, crypto_offset)?;
    crypto_offset += len;
    //debug!("QUIC frame type: {frame_type:x} offset {offset} len: {length} ");
    let crypto_data = ssl_parse_slice(
        packet_payload,
        crypto_offset..crypto_offset + length as usize,
    )?;
    /*debug!(
        "QUIC frame type: {frame_type:x} offset {offset} len: {length} data {:x?}",
        &crypto_data[0..std::cmp::min(4, crypto_data.len())]
    );*/
    let store_data = if is_client {
        packet_info.tls_client.packet_count += 1;
        &mut packet_info.tls_client.data
    } else {
        packet_info.tls_server.packet_count += 1;
        &mut packet_info.tls_server.data
    };
    let total_required = offset.checked_add(length).unwrap_or(u64::MAX);

    if total_required > MAX_HANDSHAKE_SIZE {
        return Err(Parse_error::new(
            ParseErrorType::Invalid_TLS_Packet,
            &format!("Length and offset too large {} {}", length, offset),
        )
        .into());
    }
    if store_data.len() < (total_required as usize) {
        store_data.resize(total_required as usize, 0);
    }
    store_data[offset as usize..total_required as usize].copy_from_slice(crypto_data);

    Ok((crypto_offset + length as usize) - start_offset)
}

fn parse_quic(
    packet: &mut [u8],
    config: &Config,
    packet_info_list: &mut Packet_Info_List,
    ts: DateTime<Utc>,
    source_ip: &IpAddr,
    dest_ip: &IpAddr,
    sp: u16,
    dp: u16,
    statistics: &mut Statistics,
) -> Result<(), Box<dyn Error>> {
    let is_client = config.ports.contains(&dp);
    let mut offset = 0;
    let flag = ssl_read_u8(packet, offset)?;
    let packet_key = if is_client {
        (*source_ip, *dest_ip, sp, dp)
    } else {
        (*dest_ip, *source_ip, dp, sp)
    };
    let packet_info = packet_info_list
        .packets
        .entry(packet_key)
        .or_insert_with(|| {
            Packet_info::new(
                ts,
                packet_key.2,
                packet_key.3,
                packet_key.0.clone(),
                packet_key.1.clone(),
                &TLS_Protocol::QUIC,
            )
        });
    if flag & 0x3 == 0 || flag & 0x80 != 0x80 {
        // not an i=itial packet or not a long header
        return Ok(());
    }
    if flag & 0x80 != 0x80 || flag & 0x40 == 0 {
        // Should check the Fixed Bit (0x40)
        return Ok(());
    }
    if flag & 0x30 == 0x20 {
      //  debug!("Handshake");
        process_quic_handshake_data(is_client, packet_info, statistics)?;
        return Ok(());
    }

    if flag & 0x30 != 00 {
       // debug!("Not an initial packet");
        return Ok(());
    }
    let version = ssl_read_u32(packet, offset + 1)?;
    if version != 1 {
        return Err(Parse_error::new(
            ParseErrorType::Invalid_TLS_Packet,
            &format!("Version = {:x}", version),
        )
            .into());
    }
    let d_conn_id_len = ssl_read_u8(packet, offset + 5)?;
    if d_conn_id_len > 20 {
        return Err(Parse_error::new(
            ParseErrorType::Invalid_TLS_Packet,
            &format!("D conn Id > 20 {}", d_conn_id_len),
        )
            .into());
    }
    let d_conn_id = ssl_parse_slice(packet, offset + 6..offset + 6 + d_conn_id_len as usize)?;
    offset = 6 + d_conn_id_len as usize;
    let s_conn_id_len = ssl_read_u8(packet, offset)?;
    if s_conn_id_len > 20 {
        return Err(Parse_error::new(
            ParseErrorType::Invalid_TLS_Packet,
            &format!("s conn Id > 20 {}", s_conn_id_len),
        )
            .into());
    }
    let s_conn_id = ssl_parse_slice(packet, offset + 1..offset + 1 + s_conn_id_len as usize)?;
    offset += 1 + s_conn_id_len as usize;
    /*debug!(
            "QUIC d_conn_id {:x} {:x?}, {:x }{:x?} {}",
            d_conn_id_len, d_conn_id, s_conn_id_len, s_conn_id, offset
        );*/

    if packet_info.initial_client_secret.is_empty() && is_client {
        let (client_secret, server_secret) = derive_initial_secret(d_conn_id)?;
        packet_info.initial_client_secret = client_secret;
        packet_info.initial_server_secret = server_secret;
    } else if !is_client && packet_info.initial_server_secret.is_empty() {
        return Err(Parse_error::new(
            ParseErrorType::Invalid_TLS_Packet,
            &"Missed initial d_conn_id ".to_string(),
        )
            .into());
    }
    let secret = if !is_client {
        &packet_info.initial_server_secret
    } else {
        &packet_info.initial_client_secret
    };
    let p_key = derive_packet_keys(secret)?;
    let (token_len, len) = parse_varint(packet, offset)?;
    offset += len + token_len as usize;
    let (len, size) = parse_varint(&packet, offset)?;
    offset += size;
    let pn_len = remove_header_protection(packet, offset, &p_key.hp)?;
    let packet_number = ssl_read_packet_number(packet, offset, pn_len)?;

    offset += pn_len;
    //debug!("QUIC packet nr: {packet_number} QUIC len: {len}");
   // debug!("Frame {:x}", packet[offset]);
    if len < pn_len as u64 {
        return Err(Parse_error::new(
            ParseErrorType::Invalid_TLS_Packet,
            &format!("Invalid packet length {pn_len} "),
        )
            .into());

    }
    let mut payload_slice = ssl_parse_slice(packet, offset..offset + len as usize - pn_len)?.to_vec();
    let payload_size = decrypt_quic_payload(
        &p_key.key,
        &p_key.iv,
        packet_number as u64,
        &mut payload_slice,
        &packet[0..offset],
    )?;
    debug!("QUIC packet len {} ", payload_size);
    let mut crypto_offset = 0;
    while crypto_offset < payload_size{
        let (frame_type, len) = parse_varint(&payload_slice, crypto_offset)?;
        crypto_offset += len;

        if frame_type == 0x06 {
            crypto_offset += parse_crypto_frame(
                &payload_slice,
                crypto_offset,
                is_client,
                packet_info,
                frame_type,
            )?;
        } else if frame_type == 0x02 {
            crypto_offset += parse_ack_frame(&payload_slice, crypto_offset)?;
            // ACK
        } else if frame_type == 0x00 {
            crypto_offset = payload_slice.len();
            // PADDING
        } else {
            break;
        }
    }
    // not interested in short headers, handshakes have long headers

    Ok(())
}

fn parse_ip_data(
    packet: &mut [u8],
    protocol: u8,
    packet_info_list: &mut Packet_Info_List,
    //  tcp_list: &Arc<Mutex<TCP_Connections>>,
    config: &Config,
    ts: DateTime<Utc>,
    source_ip: &IpAddr,
    dest_ip: &IpAddr,
    statistics: &mut Statistics,
) -> Result<(), Box<dyn Error>> {
    if protocol == 6 {
        // TCP
        parse_tcp(
            packet,
            packet_info_list,
            config,
            ts,
            source_ip,
            dest_ip,
            statistics,
        )
    } else if protocol == 17 {
        //  UDP
        parse_udp(
            packet,
            packet_info_list,
            config,
            ts,
            source_ip,
            dest_ip,
            statistics,
        )
    } else {
        Ok(())
    }
}

fn parse_ipv4(
    packet: &mut [u8],
    packet_info_list: &mut Packet_Info_List,
    config: &Config,
    ts: DateTime<Utc>,
    statistics: &mut Statistics,
) -> Result<(), Box<dyn Error>> {
    if packet.len() < 20 {
        return Err(Parse_error::new(ParseErrorType::Invalid_IPv4_Header, "packet size").into());
    }
    if packet[0] >> 4 != 4 {
        return Err(Parse_error::new(
            ParseErrorType::Invalid_IP_Version,
            &format!("{:x}", &packet[0] >> 4),
        )
        .into());
    }
    let ihl: usize = ((u16::from(packet[0] & 0xf)) * 4) as usize;
    let mut t: [u8; 4] = packet[12..16].try_into()?;
    let src = Ipv4Addr::from(t);
    t = packet[16..20].try_into()?;
    let dst = Ipv4Addr::from(t);
    let len: usize = ssl_read_u16(packet, 2)? as usize - ihl;
    let next_header = packet[9];
    let dest_ip = IpAddr::V4(dst);
    let source_ip = IpAddr::V4(src);
    //    packet_info.set_ip_len(len);
    parse_tunneling(
        &mut packet[ihl..ihl + len],
        next_header,
        packet_info_list,
        config,
        ts,
        &source_ip,
        &dest_ip,
        statistics,
    )
}

fn parse_tunneling(
    packet: &mut [u8],
    next_header: u8,
    packet_info_list: &mut Packet_Info_List,
    config: &Config,
    ts: DateTime<Utc>,
    source_ip: &IpAddr,
    dest_ip: &IpAddr,
    statistics: &mut Statistics,
) -> Result<(), Box<dyn Error>> {
    if next_header == 4 {
        // IPIP
        if packet.len() < 20 {
            return Err(Parse_error::new(
                ParseErrorType::Packet_Too_Small,
                &format!("packet len {}", packet.len()),
            )
            .into());
            //ip packets are always >= 20 bytes
        }
        let ip_ver = packet[0] >> 4;
        if ip_ver == 4 {
            parse_ipv4(packet, packet_info_list, config, ts, statistics)
        } else if ip_ver == 6 {
            parse_ipv6(packet, packet_info_list, config, ts, statistics)
        } else {
            Err(Parse_error::new(
                ParseErrorType::Invalid_IP_Version,
                &format!("ip version {ip_ver}"),
            )
            .into())
        }
    } else {
        parse_ip_data(
            packet,
            next_header,
            packet_info_list,
            config,
            ts,
            source_ip,
            dest_ip,
            statistics,
        )
    }
}

fn parse_ipv6(
    packet: &mut [u8],
    packet_info_list: &mut Packet_Info_List,
    //tcp_list: &Arc<Mutex<TCP_Connections>>,
    config: &Config,
    ts: DateTime<Utc>,
    statistics: &mut Statistics,
) -> Result<(), Box<dyn Error>> {
    if packet.len() < 40 {
        return Err(Parse_error::new(
            ParseErrorType::Invalid_IPv6_Header,
            &format!("packet len {}", packet.len()),
        )
        .into());
    }
    let mut t: [u8; 16] = packet[8..24].try_into()?;
    let src = Ipv6Addr::from(t);
    let _len: u16 = ssl_read_u16(packet, 4)?;
    t = packet[24..40].try_into()?;
    let dst = Ipv6Addr::from(t);
    if packet[0] >> 4 != 6 {
        return Err(Parse_error::new(
            ParseErrorType::Invalid_IP_Version,
            &format!("ip version {}", &packet[0] >> 4),
        )
        .into());
    }
    let dest_ip = IpAddr::V6(dst);
    let source_ip = IpAddr::V6(src);

    let next_header = packet[6];
    parse_tunneling(
        &mut packet[40..],
        next_header,
        packet_info_list,
        config,
        ts,
        &source_ip,
        &dest_ip,
        statistics,
    )
}

pub(crate) fn parse_eth(
    packet: &mut [u8],
    packet_info_list: &mut Packet_Info_List,
    //tcp_list: &Arc<Mutex<TCP_Connections>>,
    config: &Config,
    ts: DateTime<Utc>,
    statistics: &mut Statistics,
) -> Result<(), Box<dyn Error>> {
    //    packet_info.frame_len = u32::try_from(packet.len())?;
    let mut offset = 12;
    let mut eth_type_field = ssl_read_u16(packet, offset)?;
    offset += 2;

    if eth_type_field == 0x8100 {
        offset += 2;
        eth_type_field = ssl_read_u16(packet, offset)?;
        offset += 2;
    }

    if eth_type_field == 0x0800 {
        parse_ipv4(
            &mut packet[offset..],
            packet_info_list,
            config,
            ts,
            statistics,
        )
    } else if eth_type_field == 0x86dd {
        parse_ipv6(
            &mut packet[offset..],
            packet_info_list,
            config,
            ts,
            statistics,
        )
    } else {
        Err(Parse_error::new(
            ParseErrorType::Invalid_IP_Version,
            &format!("ip version{}", &packet[0] >> 4),
        )
        .into())
    }
}
