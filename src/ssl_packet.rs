use crate::config::Config;
use crate::errors::ParseErrorType::{Invalid_IP_Version, Invalid_IPv4_Header, Invalid_TLS_Packet};
use crate::errors::{ParseErrorType, Parse_error};
use crate::ja4::{
    compute_ja3_client_fingerprint, compute_ja3_server_fingerprint, compute_ja4_client_fingerprint,
    compute_ja4_server_fingerprint,
};
use crate::packet_info::{Packet_Info_List, Packet_info, Transport_Protocol};
use crate::ssl_helper::{
    is_grease, parse_ssl_str, ssl_parse_slice, ssl_read_u16, ssl_read_u24, ssl_read_u8,
};
use crate::ssl_quic::parse_quic;
use crate::ssl_tcp::parse_tcp;
use crate::statistics::Statistics;
use crate::tls_cipher_suites::TlsCipherSuite;
use crate::tls_extension_types::TlsExtensionType;
use crate::tls_extension_types::TlsExtensionTypeValue::{
    ApplicationLayerProtocolNegotiation, EcPointFormats, EncryptedClientHello, KeyShare,
    PreSharedKey, PskKeyExchangeModes, RecordSizeLimit, RenegotiationInfo, ServerNameIndication,
    SessionTicket, SignatureAlgorithms, SupportedGroups, SupportedVersions,
};
pub use crate::tls_groups::TlsSupportedGroup;
use crate::tls_signature_hash_algorithms::TlsSignatureScheme;
use chrono::{DateTime, Utc};
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::debug;

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
            //debug!("Unknown SNI type: {}", sni_type);
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
            Invalid_TLS_Packet,
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
            Invalid_TLS_Packet,
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
                //debug!("client group: {}", group);
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
            return Err(Parse_error::new(Invalid_TLS_Packet, "str_len is 0").into());
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
                Invalid_TLS_Packet,
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
            //debug!("ext type: GREASE value {:x}", ext_type_val);
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
                TlsExtensionType::Known(ServerNameIndication) => {
                    parse_sni_extension(data, &mut tls_extension_data)?;
                }
                TlsExtensionType::Known(SupportedGroups) => {
                    parse_supported_groups_extension(data, &mut tls_extension_data, statistics)?;
                }

                TlsExtensionType::Known(SignatureAlgorithms) => {
                    parse_signature_algorithms_extension(data, &mut tls_extension_data, statistics)?;
                }

                TlsExtensionType::Known(EcPointFormats) => {
                    parse_ec_point_formats_extension(data, &mut tls_extension_data)?;
                }
                TlsExtensionType::Known(KeyShare) => {
                    parse_key_share_extension(data, is_client, &mut tls_extension_data, statistics)?;
                }

                TlsExtensionType::Known(ApplicationLayerProtocolNegotiation) => {
                    parse_alpn_extension(data, &mut tls_extension_data, statistics)?;
                }

                TlsExtensionType::Known(SupportedVersions) => parse_supported_versions_extension(
                    data,
                    is_client,
                    &mut tls_extension_data,
                    statistics,
                )?,
                TlsExtensionType::Known(EncryptedClientHello | PskKeyExchangeModes |
RecordSizeLimit | SessionTicket | PreSharedKey | RenegotiationInfo) => {}
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
        .map_or("", |s| s.as_str())
        .to_string();
    let ja3s_hash = compute_ja3_server_fingerprint(
        server_hello_version,
        packet_info.tls_server.cipher.to_u16(),
        &tls_extension_data.ext_list,
    );
    packet_info.tls_server.ja3s = ja3s_hash;
    packet_info.tls_server.ja4s = compute_ja4_server_fingerprint(
        packet_info.tls_protocol,
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
        packet_info.tls_protocol,
        &cipher_list,
        &tls_extension_data.ext_list,
        tls_extension_data.highest_version,
        &tls_extension_data.alpn_list,
        !tls_extension_data.sni.is_empty(),
        &tls_extension_data.sig_list,
    );

    packet_info.tls_client.sni.clone_from(&tls_extension_data.sni);
    packet_info.tls_client.ja3c = compute_ja3_client_fingerprint(
        client_hello_version,
        &cipher_list,
        &tls_extension_data.ext_list,
        &tls_extension_data.group_list,
        &tls_extension_data.point_list,
    );
    packet_info.tls_client.ja4c.clone_from(&ja4_string);
    packet_info.tls_client.alpns = tls_extension_data.alpn_list.clone();
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

pub(crate) fn parse_tls_handshake(
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
         /*   debug!(
                "Content Type: certificate status {source_ip} {dest_ip} {sp} {dp}",
                source_ip = packet_info.s_addr,
                dest_ip = packet_info.d_addr,
                sp = packet_info.sp,
                dp = packet_info.dp
            );*/
        } else if handshake_type == 11 {
            //debug!("certificate");
        } else if handshake_type == 13 {
         //   debug!("certificate request");
        } else if handshake_type == 15 {
         //   debug!("certificate verify");
        } else if handshake_type == 20 {
         //   debug!("finished");
        } else if handshake_type == 24 {
          //  debug!("key update");
        } else if handshake_type == 4 {
          //  debug!("new session ticket");
        } else if handshake_type == 14 {
          //  debug!("server hello done");
        } else if handshake_type == 16 {
          //  debug!("client key exchange");
        } else if handshake_type == 12 {
            // key exchange // TLS 1.2 only
          //  debug!("Server key exchange");
            //            debug!( "Content Type: key exchange {source_ip} {dest_ip} {sp} {dp}", source_ip = packet_info.s_addr, dest_ip = packet_info.d_addr, sp = packet_info.sp, dp = packet_info.dp );
            parse_key_exchange(packet_info, packet, offset + 1)?;
        } else {
            return Err(Parse_error::new(
                Invalid_TLS_Packet,
                &format!("handshake type {handshake_type}"),
            )
            .into());
        }
        offset += 4 + length as usize;
    }
    Ok(())
}

pub(crate) fn parse_ssl(
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
                Invalid_TLS_Packet,
                &format!("Content type: {content_type}"),
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
            Invalid_TLS_Packet,
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

const UDP_MIN_PACKET_LEN:  usize = 8;
const IPV4_MIN_PACKET_LEN: usize = 20;
const IPV6_MIN_PACKET_LEN: usize = 40;


fn parse_udp(
    packet: &mut [u8],
    packet_info_list: &mut Packet_Info_List,
    config: &Config,
    ts: DateTime<Utc>,
    source_ip: &IpAddr,
    dest_ip: &IpAddr,
    statistics: &mut Statistics,
) -> Result<(), Box<dyn Error>> {
    if packet.len() < UDP_MIN_PACKET_LEN {
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
            Transport_Protocol::Udp
        )
    } else {
        Err(Parse_error::new(Invalid_TLS_Packet, &format!("UDP {dp} {sp}")).into())
    }
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
    } else if protocol == 132 {
        // sctp TODO
        Ok(())
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
    if packet.len() < IPV4_MIN_PACKET_LEN {
        return Err(Parse_error::new(Invalid_IPv4_Header, "packet size").into());
    }
    if packet[0] >> 4 != 4 {
        return Err(Parse_error::new(Invalid_IP_Version, &format!("{:x}", &packet[0] >> 4)).into());
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
            Err(Parse_error::new(Invalid_IP_Version, &format!("ip version {ip_ver}")).into())
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
    if packet.len() < IPV6_MIN_PACKET_LEN {
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
            Invalid_IP_Version,
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
    config: &Config,
    ts: DateTime<Utc>,
    statistics: &mut Statistics,
) -> Result<(), Box<dyn Error>> {
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
            Invalid_IP_Version,
            &format!("ip version{}", &packet[0] >> 4),
        )
        .into())
    }
}
