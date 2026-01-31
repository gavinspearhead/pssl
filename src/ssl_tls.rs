use crate::errors::ParseErrorType::Invalid_TLS_Packet;
use crate::errors::Parse_error;
use crate::ja4::{
    compute_ja3_client_fingerprint, compute_ja3_server_fingerprint, compute_ja4_client_fingerprint,
    compute_ja4_server_fingerprint,
};
use crate::packet_info::Packet_info;
use crate::ssl_helper::{
    is_grease, parse_ssl_str, ssl_parse_slice, ssl_read_u16, ssl_read_u24, ssl_read_u8,
};
use crate::statistics::Statistics;
use crate::tls_cipher_suites::TlsCipherSuite;
use crate::tls_extension_types::TlsExtensionType;
use crate::tls_extension_types::TlsExtensionTypeValue::{
    ApplicationLayerProtocolNegotiation, EcPointFormats, KeyShare, ServerNameIndication,
    SignatureAlgorithms, SupportedGroups, SupportedVersions,
};
pub use crate::tls_groups::TlsSupportedGroup;
use crate::tls_signature_hash_algorithms::TlsSignatureScheme;
use std::error::Error;
use tracing::debug;
use crate::tls_content_type::TlsRecordContentType;
use crate::tls_handshake_types::TlsHandshakeType;

fn parse_sni_extension(data: &[u8], tls_data: &mut TlsExtensionData) -> Result<(), Box<dyn Error>> {
    let mut cursor = 2;
    let list_len = ssl_read_u16(data, 0)? as usize;
    let end = 2 + list_len;

    while cursor + 3 <= end {
        let sni_type = ssl_read_u8(data, cursor)?;
        let sni_len = ssl_read_u16(data, cursor + 1)? as usize;
        cursor += 3;

        if sni_type == 0 {
            let name_bytes = ssl_parse_slice(data, cursor..cursor + sni_len)?;
            tls_data.sni = parse_ssl_str(name_bytes)?;
            // Usually, we stop at the first host_name
            return Ok(());
        }
        //debug!("Unknown SNI type: {}", sni_type);
        cursor += sni_len;
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
            &format!("group length not even {groups_len}"),
        )
        .into());
    }
    if 2 + groups_len as usize > data.len() {
        return Err(Parse_error::new(
            Invalid_TLS_Packet,
            &format!("group length too long {groups_len}"),
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
            .entry(TlsSupportedGroup::from_u16(group_id))
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
            &format!("signature length not even {sigs_len}"),
        )
        .into());
    }
    let mut sig_offset = 2;
    let sigs_count = sigs_len / 2;
    if 2 + sigs_len as usize > data.len() {
        return Err(Parse_error::new(
            Invalid_TLS_Packet,
            &format!("Sigs length too long {sigs_len}"),
        )
        .into());
    }
    for _i in 0..sigs_count {
        let sig_alg = ssl_read_u16(data, sig_offset)?;
        sig_offset += 2;
        if !is_grease(sig_alg) {
            tls_data.sig_list.push(sig_alg);
        }
        let scheme = TlsSignatureScheme::from_u16(sig_alg);
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
    for _ in 0..format_len {
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
        let key_share_len = ssl_read_u16(data, 0)? as usize;
        let mut gr_offset = 2;
        while gr_offset < 2 + key_share_len {
            let group = ssl_read_u16(data, gr_offset)?;
            let key_len = ssl_read_u16(data, gr_offset + 2)?;
            gr_offset += 4;
            *statistics
                .client_pk_curves
                .entry(TlsSupportedGroup::from_u16(group))
                .or_insert(0) += 1;
            //debug!("client group: {}", group);
            if !is_grease(group) && tls_data.key.is_empty() {
                tls_data.key = Vec::from(ssl_parse_slice(
                    data,
                    gr_offset..gr_offset + key_len as usize,
                )?);
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
            .entry(TlsSupportedGroup::from_u16(group))
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
        for _ in 0..version_len / 2 {
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

pub fn parse_extension(
    extension_data: &[u8],
    is_client: bool,
    statistics: &mut Statistics,
) -> Result<TlsExtensionData, Box<dyn Error>> {
    let mut offset = 0;
    let mut tls_extension_data = TlsExtensionData::default();
    while offset + 3 < extension_data.len() {
        let ext_type_val = ssl_read_u16(extension_data, offset)?;
        let ext_type = TlsExtensionType::from_u16(ext_type_val);
        let ext_len = usize::from(ssl_read_u16(extension_data, offset + 2)?);
        offset += 4;

        //debug!("ext type: GREASE value {:x}", ext_type_val);
        let stats_entry = if is_client {
            statistics.client_extensions.entry(ext_type)
        } else {
            statistics.server_extensions.entry(ext_type)
        };
        *stats_entry.or_insert(0) += 1;
        if !is_grease(ext_type_val) {
            tls_extension_data.ext_list.push(ext_type_val);
        }
        if ext_len > 0 {
            let data = ssl_parse_slice(extension_data, offset..offset + ext_len)?;
            match ext_type {
                TlsExtensionType::Known(ServerNameIndication) => {
                    parse_sni_extension(data, &mut tls_extension_data)?;
                }
                TlsExtensionType::Known(SupportedGroups) => {
                    parse_supported_groups_extension(data, &mut tls_extension_data, statistics)?;
                }

                TlsExtensionType::Known(SignatureAlgorithms) => {
                    parse_signature_algorithms_extension(
                        data,
                        &mut tls_extension_data,
                        statistics,
                    )?;
                }

                TlsExtensionType::Known(EcPointFormats) => {
                    parse_ec_point_formats_extension(data, &mut tls_extension_data)?;
                }
                TlsExtensionType::Known(KeyShare) => {
                    parse_key_share_extension(
                        data,
                        is_client,
                        &mut tls_extension_data,
                        statistics,
                    )?;
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
                _ => {}
            }
        }
        offset += ext_len;
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

    //let _random = ssl_parse_slice(packet, offset..offset + 32)?;
    offset += 32;
    //debug!("random:{:x?}", random);
    let session_id_len = ssl_read_u8(packet, offset)?;
    offset += 1;
    //debug!("session id len:{}", session_id_len);
    //let _session_id = ssl_parse_slice(packet, offset..offset + session_id_len as usize)?;
    offset += session_id_len as usize;
    //  debug!("session id :{:x?}", session_id);
    packet_info.tls_server.cipher = TlsCipherSuite::from_u16(ssl_read_u16(packet, offset)?);
    offset += 2;

    //debug!("cipher suite: {}", packet_info.tls_server.cipher.as_str());
    //  let _compression = ssl_read_u8(packet, offset)?;
    offset += 1;
    //debug!("compression: {}", compression);
    let extension_len = usize::from(ssl_read_u16(packet, offset)?);
    //debug!("extension len:{}", extension_len);
    offset += 2;
    let tls_extension_data = parse_extension(
        ssl_parse_slice(packet, offset..offset + extension_len)?,
        false,
        statistics,
    )?;
    if tls_extension_data.highest_version > 0 {
        packet_info.tls_server.version = tls_extension_data.highest_version;
    } else {
        packet_info.tls_server.version = server_hello_version;
    }
    packet_info.tls_server.curve = tls_extension_data
        .group_list
        .first()
        .map(|g| TlsSupportedGroup::from_u16(*g))
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

    offset += extension_len;
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
    // let _session_id = ssl_parse_slice(packet, offset..offset + session_id_len as usize)?;
    offset += session_id_len as usize;
    //debug!("session id :{:x?}", session_id);
    let cipher_suite_len = ssl_read_u16(packet, offset)?;
    //debug!("ciphersuite length:{}", cipher_suite_len);
    offset += 2;
    let mut cipher_list = Vec::new();
    for _ in 0..cipher_suite_len / 2 {
        let cs = ssl_read_u16(packet, offset)?;
        cipher_list.push(cs);
        let cs = TlsCipherSuite::from_u16(cs);
        packet_info.tls_client.ciphers.push(cs);
        *statistics.client_ciphers.entry(cs).or_insert(0) += 1;
        //debug!("cipher: {:}", cs.as_str());
        offset += 2;
    }
    let compression_methods_len = ssl_read_u8(packet, offset)?;
    //debug!("compression methods len:{}", compression_methods_len);
    offset += 1;
    for _ in 0..compression_methods_len {
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

    packet_info
        .tls_client
        .sni
        .clone_from(&tls_extension_data.sni);
    packet_info.tls_client.ja3c = compute_ja3_client_fingerprint(
        client_hello_version,
        &cipher_list,
        &tls_extension_data.ext_list,
        &tls_extension_data.group_list,
        &tls_extension_data.point_list,
    );
    packet_info.tls_client.ja4c.clone_from(&ja4_string);
    packet_info
        .tls_client
        .alpns
        .clone_from(&tls_extension_data.alpn_list);
    packet_info.tls_client.versions = vec![packet_info.tls_server.version];
    packet_info.tls_client.signature_algorithms = tls_extension_data
        .sig_list
        .iter()
        .map(|v| TlsSignatureScheme::from_u16(*v))
        .collect::<Vec<_>>();
    packet_info.tls_client.groups = tls_extension_data
        .group_list
        .iter()
        .map(|v| TlsSupportedGroup::from_u16(*v))
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
        let handshake_type_raw = ssl_read_u8(packet, offset)?;
        let handshake_type = TlsHandshakeType::from_u8(handshake_type_raw);
        let length = ssl_read_u24(packet, offset + 1)? as usize;
        //debug!("handshake type:{} length {} {}", handshake_type, length, offset) ;

        offset += 4;

        match handshake_type {
            TlsHandshakeType::ClientHello => {
                // debug!("client hello {source_ip} {dest_ip} {sp} {dp}");
                parse_client_hello(
                packet_info,
                ssl_parse_slice(packet, offset..offset + length)?,
                statistics,
                )?;
            }
            TlsHandshakeType::ServerHello => {
                // debug!( "server hello {source_ip} {dest_ip} {sp} {dp}", source_ip = packet_info.s_addr, dest_ip = packet_info.d_addr, sp = packet_info.sp, dp = packet_info.dp );
                parse_server_hello(
                    packet_info,
                    ssl_parse_slice(packet, offset..offset + length)?,
                    statistics,
                )?;
            }
            TlsHandshakeType::CertificateStatus => {
                /*   debug!(
                    "Content Type: certificate status {source_ip} {dest_ip} {sp} {dp}",
                    source_ip = packet_info.s_addr,
                    dest_ip = packet_info.d_addr,
                    sp = packet_info.sp,
                    dp = packet_info.dp
                );*/
            }
            TlsHandshakeType::Certificate => {
                //debug!("certificate");
            }
            TlsHandshakeType::CertificateRequest => {
                //   debug!("certificate request");
            }
            TlsHandshakeType::CertificateVerify => {
                //   debug!("certificate verify");
            }
            TlsHandshakeType::Finished => {
                //   debug!("finished");
            }
            TlsHandshakeType::KeyUpdate => {
                //  debug!("key update");
            }
            TlsHandshakeType::NewSessionTicket => {
                //  debug!("new session ticket");
            }
            TlsHandshakeType::ServerHelloDone => {
                //  debug!("server hello done");
            }
            TlsHandshakeType::ClientKeyExchange => {
                //  debug!("client key exchange");
            }
            TlsHandshakeType::ServerKeyExchange => {
                // key exchange // TLS 1.2 only
                // debug!("Server key exchange");
                parse_key_exchange(packet_info, packet, offset)?;
            }
            TlsHandshakeType::Unknown(v) => {
                return Err(Parse_error::new( Invalid_TLS_Packet, &format!("handshake type {v}")).into());
            }
        }

        offset += length;
    }
    Ok(())
}
const TLS_RECORD_HEADER_LEN : usize = 5;
pub fn parse_ssl(
    is_client: bool, 
    packet_info: &mut Packet_info,
    statistics: &mut Statistics,
) -> Result<(), Box<dyn Error>> {
    //debug!("{:?}", &packet);
    let packet = if is_client { packet_info.tls_client.data.clone() } else { packet_info.tls_server.data.clone() };
    let mut offset = 0;
    while offset + TLS_RECORD_HEADER_LEN < packet.len() {
        let content_type_raw = ssl_read_u8(&packet, offset)?;
        let content_type = TlsRecordContentType::from(content_type_raw);
        // debug!("offset {} content type {} ", offset, content_type);
        // let _tls_version = ssl_read_u16(packet, offset + 1)?;
        let tls_length = usize::from(ssl_read_u16(&packet, offset + 3)?);
        // debug!("Version:{:x} length:{}", tls_version, tls_length);
        offset += 5;

        match content_type {
            TlsRecordContentType::Handshake => {
                let data = ssl_parse_slice(&packet, offset..offset + tls_length)?;
                parse_tls_handshake(data, packet_info, statistics)?;
            }

            // stop parsing
            TlsRecordContentType::ApplicationData | TlsRecordContentType::ChangeCipherSpec => {
                return Ok(());
            }

            // known but ignored (for now)
            TlsRecordContentType::Alert
            | TlsRecordContentType::Heartbeat
            | TlsRecordContentType::Tls12Cid
            | TlsRecordContentType::Ack
            | TlsRecordContentType::ReturnRoutabilityCheck => {}

            TlsRecordContentType::Unknown(v) => {
                return Err(Parse_error::new(
                    Invalid_TLS_Packet,
                    &format!("Content type: {v}"),
                )
                .into());
            }
        }

        offset += tls_length;
    }
    Ok(())
}

fn parse_key_exchange(
    packet_info: &mut Packet_info,
    packet: &[u8],
    offset_in: usize,
) -> Result<(), Box<dyn Error>> {
    let mut offset = offset_in;

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
    packet_info.tls_server.curve = TlsSupportedGroup::from_u16(curve);

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
    packet_info.tls_server.signature_algorithm = TlsSignatureScheme::from_u16(sig_alg);

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
