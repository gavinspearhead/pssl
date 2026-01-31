use crate::config::Config;
use crate::errors::ParseErrorType::Invalid_TLS_Packet;
use crate::errors::Parse_error;
use crate::ja4::{
    compute_ja3_client_fingerprint, compute_ja3_server_fingerprint, compute_ja4_client_fingerprint,
    compute_ja4_server_fingerprint,
};
use crate::packet_info::{Packet_Info_List, Packet_info, Transport_Protocol};
use crate::ssl_helper::{ssl_parse_slice, ssl_read_u16, ssl_read_u24, ssl_read_u48, ssl_read_u8};
use crate::ssl_tls::parse_extension;
use crate::statistics::Statistics;
use crate::tls_cipher_suites::TlsCipherSuite;
pub use crate::tls_groups::TlsSupportedGroup;
use crate::tls_signature_hash_algorithms::TlsSignatureScheme;
use crate::TLS_Protocol::DTLS;
use chrono::{DateTime, Utc};
use std::error::Error;
use std::net::IpAddr;
use tracing::debug;

pub fn parse_dtls(
    packet: &mut [u8],
    packet_info_list: &mut Packet_Info_List,
    ts: DateTime<Utc>,
    source_ip: &IpAddr,
    dest_ip: &IpAddr,
    sp: u16,
    dp: u16,
    statistics: &mut Statistics,
    config: &Config,
    transport_protocol: Transport_Protocol,
) -> Result<(), Box<dyn Error>> {
    let is_client = config.dtls_ports.contains(&dp);
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
                packet_key.0,
                packet_key.1,
                DTLS,
                transport_protocol,
            )
        });
    let mut offset = 0;
    while offset < packet.len() {
        let content_type = ssl_read_u8(packet, offset)?;
        offset += 1;
        let version = ssl_read_u16(packet, offset)?;
        offset += 2;
        let epoch = ssl_read_u16(packet, offset)?;
        offset += 2;
        let sequence_number = ssl_read_u48(packet, offset)?;
        offset += 6;
        let length = ssl_read_u16(packet, offset)?;
        offset += 2;
        let start_offset = offset;

        debug!("dtls {content_type}  {version:x} {epoch} {sequence_number} {length}");
        if content_type == 22 {
            let handshake_type = ssl_read_u8(packet, offset)?;
            offset += 1;
            debug!("dtls handshake type:{}", handshake_type);
            let data = ssl_parse_slice(packet, offset..)?;
            if handshake_type == 1 {
                parse_packet(data, packet_info, statistics, handshake_type, is_client)?;
            } else if handshake_type == 2 {
                parse_packet(data, packet_info, statistics, handshake_type, is_client)?;
            } else if handshake_type == 3 {
                // hello verify request
            } else if handshake_type == 4 {
                // new session ticket
            } else if handshake_type == 11 {
                // certificate
            } else if handshake_type == 12 {
                parse_packet(data, packet_info, statistics, handshake_type, is_client)?;
                // server key exchange
            } else if handshake_type == 16 {
                parse_packet(data, packet_info, statistics, handshake_type, is_client)?;
                // client key exchange
            } else if handshake_type == 14 {
                // server handshake done
            }
        } else if content_type == 20 {
            debug!("Done - change cipher spec");
            if is_client {
                packet_info.tls_client.done = true;
                packet_info.tls_client.initial_seqnr = None;
            } else {
                packet_info.tls_server.done = true;
                packet_info.tls_server.initial_seqnr = None;
            }
        }
        offset = start_offset + length as usize;
    }
    Ok(())
}

fn parse_packet(
    packet: &[u8],
    packet_info: &mut Packet_info,
    statistics: &mut Statistics,
    handshake_type: u8,
    is_client: bool,
) -> Result<(), Box<dyn Error>> {
    let mut offset = 0;
    let length = ssl_read_u24(packet, offset)?;
    offset += 3;
    let msg_seq = ssl_read_u16(packet, offset)?;
    offset += 2;
    let fragment_offset = ssl_read_u24(packet, offset)?;
    offset += 3;
    let fragment_length = ssl_read_u24(packet, offset)?;
    offset += 3;
    //let version = ssl_read_u16(packet, offset)?;
    // offset += 2;
    debug!(
        "dtls fragment {length} {msg_seq} {fragment_offset} {fragment_length} {:x?}",
        &packet[0..8]
    );
    if fragment_offset > 16384 || length > 64 * 1024 {
        return Err(Parse_error::new(
            Invalid_TLS_Packet,
            &format!("DTLS Length {length} or fragment size {fragment_offset} exceeded "),
        )
        .into());
    }
    if length < fragment_offset + fragment_length {
        return Err(Parse_error::new(Invalid_TLS_Packet, &format!("DTLS fragment offset exceeds length {length} < {fragment_offset} + {fragment_length} ")).into());
    }
    if is_client {
        packet_info.tls_client.data.resize(length as usize, 0);
        packet_info.tls_client.data
            [fragment_offset as usize..fragment_offset as usize + fragment_length as usize]
            .copy_from_slice(ssl_parse_slice(
                packet,
                offset..offset + fragment_length as usize,
            )?);
        packet_info.tls_client.data_len += fragment_length as usize;

        if (fragment_offset as usize + fragment_length as usize) >= length as usize {
            if handshake_type == 1 {
                parse_dtls_client_hello(packet_info, statistics)?;
            } else if handshake_type == 16 {
                parse_dtls_client_keyexchange(packet_info)?;
            }
        }
    } else {
        packet_info.tls_server.data.resize(length as usize, 0);
        packet_info.tls_server.data
            [fragment_offset as usize..fragment_offset as usize + fragment_length as usize]
            .copy_from_slice(ssl_parse_slice(
                packet,
                offset..offset + fragment_length as usize,
            )?);
        packet_info.tls_server.data_len += fragment_length as usize;
        if (fragment_offset as usize + fragment_length as usize) >= length as usize {
            if handshake_type == 2 {
                parse_dtls_server_hello(packet_info, statistics)?;
            } else if handshake_type == 12 {
                parse_dtls_server_keyexchange(packet_info)?;
            }
        }
    }
    Ok(())
}

fn parse_dtls_server_hello(
    packet_info: &mut Packet_info,
    statistics: &mut Statistics,
) -> Result<(), Box<dyn Error>> {
    let mut offset = 0;
    let packet = &packet_info.tls_server.data;
    let version = ssl_read_u16(packet, offset)?;
    offset += 2;
    //let random = ssl_parse_slice(packet, offset..offset + 32)?;
    offset += 32;
    let session_id_len = ssl_read_u8(packet, offset)?;
    offset += 1;
    // let session_id = ssl_parse_slice(packet, offset..offset + session_id_len as usize)?;
    offset += session_id_len as usize;
    let cipher_suite = ssl_read_u16(packet, offset)?;
    offset += 2;
    let compression_method = ssl_read_u8(packet, offset)?;
    offset += 1;
    let extentions_length = ssl_read_u16(packet, offset)?;
    offset += 2;
    let ext_data = parse_extension(
        ssl_parse_slice(packet, offset..offset + extentions_length as usize)?,
        false,
        statistics,
    )?;
    debug!("server hello done {session_id_len} {cipher_suite:x} {compression_method} {extentions_length} {:?}", ext_data.ext_list);
    packet_info.tls_server.cipher = TlsCipherSuite::from_u16(cipher_suite);
    packet_info.tls_server.ja4s = compute_ja4_server_fingerprint(
        DTLS,
        cipher_suite,
        &ext_data.ext_list,
        version,
        ext_data.alpn_list.first().unwrap_or(&String::new()),
    );
    packet_info.tls_server.ja3s =
        compute_ja3_server_fingerprint(version, cipher_suite, &ext_data.ext_list);
    Ok(())
}

fn parse_dtls_server_keyexchange(packet_info: &mut Packet_info) -> Result<(), Box<dyn Error>> {
    let mut offset = 0;
    let curve_type = ssl_read_u8(&packet_info.tls_server.data, offset)?;
    offset += 1;
    if curve_type != 3 {
        return Err(Parse_error::new(
            Invalid_TLS_Packet,
            &format!("Invalid curve type {curve_type}"),
        )
        .into());
    }
    let curve = ssl_read_u16(&packet_info.tls_server.data, offset)?;
    offset += 2;
    let pubkey_len = ssl_read_u8(&packet_info.tls_server.data, offset)?;
    offset += 1;
    //    let pubkey = ssl_parse_slice( &packet_info.tls_server.data, offset..offset + pubkey_len as usize, )?;
    offset += pubkey_len as usize;
    let sig_alg = ssl_read_u16(&packet_info.tls_server.data, offset)?;
    offset += 2;
    // let sig_len = ssl_read_u16(&packet_info.tls_server.data, offset)?;
    offset += 2;
    //    let sig = ssl_parse_slice( &packet_info.tls_server.data, offset..offset + sig_len as usize, )?;
    packet_info.tls_server.signature_algorithm = TlsSignatureScheme::from_u16(sig_alg);
    packet_info.tls_server.curve = TlsSupportedGroup::from_u16(curve);
    Ok(())
}
fn parse_dtls_client_hello(
    packet_info: &mut Packet_info,
    statistics: &mut Statistics,
) -> Result<(), Box<dyn Error>> {
    let mut offset = 0;
    let packet = &packet_info.tls_client.data;
    let version = ssl_read_u16(packet, offset)?;
    offset += 2;
    //    let _random = ssl_parse_slice(packet, offset..offset + 32)?;
    offset += 32;
    let session_id_len = ssl_read_u8(packet, offset)?;
    offset += 1;
    let cookie_len = ssl_read_u8(packet, offset)?;
    offset += 1;
    //    let cookie = ssl_parse_slice(packet, offset..offset + cookie_len as usize)?;
    offset += cookie_len as usize;
    let cipher_suite_len = ssl_read_u16(packet, offset)?;
    offset += 2;
    let cipher_list = &mut Vec::new();
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
    debug!("client hello done {session_id_len} {cookie_len} {cipher_suite_len} {compression_methods_len} {extension_len} {:?}", tls_extension_data.ext_list);
    offset += extension_len as usize;

    let ja4_string = compute_ja4_client_fingerprint(
        packet_info.tls_protocol,
        cipher_list,
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
        version,
        cipher_list,
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
    Ok(())
}

fn parse_dtls_client_keyexchange(packet_info: &mut Packet_info) -> Result<(), Box<dyn Error>> {
    let mut offset = 0;
    let pubkey_len = ssl_read_u8(&packet_info.tls_client.data, offset)?;
    offset += 1;
    let pubkey = ssl_parse_slice(
        &packet_info.tls_client.data,
        offset..offset + pubkey_len as usize,
    )?;

    debug!("Client Key Exchange - PK: {pubkey:x?} ({pubkey_len})");
    Ok(())
}
