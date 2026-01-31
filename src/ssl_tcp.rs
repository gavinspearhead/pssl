use crate::config::Config;
use crate::errors::{ParseErrorType, Parse_error};
use crate::packet_info::{Packet_Info_List, Packet_info, Transport_Protocol};
use crate::ssl_helper::{ssl_parse_slice, ssl_read_u16, ssl_read_u32, ssl_read_u8};
use crate::ssl_tls::parse_ssl;
use crate::statistics::Statistics;
use crate::TLS_Protocol;
use chrono::{DateTime, Utc};
use std::collections::hash_map::Entry;
use std::error::Error;
use std::net::IpAddr;
use tracing::debug;

const SYN_FLAG: u16 = 2;
const FIN_FLAG: u16 = 1;
const RESET_FLAG: u16 = 4;

const TCP_MIN_PACKET_LEN: usize = 20;
const TCP_MAX_HEADER_LEN: usize = 60;
const MAX_SERVER_TLS_BYTES: usize = 128 * 1024;

pub(crate) fn parse_tcp(
    packet: &[u8],
    packet_info_list: &mut Packet_Info_List,
    config: &Config,
    ts: DateTime<Utc>,
    source_ip: &IpAddr,
    dest_ip: &IpAddr,
    statistics: &mut Statistics,
) -> Result<(), Box<dyn Error>> {
    if packet.len() < TCP_MIN_PACKET_LEN {
        return Err(Parse_error::new(ParseErrorType::Invalid_TCP_Header, "LEN < 20").into());
    }

    let src_port = ssl_read_u16(packet, 0)?;
    let dst_port = ssl_read_u16(packet, 2)?;
    let seq_nr = ssl_read_u32(packet, 4)?;

    // Header length is the high 4 bits of byte 12, multiplied by 4
    let header_len = (ssl_read_u8(packet, 12)? >> 4) as usize * 4;
    if header_len < TCP_MIN_PACKET_LEN {
        return Err(Parse_error::new(ParseErrorType::Invalid_TCP_Header, "header length < 20").into());
    }
    if header_len > TCP_MAX_HEADER_LEN {
        return Err(Parse_error::new(ParseErrorType::Invalid_TCP_Header, "header length > 60").into());
    }

    if packet.len() < header_len {
        return Err(Parse_error::new(ParseErrorType::Invalid_TCP_Header, "header length > packet length").into());
    }
    let flags = ssl_read_u16(packet, 12)? & 0x01ff;

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
            if config.tls_ports.contains(&src_port) {
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
            } else if config.tls_ports.contains(&dst_port) {
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
        if config.tls_ports.contains(&dp) {
            (source_ip, dest_ip, sp, dp, false)
        } else if config.tls_ports.contains(&sp) {
            (dest_ip, source_ip, dp, sp, true)
        } else {
            return Ok(());
        };
    let packet_info = packet_info_list
        .packets
        .entry((*client_ip, *server_ip, client_port, server_port))
        .or_insert_with(|| {
            Packet_info::new(
                ts,
                client_port,
                server_port,
                *client_ip,
                *server_ip,
                TLS_Protocol::TLS,
                Transport_Protocol::Tcp,
            )
        });

    if is_server_msg && packet_info.tls_server.initial_seqnr == None {
        packet_info.tls_server.initial_seqnr = Some(seqnr + 1);
    } else if packet_info.tls_client.initial_seqnr == None && !is_server_msg {
        packet_info.tls_client.initial_seqnr = Some(seqnr + 1);
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
    let key = if config.tls_ports.contains(&sp) {
        (*dest_ip, *source_ip, dp, sp)
    } else {
        (*source_ip, *dest_ip, sp, dp)
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
    if !p.tls_client.done && !p.tls_client.data.is_empty() {
        let rv = parse_ssl( true, p, statistics);
        if rv.is_err() {
            if p.tls_client.packet_count_limit > 25 {
                return rv;
            }
            p.tls_client.packet_count_limit += 3; // try to read 3 more packets
            return Ok(());
        }

        p.tls_client.data.clear();
    }
    p.tls_client.initial_seqnr = None;
    p.tls_client.done = true;
    Ok(())
}

fn finalize_server(p: &mut Packet_info, statistics: &mut Statistics) -> Result<(), Box<dyn Error>> {
    if !p.tls_server.done && !p.tls_server.data.is_empty() {
        //let server_data = p.tls_server.data.clone();
        let rv = parse_ssl(false, p, statistics);
        if rv.is_err() {
            if p.tls_server.packet_count_limit > 25 {
                return rv;
            }
            p.tls_server.packet_count_limit += 3;
            return Ok(());
        }
        p.tls_server.data.clear();
    }
    p.tls_server.initial_seqnr = None;
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
    let key = (*dest_ip, *source_ip, dp, sp);

    let Some(packet) = packet_info_list.packets.get_mut(&key) else {
        return Ok(());
    };

    let Some(initial_seqnr) = packet.tls_server.initial_seqnr else {
        return Ok(());
    };

    let offset = seqnr.wrapping_sub(initial_seqnr) as usize;
    if offset.saturating_add(data.len()) > MAX_SERVER_TLS_BYTES {
        debug!("TLS packet too large: {} bytes", data.len());
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

    if packet.tls_server.packet_count >= packet.tls_server.packet_count_limit {
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
    let key = (*source_ip, *dest_ip, sp, dp);
    let mut entry = match packet_info_list.packets.entry(key) {
        Entry::Occupied(e) => e,
        Entry::Vacant(_) => return Ok(()),
    };

    let v = entry.get_mut();
    let client = &mut v.tls_client;

    let Some(initial_seqnr) = client.initial_seqnr else {
        return Ok(());
    };

    let offset = seqnr.wrapping_sub(initial_seqnr) as usize;

    if offset.saturating_add(data.len()) > MAX_SERVER_TLS_BYTES {
        debug!("TLS packet too large: {} bytes", data.len());
        return Ok(());
    }
    let client_data = &mut client.data;
    let end_index = offset + data.len();
    if client_data.len() < end_index {
        client.data.resize(end_index, 0);
    }
    client.data[offset..offset + data.len()].copy_from_slice(data);
    client.packet_count += 1;

    if client.packet_count >= client.packet_count_limit {
        return finalize_client(v, statistics);
    }

    Ok(())
}
