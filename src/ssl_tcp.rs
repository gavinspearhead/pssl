use std::collections::hash_map::Entry;
use std::error::Error;
use std::net::IpAddr;
use chrono::{DateTime, Utc};
use tracing::debug;
use crate::config::Config;
use crate::errors::{ParseErrorType, Parse_error};
use crate::packet_info::{Packet_Info_List, Packet_info, Transport_Protocol};
use crate::ssl_helper::{ssl_parse_slice, ssl_read_u16, ssl_read_u32, ssl_read_u8};
use crate::statistics::Statistics;
use crate::TLS_Protocol;

const SYN_FLAG: u16 = 2;
const FIN_FLAG: u16 = 1;
const RESET_FLAG: u16 = 4;

const TCP_MIN_PACKET_LEN:  usize = 20;

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
        .entry((*client_ip, *server_ip, client_port, server_port))
        .or_insert_with(|| {
            Packet_info::new(
                ts,
                client_port,
                server_port,
                *client_ip,
                *server_ip,
                TLS_Protocol::TLS,
                Transport_Protocol::Tcp
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
        let client_data = p.tls_client.data.clone();
        crate::ssl_packet::parse_ssl(&client_data, p, statistics)?;
        p.tls_client.data.clear();
    }
    p.tls_client.initial_seqnr = 0;
    p.tls_client.done = true;
    Ok(())
}

fn finalize_server(p: &mut Packet_info, statistics: &mut Statistics) -> Result<(), Box<dyn Error>> {
    if !p.tls_server.done && !p.tls_server.data.is_empty() {
        let server_data = p.tls_server.data.clone();
        crate::ssl_packet::parse_ssl(&server_data, p, statistics)?;
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
    let key = (*dest_ip, *source_ip, dp, sp);

    let Some(packet) = packet_info_list.packets.get_mut(&key) else {
        return Ok(());
    };

    let initial_seqnr = packet.tls_server.initial_seqnr;
    if initial_seqnr == 0 {
        return Ok(());
    }

    let offset = seqnr.wrapping_sub(initial_seqnr) as usize;
    if offset >= 50000 {
        //debug!("offset too big {} seqnr {} ", offset, seqnr);
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
    let key = (*source_ip, *dest_ip, sp, dp);
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
        /*debug!(
            "offset too big {} seqnr {} {} {} ",
            offset, seqnr, client.initial_seqnr, v.tls_server.initial_seqnr
        );*/
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