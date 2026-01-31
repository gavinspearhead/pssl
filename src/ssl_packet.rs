use crate::config::Config;
use crate::errors::ParseErrorType::{
    Invalid_Eth_Type, Invalid_IP_Version, Invalid_IPv4_Header, Invalid_TLS_Packet,
};
use crate::errors::{ParseErrorType, Parse_error};
use crate::packet_info::{Packet_Info_List, Transport_Protocol};
use crate::ssl_dtls::parse_dtls;
use crate::ssl_helper::{ssl_parse_slice_mut, ssl_read_u16};
use crate::ssl_quic::parse_quic;
use crate::ssl_tcp::parse_tcp;
use crate::statistics::Statistics;
pub use crate::tls_groups::TlsSupportedGroup;
use chrono::{DateTime, Utc};
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::debug;

const UDP_MIN_PACKET_LEN: usize = 8;
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
    //  let _len = ssl_read_u16(packet, 4)?;
    // let _checksum = ssl_read_u16(packet, 6)?;
    //    debug!( "UDP sp: {} dp:{} len:{} checksum:{:x}", sp, dp, len, checksum );
    // packet_info.set_dest_port(dp);
    ////packet_info.set_source_port(sp);
    //    packet_info.set_data_len(u32::from(len) - 8);

    // TODO need to handle DTLS
    if (config.quic_ports.contains(&dp) || config.quic_ports.contains(&sp)) && config.quic {
        let data = ssl_parse_slice_mut(packet, UDP_MIN_PACKET_LEN..)?;
        parse_quic(
            data,
            config,
            packet_info_list,
            ts,
            source_ip,
            dest_ip,
            sp,
            dp,
            statistics,
            Transport_Protocol::Udp,
        )
    } else if (config.dtls_ports.contains(&dp) || config.dtls_ports.contains(&sp)) && config.dtls {
        let data = ssl_parse_slice_mut(packet, UDP_MIN_PACKET_LEN..)?;
        debug!("dtls packet: {:?} ", &data[..8].to_vec());
        parse_dtls(
            data,
            packet_info_list,
            ts,
            source_ip,
            dest_ip,
            sp,
            dp,
            statistics,
            config,
            Transport_Protocol::Udp,
        )?;
        Ok(())
    } else {
        Err(Parse_error::new(Invalid_TLS_Packet, &format!("UDP {dp} {sp}")).into())
    }
}

fn parse_ip_data(
    packet: &mut [u8],
    protocol: u8,
    packet_info_list: &mut Packet_Info_List,
    config: &Config,
    ts: DateTime<Utc>,
    source_ip: &IpAddr,
    dest_ip: &IpAddr,
    statistics: &mut Statistics,
) -> Result<(), Box<dyn Error>> {
    if protocol == 6 && config.tls {
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
    let src = Ipv4Addr::from(<[u8; 4]>::try_from(&packet[12..16])?);
    let dst = Ipv4Addr::from(<[u8; 4]>::try_from(&packet[16..20])?);
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
    if next_header == 4 || next_header == 41 {
        // IPIP
        if packet.len() < IPV4_MIN_PACKET_LEN {
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
    if packet[0] >> 4 != 6 {
        return Err(Parse_error::new(
            Invalid_IP_Version,
            &format!("ip version {}", &packet[0] >> 4),
        )
        .into());
    }
    //let _len: u16 = ssl_read_u16(packet, 4)?;
    let source_ip = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24])?));
    let dest_ip = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40])?));

    let next_header = packet[6];
    parse_tunneling(
        &mut packet[IPV6_MIN_PACKET_LEN..],
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
        Err(Parse_error::new(Invalid_Eth_Type, &format!("Ethertype {eth_type_field}")).into())
    }
}
