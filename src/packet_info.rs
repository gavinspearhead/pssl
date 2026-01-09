use crate::ssl_packet::TlsSupportedGroup;
use crate::tls_cipher_suites::TlsCipherSuite;
use crate::tls_signature_hash_algorithms::TlsSignatureScheme;
use crate::util::find_domain;
use crate::TLS_Protocol;
use asn_db2::{Database, IpEntry};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr},
};
use serde::{Deserialize, Serialize};
use tracing_rfc_5424::transport::Transport;

#[derive(Debug, Clone, Default)]
pub(crate) struct Packet_Info_List {
    pub(crate) packets: HashMap<(IpAddr, IpAddr, u16, u16), Packet_info>,
    // timelimit: u64,
    //max_tcp_len: u32,
}

impl Packet_Info_List {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct TLS_Client_data {
    pub(crate) ja3c: String,
    pub(crate) ja4c: String,
    pub(crate) groups: Vec<TlsSupportedGroup>,
    pub(crate) ciphers: Vec<TlsCipherSuite>,
    pub(crate) sni: String,
    pub(crate) signature_algorithms: Vec<TlsSignatureScheme>,
    pub(crate) point: Vec<u8>,
    pub(crate) alpns: Vec<String>,
    pub(crate) versions: Vec<u16>,
    pub(crate) data: Vec<u8>,
    pub(crate) initial_seqnr: u32,
    pub(crate) packet_count: u32,
    pub done: bool,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct TLS_Server_data {
    pub(crate) ja3s: String,
    pub(crate) ja4s: String,
    pub(crate) group: TlsSupportedGroup,
    pub(crate) version: u16,
    pub(crate) cipher: TlsCipherSuite,
    pub(crate) signature_algorithm: TlsSignatureScheme,
    pub(crate) point: u8,
    pub(crate) alpn: String,
    pub(crate) pubkey: Vec<u8>,
    pub(crate) data: Vec<u8>,
    pub(crate) initial_seqnr: u32,
    pub(crate) packet_count: u32,
    pub(crate) asn: u32,
    pub(crate) domain: String,
    pub(crate) asn_owner: String,
    pub(crate) prefix: String,
    pub done: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub(crate) enum Transport_Protocol {
    #[default]
    Tcp,
    Udp,
    Sctp,
}

#[derive(Debug, Clone)]
pub(crate) struct Packet_info {
    pub timestamp: DateTime<Utc>,
    pub q_timestamp: DateTime<Utc>,
    pub sp: u16, // source port
    pub dp: u16, // destination port
    pub s_addr: IpAddr,
    pub d_addr: IpAddr,
    pub tls_protocol: TLS_Protocol,
    pub transport_protocol: Transport_Protocol,
    pub initial_client_secret: Vec<u8>,
    pub initial_server_secret: Vec<u8>,
    pub tls_client: TLS_Client_data,
    pub tls_server: TLS_Server_data,
}

impl Default for Packet_info {
    fn default() -> Self {
        Packet_info {
            timestamp: Utc::now(),
            q_timestamp: Utc::now(),
            sp: 0,
            dp: 0,
            s_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            d_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            tls_protocol: TLS_Protocol::TLS,
            transport_protocol: Transport_Protocol::Tcp,
            initial_client_secret: Vec::new(),
            initial_server_secret: Vec::new(),
            tls_client: TLS_Client_data::default(),
            tls_server: TLS_Server_data::default(),
        }
    }
}

impl Packet_info {
    pub fn new(
        timestamp: DateTime<Utc>,
        sp: u16, // source port
        dp: u16, // destination port
        s_addr: IpAddr,
        d_addr: IpAddr,
        tls_protocol: TLS_Protocol,
        transport_protocol: Transport_Protocol
    ) -> Self {
        let mut p = Packet_info::default();
        p.s_addr = s_addr;
        p.d_addr = d_addr;
        p.sp = sp;
        p.dp = dp;
        p.timestamp = timestamp;
        p.tls_protocol = tls_protocol;
        p.transport_protocol = transport_protocol;
        p
    }

    pub fn set_timestamp(&mut self, timestamp: DateTime<Utc>) {
        self.timestamp = timestamp;
    }
    pub fn set_source_port(&mut self, port: u16) {
        self.sp = port;
    }
    pub fn set_protocol(&mut self, protocol: TLS_Protocol) {
        self.tls_protocol = protocol;
    }
    pub fn set_dest_port(&mut self, port: u16) {
        self.dp = port;
    }
    pub fn set_source_ip(&mut self, s_ip: IpAddr) {
        self.s_addr = s_ip;
    }
    pub fn set_dest_ip(&mut self, d_ip: IpAddr) {
        self.d_addr = d_ip;
    }

    pub fn to_csv(&self) -> String {
        let s = String::new();
        s
    }
    pub fn to_json(&self) -> String {
        let s = String::new();
        s
    }
    #[inline]
    fn find_asn<'a>(asn_db: &'a Database, ip: &'a str) -> Option<IpEntry<'a>> {
        if let Ok(ip_addr) = ip.parse::<IpAddr>() {
            asn_db.lookup(ip_addr)
        } else {
            None
        }
    }
    pub fn update_asn(&mut self, asn_db: &Database) {
        if let Some(ip_asn_data) = Packet_info::find_asn(asn_db, &self.d_addr.to_string()) {
            match ip_asn_data {
                IpEntry::V4(v4) => {
                    self.tls_server.asn = v4.as_number;
                    self.tls_server.asn_owner = v4.owner.clone();
                    self.tls_server.prefix = v4.subnet.to_string();
                }
                IpEntry::V6(v6) => {
                    self.tls_server.asn = v6.as_number;
                    self.tls_server.asn_owner = v6.owner.clone();
                    self.tls_server.prefix = v6.subnet.to_string();
                }
            }
        }
    }

    pub fn update_public_suffix(&mut self, publicsuffixlist: &publicsuffix::List) {
        if !self.tls_client.sni.is_empty() {
            self.tls_server.domain = find_domain(publicsuffixlist, &self.tls_client.sni);
        }
    }
}

impl fmt::Display for Packet_info {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "{}:{} => {}:{} ({}) v:{} sni:{} ja4c:{:?} ja4s:{} asn:{} domain:{} owner:{} prefix:{}
            ja3c:{:?} ja3s:{} gr:{} ci:{} sig:{} pt:{} alpn:{}
            cphs:{:?} sigs:{:?} pts:{:?} alps:{:?} vs:{:?} grs:{:?}",
            self.s_addr,
            self.sp,
            self.d_addr,
            self.dp,
            self.tls_protocol.as_str(),
            self.tls_server.version,
            self.tls_client.sni,
            self.tls_client.ja4c,
            self.tls_server.ja4s,
            self.tls_server.asn,
            self.tls_server.domain,
            self.tls_server.asn_owner,
            self.tls_server.prefix,
            self.tls_client.ja3c,
            self.tls_server.ja3s,
            self.tls_server.group.as_str(),
            self.tls_server.cipher.as_str(),
            self.tls_server.signature_algorithm.as_str(),
            self.tls_server.point,
            self.tls_server.alpn,
            self.tls_client.ciphers,
            self.tls_client.signature_algorithms,
            self.tls_client.point,
            self.tls_client.alpns,
            self.tls_client.versions,
            self.tls_client.groups
        )
        .expect("Cannot write output format ");

        write!(f, "")
    }
}
