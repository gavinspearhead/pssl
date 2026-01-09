#![allow(non_camel_case_types)]
extern crate core;

pub mod config;
pub mod errors;
pub mod http_server;
pub mod ja4;
pub mod mysql_connection;
pub mod packet_info;
pub mod packet_queue;
pub mod rank;
pub mod ssl_helper;
pub mod ssl_packet;
pub mod statistics;
pub mod time_stats;
pub mod tls_cipher_suites;
pub mod tls_extension_types;
pub mod tls_groups;
pub mod tls_signature_hash_algorithms;
pub mod util;
pub mod version;
pub mod ssl_quic;
pub mod ssl_tcp;

use crate::version::PROGNAME;
use crate::version::VERSION;
use chrono::{DateTime, Utc};
use clap::Parser;
use config::parse_config;
use daemonize_me::{Daemon, Group, User};
use futures::executor::block_on;
use mysql_connection::Mysql_connection;
use packet_info::Packet_info;
use parking_lot::Mutex;
use pcap::{Activated, Active, Capture, Linktype};
use signal_hook::iterator::Signals;
use std::fs::{File, OpenOptions};
use std::io;
use std::io::Write;
use std::net::IpAddr;
use std::process::exit;
use std::str::{self, FromStr};
use std::sync::{mpsc, Arc};
use std::thread;
use std::thread::sleep;
use std::time::Duration;
use strum_macros::{EnumIter, EnumString, FromRepr, IntoStaticStr};
use tracing::{debug, error};
use tracing_rfc_5424::layer::Layer;
use tracing_rfc_5424::transport::UnixSocket;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{filter, fmt, prelude::*, reload}; // Needed to get `with()`

use crate::config::Config;
use crate::http_server::listen;
use crate::mysql_connection::create_database;
use crate::packet_info::Packet_Info_List;
use crate::packet_queue::Packet_Queue;
use crate::ssl_packet::{parse_eth, TlsSupportedGroup};
use crate::statistics::Statistics;
use crate::tls_cipher_suites::{TlsCipherSuite, TlsCipherSuiteValue};
use crate::tls_signature_hash_algorithms::{TlsSignatureScheme, TlsSignatureSchemeValue};
use crate::util::{load_asn_database, read_public_suffix_file};

#[derive(
    Debug, Clone, PartialEq, Eq, EnumIter, EnumString, FromRepr, IntoStaticStr, Copy, Hash,
)]
pub enum TLS_Protocol {
    TLS,
    DTLS,
    QUIC,
}


impl TLS_Protocol {
    #[must_use] 
    pub fn as_str(self) -> &'static str {
        self.into()
    }
}

#[derive(Parser, Clone, Debug, PartialEq)]
struct Args {
    #[arg(short, long)]
    path: std::path::PathBuf,
}

fn packet_loop<T: Activated + 'static>(cap: &mut Capture<T>, packet_queue: &Packet_Queue) {
    let link_type = cap.get_datalink();
    if link_type != Linktype::ETHERNET {
        error!("Not ethernet {link_type:?}");
        exit(-1);
    }

    debug!("Starting loop");
    loop {
        match cap.next_packet() {
            Ok(packet) => {
                let ts = DateTime::<Utc>::from_timestamp(
                    packet.header.ts.tv_sec,
                    packet.header.ts.tv_usec as u32 * 1000,
                )
                .unwrap_or_else(Utc::now);
                packet_queue.push_back(Some((packet.data.to_vec(), ts)));
            }
            Err(pcap::Error::TimeoutExpired) => {
                debug!("Packet capture error: {}", pcap::Error::TimeoutExpired);
            }
            Err(e) => {
                error!("Packet capture error: {e}");
                packet_queue.push_back(None);
                break;
            }
        }
    }
}

fn parse_tls_packet(
    packet_queue: &Packet_Queue,
    stats: &Arc<Mutex<Statistics>>,
    // tcp_list: &Arc<Mutex<TCP_Connections>>,
    config: &Config,
    packet_info_list: &mut Packet_Info_List,
) -> bool {
    if let Some(a_packet) = packet_queue.pop_front() {
        match a_packet {
            Some((mut packet, ts)) => {
                let result =
                    parse_eth(&mut packet, packet_info_list, config, ts, &mut stats.lock());
                if let Err(error) = result { 
                    debug!("{error:?}"); 
                }
            }
            None => {
                return false;
            }
        }
    } else {
        sleep(Duration::from_millis(20));
    }
    true
}

const PACKET_LIST_TIMEOUT: i64 = 6000;

fn poll(
    packet_queue: &Packet_Queue,
    config: &Config,
    _rx: mpsc::Receiver<String>,
    stats: &Arc<Mutex<Statistics>>,
) {
    debug!("Starting poll()");
    let mut output_file = open_output_file(config);
    let mut database_conn = connect_database(config);
    let asn_database = load_asn_database(config);
    let publicsuffixlist: publicsuffix::List = read_public_suffix_file(&config.public_suffix_file);
    let mut last_cleanup = Utc::now().timestamp();

    let mut packet_info = Packet_Info_List::new();
    loop {
        let _res = parse_tls_packet(packet_queue, stats, config, &mut packet_info);
        /*  if !packet_info.packets.is_empty() {
            debug!("parse_tls_packet returned {:?} packets", packet_info.packets );
        }*/
        let now = Utc::now().timestamp();
        if now - last_cleanup >= 1 {
            last_cleanup = now;

            let to_remove: Vec<(IpAddr, IpAddr, u16, u16)> = packet_info
                .packets
                .iter()
                .filter(|(_, v)| {
                    (v.tls_client.done && v.tls_server.done)
                        || now > (v.q_timestamp.timestamp() + PACKET_LIST_TIMEOUT)
                })
                .map(|(k, _)| *k)
                .collect();

            // Then remove them and act on the removed records
            for k in to_remove {
                //debug!("Removing {:?} from packet_info", k);

                if let Some(mut p1) = packet_info.packets.remove(&k) {
                    update_stats(&mut stats.lock(), &p1);
                    p1.update_asn(&asn_database);
                    p1.update_public_suffix(&publicsuffixlist);
                    export_session(k, &p1, config, &mut output_file, &mut database_conn);
                } else {
                    debug!("Terminating poll()");
                    return;
                }
            }
        }
    }
}

fn update_stats(stats: &mut Statistics, packet_info: &Packet_info) {
    // ... existing code ...
    match packet_info.tls_protocol {
        TLS_Protocol::TLS => stats.tls += 1,
        TLS_Protocol::QUIC => stats.quic += 1,
        TLS_Protocol::DTLS => stats.dtls += 1,
    }
    // ... existing code ...
    if packet_info.d_addr.is_ipv4() {
        stats.ipv4 += 1;
    } else {
        stats.ipv6 += 1;
    }

    if packet_info.tls_server.cipher != TlsCipherSuite::Known(TlsCipherSuiteValue::TLS_NULL_WITH_NULL_NULL) {
        *stats
            .ciphers
            .entry(packet_info.tls_server.cipher)
            .or_insert(0) += 1;
    }
    if packet_info.tls_server.signature_algorithm != TlsSignatureScheme::Known(TlsSignatureSchemeValue::Unknown) {
        *stats
            .signature_algorithms
            .entry(packet_info.tls_server.signature_algorithm)
            .or_insert(0) += 1;
    }
    if packet_info.tls_server.group != TlsSupportedGroup::default() {
        *stats
            .curves
            .entry(packet_info.tls_server.group)
            .or_insert(0) += 1;
    }

    stats.sources.add(&packet_info.s_addr);
    stats.destinations.add(&packet_info.d_addr);
    if !packet_info.tls_server.ja3s.is_empty() {
        stats.ja3s.add(&packet_info.tls_server.ja3s);
    }

    if !packet_info.tls_client.ja3c.is_empty() {
        stats.ja3c.add(&packet_info.tls_client.ja3c);
    }
    if !packet_info.tls_server.ja4s.is_empty() {
        stats.ja4s.add(&packet_info.tls_server.ja4s);
    }
    if !packet_info.tls_client.ja4c.is_empty() {
        stats.ja4c.add(&packet_info.tls_client.ja4c);
    }
}

fn open_output_file(config: &Config) -> Option<File> {
    if !config.output.is_empty() && config.output != "-" {
        let mut options = OpenOptions::new();
        Some(
            options
                .append(true)
                .create(true)
                .open(&config.output)
                .expect("Cannot open file"),
        )
    } else {
        None
    }
}

fn connect_database(config: &Config) -> Option<Mysql_connection> {
    if config.database.is_empty() {
        None
    } else {
        Some(block_on(Mysql_connection::connect(
            &config.dbhostname,
            &config.dbusername,
            &config.dbpassword,
            &config.dbport,
            &config.dbname,
        )))
    }
}

fn is_valid_session(packet_info: &Packet_info) -> bool {
    let has_packets =
        packet_info.tls_client.packet_count > 0 || packet_info.tls_server.packet_count > 0;
    let has_tls_data =
        packet_info.tls_server.version != 0 || !packet_info.tls_client.versions.is_empty();

    if !has_packets || !has_tls_data {
        return false;
    }
    if packet_info.tls_client.sni.is_empty() || packet_info.tls_server.version == 0 {
        return false;
    }
    true
}

fn export_session(
    key: (IpAddr, IpAddr, u16, u16),
    packet_info: &Packet_info,
    config: &Config,
    output_file: &mut Option<File>,
    database_conn: &mut Option<Mysql_connection>,
) {
    if !is_valid_session(packet_info) {
        /*debug!(
            "Session {:?} is invalid or incomplete, skipping export",
            key
        );*/
        return;
    }

    if let Some(ref mut file) = output_file {
        let content = match config.output_type.as_str() {
            "csv" => Some(packet_info.to_csv()),
            "json" => Some(packet_info.to_json()),
            _ => None,
        };

        if let Some(data) = content {
            file.write_all(data.as_bytes()).expect("Write failed");
        }
    }

    if let Some(ref mut db) = database_conn {
        db.insert_or_update_record(packet_info);
    }

    if config.output == "-" {
        println!("{packet_info}");
    }
}

fn capture_from_file(
    config: &Config,
    pcap_path: &str,
    stats: &Arc<Mutex<Statistics>>,
    packet_queue: &Packet_Queue,
) {
    let (_pq_tx, pq_rx) = mpsc::channel();
    let (tcp_tx, _tcp_rx) = mpsc::channel();
    debug!("Reading PCAP file e {pcap_path}");
    let cap = Capture::from_file(pcap_path);
    match cap {
        Ok(mut c) => {
            if let Err(e) = c.filter(&config.filter, false) {
                error!("Cannot apply filter {}: {e}", config.filter);
                exit(-2);
            }
            thread::scope(|s| {
                // let handle_tcp_list = s.spawn(|| clean_tcp_list(&tcp_list.clone(), tcp_rx));
                let handle_poll = s.spawn(|| poll(&packet_queue.clone(), config, pq_rx, stats));
                let handle_packet_loop = s.spawn(|| {
                    packet_loop(&mut c, &packet_queue.clone());
                });
                handle_packet_loop.join().unwrap();
                // we wait for the main threat to terminate; then cancel the tcp cleanup threat
                let _ = tcp_tx.send(String::from_str("the end").unwrap());
                handle_poll.join().unwrap();
            });
        }
        Err(e) => {
            error!("Error reading PCAP file: {e:?}");
            exit(-2);
        }
    }
}

fn cleanup_task(config: &Config) {
    if !config.database.is_empty() {
        loop {
            let x = block_on(Mysql_connection::connect(
                &config.dbhostname,
                &config.dbusername,
                &config.dbpassword,
                &config.dbport,
                &config.dbname,
            ));
            x.clean_database(config);
            sleep(Duration::from_secs(24 * 3600));
        }
    }
}

fn stats_dump(config: &Config, statistics: &Arc<Mutex<Statistics>>) {
    if config.stats_dump_interval > 0 {
       /* debug!(
            "stats interval {} to file {}",
            config.stats_dump_interval, &config.export_stats
        );*/
        loop {
            if let Err(e) = statistics.lock().dump_stats(config, false) {
                error!("Cannot dump stats: {e}");
            }
            sleep(Duration::from_secs(config.stats_dump_interval as u64));
        }
    }
}

fn devnull() -> io::Result<File> {
    File::open("/dev/null")
}

fn terminate_loop(stats: &Arc<Mutex<Statistics>>, config: &Arc<Config>) {
    let mut signals = Signals::new([signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM])
        .expect("Failed to register signal handler");

    // We don't necessarily need a separate thread if the main thread
    // is just going to park anyway!
    debug!("Waiting for termination...");

    if let Some(sig) = signals.forever().next() {
        debug!("Received signal: {:?}", sig);

        let s = stats.lock();
        if let Err(e) = s.dump_stats(config, true) {
            error!("Failed to dump stats on exit: {}", e);
        }
    }

    debug!("Shutting down.");
    exit(0);
}
fn capture_from_interface(
    config: &Config,
    stats: &Arc<Mutex<Statistics>>,
    packet_queue: &Packet_Queue,
    mut cap_in: Capture<Active>,
) {
    debug!("Listening on interface {}", config.interface);
    let (_pq_tx, pq_rx) = mpsc::channel();
    let (tcp_tx, _tcp_rx) = mpsc::channel();
    debug!("Filter: {}", config.filter);
    if let Err(e) = cap_in.filter(&config.filter, false) {
        error!("Cannot apply filter {}: {e}", config.filter);
        exit(-1);
    }
    let config_arc = Arc::new(config.clone());

    thread::scope(|s| {
        let handle_poll = s.spawn(|| poll(packet_queue, config, pq_rx, stats));
        let handle_http = s.spawn(|| {
            let _ = listen(stats, config);
        });
        let handle_stats_dump = s.spawn(|| stats_dump(config, stats));
        let handle_cleanup = s.spawn(|| cleanup_task(config));
        let handle_packet_loop = s.spawn(|| {
            packet_loop(&mut cap_in, packet_queue);
        });

        terminate_loop(stats, &config_arc);
        let _ = handle_packet_loop.join();
        // we wait for the main threat to terminate; then cancel the tcp cleanup threat
        let _ = tcp_tx.send(String::from_str("the end").unwrap());
        let _ = handle_http.join();
        let _ = handle_cleanup.join();
        let _ = handle_poll.join();
        let _ = handle_stats_dump.join();
    });
}

fn run(
    config: &Config,
    cap_in: Option<Capture<Active>>,
    pcap_path: &str,
    stats: &Arc<Mutex<Statistics>>,
) {
    let packet_queue = Packet_Queue::new();
    if !pcap_path.is_empty() {
        capture_from_file(config, pcap_path, stats, &packet_queue);
    } else if !config.interface.is_empty() {
        let Some(cap) = cap_in else {
            error!("Something wrong with the capture");
            exit(-1);
        };
        capture_from_interface(config, stats, &packet_queue, cap);
    }
}

fn main() {
    let mut config = Config::new();
    let mut pcap_path = String::new();
    let layers = vec![fmt::Layer::default().boxed()];
    let filter = filter::LevelFilter::WARN;
    let (filter, reload_handle) = reload::Layer::new(filter);
    let (tracing_layers, reload_handle1) = reload::Layer::new(layers);
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_layers)
        .init();

    parse_config(&mut config, &mut pcap_path);

    if config.debug {
        let _ = reload_handle.modify(|filter| *filter = filter::LevelFilter::DEBUG);
    }
    debug!("Config: {:?}", config);
    if !config.log_file.is_empty() {
        //debug!("Logging to {}", config.log_file);
        let _ = reload_handle1.modify(|layers| {
            let file = match OpenOptions::new()
                .append(true)
                .create(true)
                .open(&config.log_file)
            {
                Ok(f) => f,
                Err(e) => {
                    error!("Cannot create file {} {e}", config.log_file);
                    exit(-1);
                }
            };
            let layer = tracing_subscriber::fmt::layer().with_writer(file).boxed();
            (*layers).push(layer);
        });
    }

    if config.syslog {
        let _ = reload_handle1.modify(|layers| {
            (*layers).push(
                Layer::with_transport(UnixSocket::new("/var/run/systemd/journal/syslog").unwrap())
                    .boxed(),
            );
        });
    }
    debug!("Starting {PROGNAME} {VERSION}");
    if config.create_db {
        create_database(&config);
        exit(0);
    }
    let mut cap = None;
    if !config.interface.is_empty() {
        // do it here otherwise PCAP hangs on open if we do it after daemonizing
        cap = match Capture::from_device(config.interface.as_str())
            .unwrap()
            .timeout(1000)
            .promisc(config.promisc) // todo make a parameter
            //                .immediate_mode(true) //seems to break on ubuntu?
            .open()
        {
            Ok(x) => Some(x),
            Err(e) => {
                error!(
                    "Cannot open capture on interface '{}' {e}",
                    &config.interface
                );
                exit(-1);
            }
        };
    }
    /*let mut options = OpenOptions::new();
    std::fs::write(
        "config.json",
        serde_json::to_string_pretty(&config).unwrap(),
    );*/

    let stats = if config.import_stats.is_empty() {
        Arc::new(Mutex::new(Statistics::new(config.toplistsize)))
    } else {
        debug!("import stats from : {}", config.import_stats);
        Arc::new(Mutex::new(
            match Statistics::import(&config.import_stats, config.toplistsize) {
                Ok(x) => x,
                Err(e) => {
                    error!("Cannot import file '{}' {e}", config.import_stats);
                    exit(-1);
                }
            },
        ))
    };

    if config.daemon {
        debug!("Daemonising");

        let daemon = Daemon::new()
            .pid_file(&config.pid_file, Some(false))
            .work_dir("/tmp")
            .user(User::try_from(&config.uid).expect("Invalid user"))
            .group(Group::try_from(&config.gid).expect("Invalid group"))
            .umask(0o077)
            .stdout(devnull().expect("Cannot open /dev/null"))
            .stderr(devnull().expect("Cannot open /dev/null"));

        match daemon.start() {
            Ok(()) => {
                debug!("Daemonised");
                run(&config, cap, &pcap_path, &stats);
            }
            Err(e) => {
                error!("Error daemonising: {}", e);
                exit(-1);
            }
        }
    } else {
        debug!("NOT Daemonising");
        run(&config, cap, &pcap_path, &stats);
    }
}
