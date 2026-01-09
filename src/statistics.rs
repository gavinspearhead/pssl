use crate::rank::Rank;
use crate::util::ordered_map;
use serde::{Deserialize, Serialize};
use serde_json;
use serde_with::rust::deserialize_ignore_any;

use crate::config::Config;
use crate::ssl_packet::TlsSupportedGroup;
use crate::tls_cipher_suites::TlsCipherSuite;
use crate::tls_extension_types::TlsExtensionType;
use crate::tls_signature_hash_algorithms::TlsSignatureScheme;
use chrono::Utc;
use flate2::write::GzEncoder;
use std::collections::HashMap;
use std::io::{BufWriter, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::{fs::File, io::BufReader};
use tracing::debug;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub(crate) struct Statistics {
    pub dtls: u128,
    pub tls: u128,
    pub quic: u128,
    pub ipv6: u128,
    pub ipv4: u128,
    pub tcp: u128,
    pub udp: u128,
    pub sctp: u128,
    #[serde(serialize_with = "ordered_map")]
    pub alpns: HashMap<String, u128>,
    #[serde(serialize_with = "ordered_map")]
    pub curves: HashMap<TlsSupportedGroup, u128>,
    #[serde(serialize_with = "ordered_map")]
    pub client_pk_curves: HashMap<TlsSupportedGroup, u128>,
    #[serde(serialize_with = "ordered_map")]
    pub client_curves: HashMap<TlsSupportedGroup, u128>,
    #[serde(serialize_with = "ordered_map")]
    pub ciphers: HashMap<TlsCipherSuite, u128>,
    #[serde(serialize_with = "ordered_map")]
    pub client_ciphers: HashMap<TlsCipherSuite, u128>,
    #[serde(serialize_with = "ordered_map")]
    pub tls_versions: HashMap<u16, u128>,
    #[serde(serialize_with = "ordered_map")]
    pub client_tls_versions: HashMap<u16, u128>,
    #[serde(serialize_with = "ordered_map")]
    pub signature_algorithms: HashMap<TlsSignatureScheme, u128>,
    #[serde(serialize_with = "ordered_map")]
    pub client_signature_algorithms: HashMap<TlsSignatureScheme, u128>,

    #[serde(deserialize_with = "deserialize_ignore_any")]
    pub sources: Rank<IpAddr>,
    #[serde(deserialize_with = "deserialize_ignore_any")]
    pub destinations: Rank<IpAddr>,
    #[serde(deserialize_with = "deserialize_ignore_any")]
    pub ja3c: Rank<String>,
    #[serde(deserialize_with = "deserialize_ignore_any")]
    pub ja3s: Rank<String>,
    #[serde(deserialize_with = "deserialize_ignore_any")]
    pub ja4c: Rank<String>,
    #[serde(deserialize_with = "deserialize_ignore_any")]
    pub ja4s: Rank<String>,
    #[serde(deserialize_with = "deserialize_ignore_any")]
    pub client_extensions: HashMap<TlsExtensionType, u128>,
    #[serde(deserialize_with = "deserialize_ignore_any")]
    pub server_extensions: HashMap<TlsExtensionType, u128>,
}

impl Statistics {
    pub fn new(toplistsize: usize) -> Statistics {
        Statistics {
            ipv4: 0,
            tcp: 0,
            udp: 0,
            ipv6: 0,
            sources: Rank::new(toplistsize),
            destinations: Rank::new(toplistsize),
            dtls: 0,
            tls: 0,
            quic: 0,
            curves: HashMap::new(),
            client_curves: HashMap::new(),
            client_pk_curves: HashMap::new(),
            ciphers: HashMap::new(),
            client_ciphers: HashMap::new(),
            tls_versions: HashMap::new(),
            signature_algorithms: HashMap::new(),
            client_signature_algorithms: HashMap::new(),
            client_tls_versions: HashMap::new(),
            server_extensions: HashMap::new(),
            client_extensions: HashMap::new(),
            ja3s: Rank::new(toplistsize),
            ja3c: Rank::new(toplistsize),
            ja4s: Rank::new(toplistsize),
            ja4c: Rank::new(toplistsize),
            alpns: HashMap::new(),
            sctp: 0,
        }
    }

    pub fn import(
        filename: &str,
        toplistsize: usize,
    ) -> Result<Statistics, Box<dyn std::error::Error>> {
        let file = File::open(filename)?;
        let reader = BufReader::new(file);
        let mut statistics: Statistics = serde_json::from_reader(reader)?;
        statistics.sources = Rank::new(toplistsize);
        statistics.destinations = Rank::new(toplistsize);
        Ok(statistics)
    }

    pub fn dump_stats(&self, config: &Config, unique: bool) -> std::io::Result<()> {
        if config.export_stats.is_empty() {
            return Ok(());
        }

        let filename = self.generate_stats_path(config, unique)?;

        let mut attempts = 0;
        loop {
            match File::create_new(&filename) {
                Ok(file) => return self.write_to_file(file, &filename, config.compress_stats),
                Err(e) if attempts < 5 => {
                    attempts += 1;
                    debug!("Retry creating file {filename:?} (attempt {attempts}) ){e}");
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn generate_stats_path(&self, config: &Config, unique: bool) -> std::io::Result<PathBuf> {
        let base = Path::new(&config.export_stats);
        if unique {
            let timestamp = Utc::now().to_rfc3339();
            Ok(base.join(format!("stats-{timestamp}.json")))
        } else {
            let name = if config.compress_stats {
                "stats.json.gz"
            } else {
                "stats.json"
            };
            let path = base.join(name);
            if let Err(e) = std::fs::remove_file(&path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    return Err(e);
                }
            }
            Ok(path)
        }
    }

    fn write_to_file(&self, file: File, path: &Path, compress: bool) -> std::io::Result<()> {
        let writer: Box<dyn Write> = if compress {
            debug!("Dumping and compressing stats to {:?}", path);
            Box::new(GzEncoder::new(file, flate2::Compression::default()))
        } else {
            debug!("Dumping stats to {:?}", path);
            Box::new(file)
        };

        let mut buffered_writer = BufWriter::new(writer);
        serde_json::to_writer_pretty(&mut buffered_writer, self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        buffered_writer.flush()
    }
}
