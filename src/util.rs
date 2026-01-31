use crate::config::Config;
use core::cmp::Ordering::Equal;
use publicsuffix::Psl;
use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::process::exit;
use tracing::{debug, error};

// For use with serde's [serialize_with] attribute
pub(crate) fn ordered_map<S, K: Ord + Serialize + ToString, V: Serialize + PartialOrd>(
    value: &HashMap<K, V>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut l: Vec<_> = value.iter().collect();
    l.sort_by(|a, b| {
        a.0.to_string()
            .partial_cmp(&b.0.to_string())
            .unwrap_or(Equal)
    });

    let mut map = serializer.serialize_map(Some(l.len()))?;
    for i in l {
        map.serialize_entry(&i.0, i.1)?;
    }
    map.end()
}

pub(crate) fn load_asn_database(config: &Config) -> asn_db2::Database {
    debug!("ASN Database: {}", config.asn_database_file);
    let Ok(f) = File::open(&config.asn_database_file) else {
        error!("Cannot open ASN database {}", &config.asn_database_file);
        exit(-1);
    };
    let Ok(asn_database) = asn_db2::Database::from_reader(BufReader::new(f)) else {
        error!("Cannot read ASN database {}", &config.asn_database_file);
        exit(-1);
    };
    asn_database
}

pub(crate) fn find_domain(publicsuffixlist: &publicsuffix::List, name: &str) -> String {
    let domain = publicsuffixlist.domain(name.as_bytes());
    if let Some(d) = domain {
        let x = d.as_bytes().to_owned();
        String::from_utf8(x).unwrap_or_default()
    } else {
        //debug!("Domain not found: {name}");
        String::new()
    }
}

pub(crate) fn read_public_suffix_file(public_suffix_file: &str) -> publicsuffix::List {
    debug!("Reading public suffix list {}", public_suffix_file);
    if let Ok(c) = fs::read_to_string(public_suffix_file) {
        if let Ok(d) = c.as_str().parse() {
            d
        } else {
            error!("Cannot parse public suffix file: {public_suffix_file}");
            exit(-1);
        }
    } else {
        error!("Cannot read file {public_suffix_file}");
        exit(-1);
    }
}
