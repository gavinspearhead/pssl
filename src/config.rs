use crate::version::{AUTHOR, DESCRIPTION, PROGNAME, VERSION};
use clap::{arg, value_parser, ArgAction, Command};
use std::process::exit;
use tracing::error;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Config {
    pub interface: String,
    pub filter: String,
    pub output: String,
    pub output_type: String,
    pub database: String,
    pub http_server: String,
    pub http_port: u16,
    pub daemon: bool,
    pub promisc: bool,
    pub config_file: String,
    pub dbhostname: String,
    pub dbusername: String,
    pub dbport: u16,
    pub dbpassword: String,
    pub dbname: String,
    pub toplistsize: usize,
    pub pid_file: String,
    pub uid: String,
    pub gid: String,
    pub asn_database_file: String,
    pub public_suffix_file: String,
    pub debug: bool,
    pub live_dump_port: u16,
    pub live_dump_host: String,
    pub syslog: bool,
    pub log_file: String,
    pub clean_interval: i64,
    pub create_db: bool,
    pub stats_dump_interval: u32,
    pub compress_stats: bool,
    pub export_stats: String,
    pub import_stats: String,
    pub tls_ports: Vec<u16>,
    pub quic_ports: Vec<u16>,
    pub dtls_ports: Vec<u16>,
    pub tls: bool,
    pub quic: bool,
    pub dtls: bool,
}

impl Config {
    pub(crate) fn new() -> Config {
        Config {
            interface: String::new(),
            filter: String::new(),
            output: String::new(),
            output_type: String::new(),
            database: String::new(),
            http_server: String::new(),
            http_port: 0,
            daemon: false,
            promisc: false,
            config_file: String::new(),
            dbhostname: String::new(),
            dbpassword: String::new(),
            dbport: 0,
            dbusername: String::new(),
            dbname: String::new(),
            toplistsize: 20,
            pid_file: String::new(),
            gid: String::new(),
            uid: String::new(),
            asn_database_file: String::new(),
            public_suffix_file: String::new(),
            debug: false,
            live_dump_port: 0,
            live_dump_host: String::new(),
            syslog: false,
            log_file: String::new(),
            clean_interval: 0,
            stats_dump_interval: 3600,
            compress_stats: false,
            create_db: false,
            export_stats: String::new(),
            import_stats: String::new(),
            tls_ports: vec![443],
            quic_ports: vec![443],
            dtls_ports: vec![4433],
            tls: true,
            quic: true,
            dtls: false,
        }
    }
    pub(crate) fn from_str(config_str: &str) -> Result<Config, serde_json::Error> {
        serde_json::from_str(config_str)
    }
}

pub(crate) fn parse_config(config: &mut Config, pcap_path: &mut String) {
    let matches = Command::new(PROGNAME)
        .version(VERSION)
        .author(AUTHOR)
        .about(DESCRIPTION)
        .name(DESCRIPTION)
        .flatten_help(true)
        .arg(
            arg!(-c --config <VALUE>)
                .required(false)
                .long_help("location of the config file"),
        )
        .arg(
            arg!(-H --dbhostname <VALUE>)
                .required(false)
                .long_help("hostname of the database"),
        )
        .arg(
            arg!(-T --dbport <VALUE>)
                .required(false)
                .value_parser(value_parser!(u16))
                .long_help("port number of the database"),
        )
        .arg(
            arg!(-u --dbusername <VALUE>)
                .required(false)
                .long_help("username for the database"),
        )
        .arg(
            arg!(-w --dbpassword <VALUE>)
                .required(false)
                .long_help("password for the database"),
        )
        .arg(
            arg!(-p --path <VALUE>)
                .required(false)
                .long_help("Location of a pcap file to parse"),
        )
        .arg(
            arg!(-l --listen <VALUE>)
                .required(false)
                .long_help("Hostname or IP address for the internal web server to listen to"),
        )
        .arg(
            arg!(-P --port <VALUE>)
                .required(false)
                .value_parser(value_parser!(u16))
                .long_help("Port number for the internal web server to listen on (0 to disable)"),
        )
        .arg(
            arg!(-r --rrtypes <VALUE>)
                .required(false)
                .long_help("Comma-separated list of RR types to record"),
        )
        .arg(
            arg!(-i --interface <VALUE>)
                .required(false)
                .long_help("Interface to listen on for packet capture"),
        )
        .arg(
            arg!(-f --filter <VALUE>)
                .required(false)
                .long_help("BPF filter definition (port 53)"),
        )
        .arg(
            arg!(-o --output <VALUE>)
                .required(false)
                .long_help("Write output to a file; - for standard out"),
        )
        .arg(
            arg!(-d --database <VALUE>)
                .required(false)
                .long_help("Write output to a database (mysql)"),
        )
        .arg(
            arg!(-L --toplistsize <VALUE>)
                .required(false)
                .value_parser(value_parser!(usize))
                .long_help("Number of entries in the statistics"),
        )
        .arg(
            arg!(-U --uid <VALUE>)
                .required(false)
                .long_help("UID to change to after dropping privileges"),
        )
        .arg(
            arg!(-A --asn_database_file <VALUE>)
                .required(false)
                .long_help("Location of the ASN database (ip2asn-combined.tsv)"),
        )
        .arg(
            arg!(-g --gid <VALUE>)
                .required(false)
                .long_help("GID to change to after dropping privileges"),
        )
        .arg(
            arg!(--debug)
                .required(false)
                .action(ArgAction::SetTrue)
                .long_help("Enable debugging mode"),
        )
        .arg(
            arg!(--create_database)
                .required(false)
                .action(ArgAction::SetTrue)
                .long_help("Create a database"),
        )
        .arg(
            arg!(-C --promisc <VALUE>)
                .required(false)
                .action(ArgAction::SetTrue)
                .long_help("Put the interface is promiscuous mode when capturing"),
        ).arg(
        arg!(--quic)
            .required(false)
            .overrides_with("noquic")
            .action(ArgAction::SetTrue)
            .long_help("Parse QUIC traffic"),
    )
        .arg(
            arg!(--tls)
                .required(false)
                .overrides_with("notls")
                .action(ArgAction::SetTrue)
                .long_help("Parse TLS traffic"),
        )
        .arg(
            arg!(--dtls)
                .required(false)
                .overrides_with("nodtls")
                .action(ArgAction::SetTrue)
                .long_help("Parse DTLS traffic"),
        ).arg(
        arg!(--noquic)
            .required(false)
            .overrides_with("quic")
            .action(ArgAction::SetTrue)
            .long_help("Do not Parse QUIC traffic"),

    ).arg(
        arg!(--notls)
            .required(false)
            .overrides_with("tls")
            .action(ArgAction::SetTrue)
            .long_help("Parse TLS traffic"),
    ) .arg(
        arg!(--nodtls)
            .required(false)
            .overrides_with("dtls")
            .action(ArgAction::SetTrue)
            .long_help("Parse DTLS traffic"),
    )
        .arg(
            arg!(-D --daemon)
                .required(false)
                .action(ArgAction::SetTrue)
                .long_help("Start as a background process (daemon)"),
        )
        .arg(
            arg!(-I --pid_file <VALUE>)
                .required(false)
                .default_missing_value("/var/run/pdns.pid")
                .long_help("Location of the PID file"),
        )
        .arg(
            arg!(-t --output_type <VALUE>)
                .required(false)
                .default_missing_value("csv")
                .long_help("Output format (CSV or JSON)"),
        )
        .arg(
            arg!(--live_dump_host <VALUE>)
                .required(false)
                .long_help("Hostname or IP address for the live dump to listen to"),
        )
        .arg(
            arg!(--live_dump_port <VALUE>)
                .required(false)
                .value_parser(value_parser!(u16))
                .long_help("Port number for the live dump to listen on (0 to disable)"),
        )
        .arg(
            arg!(-M --import_stats <VALUE>)
                .required(false)
                .default_missing_value("")
                .long_help("Import stats from json file"),
        )
        .arg(arg!(--tls_ports <VALUE>).required(false)
            .value_delimiter(',')
            .num_args(1..)
            .value_parser(value_parser!(u16))
            .long_help(
                "TLS Port numbers to listen on for packet capture, comma separated (default 443)",
            ))
        .arg(arg!(--quic_ports <VALUE>).required(false)
            .value_delimiter(',')
            .num_args(1..)
            .value_parser(value_parser!(u16))
            .long_help(
                "QUIC Port numbers to listen on for packet capture, comma separated (default 443)",
            ))
        .arg(arg!(--dtls_ports <VALUE>).required(false)
            .value_delimiter(',')
            .num_args(1..)
            .value_parser(value_parser!(u16))
            .long_help(
                "DTLS Port numbers to listen on for packet capture, comma separated (default 443)",
            ))
        .get_matches();
    let empty_str = String::new();
    config
        .config_file
        .clone_from(matches.get_one::<String>("config").unwrap_or(&empty_str));
    if !config.config_file.is_empty() {
        let config_str = std::fs::read_to_string(&config.config_file).unwrap_or_default();
        if !config_str.is_empty() {
            match Config::from_str(&config_str) {
                Ok(x) => {
                    x.clone_into(config);
                }
                Err(e) => {
                    let err_msg =
                        format!("Failed to parse config file: {} {}", config.config_file, e);
                    error!("{err_msg}");
                    exit(-1);
                }
            }
        }
    }

    config.create_db = *matches.get_one::<bool>("create_database").unwrap_or(&false);

    config.http_server = matches
        .get_one::<String>("listen")
        .unwrap_or(&config.http_server)
        .clone();
    config.http_port = matches
        .get_one::<String>("port")
        .unwrap_or(&format!("{}", config.http_port))
        // .clone()
        .parse::<u16>()
        .unwrap();
    matches
        .get_one::<String>("path")
        .unwrap_or(&empty_str)
        .clone_into(pcap_path);
    config.interface = matches
        .get_one::<String>("interface")
        .unwrap_or(&config.interface)
        .clone();
    config.filter = matches
        .get_one::<String>("filter")
        .unwrap_or(&config.filter)
        .clone();
    config.import_stats = matches
        .get_one::<String>("import_stats")
        .unwrap_or(&config.import_stats)
        .clone();
    config.output = matches
        .get_one::<String>("output")
        .unwrap_or(&config.output)
        .clone();
    config.output_type = matches
        .get_one::<String>("output_type")
        .unwrap_or(&config.output_type)
        .clone();
    config.database = matches
        .get_one::<String>("database")
        .unwrap_or(&config.database)
        .clone();
    if matches.get_flag("tls") {
        config.tls = true;
    } else if matches.get_flag("notls") {
        config.tls = false;
    }

    if matches.get_flag("dtls") {
        config.dtls = true;
    } else if matches.get_flag("nodtls") {
        config.dtls = false;
    }

    if matches.get_flag("quic") {
        config.quic = true;
    } else if matches.get_flag("noquic") {
        config.quic = false;
    }

    config.daemon = *matches.get_one::<bool>("daemon").unwrap_or(&config.daemon);
    config.debug = *matches.get_one::<bool>("debug").unwrap_or(&config.debug);
    config.promisc = *matches
        .get_one::<bool>("promisc")
        .unwrap_or(&config.promisc);
    config.toplistsize = *matches
        .get_one::<usize>("toplistsize")
        .unwrap_or(&config.toplistsize);
    config.pid_file = matches
        .get_one::<String>("pid_file")
        .unwrap_or(&config.pid_file)
        .clone();
    config.gid = matches
        .get_one::<String>("gid")
        .unwrap_or(&config.gid)
        .clone();
    config.uid = matches
        .get_one::<String>("uid")
        .unwrap_or(&config.uid)
        .clone();

    config.asn_database_file = matches
        .get_one::<String>("asn_database_file")
        .unwrap_or(&config.asn_database_file)
        .clone();
    config.live_dump_host = matches
        .get_one::<String>("live_dump_host")
        .unwrap_or(&config.live_dump_host)
        .clone();
    config.live_dump_port = *matches
        .get_one::<u16>("live_dump_port")
        .unwrap_or(&config.live_dump_port);
    let tls_ports: Vec<u16> = matches
        .get_many::<u16>("tls_ports")
        .unwrap_or_default() // Returns an empty iterator if arg is missing
        .copied() // &u16 -> u16
        .collect();
    if !tls_ports.is_empty() {
        config.tls_ports = tls_ports;
    }
    let quic_ports: Vec<u16> = matches
        .get_many::<u16>("quic_ports")
        .unwrap_or_default() // Returns an empty iterator if arg is missing
        .copied() // &u16 -> u16
        .collect();
    if !quic_ports.is_empty() {
        config.quic_ports = quic_ports;
    }
    let dtls_ports: Vec<u16> = matches
        .get_many::<u16>("dtls_ports")
        .unwrap_or_default() // Returns an empty iterator if arg is missing
        .copied() // &u16 -> u16
        .collect();
    if !dtls_ports.is_empty() {
        config.dtls_ports = dtls_ports;
    }
}
