use chrono::{Duration, Utc};
use futures::executor::block_on;
use sqlx::{mysql::MySqlPoolOptions, MySql, Pool};
use std::process::exit;
use tracing::{debug, error};

use crate::config::Config;
use crate::packet_info::Packet_info;

#[derive(Debug, Clone)]
pub(crate) struct Mysql_connection {
    pool: Pool<MySql>,
}

impl Mysql_connection {
    pub async fn connect(
        host: &str,
        user: &str,
        pass: &str,
        port: &u16,
        dbname: &str,
    ) -> Mysql_connection {
        let database_url = format!("mysql://{user}:{pass}@{host}:{port}/{dbname}");
        match MySqlPoolOptions::new()
            .max_connections(10)
            .connect(&database_url)
            .await
        {
            Ok(mysql_pool) => {
                debug!("Connection to the database is successful!");
                Mysql_connection { pool: mysql_pool }
            }
            Err(err) => {
                error!("Failed to connect to the database: {:?}", err);
                exit(1);
            }
        }
    }
    pub fn insert_or_update_record(&mut self, record: &Packet_info) {
        let i = record;
        let ts = i.timestamp.timestamp();
        let q = r"INSERT INTO pssl (ip, port, host, version, cipher, curve, last_seen, first_seen, ja4s, count, asn, asn_owner, domain, prefix, protocol)
            VALUES (
                ?, ?, ? ,?, ?, ?, FROM_UNIXTIME(?),FROM_UNIXTIME(?),?, ?, ?, ?, ?, ?, ?)
               ON DUPLICATE KEY UPDATE
                COUNT = COUNT + ?,
                LAST_SEEN = GREATEST(LAST_SEEN, FROM_UNIXTIME(?)),
                FIRST_SEEN = LEAST(FROM_UNIXTIME(?), FIRST_SEEN)
                ";
       /* debug!(
            "{} {} {} {} {}",
            i.d_addr.to_string(),
            i.dp,
            i.tls_client.sni,
            i.tls_server.version,
            i.tls_server.group.to_u16(),
        );*/

        let q_res = block_on(
            sqlx::query(q)
                .bind(i.d_addr.to_string())
                .bind(i.dp)
                .bind(&i.tls_client.sni)
                .bind(i.tls_server.version)
                .bind(i.tls_server.cipher.as_str())
                .bind(i.tls_server.group.as_str())
                .bind(ts)
                .bind(ts)
                .bind(&i.tls_server.ja4s)
                .bind(1)
                .bind(i.tls_server.asn)
                .bind(&i.tls_server.asn_owner)
                .bind(&i.tls_server.domain)
                .bind(&i.tls_server.prefix)
                .bind(i.tls_protocol.as_str())
                .bind(1)
                .bind(ts)
                .bind(ts)
                .execute(&self.pool),
        );

        match q_res {
            Ok(_x) => {
                //debug!("Success PSSL {:?}", x);
            }
            Err(e) => {
                error!("Error: {}", e);
            }
        }
        let q2 = r"INSERT INTO pssl_client (ip, version, last_seen, first_seen, ja4c, count, protocol)
            VALUES (
                ?, ?, FROM_UNIXTIME(?),FROM_UNIXTIME(?),?, ?, ?)
               ON DUPLICATE KEY UPDATE
                COUNT = COUNT + ?,
                LAST_SEEN = GREATEST(LAST_SEEN, FROM_UNIXTIME(?)),
                FIRST_SEEN = LEAST(FROM_UNIXTIME(?), FIRST_SEEN)
                ";
        let q_res = block_on(
            sqlx::query(q2)
                .bind(i.s_addr.to_string())
                .bind(i.tls_server.version)
                .bind(ts)
                .bind(ts)
                .bind(&i.tls_client.ja4c)
                .bind(1)
                .bind(i.tls_protocol.as_str())
                .bind(1)
                .bind(ts)
                .bind(ts)
                .execute(&self.pool),
        );
        match q_res {
            Ok(x) => {
               // debug!("Success PSSL_Client {:?}", x);
            }
            Err(e) => {
                error!("Error: {}", e);
            }
        }
    }
    pub fn create_database(&mut self) {
        let create_cmd1 = r"
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `ip` varchar(64) DEFAULT NULL,
  'protocol' varchar(16) DEFAULT NULL,
  `version` varchar(16) DEFAULT NULL,
  `ja4c` varchar(256) DEFAULT NULL,
  `last_seen` datetime DEFAULT NULL,
  `first_seen` datetime DEFAULT NULL,
  `count` bigint(20) DEFAULT NULL,

  PRIMARY KEY (`id`),
  UNIQUE KEY `dups1` (`ip`,`version`, `ja4s`, `protocol`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
        ";
        match block_on(sqlx::query(create_cmd1).execute(&self.pool)) {
            Ok(x) => {
               // debug!("Success {:?}", x);
            }
            Err(e) => {
                error!("Error: {}", e);
                exit(-1);
            }
        }

        let create_cmd2 = r"
        CREATE TABLE `pssl` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `ip` varchar(64) DEFAULT NULL,
  `port` int(11) DEFAULT NULL,
  'protocol' varchar(16) DEFAULT NULL,
  `host` varchar(255) DEFAULT NULL,
  `version` varchar(16) DEFAULT NULL,
  `cipher` varchar(256) DEFAULT NULL,
  `curve` varchar(256) DEFAULT NULL,
  `last_seen` datetime DEFAULT NULL,
  `first_seen` datetime DEFAULT NULL,
  `count` bigint(20) DEFAULT NULL,
  `ja4s` varchar(256) DEFAULT NULL,
  `asn` int(20) DEFAULT NULL,
  `asn_owner` varchar(256) DEFAULT NULL,
  `domain` varchar(256) DEFAULT NULL,
  `prefix` varchar(256) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `dups1` (`ip`,`port`,`host`,`version`,`cipher`, `curve`, `ja4s`, `protocol`))
) ENGINE=MyISAM DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

      ";
        match block_on(sqlx::query(create_cmd2).execute(&self.pool)) {
            Ok(x) => {
               // debug!("Success {:?}", x);
            }
            Err(e) => {
                error!("Error: {}", e);
                exit(-1);
            }
        }
    }
    pub fn clean_database(self, config: &Config) {
        if config.clean_interval <= 0 {
            return;
        }
        let current_time = Utc::now() - Duration::days(config.clean_interval);
        debug!("Cleaning timestamp: {current_time}");

        static CLEAN_CMD: &str = "DELETE FROM pssl WHERE LAST_SEEN < ?";
        if let Err(e) = block_on(
            sqlx::query(CLEAN_CMD)
                .bind(current_time)
                .execute(&self.pool),
        ) {
            error!("Cannot execute cleanup query: {e}");
        }

        static CLEAN_CMD1: &str = "DELETE FROM pssl_client WHERE LAST_SEEN < ?";
        if let Err(e) = block_on(
            sqlx::query(CLEAN_CMD1)
                .bind(current_time)
                .execute(&self.pool),
        ) {
            error!("Cannot execute cleanup query: {e}");
        }
    }
}

pub(crate) fn create_database(config: &Config) {
    if !config.database.is_empty() {
        let x = block_on(Mysql_connection::connect(
            &config.dbhostname,
            &config.dbusername,
            &config.dbpassword,
            &config.dbport,
            &config.dbname,
        ));

        if let Some(ref mut db) = Some(x) {
            debug!("Database created");
            db.create_database();
        } else {
            error!("No database configured");
            panic!("No database configured");
        }
    }
}
