use crate::config::Config;
use crate::statistics::Statistics;
use crate::time_stats::STAT_ITEM::{DAY, HOUR, MINUTE, MONTH, SECOND};
use crate::version::VERSION;
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use log::debug;
use parking_lot::Mutex;
use std::sync::Arc;

async fn get_version() -> impl Responder {
    HttpResponse::Ok().json(VERSION)
}
async fn get_tls_versions(stats: web::Data<Arc<Mutex<Statistics>>>) -> impl Responder {
    let stats_data = stats.lock().clone();
    HttpResponse::Ok().json(stats_data.tls_versions)
}
async fn get_possible_ciphers(stats: web::Data<Arc<Mutex<Statistics>>>) -> impl Responder {
    let stats_data = stats.lock().clone();
    HttpResponse::Ok().json(stats_data.client_ciphers)
}
async fn get_signature_algorithms(stats: web::Data<Arc<Mutex<Statistics>>>) -> impl Responder {
    let stats_data = stats.lock().clone();
    HttpResponse::Ok().json(stats_data.signature_algorithms)
}
async fn get_curves(stats: web::Data<Arc<Mutex<Statistics>>>) -> impl Responder {
    let stats_data = stats.lock().clone();
    debug!("{:?}", &stats_data.curves);
    HttpResponse::Ok().json(stats_data.curves)
}

async fn get_stats(stats: web::Data<Arc<Mutex<Statistics>>>) -> impl Responder {
    let stats_data = stats.lock().clone();
    HttpResponse::Ok().json(stats_data)
}

async fn get_destinations(stats: web::Data<Arc<Mutex<Statistics>>>) -> impl Responder {
    let stats_data = stats.lock().clone();
    HttpResponse::Ok().json(stats_data.destinations)
}
async fn get_config(config: web::Data<Config>) -> impl Responder {
    let mut config_copy = config.get_ref().clone();
    if !config_copy.dbpassword.is_empty() {
        "****".clone_into(&mut config_copy.dbpassword);
    }
    HttpResponse::Ok().json(&config_copy)
}

async fn get_endpoints() -> impl Responder {
    let endpoints = vec![
        "/",
        "/signatures",
        "/curves",
        "/ciphers",
        "/stats",
        "/tls_versions",
        "/destinations",
        "/config",
        "/version",
    ];
    HttpResponse::Ok().json(endpoints)
}
#[actix_web::main]
pub(crate) async fn listen(stats: &Arc<Mutex<Statistics>>, config: &Config) -> std::io::Result<()> {
    if config.http_server.is_empty() || config.http_port == 0 {
        return Ok(());
    }
    debug!("Listening on {}:{}", config.http_server, config.http_port);
    let stats_clone = Arc::clone(stats);
    let config_clone = config.clone();
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(stats_clone.clone())) // Share statistics across handlers
            .app_data(web::Data::new(config_clone.clone())) // Share config across handlers
            .route("/signatures", web::get().to(get_signature_algorithms))
            .route("/curves", web::get().to(get_curves))
            .route("/ciphers", web::get().to(get_possible_ciphers))
            .route("/stats", web::get().to(get_stats))
            .route("/tls_versions", web::get().to(get_tls_versions))
            .route("/destinations", web::get().to(get_destinations))
            .route("/config", web::get().to(get_config))
            .route("/version", web::get().to(get_version))
            .route("/", web::get().to(get_endpoints))
    })
    .bind(format!("{}:{}", config.http_server, config.http_port))?
    .run()
    .await
}
