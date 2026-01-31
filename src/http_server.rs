use crate::config::Config;
use crate::statistics::Statistics;
use crate::version::VERSION;
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use log::debug;
use parking_lot::Mutex;
use std::sync::Arc;

async fn get_version() -> impl Responder {
    HttpResponse::Ok().json(VERSION)
}
// Assuming you switch to parking_lot or handle the Result of std::sync::Mutex
async fn get_tls_versions(stats: web::Data<Mutex<Statistics>>) -> impl Responder {
    // 1. We lock and only clone the specific field we need
    // 2. We use a block to ensure the lock is dropped as soon as possible
    let tls_versions = {
        let data = stats.lock(); // If using std::sync, add .expect("lock poisoned")
        data.tls_versions.clone()
    };

    // The lock is now released, and we only cloned one HashMap instead of the whole struct
    HttpResponse::Ok().json(tls_versions)
}
async fn get_possible_ciphers(stats: web::Data<Mutex<Statistics>>) -> impl Responder {
    // Lock, clone only what we need, and drop the lock immediately
    let client_ciphers = {
        let guard = stats.lock();
        guard.client_ciphers.clone()
    }; // guard dropped here

    HttpResponse::Ok().json(client_ciphers)
}
async fn get_signature_algorithms(stats: web::Data<Arc<Mutex<Statistics>>>) -> impl Responder {
    let signature_algorithms = {
        let stats_guard = stats.lock();
        stats_guard.signature_algorithms.clone()
    }; // Lock is released here

    HttpResponse::Ok().json(signature_algorithms)
}
async fn get_curves(stats: web::Data<Mutex<Statistics>>) -> impl Responder {
    // Lock, clone only what's needed, and drop the lock immediately
    let curves = {
        let stats_guard = stats.lock();
        stats_guard.curves.clone()
    };

    debug!("{:?}", &curves);
    HttpResponse::Ok().json(curves)
}

async fn get_stats(stats: web::Data<Arc<Mutex<Statistics>>>) -> impl Responder {
    let stats_data = stats.lock().clone();
    HttpResponse::Ok().json(stats_data)
}

async fn get_destinations(stats: web::Data<Mutex<Statistics>>) -> impl Responder {
    // 1. Lock only to extract the data we need
    let destinations = {
        let guard = stats.lock();
        // 2. Only clone the specific field, not the whole struct
        guard.destinations.clone()
    }; // Lock is dropped here immediately

    // 3. Serialize the cloned field into the response
    HttpResponse::Ok().json(destinations)
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
    let config_cloned = config.clone(); // Create a fully owned copy
    let stats_clone = Arc::clone(stats);

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(stats_clone.clone())) // Share statistics across handlers
            .app_data(web::Data::new(config_cloned.clone())) // Create new Data wrapper on each call
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
