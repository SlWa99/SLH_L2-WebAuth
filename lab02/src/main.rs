//! Point d'entrée principal de l'application.
//! Initialise les bases de données, configure Handlebars pour le rendu des templates,
//! et démarre le serveur web avec Axum.

mod backend;
mod database;
mod utils;
mod email;
mod consts;

use std::{net::SocketAddr, sync::Arc};
use axum::Extension;
use dotenv::dotenv;
use handlebars::Handlebars;
use log::info;
use once_cell::sync::Lazy;
use crate::{
    consts::HTTP_PORT,
    backend::handlers_auth::{load_posts_from_file, save_posts_to_file},
};

// Initialisation de Handlebars pour le rendu des templates
static HBS: Lazy<Handlebars> = Lazy::new(|| {
    let mut hbs = Handlebars::new();
    hbs.register_templates_directory(".hbs", "templates/")
        .expect("Could not register template directory");
    hbs
});

#[tokio::main]
async fn main() {
    // Charger les variables d'environnement
    dotenv().ok();
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    // Charger les données des posts
    if let Err(e) = load_posts_from_file() {
        eprintln!("Erreur lors du chargement des posts: {}", e);
    }

    // Charger les autres bases de données
    database::user::load().ok();
    database::email::load().ok();

    // Configurer Handlebars comme extension pour le routeur
    let hbs = Arc::new(HBS.clone());
    let app = backend::router::get_router().layer(Extension(hbs));

    // Ajouter une gestion de fin pour sauvegarder les posts
    tokio::spawn(async {
        tokio::signal::ctrl_c().await.unwrap();
        if let Err(e) = save_posts_to_file() {
            eprintln!("Erreur lors de la sauvegarde des posts: {}", e);
        }
    });

    // Démarrer le serveur web
    let addr = SocketAddr::from(([0, 0, 0, 0], HTTP_PORT));
    info!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to open web server listener");

    axum::serve(listener, app)
        .await
        .expect("Failed to bind Axum to listener");
}
