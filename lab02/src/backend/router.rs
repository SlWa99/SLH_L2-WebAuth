//! Configuration des routes pour l'application.
//! Définit les routes accessibles avec ou sans authentification et configure les middlewares.

use axum::{Router, routing::{get, post}, BoxError};
use axum::error_handling::HandleErrorLayer;
use http::StatusCode;
use tower_sessions::{SessionManagerLayer, MemoryStore};
use tower_http::cors::{Any, CorsLayer};
use tower::{ServiceBuilder};
use crate::backend::handlers_unauth::{
    register_begin, register_complete, login_begin, login_complete,
    index, login_page, register_page, validate_account, logout,
    recover_page, recover_account, reset_account,
};
use crate::backend::handlers_auth::{create_post, home, like_post};

/// Initialisation du routeur principal et des middlewares
pub fn get_router() -> Router {
    // Configuration CORS pour permettre les requêtes de n'importe quelle origine (en mode debug uniquement)
    let router = if cfg!(debug_assertions) {
        let cors = CorsLayer::new()
            .allow_methods(tower_http::cors::AllowMethods::any())
            .allow_origin(Any);
        Router::new().layer(cors)
    } else {
        Router::new()
    };

    // Configuration des sessions en mémoire
    let store = MemoryStore::default(); // Initialisation du MemoryStore
    let session_manager = SessionManagerLayer::new(store).with_http_only(true);

    let service = ServiceBuilder::new()
        .layer(HandleErrorLayer::new(|_e: BoxError| async move {
            StatusCode::BAD_REQUEST
        }))
        .layer(session_manager);

    router
        .merge(unauth_routes())
        .merge(auth_routes())
        .layer(service)
}

/// Routes accessibles sans authentification
fn unauth_routes() -> Router {
    Router::new()
        .route("/", get(index)) // Page d'accueil
        .route("/validate/:token", get(validate_account)) // Validation d'un compte
        .route("/register", get(register_page).post(register_begin)) // Début de l'enregistrement WebAuthn
        .route("/register/complete", post(register_complete)) // Fin de l'enregistrement WebAuthn
        .route("/login", get(login_page).post(login_begin)) // Page de connexion
        .route("/login/complete", post(login_complete)) // Fin de l'authentification WebAuthn
        .route("/logout", get(logout)) // Déconnexion
        .route("/recover", get(recover_page).post(recover_account)) // Page et handler de récupération
        .route("/recover/:token", get(reset_account)) // Lien pour la récupération de compte
}

/// Routes nécessitant une authentification
fn auth_routes() -> Router {
    Router::new()
        .route("/home", get(home)) // Page principale
        .route("/post/like", post(like_post)) // Ajout d'un like à un post
        .route("/post/create", post(create_post)) // Ajout d'un post
        .layer(axum::middleware::from_extractor::<crate::backend::middlewares::SessionUser>()) // Middleware pour vérifier l'utilisateur connecté
}
