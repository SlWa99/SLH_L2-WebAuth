//! Module principal pour le backend de l'application.
//! Contient les gestionnaires pour les routes, les modèles de données, 
//! le routeur, et les middlewares.
pub mod handlers_auth;
mod models;
mod middlewares;
pub mod router;
pub mod handlers_unauth;
