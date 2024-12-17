//! Gestion des routes accessibles sans authentification.
//! Contient les handlers pour les pages publiques, l'inscription, la connexion,
//! la récupération de compte et la validation d'utilisateur.

use axum::{
    extract::{Json, Path, Query},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
};

use crate::database::token::generate;
use crate::database::user::{create, exists, set_passkey};
use crate::database::{token, user};
use crate::email::send_mail;
use crate::utils::webauthn::{begin_authentication, begin_registration, complete_authentication, complete_registration, StoredRegistrationState, CREDENTIAL_STORE};
use crate::HBS;
use log::debug;
use once_cell::sync::Lazy;
use serde_json::json;
use std::collections::HashMap;
use tokio::sync::RwLock;
use validator::{ValidateEmail};
use webauthn_rs::prelude::{
    PasskeyAuthentication, PublicKeyCredential, RegisterPublicKeyCredential,
};
use crate::utils::input::is_valid_display_name;

/// Structure pour gérer un état temporaire avec un challenge
struct TimedStoredState<T> {
    state: T,
    server_challenge: String,
}

/// Stockage des états d'enregistrement et d'authentification
pub(crate) static REGISTRATION_STATES: Lazy<RwLock<HashMap<String, StoredRegistrationState>>> =
    Lazy::new(Default::default);
static AUTHENTICATION_STATES: Lazy<
    RwLock<HashMap<String, TimedStoredState<PasskeyAuthentication>>>,
> = Lazy::new(Default::default);

/// Début du processus d'enregistrement WebAuthn
pub async fn register_begin(
    Json(payload): Json<serde_json::Value>,
) -> axum::response::Result<Json<serde_json::Value>> {
    let email = payload
        .get("email")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::BAD_REQUEST, "Email is required"))?;

    if !email.validate_email() {
        return Err((StatusCode::BAD_REQUEST, "Invalid email format").into());
    }

    let reset_mode = payload
        .get("reset_mode")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    match (reset_mode, exists(email)) {
        (false, Ok(false)) => (),
        (true, Ok(true)) => (),
        (true, Ok(false)) => (),
        (_, _) => return Err((StatusCode::BAD_REQUEST, "Invalid registration request").into()),
    }

    let (public_key, pskr) = begin_registration(email, email)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let stored_registration_state = StoredRegistrationState {
        challenge: public_key["challenge"].as_str().unwrap().to_string(),
        registration_state: pskr,
    };

    let state_id = uuid::Uuid::new_v4().to_string();
    REGISTRATION_STATES
        .write()
        .await
        .insert(state_id.clone(), stored_registration_state);

    CREDENTIAL_STORE.write().await.remove(email);

    Ok(Json(json!({
        "publicKey": public_key,
        "state_id": state_id,
    })))
}

/// Fin du processus d'enregistrement WebAuthn
pub async fn register_complete(
    Json(payload): Json<serde_json::Value>,
) -> axum::response::Result<StatusCode> {
    let email = payload
        .get("email")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::BAD_REQUEST, "Email is required"))?;

    if !email.validate_email() {
        return Err((StatusCode::BAD_REQUEST, "Invalid email format").into());
    }

    let reset_mode = payload
        .get("reset_mode")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let first_name = payload
        .get("first_name")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::BAD_REQUEST, "First name is required"))?;
    let last_name = payload
        .get("last_name")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::BAD_REQUEST, "Last name is required"))?;

    if !is_valid_display_name(first_name) {
        return Err((StatusCode::BAD_REQUEST, "Invalid first name").into());
    }

    if !is_valid_display_name(last_name) {
        return Err((StatusCode::BAD_REQUEST, "Invalid last name").into());
    }

    let state_id = payload
        .get("state_id")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::BAD_REQUEST, "State ID is required"))?;

    let response: RegisterPublicKeyCredential = serde_json::from_value(
        payload
            .get("response")
            .cloned()
            .ok_or((StatusCode::BAD_REQUEST, "Response is required"))?,
    )
    .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid response format"))?;

    match (reset_mode, exists(email)) {
        (false, Ok(false)) => {
            create(email, first_name, last_name)
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create user"))?;
        }
        (true, Ok(true)) => { // TODO WSI : Régler pb et test images
            let passkey = CREDENTIAL_STORE.read().await.get(email).unwrap().clone();
            set_passkey(email, passkey)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        },

        (_, _) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to check user existence",
            ).into());
        }
    }

    let stored_state = {
        let mut states = REGISTRATION_STATES.write().await;
        states
            .remove(state_id)
            .ok_or((StatusCode::BAD_REQUEST, "Invalid registration session"))?
    };

    complete_registration(email, &response, &stored_state)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    if let Ok(verification_token) = generate(email) {
        let verification_link = format!("http://localhost:8080/validate/{}", verification_token);

        if let Err(err) = send_mail(
            email,
            "Verifier votre compte",
            &format!(
                "Bienvenu! Veuillez verifier votre compte en clickant sur le lien: {}\n\n\
             Si vous n'etes pas à l'origine de l'action, ignorez cette email.",
                verification_link
            ),
        ) {
            eprintln!("Failed to send verification email to {}: {:?}", email, err);
        }
    }

    Ok(StatusCode::CREATED)
}

/// Début du processus d'authentification WebAuthn
pub async fn login_begin(
    Json(payload): Json<serde_json::Value>,
) -> axum::response::Result<Json<serde_json::Value>> {
    let email = payload
        .get("email")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::BAD_REQUEST, "Email is required"))?;

    if !email.validate_email() {
        return Err((StatusCode::BAD_REQUEST, "Invalid email format").into());
    }

    let (public_key, pska) = begin_authentication(email)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let state_id = uuid::Uuid::new_v4().to_string();
    let mut authentication_states = AUTHENTICATION_STATES.write().await;

    authentication_states.insert(
        state_id.clone(),
        TimedStoredState {
            state: pska,
            server_challenge: public_key["challenge"].as_str().unwrap_or("").to_string(),
        },
    );

    Ok(Json(json!({
        "publicKey": public_key,
        "state_id": state_id,
    })))
}

/// Fin du processus d'authentification WebAuthn
pub async fn login_complete(
    Json(payload): Json<serde_json::Value>,
) -> axum::response::Result<Redirect> {
    let response = payload
        .get("response")
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Response is required"))?;
    let state_id = payload
        .get("state_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "State ID is required"))?;

    let credential: PublicKeyCredential = serde_json::from_value(response.clone())
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid response format"))?;

    let mut authentication_states = AUTHENTICATION_STATES.write().await;

    let stored_state = authentication_states.remove(state_id).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "Invalid or expired authentication state",
        )
    })?;

    complete_authentication(
        &credential,
        &stored_state.state,
        &stored_state.server_challenge,
    )
    .await
    .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;

    Ok(Redirect::to("/home"))
}

/// Gère la déconnexion de l'utilisateur
pub async fn logout() -> impl IntoResponse {
    Redirect::to("/")
}

/// Valide un compte utilisateur via un token
pub async fn validate_account(Path(token): Path<String>) -> impl IntoResponse {
    match token::consume(&token) {
        Ok(email) => match user::verify(&email) {
            Ok(_) => Redirect::to("/login?validated=true"),
            Err(_) => Redirect::to("/register?error=validation_failed"),
        },
        Err(_) => Redirect::to("/register?error=invalid_token"),
    }
}

/// Envoie un email de récupération de compte à l'utilisateur
pub async fn recover_account(
    Json(payload): Json<serde_json::Value>,
) -> axum::response::Result<Html<String>> {
    let mut data = HashMap::new();

    let email = payload
        .get("email")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::BAD_REQUEST, "Email is required"))?;

    let user_exists = match exists(email) {
        Ok(true) => true,
        Ok(false) => false,
        Err(..) => {
            debug!(
                "Database error while checking user existence for email: {}",
                email
            );
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong").into());
        }
    };

    if user_exists {
        let token = generate(email).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to generate token",
            )
        })?;

        let recovery_link = format!("http://localhost:8080/recover/{}", token);
        let subject = "Récupération de compte";
        let body = format!(
            "Cliquez sur ce lien pour récupérer votre compte : {}",
            recovery_link
        );

        send_mail(email, subject, &body)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to send email"))?;

        data.insert(
            "message",
            "Si ce mail exist, un message de récupération a été envoyé à cette adresse.",
        );
    }

    HBS.render("recover", &data)
        .map(Html)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error.").into())
}

/// Gère la réinitialisation du compte utilisateur via un token de récupération
pub async fn reset_account(Path(token): Path<String>) -> Html<String> {
    match token::consume(&token) {
        Ok(email) => {
            let redirect_url = format!("/register?reset_mode=true&email={}&success=true", email);
            Html(format!(
                "<meta http-equiv='refresh' content='0;url={}'/>",
                redirect_url
            ))
        }
        Err(_) => {
            let redirect_url = "/register?error=recovery_failed";
            Html(format!(
                "<meta http-equiv='refresh' content='0;url={}'/>",
                redirect_url
            ))
        }
    }
}

/// --- Affichage des pages ---
///
/// Affiche la page d'accueil
pub async fn index(session: tower_sessions::Session) -> impl IntoResponse {
    let is_logged_in = session.get::<String>("email").is_ok();
    let mut data = HashMap::new();
    data.insert("logged_in", is_logged_in);

    HBS.render("index", &data)
        .map(Html)
        .unwrap_or_else(|_| Html("Internal Server Error".to_string()))
}

/// Affiche la page de connexion
pub async fn login_page() -> impl IntoResponse {
    Html(include_str!("../../templates/login.hbs"))
}

/// Affiche la page d'inscription avec des messages contextuels si présents
pub async fn register_page(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    let mut context = HashMap::new();
    if let Some(success) = params.get("success") {
        if success == "true" {
            context.insert(
                "success_message",
                "Account recovery successful. Please reset your passkey.",
            );
        }
    }
    if let Some(error) = params.get("error") {
        if error == "recovery_failed" {
            context.insert(
                "error_message",
                "Invalid or expired recovery link. Please try again.",
            );
        }
    }

    HBS.render("register", &context)
        .map(Html)
        .unwrap_or_else(|_| Html("<h1>Internal Server Error</h1>".to_string()))
}

/// Affiche la page de récupération de compte
pub async fn recover_page() -> impl IntoResponse {
    Html(include_str!("../../templates/recover.hbs"))
}
