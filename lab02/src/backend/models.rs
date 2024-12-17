//! Définitions des structures pour les interactions avec l'API.
//! Contient les structures pour l'enregistrement, l'authentification et la récupération.

use serde::Serialize;

/// Structure pour représenter les réponses aux défis WebAuthn
#[derive(Serialize)]
pub struct WebAuthnChallenge {
    pub challenge: serde_json::Value, // Données du défi
    pub state_id: String,            // Identifiant d'état du défi
}