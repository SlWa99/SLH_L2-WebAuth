//! Gestion des fonctionnalités liées aux emails, telles que l'envoi et la création de liens de vérification.

use anyhow::Result;
use log::info;
use crate::database;

/// Envoie un email simulé en ajoutant ses détails à la base de données.
pub fn send_mail(to: &str, subject: &str, body: &str) -> Result<()> {
    info!("Sending an email");
    database::email::add(to, subject, body)?;
    Ok(())
}