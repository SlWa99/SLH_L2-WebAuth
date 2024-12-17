//! Gestion des bases de données pour les utilisateurs, tokens, et emails.

use std::{
    collections::HashMap,
    fs::{create_dir_all, File},
    path::Path,
    sync::RwLock,
};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_yaml::{self, to_writer};
use crate::consts;

// Gestion des utilisateurs
pub mod user {
    use super::*;
    use once_cell::sync::Lazy;
    use webauthn_rs::prelude::Passkey;

    #[derive(Clone, Serialize, Deserialize, Debug)]
    pub struct User {
        pub first_name: String,
        pub last_name: String,
        pub email: String,
        pub passkey: Option<Passkey>,
        pub verified: bool,
        pub stash: Vec<String>,
        pub liked_posts: Vec<u64>,
    }

    type Db = HashMap<String, User>;
    static DB: Lazy<RwLock<Db>> = Lazy::new(Default::default);

    pub fn create(email: &str, first_name: &str, last_name: &str) -> Result<bool> {
        let user = User {
            first_name: first_name.to_string(),
            last_name: last_name.to_string(),
            email: email.to_string(),
            passkey: None,
            verified: false,
            stash: Vec::new(),
            liked_posts: Vec::new(),
        };

        let mut db = DB.write().or(Err(anyhow!("DB poisoned")))?;

        if db.contains_key(email) {
            return Ok(false);
        }

        db.insert(email.to_string(), user);
        save(&db)?;
        Ok(true)
    }

    pub fn set_passkey(email: &str, passkey: Passkey) -> Result<()> {
        let mut db = DB.write().or(Err(anyhow!("DB poisoned")))?;
        let user = db.get_mut(email).ok_or_else(|| anyhow!("User not found"))?;
        user.passkey = Some(passkey);
        save(&db)?;
        Ok(())
    }

    pub fn get_passkey(email: &str) -> Result<Option<Passkey>> {
        let db = DB.read().or(Err(anyhow!("DB poisoned")))?;
        let user = db.get(email).ok_or_else(|| anyhow!("User not found"))?;
        Ok(user.passkey.clone())
    }

    pub fn get(email: &str) -> Option<User> {
        DB.read().ok()?.get(email).cloned()
    }

    pub fn exists(email: &str) -> Result<bool> {
        Ok(DB.read().or(Err(anyhow!("DB poisoned")))?.contains_key(email))
    }

    pub fn verify(email: &str) -> Result<()> {
        let mut db = DB.write().or(Err(anyhow!("DB poisoned")))?;

        let user = db.get_mut(email).ok_or(anyhow!("User not found"))?;
        if user.verified {
            return Ok(());
        }

        user.verified = true;
        save(&db)?;
        Ok(())
    }

    pub fn load() -> Result<()> {
        super::load(&DB, consts::USERS_DB_PATH)
    }

    fn save(db: &Db) -> Result<()> {
        super::save(db, consts::USERS_DB_PATH)
    }
}

/// Gestion des tokens
pub mod token {
    use super::*;
    use once_cell::sync::Lazy;

    type Db = HashMap<String, String>;
    static DB: Lazy<RwLock<Db>> = Lazy::new(Default::default);

    pub fn generate(email: &str) -> Result<String> {
        let token = uuid::Uuid::new_v4().to_string();
        let mut db = DB.write().or(Err(anyhow!("DB poisoned")))?;
        db.insert(token.clone(), email.to_string());
        Ok(token)
    }

    pub fn consume(token: &str) -> Result<String> {
        let mut db = DB.write().or(Err(anyhow!("DB poisoned")))?;
        db.remove(token).ok_or_else(|| anyhow!("Token not found"))
    }
}

// Gestion des emails
pub mod email {
    use super::*;
    use once_cell::sync::Lazy;

    #[derive(Clone, Serialize, Deserialize, Debug)]
    pub struct Email {
        pub pk: u64,
        pub to: String,
        pub subject: String,
        pub body: String,
    }

    #[derive(Default, Serialize, Deserialize)]
    struct Db {
        pub next_pk: u64,
        pub emails: HashMap<u64, Email>,
    }

    static DB: Lazy<RwLock<Db>> = Lazy::new(Default::default);

    pub fn add(to: &str, subject: &str, body: &str) -> Result<()> {
        let mut db = DB.write().or(Err(anyhow!("DB poisoned")))?;

        let pk = db.next_pk;
        db.next_pk += 1;
        let email = Email {
            pk,
            to: to.to_string(),
            subject: subject.to_string(),
            body: body.to_string(),
        };

        db.emails.insert(pk, email);
        save(&db)?;
        Ok(())
    }

    pub fn load() -> Result<()> {
        super::load(&DB, consts::EMAILS_DB_PATH)
    }

    fn save(db: &Db) -> Result<()> {
        super::save(db, consts::EMAILS_DB_PATH)
    }
}

pub mod post {
    use super::*;

    #[derive(Clone, Serialize, Deserialize, Debug)]
    pub struct Post {
        pub id: String,
        pub text: String,
        pub image_path: String,
        pub likes: i32,
    }
}

/// Fonctions de sauvegarde et chargement YAML
fn save<T: Serialize>(db: &T, path: &str) -> Result<()> {
    let path_obj = Path::new(path);

    // Crée le dossier parent s'il n'existe pas
    if let Some(parent_dir) = path_obj.parent() {
        if !parent_dir.exists() {
            create_dir_all(parent_dir).or(Err(anyhow!("Failed to create directory")))?;
        }
    }

    let file = File::create(path_obj)?;
    to_writer(file, db).or(Err(anyhow!("Failed to serialize DB")))?;
    Ok(())
}

fn load<T: for<'de> Deserialize<'de> + Default>(db: &RwLock<T>, path: &str) -> Result<()> {
    // Chargement de la base de données depuis le fichier YAML
    if let Ok(file) = File::open(path) {
        let db_content: T = serde_yaml::from_reader(file).unwrap_or_default();
        let mut db = db.write().or(Err(anyhow!("DB poisoned")))?;
        *db = db_content;
    } else {
        let mut db = db.write().or(Err(anyhow!("DB poisoned")))?;
        *db = T::default();
    }
    Ok(())
}
