//! Owned prelogin decoding and installation-local unknown-account KDF selection.
//! Protocol behavior is independently implemented; storage and HMAC stay here.

use crate::{Failure, store::Store};
use hmac::{Hmac, Mac};
use no_warden::{
    prelogin::{PreloginLookup, PreloginStorage, UNKNOWN_KDF_CATALOG, UnknownKdfIndex},
    wire::{PreloginKdfSettings, PreloginRequest},
};
use rand::{RngCore, rngs::OsRng};
use rusqlite::{Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::Value;
use sha2::Sha256;

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS prelogin_key(singleton INTEGER PRIMARY KEY CHECK(singleton=1),secret BLOB NOT NULL CHECK(length(secret)=32));";

/// Initialize an independent installation secret before serving requests.
pub fn initialize(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch(SCHEMA)?;
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM prelogin_key WHERE singleton=1)",
        [],
        |row| row.get(0),
    )?;
    if !exists {
        let mut secret = [0_u8; 32];
        OsRng.fill_bytes(&mut secret);
        db.execute(
            "INSERT OR IGNORE INTO prelogin_key(singleton,secret) VALUES(1,?1)",
            [secret.as_slice()],
        )?;
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct Input {
    email: String,
}
impl Input {
    pub fn parse(body: &[u8]) -> Result<Self, Failure> {
        // Validate the complete body before Serde can skip unknown fields.
        let text = core::str::from_utf8(body).map_err(|_| crate::invalid())?;
        serde_json::from_str(text).map_err(crate::json_guard_error)
    }
    pub fn request(&self) -> PreloginRequest<'_> {
        PreloginRequest { email: &self.email }
    }
}

fn integer(value: &Value) -> rusqlite::Result<i32> {
    value
        .as_i64()
        .and_then(|number| i32::try_from(number).ok())
        .ok_or(rusqlite::Error::InvalidQuery)
}
fn optional_integer(account: &Value, field: &str) -> rusqlite::Result<Option<i32>> {
    account
        .get(field)
        .filter(|value| !value.is_null())
        .map(integer)
        .transpose()
}
fn settings(account: &Value) -> rusqlite::Result<PreloginKdfSettings> {
    Ok(PreloginKdfSettings {
        kdf_type: account.get("kdf").map(integer).transpose()?.unwrap_or(0),
        iterations: account
            .get("kdfIterations")
            .map(integer)
            .transpose()?
            .unwrap_or(600_000),
        memory: optional_integer(account, "kdfMemory")?,
        parallelism: optional_integer(account, "kdfParallelism")?,
    })
}

impl PreloginStorage for Store {
    fn prelogin(&mut self, raw_email: &str) -> rusqlite::Result<PreloginLookup> {
        let email = raw_email.trim().to_lowercase();
        if let Some(account) = self.account("email", &email)? {
            return settings(&account).map(PreloginLookup::Known);
        }
        let secret: Vec<u8> = self
            .db
            .query_row(
                "SELECT secret FROM prelogin_key WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .optional()?
            .filter(|key: &Vec<u8>| key.len() == 32)
            .ok_or(rusqlite::Error::InvalidQuery)?;
        let mut hash =
            Hmac::<Sha256>::new_from_slice(&secret).map_err(|_| rusqlite::Error::InvalidQuery)?;
        hash.update(email.as_bytes());
        let digest = hash.finalize().into_bytes();
        let choice =
            (usize::from(digest[0]) * 256 + usize::from(digest[1])) % UNKNOWN_KDF_CATALOG.len();
        let index = UnknownKdfIndex::new(choice).ok_or(rusqlite::Error::InvalidQuery)?;
        Ok(PreloginLookup::Unknown(index))
    }
}

#[cfg(test)]
mod tests;
