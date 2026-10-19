//! Password changes and private, previously issued bearer metadata.
//! Vaultwarden 58a980f850464f7d9cdc99a765df36f0a3308b91:
//! accounts.rs:621-687; user.rs:190-250; auth.rs:664-715.
//! Bearer digests and stamps are private authority; none come from JSON/JWT input.

use crate::Failure;
use no_warden::{
    account_password::{PasswordChangeStampPolicy, PreviousStampAuthorization},
    identity::Secret,
    wire::{AccountKdfAuthentication, AccountKdfUnlock, AccountPasswordRequest, RegistrationKdf},
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;

// The account FK is intentional. Session/device FKs would destroy still-valid
// exception authority when a direct reset deletes devices and sessions.
pub const SCHEMA:&str="CREATE TABLE IF NOT EXISTS account_password_exceptions(owner TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,stamp TEXT NOT NULL,generation TEXT NOT NULL,expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS account_password_access(access TEXT PRIMARY KEY,owner TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,identifier TEXT NOT NULL,stamp TEXT NOT NULL,access_expires INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS account_password_access_owner ON account_password_access(owner);";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Input {
    master_password_hash: String,
    master_password_hint: Option<String>,
    authentication_data: Option<Authentication>,
    unlock_data: Option<Unlock>,
    new_master_password_hash: Option<String>,
    key: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Authentication {
    #[serde(alias = "Salt")]
    salt: String,
    #[serde(alias = "Kdf")]
    kdf: RegistrationKdf,
    #[serde(alias = "MasterPasswordAuthenticationHash")]
    master_password_authentication_hash: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Unlock {
    salt: String,
    kdf: RegistrationKdf,
    master_key_wrapped_user_key: String,
}
impl Input {
    pub fn request(&self) -> AccountPasswordRequest<'_> {
        AccountPasswordRequest {
            master_password_hash: Secret::new(&self.master_password_hash),
            master_password_hint: self.master_password_hint.as_deref(),
            authentication_data: self.authentication_data.as_ref().map(|data| {
                AccountKdfAuthentication {
                    salt: &data.salt,
                    kdf: data.kdf,
                    master_password_authentication_hash: Secret::new(
                        &data.master_password_authentication_hash,
                    ),
                }
            }),
            unlock_data: self.unlock_data.as_ref().map(|data| AccountKdfUnlock {
                salt: &data.salt,
                kdf: data.kdf,
                master_key_wrapped_user_key: Secret::new(&data.master_key_wrapped_user_key),
            }),
            new_master_password_hash: self.new_master_password_hash.as_deref().map(Secret::new),
            key: self.key.as_deref().map(Secret::new),
        }
    }
}
pub fn parse(body: &[u8]) -> Result<Input, Failure> {
    serde_json::from_slice(body).map_err(crate::json_guard_error)
}

// Called within bound issuance's transaction, with the host's verified stamp.
// Retain immutable metadata even after normal session/device deletion: stale
// but unexpired JWTs still encounter expiry cleanup before stamp mismatch.
pub fn remember_access(
    db: &Connection,
    owner: &str,
    identifier: &str,
    access: &str,
    stamp: &str,
    access_expires: i64,
) -> rusqlite::Result<()> {
    db.execute(
        "DELETE FROM account_password_access WHERE access_expires<=?1",
        [chrono::Utc::now().timestamp()],
    )?;
    db.execute("INSERT OR IGNORE INTO account_password_access(access,owner,identifier,stamp,access_expires) VALUES(?1,?2,?3,?4,?5)",params![crate::digest(access),owner,identifier,stamp,access_expires])?;
    Ok(())
}

// Backfill existing private sessions before changing credentials/stamp. Never
// relabel an already remembered bearer with the account's newer stamp.
pub fn remember_sessions(
    db: &Connection,
    owner: &str,
    stamp: &str,
    now: i64,
) -> rusqlite::Result<()> {
    db.execute("INSERT OR IGNORE INTO account_password_access(access,owner,identifier,stamp,access_expires) SELECT s.access,s.owner,d.identifier,?2,s.access_expires FROM sessions s JOIN session_devices d ON d.access=s.access AND d.owner=s.owner JOIN device_registry r ON r.owner=d.owner AND r.identifier=d.identifier WHERE s.owner=?1 AND s.access_expires>?3",params![owner,stamp,now])?;
    Ok(())
}

// Caller holds the password-change savepoint and has reverified the old proof.
// Only the owner's current exception is replaced; bearer metadata remains.
pub fn snapshot(
    db: &Connection,
    owner: &str,
    stamp: &str,
    policy: PasswordChangeStampPolicy,
    now: i64,
) -> rusqlite::Result<()> {
    let expires = policy
        .expires_at(now)
        .ok_or(rusqlite::Error::InvalidQuery)?;
    let generation = uuid::Uuid::new_v4().to_string();
    remember_sessions(db, owner, stamp, now)?;
    db.execute("INSERT INTO account_password_exceptions(owner,stamp,generation,expires) VALUES(?1,?2,?3,?4) ON CONFLICT(owner) DO UPDATE SET stamp=excluded.stamp,generation=excluded.generation,expires=excluded.expires",params![owner,stamp,generation,expires])?;
    Ok(())
}

fn clear_expired(
    db: &mut Connection,
    owner: &str,
    generation: &str,
    now: i64,
) -> rusqlite::Result<()> {
    let tx = db.savepoint()?;
    let removed = tx.execute(
        "DELETE FROM account_password_exceptions WHERE owner=?1 AND generation=?2 AND expires<?3",
        params![owner, generation, now],
    )?;
    if removed == 1 {
        let revision = crate::store::next_revision(&tx, owner)?;
        crate::store::bump(&tx, owner, &revision)?;
    }
    tx.commit()
}

// Normal sessions are checked first by dispatch. Remembered metadata preserves the
// original strict adapter access deadline; it never extends a bearer by120s.
// Device existence precedes exception expiry/route/stamp checks, matching Headers.
pub fn previous_owner(
    db: &mut Connection,
    access: &str,
    logical_route: &str,
    now: i64,
) -> rusqlite::Result<Option<String>> {
    type Row = (
        String,
        String,
        String,
        i64,
        Option<String>,
        Option<String>,
        Option<i64>,
    );
    let row:Option<Row>=db.query_row("SELECT a.owner,a.identifier,a.stamp,a.access_expires,e.stamp,e.generation,e.expires FROM account_password_access a LEFT JOIN account_password_exceptions e ON e.owner=a.owner WHERE a.access=?1",[access],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?))).optional()?;
    let Some((
        owner,
        identifier,
        stamp,
        access_expires,
        previous_stamp,
        previous_generation,
        expires,
    )) = row
    else {
        return Ok(None);
    };
    if access_expires <= now {
        return Ok(None);
    }
    let device: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM device_registry WHERE owner=?1 AND identifier=?2)",
        params![owner, identifier],
        |row| row.get(0),
    )?;
    if !device {
        return Ok(None);
    }
    let (Some(previous_stamp), Some(previous_generation), Some(expires)) =
        (previous_stamp, previous_generation, expires)
    else {
        return Ok(None);
    };
    match PasswordChangeStampPolicy.authorize_previous_stamp(
        now,
        expires,
        logical_route,
        stamp == previous_stamp,
    ) {
        PreviousStampAuthorization::Allowed => Ok(Some(owner)),
        PreviousStampAuthorization::Expired => {
            // Upstream best-effort user.save must not turn stale auth into500.
            let _ = clear_expired(db, &owner, &previous_generation, now);
            Ok(None)
        }
        PreviousStampAuthorization::RouteDenied | PreviousStampAuthorization::StampDenied => {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    #[test]
    fn account_password_owned_schema_preserves_optional_slots_aliases_opaque_values_and_redaction()
    {
        for body in [
            br#"{"masterPasswordHash":""}"#.as_slice(),
            br#"{"masterPasswordHash":"old-private","newMasterPasswordHash":"new-private\u0000\u96ea","key":"wrapped-private\u0000\u96ea","unknown":{"ignored":true}}"#,
            br#"{"masterPasswordHash":"old","masterPasswordHint":null,"authenticationData":{"Salt":"a","Kdf":{"kdfType":-7,"iterations":-8},"MasterPasswordAuthenticationHash":""},"unlockData":{"salt":"a","kdf":{"kdf":-7,"kdfIterations":-8},"masterKeyWrappedUserKey":""}}"#,
            br#"["old",null,null,null,"new","key"]"#,
            br#"["old",null,["a",[0,100000,null,null],"new"],["a",[0,100000,null,null],"key"],null,null]"#,
        ] {
            let input=parse(body).unwrap_or_else(|_|panic!("Valid password-change schema rejected."));
            let debug=format!("{:?}",input.request());
            for secret in ["old-private","new-private","wrapped-private"] {
                assert!(!debug.contains(secret),"Password-change request exposed a secret.");
            }
        }
        for body in [
            b"{}".as_slice(),b"[]",br#"["old"]"#,
            br#"{"MasterPasswordHash":"old","newMasterPasswordHash":"new","key":"key"}"#,
            br#"{"masterPasswordHash":null}"#,
            br#"{"masterPasswordHash":"old","key":3}"#,
            br#"{"masterPasswordHash":"old","masterPasswordHint":false}"#,
            br#"{"masterPasswordHash":"old","masterPasswordHash":"again"}"#,
            br#"{"masterPasswordHash":"old","authenticationData":{"salt":"a","Salt":"a","kdf":{"kdf":0,"kdfIterations":100000},"masterPasswordAuthenticationHash":"new"}}"#,
            br#"{"masterPasswordHash":"old","unlockData":{"Salt":"a","kdf":{"kdf":0,"kdfIterations":100000},"masterKeyWrappedUserKey":"key"},"newMasterPasswordHash":"new","key":"key"}"#,
            br#"{"masterPasswordHash":"old","authenticationData":{},"newMasterPasswordHash":"new","key":"key"}"#,
        ] {
            let Err(error)=parse(body) else {panic!("Invalid password-change schema accepted.")};
            assert_eq!(error.0,StatusCode::UNPROCESSABLE_ENTITY);
        }
        for body in [
            b"{".as_slice(),
            br#"["old",null,null,null,"new","key",null]"#,
        ] {
            let Err(error) = parse(body) else {
                panic!("Invalid password-change syntax accepted.")
            };
            assert_eq!(error.0, StatusCode::BAD_REQUEST);
        }
    }
}
