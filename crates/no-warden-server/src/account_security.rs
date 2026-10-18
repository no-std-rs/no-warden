//! Account proof parsing and private security-stamp persistence.
//! Pinned Vaultwarden 58a980f850464f7d9cdc99a765df36f0a3308b91:
//! accounts.rs:1084-1098,1441-1476; user.rs:226-230; device.rs:174-181.

use crate::Failure;
use no_warden::{
    identity::Secret,
    wire::{PasswordOrOtpRequest, SecretVerificationRequest},
};
use rusqlite::{Connection, params};
use serde::Deserialize;

pub const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS account_security(owner TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,stamp TEXT NOT NULL);";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationInput {
    master_password_hash: String,
}
impl VerificationInput {
    pub fn request(&self) -> SecretVerificationRequest<'_> {
        SecretVerificationRequest {
            master_password_hash: Secret::new(&self.master_password_hash),
        }
    }
}
pub fn parse_verification(body: &[u8]) -> Result<VerificationInput, Failure> {
    serde_json::from_slice(body).map_err(crate::json_guard_error)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StampInput {
    #[serde(alias = "MasterPasswordHash")]
    master_password_hash: Option<String>,
    otp: Option<String>,
}
impl StampInput {
    pub fn request(&self) -> PasswordOrOtpRequest<'_> {
        PasswordOrOtpRequest {
            master_password_hash: self.master_password_hash.as_deref().map(Secret::new),
            otp: self.otp.as_deref().map(Secret::new),
        }
    }
}
pub fn parse_stamp(body: &[u8]) -> Result<StampInput, Failure> {
    serde_json::from_slice(body).map_err(crate::json_guard_error)
}

// Missing private state uses the existing account ID. Never read a stamp from
// document extensions, even before the first explicit renewal.
pub fn stamp(db: &Connection, owner: &str) -> rusqlite::Result<String> {
    db.query_row("SELECT COALESCE(s.stamp,a.id) FROM accounts a LEFT JOIN account_security s ON s.owner=a.id WHERE a.id=?1",[owner],|row|row.get(0))
}

pub fn reset(db: &mut Connection, owner: &str) -> rusqlite::Result<()> {
    let tx = db.savepoint()?;
    let revision = crate::store::next_revision(&tx, owner)?;
    let stamp = uuid::Uuid::new_v4().to_string();
    tx.execute("INSERT INTO account_security(owner,stamp) VALUES(?1,?2) ON CONFLICT(owner) DO UPDATE SET stamp=excluded.stamp",params![owner,stamp])?;
    crate::store::bump(&tx, owner, &revision)?;
    tx.execute("DELETE FROM sessions WHERE owner=?1", [owner])?;
    // Composite foreign keys remove only this owner's bindings/push tokens.
    // Upstream's direct device deletion leaves auth requests intact.
    tx.execute("DELETE FROM device_registry WHERE owner=?1", [owner])?;
    tx.commit()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    #[test]
    fn account_security_owned_guards_preserve_schema_aliases_sequences_and_secrets() {
        for body in [
            br#"{"masterPasswordHash":""}"#.as_slice(),
            br#"["NUL\u0000\u96ea"]"#,
            br#"{"masterPasswordHash":"opaque","owner":"forged","securityStamp":"forged"}"#,
        ] {
            assert!(parse_verification(body).is_ok());
        }
        for body in [
            b"{}".as_slice(),
            b"[]",
            br#"{"MasterPasswordHash":"wrong-alias"}"#,
            br#"{"masterPasswordHash":null}"#,
            br#"{"masterPasswordHash":1}"#,
            br#"{"masterPasswordHash":"a","masterPasswordHash":"b"}"#,
        ] {
            let Err(error) = parse_verification(body) else {
                panic!("Invalid password verification schema accepted.")
            };
            assert_eq!(error.0, StatusCode::UNPROCESSABLE_ENTITY);
        }
        for body in [
            br#"{}"#.as_slice(),
            br#"{"MasterPasswordHash":""}"#,
            br#"["NUL\u0000\u96ea",null]"#,
            br#"[null,"opaque"]"#,
            br#"{"masterPasswordHash":null,"otp":null}"#,
        ] {
            assert!(parse_stamp(body).is_ok());
        }
        for body in [
            b"[]".as_slice(),
            br#"["short"]"#,
            br#"{"masterPasswordHash":true}"#,
            br#"{"masterPasswordHash":"a","MasterPasswordHash":"b"}"#,
            br#"{"otp":1}"#,
            br#"{"otp":"a","otp":"b"}"#,
        ] {
            let Err(error) = parse_stamp(body) else {
                panic!("Invalid stamp schema accepted.")
            };
            assert_eq!(error.0, StatusCode::UNPROCESSABLE_ENTITY);
        }
        for body in [b"{".as_slice(), br#"["proof",null,null]"#] {
            let Err(error) = parse_stamp(body) else {
                panic!("Invalid stamp syntax accepted.")
            };
            assert_eq!(error.0, StatusCode::BAD_REQUEST);
        }
        let input = parse_verification(br#"{"masterPasswordHash":"private-proof"}"#)
            .unwrap_or_else(|_| panic!("Fixture parse failed."));
        assert!(!format!("{:?}", input.request()).contains("private-proof"));
    }
}
