//! Independently authored adapter for the one-time opaque user-key-ID backfill.
use crate::{Failure, store};
use axum::http::StatusCode;
use no_warden::{
    account_key_id::{AccountKeyIdStorage, ValidatedUserKeyId},
    wire::UserKeyIdRequest,
};
use rusqlite::{TransactionBehavior, params};
use serde::Deserialize;

// Owned decoding accepts JSON escapes before borrowing the no-allocation DTO.
// The identifier is protocol metadata, not key material or a UUID-only field.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Input {
    user_key_id: String,
}
impl Input {
    pub fn parse(body: &[u8]) -> Result<Self, Failure> {
        let text = core::str::from_utf8(body)
            .map_err(|_| Failure(StatusCode::BAD_REQUEST, "Invalid key identifier"))?;
        serde_json::from_str(text).map_err(|error| {
            Failure(
                if error.is_data() {
                    StatusCode::UNPROCESSABLE_ENTITY
                } else {
                    StatusCode::BAD_REQUEST
                },
                "Invalid key identifier",
            )
        })
    }
    pub fn request(&self) -> UserKeyIdRequest<'_> {
        UserKeyIdRequest {
            user_key_id: &self.user_key_id,
        }
    }
}

impl AccountKeyIdStorage for store::Store {
    fn set_user_key_id_if_absent(
        &mut self,
        owner: &str,
        update: &ValidatedUserKeyId<'_>,
    ) -> rusqlite::Result<bool> {
        // Serialize the check and revision with every writer, including another
        // connection. A rejected repeat must leave the revision unchanged.
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE accounts SET document=json_set(document,'$.userKeyId',?1) WHERE id=?2 AND (json_type(document,'$.userKeyId') IS NULL OR json_type(document,'$.userKeyId')='null')",
            params![update.user_key_id(), owner],
        )?;
        if changed == 0 {
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM accounts WHERE id=?1)",
                [owner],
                |row| row.get(0),
            )?;
            return if exists {
                Ok(false)
            } else {
                Err(rusqlite::Error::QueryReturnedNoRows)
            };
        }
        let revision = store::next_revision(&tx, owner)?;
        store::bump(&tx, owner, &revision)?;
        tx.commit()?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests;
