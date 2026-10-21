//! Owned decoding and minimal scoped account-public-key joins.
use crate::{Failure, Store};
use axum::{
    Json,
    response::{IntoResponse, Response},
};
use no_warden::VaultService;
use no_warden::organization_member_public_keys::{
    OrganizationMemberPublicKeyRecord, OrganizationMemberPublicKeyStorage,
    OrganizationMemberPublicKeysData,
};
use rusqlite::{OptionalExtension, params};
use serde::{
    Deserialize, Deserializer,
    de::{self, IgnoredAny, SeqAccess, Visitor},
};

// Host work budget, independent of the allocation-free core's indexed input.
// Decode at most this many IDs before allocating result slots or taking lookups.
pub const MAX_PUBLIC_KEY_IDS: usize = 4096;
// Include repeated results in a byte budget before allocating their owned keys.
// The fixed row charge covers response names/framing; JSON escaping can expand
// string bytes, so this is an unescaped material budget, not encoded-byte parity.
pub const MAX_PUBLIC_KEY_RESULT_MATERIAL: usize = 8 * 1024 * 1024;
const PUBLIC_KEY_ROW_CHARGE: usize = 128;

fn deserialize_ids<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    struct Ids;
    impl<'de> Visitor<'de> for Ids {
        type Value = Vec<String>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a public-key ID list within the host item budget")
        }
        fn visit_seq<S: SeqAccess<'de>>(self, mut sequence: S) -> Result<Self::Value, S::Error> {
            // Never reserve an untrusted sequence size hint.
            let mut ids = Vec::new();
            loop {
                if ids.len() == MAX_PUBLIC_KEY_IDS {
                    return if sequence.next_element::<IgnoredAny>()?.is_some() {
                        Err(de::Error::custom(
                            "Public-key batch exceeds the host item budget",
                        ))
                    } else {
                        Ok(ids)
                    };
                }
                match sequence.next_element::<String>()? {
                    Some(id) => ids.push(id),
                    None => return Ok(ids),
                }
            }
        }
    }
    deserializer.deserialize_seq(Ids)
}

#[derive(Deserialize)]
pub struct Input {
    #[serde(deserialize_with = "deserialize_ids")]
    ids: Vec<String>,
}
impl Input {
    pub fn parse(body: &[u8]) -> Result<Self, Failure> {
        let body = std::str::from_utf8(body).map_err(|_| crate::invalid())?;
        serde_json::from_str(body).map_err(crate::json_guard_error)
    }
    pub fn validate_result_budget(&self, store: &Store, organization: &str) -> Result<(), Failure> {
        // SQLite returns only lengths here, rather than an owned key for each
        // duplicate. Account documents and joins remain scoped exactly as below.
        let mut statement = store.db.prepare(
            "SELECT length(CAST(m.id AS BLOB)),length(CAST(a.id AS BLOB)),
                    length(CAST(json_extract(a.document,'$.keys.publicKey') AS BLOB))
             FROM organization_memberships m JOIN accounts a ON a.id=m.user_id
             WHERE m.organization_id=?1 AND m.id=?2",
        )?;
        let mut remaining = MAX_PUBLIC_KEY_RESULT_MATERIAL;
        for id in &self.ids {
            let row: Option<(usize, usize, Option<usize>)> = statement
                .query_row(params![organization, id], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })
                .optional()?;
            if let Some((member_bytes, user_bytes, key_bytes)) = row {
                for charge in [
                    PUBLIC_KEY_ROW_CHARGE,
                    member_bytes,
                    user_bytes,
                    key_bytes.unwrap_or(0),
                ] {
                    remaining = remaining.checked_sub(charge).ok_or(Failure(
                        axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                        "Public-key result exceeds the host byte budget",
                    ))?;
                }
            }
        }
        Ok(())
    }
}
/// Complete host preflight before allocating owned record snapshots.
pub fn response(
    store: &mut Store,
    owner: &str,
    organization: &str,
    input: &Input,
) -> Result<Response, Failure> {
    input.validate_result_budget(store, organization)?;
    let mut scratch = Vec::with_capacity(input.len());
    scratch.resize_with(input.len(), || None);
    let response = VaultService::new(store).get_org_member_public_keys(
        owner,
        organization,
        input,
        &mut scratch,
    )?;
    Ok(Json(response).into_response())
}

impl OrganizationMemberPublicKeysData for Input {
    fn len(&self) -> usize {
        self.ids.len()
    }
    fn get(&self, index: usize) -> Option<&str> {
        self.ids.get(index).map(String::as_str)
    }
}
impl OrganizationMemberPublicKeyStorage for Store {
    type Id = String;
    type PublicKey = String;
    fn member_public_key(
        &mut self,
        organization: &str,
        membership: &str,
    ) -> rusqlite::Result<Option<OrganizationMemberPublicKeyRecord<String, String>>> {
        self.db
            .query_row(
                "SELECT m.id,m.organization_id,a.id,json_extract(a.document,'$.keys.publicKey')
             FROM organization_memberships m JOIN accounts a ON a.id=m.user_id
             WHERE m.organization_id=?1 AND m.id=?2",
                params![organization, membership],
                |row| {
                    Ok(OrganizationMemberPublicKeyRecord {
                        membership_id: row.get(0)?,
                        organization_id: row.get(1)?,
                        user_id: row.get(2)?,
                        public_key: row.get(3)?,
                    })
                },
            )
            .optional()
    }
}

#[cfg(test)]
mod tests;
