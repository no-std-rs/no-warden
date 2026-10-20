//! Owned decoding and minimal scoped account-public-key joins.
use crate::{Failure, Store};
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
