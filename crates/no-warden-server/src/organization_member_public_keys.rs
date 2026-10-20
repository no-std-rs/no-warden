//! Owned decoding and minimal scoped account-public-key joins.
use crate::{Failure, Store};
use no_warden::organization_member_public_keys::{
    OrganizationMemberPublicKeyRecord, OrganizationMemberPublicKeyStorage,
    OrganizationMemberPublicKeysData,
};
use rusqlite::{OptionalExtension, params};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input {
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
