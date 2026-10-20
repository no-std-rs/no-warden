//! Ordered member-removal adapter with request-local batch authority.
use crate::{Failure, Store, organization_member_removal};
use no_warden::organization_member_removal::{
    OrganizationBulkMemberRemovalData, OrganizationBulkMemberRemovalStorage,
    OrganizationMemberRemovalBatchAuthority, ValidatedOrganizationBulkMemberRemoval,
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
impl OrganizationBulkMemberRemovalData for Input {
    fn len(&self) -> usize {
        self.ids.len()
    }
    fn get(&self, index: usize) -> Option<&str> {
        self.ids.get(index).map(String::as_str)
    }
}

// This owned context is created only from a sealed initial core authority. It is
// held inside one service call, and never returned to the HTTP client or stored.
pub struct Batch {
    pub(super) owner: String,
    pub(super) organization: String,
    pub(super) membership: String,
    pub(super) role: i32,
    pub(super) removed: bool,
}
impl OrganizationBulkMemberRemovalStorage for Store {
    type Batch = Batch;
    fn begin_member_removal_batch(
        &mut self,
        authority: &OrganizationMemberRemovalBatchAuthority<'_>,
    ) -> rusqlite::Result<Batch> {
        let actor: Option<(String, i32, i32)> = self.db.query_row(
            "SELECT id,role,status FROM organization_memberships WHERE organization_id=?1 AND user_id=?2",
            params![authority.organization(), authority.owner()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).optional()?;
        let Some((membership, role @ (0 | 1), 2)) = actor else {
            return Err(rusqlite::Error::InvalidQuery);
        };
        if role != authority.actor_role() {
            return Err(rusqlite::Error::InvalidQuery);
        }
        Ok(Batch {
            owner: authority.owner().into(),
            organization: authority.organization().into(),
            membership,
            role,
            removed: false,
        })
    }
    fn remove_organization_member_in_batch(
        &mut self,
        batch: &mut Batch,
        plan: &ValidatedOrganizationBulkMemberRemoval<'_, String>,
    ) -> rusqlite::Result<()> {
        organization_member_removal::commit(
            self,
            organization_member_removal::RemovalCommit::Bulk(batch, plan),
        )
    }
}

#[cfg(test)]
mod tests;
