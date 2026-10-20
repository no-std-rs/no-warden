//! Independently authored single-member confirmation adapter.
//! Keys remain opaque; only clients perform organization-key encryption.
use crate::{Failure, Store};
use no_warden::{
    identity::Secret,
    organization_confirmations::{
        OrganizationConfirmationPolicy, OrganizationConfirmationRecord,
        OrganizationConfirmationStorage, ValidatedOrganizationConfirmation,
    },
    wire::OrganizationConfirmRequest,
};
use rusqlite::{OptionalExtension, params};
use serde::Deserialize;

// Declaration order is the positional JSON contract. The optional body ID is
// decoded for schema compatibility; the scoped path ID selects the member.
#[derive(Deserialize)]
pub struct Input {
    id: Option<String>,
    key: Option<String>,
}
impl Input {
    pub fn parse(body: &[u8]) -> Result<Self, Failure> {
        let body = std::str::from_utf8(body).map_err(|_| crate::invalid())?;
        serde_json::from_str(body).map_err(crate::json_guard_error)
    }
    pub fn request(&self) -> OrganizationConfirmRequest<'_> {
        OrganizationConfirmRequest {
            id: self.id.as_deref(),
            key: self.key.as_deref().map(Secret::new),
        }
    }
}

pub fn is_confirmation_error(message: &str) -> bool {
    matches!(
        message,
        "Key or UserId is not set, unable to process request"
            | "Only Owners can confirm Managers, Admins or Owners"
            | "User in invalid state"
    )
}

impl OrganizationConfirmationStorage for Store {
    type Id = String;
    fn confirmation_member(
        &mut self,
        organization: &str,
        member: &str,
    ) -> rusqlite::Result<Option<OrganizationConfirmationRecord<String>>> {
        self.db.query_row(
            "SELECT id,organization_id,user_id,role,status FROM organization_memberships WHERE organization_id=?1 AND id=?2",
            params![organization,member],
            |r| Ok(OrganizationConfirmationRecord { membership_id:r.get(0)?,organization_id:r.get(1)?,user_id:r.get(2)?,role:r.get(3)?,status:r.get(4)? }),
        ).optional()
    }
    fn confirmation_policy(
        &mut self,
        _plan: &ValidatedOrganizationConfirmation<'_, String>,
    ) -> rusqlite::Result<OrganizationConfirmationPolicy> {
        // The local adapter has no organization-policy administration. This is
        // the default policy for its own organizations, not a fictional policy.
        Ok(OrganizationConfirmationPolicy::Allowed)
    }
    fn confirm_organization_member(
        &mut self,
        plan: &ValidatedOrganizationConfirmation<'_, String>,
    ) -> rusqlite::Result<()> {
        let tx = self.db.savepoint()?;
        let actor: Option<(i32,i32)> = tx.query_row(
            "SELECT role,status FROM organization_memberships WHERE organization_id=?1 AND user_id=?2",
            params![plan.organization(),plan.owner()], |r| Ok((r.get(0)?,r.get(1)?)),
        ).optional()?;
        let Some((actor_role, 2)) = actor else {
            return Err(rusqlite::Error::InvalidQuery);
        };
        if !matches!(actor_role, 0 | 1) || (plan.role() != 2 && actor_role != 0) {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let changed = tx.execute(
            "UPDATE organization_memberships SET status=?1,key=?2 WHERE organization_id=?3 AND id=?4 AND user_id=?5 AND role=?6 AND status=?7",
            params![plan.status(),plan.key().expose_secret(),plan.organization(),plan.membership_id(),plan.user_id(),plan.role(),plan.previous_status()],
        )?;
        if changed != 1 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let revision = crate::store::next_revision(&tx, plan.user_id())?;
        crate::store::bump(&tx, plan.user_id(), &revision)?;
        tx.commit()
    }
}

#[cfg(test)]
mod tests;
