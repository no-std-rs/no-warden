//! Independently authored single-member access transitions.
//! Membership keys and grants survive revocation; clients enforce local caches.
use crate::Store;
use no_warden::organization_member_status::{
    OrganizationMemberRestorationPolicy, OrganizationMemberStatusRecord,
    OrganizationMemberStatusStorage, ValidatedOrganizationMemberStatus,
};
use rusqlite::{OptionalExtension, params};

pub fn is_status_error(message: &str) -> bool {
    matches!(
        message,
        "User not found in organization"
            | "User is already revoked"
            | "You cannot revoke yourself"
            | "Only owners can revoke other owners"
            | "Organization must have at least one confirmed owner"
            | "User is already active"
            | "You cannot restore yourself"
            | "Only owners can restore other owners"
    )
}

impl OrganizationMemberStatusStorage for Store {
    type Id = String;

    fn status_member(
        &mut self,
        organization: &str,
        member: &str,
    ) -> rusqlite::Result<Option<OrganizationMemberStatusRecord<String>>> {
        self.db
            .query_row(
                "SELECT id,organization_id,user_id,role,status FROM organization_memberships
                 WHERE organization_id=?1 AND id=?2",
                params![organization, member],
                |row| {
                    Ok(OrganizationMemberStatusRecord {
                        membership_id: row.get(0)?,
                        organization_id: row.get(1)?,
                        user_id: row.get(2)?,
                        role: row.get(3)?,
                        status: row.get(4)?,
                    })
                },
            )
            .optional()
    }

    fn status_confirmed_owner_count(&mut self, organization: &str) -> rusqlite::Result<u64> {
        self.db.query_row(
            "SELECT count(*) FROM organization_memberships
             WHERE organization_id=?1 AND role=0 AND status=2",
            [organization],
            |row| row.get(0),
        )
    }

    fn restoration_policy(
        &mut self,
        _plan: &ValidatedOrganizationMemberStatus<'_, String>,
    ) -> rusqlite::Result<OrganizationMemberRestorationPolicy> {
        // The adapter cannot configure organization policies. This represents
        // its default organizations, without promising configured-policy parity.
        Ok(OrganizationMemberRestorationPolicy::Allowed)
    }

    fn set_organization_member_status(
        &mut self,
        plan: &ValidatedOrganizationMemberStatus<'_, String>,
    ) -> rusqlite::Result<()> {
        let tx = self.db.savepoint()?;
        let actor: Option<(i32, i32)> = tx
            .query_row(
                "SELECT role,status FROM organization_memberships
                 WHERE organization_id=?1 AND user_id=?2",
                params![plan.organization(), plan.owner()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((actor_role @ (0 | 1), 2)) = actor else {
            return Err(rusqlite::Error::InvalidQuery);
        };
        if plan.user_id() == plan.owner() || (plan.role() == 0 && actor_role != 0) {
            return Err(rusqlite::Error::InvalidQuery);
        }
        if plan.requires_owner_count() {
            let count: u64 = tx.query_row(
                "SELECT count(*) FROM organization_memberships
                 WHERE organization_id=?1 AND role=0 AND status=2",
                [plan.organization()],
                |row| row.get(0),
            )?;
            if count <= 1 {
                return Err(rusqlite::Error::InvalidQuery);
            }
        }
        // Compare the exact scoped target read by the core. SQLite holds the
        // read/write boundary; any failed write or revision rolls back together.
        let changed = tx.execute(
            "UPDATE organization_memberships SET status=?1
             WHERE organization_id=?2 AND id=?3 AND user_id=?4 AND role=?5 AND status=?6",
            params![
                plan.status(),
                plan.organization(),
                plan.membership_id(),
                plan.user_id(),
                plan.role(),
                plan.previous_status()
            ],
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
