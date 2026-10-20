//! Scoped membership removal; account credentials and personal vault data survive.
//! Independently authored against pinned protocol observations.
use crate::Store;
use no_warden::organization_member_removal::{
    OrganizationMemberRemovalRecord, OrganizationMemberRemovalStorage,
    ValidatedOrganizationMemberRemoval,
};
use rusqlite::{OptionalExtension, params};

pub fn is_removal_error(message: &str) -> bool {
    matches!(
        message,
        "User to delete isn't member of the organization"
            | "Only Owners can delete Admins or Owners"
            | "Can't delete the last owner"
    )
}

impl OrganizationMemberRemovalStorage for Store {
    type Id = String;

    fn removal_member(
        &mut self,
        organization: &str,
        member: &str,
    ) -> rusqlite::Result<Option<OrganizationMemberRemovalRecord<String>>> {
        self.db.query_row(
            "SELECT m.id,m.organization_id,m.user_id,m.role,m.status,
             EXISTS(SELECT 1 FROM accounts a WHERE a.id=m.user_id),
             EXISTS(SELECT 1 FROM organization_memberships other WHERE other.user_id=m.user_id AND other.status=0 AND other.id<>m.id)
             FROM organization_memberships m WHERE m.organization_id=?1 AND m.id=?2",
            params![organization, member],
            |row| Ok(OrganizationMemberRemovalRecord {
                membership_id: row.get(0)?, organization_id: row.get(1)?, user_id: row.get(2)?,
                role: row.get(3)?, status: row.get(4)?, mail_enabled: false,
                user_exists: row.get(5)?, other_invited_memberships: row.get(6)?,
            }),
        ).optional()
    }

    fn confirmed_owner_count(&mut self, organization: &str) -> rusqlite::Result<u64> {
        self.db.query_row(
            "SELECT count(*) FROM organization_memberships WHERE organization_id=?1 AND role=0 AND status=2",
            [organization], |row| row.get(0),
        )
    }

    fn remove_organization_member(
        &mut self,
        plan: &ValidatedOrganizationMemberRemoval<'_, String>,
    ) -> rusqlite::Result<()> {
        let tx = self.db.savepoint()?;
        let actor: Option<(i32, i32)> = tx.query_row(
            "SELECT role,status FROM organization_memberships WHERE organization_id=?1 AND user_id=?2",
            params![plan.organization(), plan.owner()], |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional()?;
        let Some((actor_role @ (0 | 1), 2)) = actor else {
            return Err(rusqlite::Error::InvalidQuery);
        };
        if plan.role() != 2 && actor_role != 0 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let target: Option<(String, i32, i32)> = tx.query_row(
            "SELECT user_id,role,status FROM organization_memberships WHERE organization_id=?1 AND id=?2",
            params![plan.organization(), plan.membership_id()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).optional()?;
        if target
            .as_ref()
            .map(|(user, role, status)| (user.as_str(), *role, *status))
            != Some((plan.user_id(), plan.role(), plan.status()))
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        if plan.requires_other_confirmed_owner() {
            let owners: u64 = tx.query_row(
                "SELECT count(*) FROM organization_memberships WHERE organization_id=?1 AND role=0 AND status=2",
                [plan.organization()], |row| row.get(0),
            )?;
            if owners <= 1 {
                return Err(rusqlite::Error::InvalidQuery);
            }
        }
        let email: Option<String> = tx
            .query_row(
                "SELECT email FROM accounts WHERE id=?1",
                [plan.user_id()],
                |row| row.get(0),
            )
            .optional()?;
        let other_invited: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM organization_memberships WHERE user_id=?1 AND status=0 AND id<>?2)",
            params![plan.user_id(), plan.membership_id()], |row| row.get(0),
        )?;
        // This adapter has no SMTP configuration. Check the marker decision again
        // inside the write boundary so concurrent membership changes cannot remove
        // another pending invitation's registration authority.
        if (email.is_some() && !other_invited) != plan.remove_invitation() {
            return Err(rusqlite::Error::InvalidQuery);
        }
        tx.execute(
            "DELETE FROM organization_collection_users WHERE user_id=?1 AND collection_id IN (SELECT id FROM organization_collections WHERE organization_id=?2)",
            params![plan.user_id(), plan.organization()],
        )?;
        tx.execute(
            "DELETE FROM organization_member_inviters WHERE membership_id=?1",
            [plan.membership_id()],
        )?;
        if plan.remove_invitation()
            && let Some(email) = email.as_ref()
        {
            tx.execute(
                "DELETE FROM organization_invitations WHERE email=?1",
                [email],
            )?;
        }
        let changed = tx.execute(
            "DELETE FROM organization_memberships WHERE organization_id=?1 AND id=?2 AND user_id=?3 AND role=?4 AND status=?5",
            params![plan.organization(), plan.membership_id(), plan.user_id(), plan.role(), plan.status()],
        )?;
        if changed != 1 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        if email.is_some() {
            let revision = crate::store::next_revision(&tx, plan.user_id())?;
            crate::store::bump(&tx, plan.user_id(), &revision)?;
        }
        tx.commit()
    }
}

#[cfg(test)]
mod tests;
