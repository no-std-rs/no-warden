//! Independent replacement/deletion adapter. Cipher data stays opaque and intact.
use super::*;
use no_warden::organization_collection_mutations::{
    OrganizationCollectionMutationStorage, ValidatedCollectionDelete, ValidatedCollectionUpdate,
};

fn scoped(db: &Connection, org: &str, col: &str) -> rusqlite::Result<Option<Record>> {
    db.query_row(
        "SELECT id,organization_id,name,external_id FROM organization_collections WHERE organization_id=?1 AND id=?2",
        params![org,col],record,
    ).optional()
}

fn authorize(db: &Connection, owner: &str, org: &str, col: &str) -> rusqlite::Result<()> {
    let member = member(db, owner, org)?.ok_or(rusqlite::Error::InvalidQuery)?;
    if member.status != 2
        || !matches!(member.role, 0 | 1 | 3)
        || !manageable(db, owner, col)?
        || scoped(db, org, col)?.is_none()
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(())
}

fn recipients(db: &Connection, org: &str, col: &str) -> rusqlite::Result<Vec<String>> {
    // Full access is a stored membership bit here, without a role/status shortcut.
    // Old direct grantees must still advance after their assignment is removed.
    let mut statement = db.prepare("SELECT user_id FROM organization_memberships WHERE organization_id=?1 AND access_all=1 UNION SELECT user_id FROM organization_collection_users WHERE collection_id=?2")?;
    statement
        .query_map(params![org, col], |row| row.get(0))?
        .collect()
}

fn advance(db: &Connection, mut users: Vec<String>) -> rusqlite::Result<()> {
    users.sort();
    users.dedup();
    for user in users {
        let revision = store::next_revision(db, &user)?;
        store::bump(db, &user, &revision)?;
    }
    Ok(())
}

impl OrganizationCollectionMutationStorage for Store {
    fn mutation_collection(
        &mut self,
        org: &str,
        col: &str,
    ) -> rusqlite::Result<Option<CollectionRecord<'_>>> {
        self.organization_collection_cache.mutation_record = scoped(&self.db, org, col)?;
        Ok(self
            .organization_collection_cache
            .mutation_record
            .as_ref()
            .map(Record::view))
    }

    fn update_collection<D: CollectionCreateData + ?Sized>(
        &mut self,
        owner: &str,
        org: &str,
        col: &str,
        plan: &ValidatedCollectionUpdate<'_, D>,
    ) -> rusqlite::Result<UserCollectionRecord<'_>> {
        let request = plan.request();
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorize(&tx, owner, org, col)?;
        // This host has no group rows/lifecycle. Reject rather than drop grants.
        if request.groups_len() != 0 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let mut affected = recipients(&tx, org, col)?;
        tx.execute("UPDATE organization_collections SET name=?1,external_id=?2 WHERE id=?3 AND organization_id=?4",params![request.name(),plan.external_id(),col,org])?;
        tx.execute(
            "DELETE FROM organization_collection_users WHERE collection_id=?1",
            [col],
        )?;
        for index in 0..request.users_len() {
            let selection = request.user(index).ok_or(rusqlite::Error::InvalidQuery)?;
            let (user, all): (String, bool) = tx.query_row("SELECT user_id,access_all FROM organization_memberships WHERE organization_id=?1 AND id=?2",params![org,selection.id],|row|Ok((row.get(0)?,row.get(1)?)))?;
            if !all {
                tx.execute("INSERT INTO organization_collection_users VALUES(?1,?2,?3,?4,?5) ON CONFLICT(collection_id,user_id) DO UPDATE SET read_only=excluded.read_only,hide_passwords=excluded.hide_passwords,manage=excluded.manage",params![col,user,selection.read_only,selection.hide_passwords,selection.manage])?;
            }
        }
        affected.extend(recipients(&tx, org, col)?);
        advance(&tx, affected)?;
        // The actor may have removed their own last direct grant. Keep the
        // source-compatible non-readable response rather than failing after write.
        let staged = detail(&tx, owner, col)?.ok_or(rusqlite::Error::InvalidQuery)?;
        tx.commit()?;
        self.organization_collection_cache.detail = Some(staged);
        Ok(self
            .organization_collection_cache
            .detail
            .as_ref()
            .expect("Staged collection update")
            .view())
    }

    fn delete_collection(&mut self, plan: &ValidatedCollectionDelete<'_>) -> rusqlite::Result<()> {
        let (owner, org, col) = (plan.owner(), plan.organization(), plan.collection());
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorize(&tx, owner, org, col)?;
        let affected = recipients(&tx, org, col)?;
        // Foreign-key cascades remove direct grants and collection/cipher links;
        // they never delete or rewrite cipher/attachment rows.
        tx.execute(
            "DELETE FROM organization_collections WHERE organization_id=?1 AND id=?2",
            params![org, col],
        )?;
        advance(&tx, affected)?;
        tx.commit()?;
        self.organization_collection_cache.detail = None;
        self.organization_collection_cache.mutation_record = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
