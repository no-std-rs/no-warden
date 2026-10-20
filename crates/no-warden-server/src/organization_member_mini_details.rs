//! Minimal organization/account joins, excluding keys and unrelated metadata.
use crate::Store;
use no_warden::organization_member_mini_details::{
    OrganizationMemberMiniData, OrganizationMemberMiniRecord, OrganizationMemberMiniStorage,
};
use rusqlite::params;

struct Member {
    id: String,
    organization: String,
    user: String,
    email: String,
    name: String,
    role: i32,
    status: i32,
}
pub struct Members(Vec<Member>);
impl OrganizationMemberMiniData for Members {
    fn len(&self) -> usize {
        self.0.len()
    }
    fn get(&self, index: usize) -> Option<OrganizationMemberMiniRecord<'_>> {
        self.0.get(index).map(|row| OrganizationMemberMiniRecord {
            membership_id: &row.id,
            organization_id: &row.organization,
            user_id: &row.user,
            email: &row.email,
            name: &row.name,
            role: row.role,
            status: row.status,
        })
    }
}
impl OrganizationMemberMiniStorage for Store {
    type MiniMembers<'a> = Members;
    fn organization_member_mini_details(
        &mut self,
        organization: &str,
    ) -> rusqlite::Result<Members> {
        let mut statement=self.db.prepare(
            "SELECT m.id,m.organization_id,m.user_id,a.email,json_extract(a.document,'$.name'),m.role,m.status
             FROM organization_memberships m JOIN accounts a ON a.id=m.user_id
             WHERE m.organization_id=?1 ORDER BY m.rowid"
        )?;
        let records = statement
            .query_map(params![organization], |row| {
                Ok(Member {
                    id: row.get(0)?,
                    organization: row.get(1)?,
                    user: row.get(2)?,
                    email: row.get(3)?,
                    name: row.get::<_, Option<String>>(4)?.unwrap_or_default(),
                    role: row.get(5)?,
                    status: row.get(6)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Members(records))
    }
}

#[cfg(test)]
mod tests;
