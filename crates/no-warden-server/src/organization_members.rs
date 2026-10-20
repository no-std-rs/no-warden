//! Public organization-member discovery; no membership keys enter this cache.
use crate::{Failure, Store, organization_collections};
use no_warden::organization_members::{
    OrganizationMemberCollection, OrganizationMemberGroup, OrganizationMemberListData,
    OrganizationMemberQuery, OrganizationMemberRecord, OrganizationMemberStorage,
};
use rusqlite::params;

struct Collection {
    id: String,
    organization: String,
    read_only: bool,
    hide_passwords: bool,
    manage: bool,
}
struct Member {
    id: String,
    user: String,
    organization: String,
    name: Option<String>,
    email: String,
    avatar: Option<String>,
    status: i32,
    role: i32,
    access_all: bool,
    has_password: bool,
    collections: Vec<Collection>,
}

#[derive(Default)]
pub struct Members(Vec<Member>);

impl OrganizationMemberListData for Members {
    fn len(&self) -> usize {
        self.0.len()
    }
    fn get(&self, index: usize) -> Option<OrganizationMemberRecord<'_>> {
        self.0.get(index).map(|row| OrganizationMemberRecord {
            membership_id: &row.id,
            user_id: &row.user,
            organization_id: &row.organization,
            name: row.name.as_deref(),
            email: &row.email,
            external_id: None,
            avatar_color: row.avatar.as_deref(),
            status: row.status,
            role: row.role,
            access_all: row.access_all,
            two_factor_enabled: false,
            reset_password_enrolled: false,
            has_master_password: row.has_password,
            full_access_group: false,
        })
    }
    fn groups_enabled(&self) -> bool {
        false
    }
    fn groups_len(&self, _member: usize) -> usize {
        0
    }
    fn group(&self, _member: usize, _index: usize) -> Option<OrganizationMemberGroup<'_>> {
        None
    }
    fn collections_len(&self, member: usize) -> usize {
        self.0.get(member).map_or(0, |row| row.collections.len())
    }
    fn collection(&self, member: usize, index: usize) -> Option<OrganizationMemberCollection<'_>> {
        self.0
            .get(member)?
            .collections
            .get(index)
            .map(|row| OrganizationMemberCollection {
                id: &row.id,
                organization_id: &row.organization,
                read_only: row.read_only,
                hide_passwords: row.hide_passwords,
                manage: row.manage,
            })
    }
}

impl OrganizationMemberStorage for Store {
    type Members<'a> = &'a Members;

    fn organization_members(&mut self, organization: &str) -> rusqlite::Result<Self::Members<'_>> {
        let mut statement = self.db.prepare(
            "SELECT m.id,m.user_id,m.organization_id,json_extract(a.document,'$.name'),a.email,
                    json_extract(a.document,'$.avatarColor'),m.status,m.role,m.access_all,a.password<>''
             FROM organization_memberships m JOIN accounts a ON a.id=m.user_id
             WHERE m.organization_id=?1 ORDER BY m.rowid",
        )?;
        let mut members = statement
            .query_map([organization], |row| {
                Ok(Member {
                    id: row.get(0)?,
                    user: row.get(1)?,
                    organization: row.get(2)?,
                    name: row.get(3)?,
                    email: row.get(4)?,
                    avatar: row.get(5)?,
                    status: row.get(6)?,
                    role: row.get(7)?,
                    access_all: row.get(8)?,
                    has_password: row.get(9)?,
                    collections: Vec::new(),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut collections = self.db.prepare(
            "SELECT c.id,c.organization_id,g.read_only,g.hide_passwords,g.manage
             FROM organization_collection_users g JOIN organization_collections c ON c.id=g.collection_id
             WHERE c.organization_id=?1 AND g.user_id=?2 ORDER BY g.rowid",
        )?;
        for member in &mut members {
            member.collections = collections
                .query_map(params![organization, member.user], |row| {
                    Ok(Collection {
                        id: row.get(0)?,
                        organization: row.get(1)?,
                        read_only: row.get(2)?,
                        hide_passwords: row.get(3)?,
                        manage: row.get(4)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
        }
        self.organization_members_cache = Members(members);
        Ok(&self.organization_members_cache)
    }
}

// Rocket Option<bool> is infallible with a strict inner parser: malformed or
// duplicate fields become None. The upstream handler then defaults to false.
#[derive(Default)]
struct Flag {
    seen: bool,
    value: bool,
}
impl Flag {
    fn push(&mut self, value: &str) {
        self.value = !self.seen
            && (value.is_empty()
                || ["on", "yes", "true"]
                    .iter()
                    .any(|truth| value.eq_ignore_ascii_case(truth)));
        self.seen = true;
    }
}
pub fn query(raw: Option<&str>) -> OrganizationMemberQuery {
    let (mut collections, mut groups) = (Flag::default(), Flag::default());
    if let Some(raw) = raw {
        for (name, value) in url::form_urlencoded::parse(raw.as_bytes()) {
            match organization_collections::query_root(&name) {
                "includeCollections" => collections.push(&value),
                "includeGroups" => groups.push(&value),
                _ => {}
            }
        }
    }
    OrganizationMemberQuery {
        include_collections: collections.value,
        include_groups: groups.value,
    }
}

pub fn path(
    store: &mut Store,
    owner: &str,
    raw: &str,
    query: Option<&str>,
) -> Result<String, Failure> {
    organization_collections::paths(store, owner, raw, None, query).map(|(org, _)| org)
}

#[cfg(test)]
mod tests;
