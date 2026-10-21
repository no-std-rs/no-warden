//! Independent organization-collection adapter; encrypted names remain opaque.
//! The local host has no group administration. Embedders provide group storage
//! and policy through the core trait rather than enabling fictional grants here.
use crate::{Failure, Store, json_guard_error, store};
use axum::http::StatusCode;
use no_warden::{
    VaultService,
    organization_collections::{
        CollectionAccessData, CollectionAccessEntry, CollectionCreateData, CollectionListData,
        OrganizationCollectionMembership, OrganizationCollectionStorage, ValidatedCollectionCreate,
    },
    organizations::{CollectionRecord, OrganizationMembership, UserCollectionRecord},
    wire::CollectionSelectionRequest,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::Deserialize;

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS organization_collection_users(
 collection_id TEXT NOT NULL REFERENCES organization_collections(id) ON DELETE CASCADE,
 user_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 read_only INTEGER NOT NULL, hide_passwords INTEGER NOT NULL, manage INTEGER NOT NULL,
 PRIMARY KEY(collection_id,user_id));
CREATE TABLE IF NOT EXISTS organization_collection_ciphers(
 collection_id TEXT NOT NULL REFERENCES organization_collections(id) ON DELETE CASCADE,
 cipher_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
 PRIMARY KEY(collection_id,cipher_id));";

// Preserve declaration order for positional JSON and duplicate-field checking.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Selection {
    hide_passwords: bool,
    id: String,
    read_only: bool,
    manage: bool,
}
impl Selection {
    fn view(&self) -> CollectionSelectionRequest<'_> {
        CollectionSelectionRequest {
            hide_passwords: self.hide_passwords,
            id: &self.id,
            read_only: self.read_only,
            manage: self.manage,
        }
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Input {
    name: String,
    groups: Vec<Selection>,
    users: Vec<Selection>,
    external_id: Option<String>,
}
impl Input {
    pub fn parse(body: &[u8]) -> Result<Self, Failure> {
        let body = std::str::from_utf8(body).map_err(|_| crate::invalid())?;
        serde_json::from_str(body).map_err(json_guard_error)
    }
}
impl CollectionCreateData for Input {
    fn name(&self) -> &str {
        &self.name
    }
    fn external_id(&self) -> Option<&str> {
        self.external_id.as_deref()
    }
    fn groups_len(&self) -> usize {
        self.groups.len()
    }
    fn group(&self, index: usize) -> Option<CollectionSelectionRequest<'_>> {
        self.groups.get(index).map(Selection::view)
    }
    fn users_len(&self) -> usize {
        self.users.len()
    }
    fn user(&self, index: usize) -> Option<CollectionSelectionRequest<'_>> {
        self.users.get(index).map(Selection::view)
    }
}

#[derive(Default)]
pub struct Cache {
    membership: Option<Member>,
    collections: Rows,
    detail: Option<Detail>,
    mutation_record: Option<Record>,
}
struct Member {
    user: String,
    org: String,
    role: i32,
    status: i32,
    all: bool,
}
impl Member {
    fn view(&self) -> OrganizationMembership<'_> {
        OrganizationMembership {
            user_id: &self.user,
            organization_id: &self.org,
            role: self.role,
            status: self.status,
        }
    }
    fn full(&self) -> bool {
        self.all || matches!(self.role, 0 | 1)
    }
}
fn member(db: &Connection, owner: &str, org: &str) -> rusqlite::Result<Option<Member>> {
    db.query_row("SELECT user_id,organization_id,role,status,access_all FROM organization_memberships WHERE user_id=?1 AND organization_id=?2",params![owner,org], |row| Ok(Member {user:row.get(0)?,org:row.get(1)?,role:row.get(2)?,status:row.get(3)?,all:row.get(4)?})).optional()
}
struct Record {
    id: String,
    org: String,
    name: String,
    external: Option<String>,
}
impl Record {
    fn view(&self) -> CollectionRecord<'_> {
        CollectionRecord {
            id: &self.id,
            organization_id: &self.org,
            name: &self.name,
            external_id: self.external.as_deref(),
        }
    }
}
fn record(row: &rusqlite::Row<'_>) -> rusqlite::Result<Record> {
    Ok(Record {
        id: row.get(0)?,
        org: row.get(1)?,
        name: row.get(2)?,
        external: row.get(3)?,
    })
}
#[derive(Default)]
pub struct Rows(Vec<Record>);
impl CollectionListData for Rows {
    fn len(&self) -> usize {
        self.0.len()
    }
    fn get(&self, index: usize) -> Option<CollectionRecord<'_>> {
        self.0.get(index).map(Record::view)
    }
}
struct Grant {
    org: String,
    id: String,
    ro: bool,
    hide: bool,
    manage: bool,
}
pub struct Detail {
    row: Record,
    member: Member,
    read_only: bool,
    hide: bool,
    manage: bool,
    assigned: bool,
    users: Vec<Grant>,
}
impl Detail {
    fn view(&self) -> UserCollectionRecord<'_> {
        UserCollectionRecord {
            collection: self.row.view(),
            membership: self.member.view(),
            readable: self.assigned,
            read_only: self.read_only,
            hide_passwords: self.hide,
            manage: self.manage,
        }
    }
}
impl CollectionAccessData for Detail {
    fn collection(&self) -> UserCollectionRecord<'_> {
        self.view()
    }
    fn assigned(&self) -> bool {
        self.assigned
    }
    fn users_len(&self) -> usize {
        self.users.len()
    }
    fn user(&self, index: usize) -> Option<CollectionAccessEntry<'_>> {
        self.users.get(index).map(|g| CollectionAccessEntry {
            organization_id: &g.org,
            id: &g.id,
            read_only: g.ro,
            hide_passwords: g.hide,
            manage: g.manage,
        })
    }
    fn groups_len(&self) -> usize {
        0
    }
    fn group(&self, _index: usize) -> Option<CollectionAccessEntry<'_>> {
        None
    }
    fn groups_enabled(&self) -> bool {
        false
    }
}

fn detail(db: &Connection, owner: &str, id: &str) -> rusqlite::Result<Option<Detail>> {
    let Some(row) = db
        .query_row(
            "SELECT id,organization_id,name,external_id FROM organization_collections WHERE id=?1",
            [id],
            record,
        )
        .optional()?
    else {
        return Ok(None);
    };
    let Some(member) = member(db, owner, &row.org)? else {
        return Ok(None);
    };
    let own:Option<(bool,bool,bool)> = db.query_row("SELECT read_only,hide_passwords,manage FROM organization_collection_users WHERE collection_id=?1 AND user_id=?2",params![id,owner], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
    let assigned = member.status == 2 && (member.full() || own.is_some());
    let full = member.full();
    let (read_only, hide, stored_manage) = own.unwrap_or((true, false, false));
    let manage = full || stored_manage || (member.role == 3 && !read_only && !hide);
    let mut statement=db.prepare("SELECT m.organization_id,m.id,g.read_only,g.hide_passwords,g.manage,m.role FROM organization_collection_users g JOIN organization_memberships m ON m.user_id=g.user_id WHERE g.collection_id=?1 AND m.organization_id=?2 ORDER BY g.rowid")?;
    let users = statement
        .query_map(params![id, row.org], |r| {
            let ro: bool = r.get(2)?;
            let hide: bool = r.get(3)?;
            let role: i32 = r.get(5)?;
            Ok(Grant {
                org: r.get(0)?,
                id: r.get(1)?,
                ro,
                hide,
                manage: matches!(role, 0 | 1)
                    || r.get::<_, bool>(4)?
                    || (role == 3 && !ro && !hide),
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    // These are non-sync projections: manageable collections are writable even
    // when the stored direct selection carries restrictive flags.
    Ok(Some(Detail {
        row,
        member,
        read_only: !manage && read_only,
        hide: !manage && hide,
        manage,
        assigned,
        users,
    }))
}

/// Aggregate list projection includes implicit full-access memberships, unlike
/// the separately verified single-collection direct-selection projection.
pub(crate) fn web_details(
    db: &Connection,
    owner: &str,
    org: &str,
) -> rusqlite::Result<Vec<Detail>> {
    let ids = {
        let mut statement = db.prepare(
            "SELECT id FROM organization_collections WHERE organization_id=?1 ORDER BY rowid",
        )?;
        statement
            .query_map([org], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let mut rows = Vec::new();
    for id in ids {
        let Some(mut row) = detail(db, owner, &id)? else {
            continue;
        };
        if !row.assigned {
            continue;
        }
        let mut statement = db.prepare("SELECT m.organization_id,m.id,COALESCE(g.read_only,0),COALESCE(g.hide_passwords,0),COALESCE(g.manage,0),m.role,m.access_all,m.status FROM organization_memberships m LEFT JOIN organization_collection_users g ON g.user_id=m.user_id AND g.collection_id=?1 WHERE m.organization_id=?2 AND ((m.status=2 AND (m.role IN(0,1) OR m.access_all=1)) OR g.user_id IS NOT NULL) ORDER BY m.rowid")?;
        row.users = statement
            .query_map(params![id, org], |r| {
                let full = r.get::<_, i32>(7)? == 2
                    && (matches!(r.get::<_, i32>(5)?, 0 | 1) || r.get::<_, bool>(6)?);
                let ro = r.get::<_, bool>(2)?;
                let hide = r.get::<_, bool>(3)?;
                Ok(Grant {
                    org: r.get(0)?,
                    id: r.get(1)?,
                    ro: !full && ro,
                    hide: !full && hide,
                    manage: full
                        || r.get::<_, bool>(4)?
                        || (r.get::<_, i32>(5)? == 3 && !ro && !hide),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.push(row);
    }
    Ok(rows)
}

// Query fallbacks are request-guard inputs, not successful route parameters.
// Typed path failures remain 422 after all membership/collection guards succeed.
pub(super) fn query_root(name: &str) -> &str {
    if let Some(rest) = name.strip_prefix('[') {
        return rest.split(']').next().unwrap_or_default();
    }
    name.strip_prefix('.')
        .unwrap_or(name)
        .split(['.', '['])
        .next()
        .unwrap_or_default()
}
pub(super) fn selected(
    raw: &str,
    query: Option<&str>,
    key: &str,
) -> Result<(Result<String, Failure>, String), Failure> {
    let parsed = crate::auth_requests::path_id(raw);
    let selected = match &parsed {
        Ok(value) => value.clone(),
        Err(_) => query
            .and_then(|q| {
                url::form_urlencoded::parse(q.as_bytes())
                    .find(|(name, _)| query_root(name) == key)
                    .map(|(_, value)| value.into_owned())
            })
            .ok_or_else(crate::unauthorized)?,
    };
    if uuid::Uuid::parse_str(&selected).is_err() {
        return Err(crate::unauthorized());
    }
    Ok((parsed, selected))
}
pub fn paths(
    store: &mut Store,
    owner: &str,
    org: &str,
    col: Option<&str>,
    query: Option<&str>,
) -> Result<(String, Option<String>), Failure> {
    let (parsed_org, selected_org) = selected(org, query, "organizationId")?;
    // OrgHeaders are evaluated before even selecting the collection fallback.
    VaultService::new(&mut *store).authorize_org_collection_manager(owner, &selected_org)?;
    let parsed_col = if let Some(col) = col {
        let (parsed, selected) = selected(col, query, "collectionId")?;
        VaultService::new(&mut *store).authorize_org_collection_details(
            owner,
            &selected_org,
            &selected,
        )?;
        Some(parsed)
    } else {
        None
    };
    let org = parsed_org
        .map_err(|_| Failure(StatusCode::UNPROCESSABLE_ENTITY, "Invalid organization ID"))?;
    let col = parsed_col
        .transpose()
        .map_err(|_| Failure(StatusCode::UNPROCESSABLE_ENTITY, "Invalid collection ID"))?;
    Ok((org, col))
}

impl OrganizationCollectionStorage for Store {
    type OrgCollections<'a> = &'a Rows;
    type AccessDetails<'a> = &'a Detail;
    fn collection_membership(
        &mut self,
        owner: &str,
        org: &str,
    ) -> rusqlite::Result<Option<OrganizationCollectionMembership<'_>>> {
        self.organization_collection_cache.membership = member(&self.db, owner, org)?;
        Ok(self
            .organization_collection_cache
            .membership
            .as_ref()
            .map(|m| OrganizationCollectionMembership {
                membership: m.view(),
                access_all: m.all,
            }))
    }
    fn org_collections(&mut self, org: &str) -> rusqlite::Result<Self::OrgCollections<'_>> {
        let mut statement=self.db.prepare("SELECT id,organization_id,name,external_id FROM organization_collections WHERE organization_id=?1 ORDER BY rowid")?;
        self.organization_collection_cache.collections = Rows(
            statement
                .query_map([org], record)?
                .collect::<rusqlite::Result<Vec<_>>>()?,
        );
        Ok(&self.organization_collection_cache.collections)
    }
    fn can_manage_collection(&mut self, owner: &str, col: &str) -> rusqlite::Result<bool> {
        manageable(&self.db, owner, col)
    }
    fn collection_access_details(
        &mut self,
        owner: &str,
        col: &str,
    ) -> rusqlite::Result<Option<Self::AccessDetails<'_>>> {
        self.organization_collection_cache.detail = detail(&self.db, owner, col)?;
        Ok(self.organization_collection_cache.detail.as_ref())
    }
    fn collection_group_exists(&mut self, _org: &str, _id: &str) -> rusqlite::Result<bool> {
        // No group rows/lifecycle in this adapter; never silently discard a grant.
        Ok(false)
    }
    fn collection_member_exists(&mut self, org: &str, id: &str) -> rusqlite::Result<bool> {
        self.db.query_row("SELECT EXISTS(SELECT 1 FROM organization_memberships WHERE organization_id=?1 AND id=?2)",params![org,id],|r|r.get(0))
    }
    fn create_collection<D: CollectionCreateData + ?Sized>(
        &mut self,
        owner: &str,
        org: &str,
        plan: &ValidatedCollectionCreate<'_, D>,
    ) -> rusqlite::Result<UserCollectionRecord<'_>> {
        let input = plan.request();
        let id = uuid::Uuid::new_v4().to_string();
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let authority = member(&tx, owner, org)?.ok_or(rusqlite::Error::InvalidQuery)?;
        if authority.status != 2
            || !matches!(authority.role, 0 | 1 | 3)
            || (authority.role == 3 && !authority.all)
            || input.groups_len() != 0
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        tx.execute(
            "INSERT INTO organization_collections VALUES(?1,?2,?3,?4)",
            params![id, org, input.name(), plan.external_id()],
        )?;
        // Foreign memberships cannot become grants, even if an embedding adapter
        // changes state between validation and the transaction.
        for i in 0..input.users_len() {
            let selection = input.user(i).ok_or(rusqlite::Error::InvalidQuery)?;
            let (user,all):(String,bool)=tx.query_row("SELECT user_id,access_all FROM organization_memberships WHERE organization_id=?1 AND id=?2",params![org,selection.id],|r|Ok((r.get(0)?,r.get(1)?)))?;
            if !all {
                tx.execute("INSERT INTO organization_collection_users VALUES(?1,?2,?3,?4,?5) ON CONFLICT(collection_id,user_id) DO UPDATE SET read_only=excluded.read_only,hide_passwords=excluded.hide_passwords,manage=excluded.manage",params![id,user,selection.read_only,selection.hide_passwords,selection.manage])?;
            }
        }
        let affected: Vec<String> = {
            let mut statement=tx.prepare("SELECT user_id FROM organization_memberships WHERE organization_id=?1 AND access_all=1 UNION SELECT user_id FROM organization_collection_users WHERE collection_id=?2")?;
            statement
                .query_map(params![org, id], |r| r.get(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        for user in affected {
            let revision = store::next_revision(&tx, &user)?;
            store::bump(&tx, &user, &revision)?;
        }
        // Stage every fallible read and allocation before commit. Atomicity is
        // stronger than the reference's sequential row/grant/revision saves.
        let staged = detail(&tx, owner, &id)?.ok_or(rusqlite::Error::InvalidQuery)?;
        tx.commit()?;
        self.organization_collection_cache.detail = Some(staged);
        Ok(self
            .organization_collection_cache
            .detail
            .as_ref()
            .expect("Staged collection")
            .view())
    }
}

#[cfg(test)]
pub(crate) mod tests;

mod mutations;

fn manageable(db: &Connection, owner: &str, col: &str) -> rusqlite::Result<bool> {
    db.query_row("SELECT EXISTS(SELECT 1 FROM organization_collections c JOIN organization_memberships m ON m.organization_id=c.organization_id LEFT JOIN organization_collection_users g ON g.collection_id=c.id AND g.user_id=m.user_id WHERE c.id=?1 AND m.user_id=?2 AND m.status=2 AND (m.access_all=1 OR m.role IN (0,1) OR g.manage=1))",params![col,owner],|r|r.get(0))
}

pub fn is_collection_error(message: &str) -> bool {
    matches!(
        message,
        "Invalid group"
            | "Invalid member"
            | "You don't have permission to create collections"
            | "Resource not found."
            | "Collection is not owned by organization"
            | "Collection not found"
            | "User is not part of organization"
    )
}
