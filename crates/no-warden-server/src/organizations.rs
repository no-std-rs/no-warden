//! Independently authored owner creation/discovery adapter. Crypto stays client-side.
//! Pinned protocol: vaultwarden 58a980f, organizations.rs and organization/collection models.
use crate::{Failure, Store, json_guard_error, registration, store};
use axum::http::StatusCode;
use no_warden::{
    identity::Secret,
    organizations::{
        CollectionRecord, OrganizationCreationPolicy, OrganizationFeatures, OrganizationMembership,
        OrganizationProfileListData, OrganizationProfileRecord, OrganizationRecord,
        OrganizationStorage, UserCollectionListData, UserCollectionRecord,
        ValidatedOrganizationCreate,
    },
    wire::{AccountKeys, OrganizationCreateRequest, OrganizationPlanType},
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::Deserialize;

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS organizations(id TEXT PRIMARY KEY, name TEXT NOT NULL, billing_email TEXT NOT NULL, public_key TEXT, encrypted_private_key TEXT);
CREATE TABLE IF NOT EXISTS organization_memberships(id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE, user_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, key TEXT NOT NULL, role INTEGER NOT NULL, status INTEGER NOT NULL, access_all INTEGER NOT NULL, UNIQUE(organization_id,user_id));
CREATE INDEX IF NOT EXISTS organization_memberships_user ON organization_memberships(user_id);
CREATE TABLE IF NOT EXISTS organization_collections(id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE, name TEXT NOT NULL, external_id TEXT);
CREATE INDEX IF NOT EXISTS organization_collections_org ON organization_collections(organization_id);";

#[derive(Deserialize)]
#[serde(untagged)]
enum PlanType {
    Integer(i64),
    String(String),
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Keys {
    encrypted_private_key: String,
    public_key: String,
}
// Order is part of the positional JSON contract. Do not deserialize through Value:
// that would erase duplicate-field errors before the typed decoder sees them.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Input {
    billing_email: String,
    collection_name: String,
    key: String,
    name: String,
    keys: Option<Keys>,
    plan_type: PlanType,
}
impl Input {
    pub fn parse(body: &[u8]) -> Result<Self, Failure> {
        let body = std::str::from_utf8(body).map_err(|_| crate::invalid())?;
        serde_json::from_str(body).map_err(json_guard_error)
    }
    pub fn request(&self) -> OrganizationCreateRequest<'_> {
        OrganizationCreateRequest {
            billing_email: &self.billing_email,
            collection_name: &self.collection_name,
            key: Secret::new(&self.key),
            name: &self.name,
            keys: self.keys.as_ref().map(|keys| AccountKeys {
                encrypted_private_key: &keys.encrypted_private_key,
                public_key: &keys.public_key,
            }),
            plan_type: match &self.plan_type {
                PlanType::Integer(value) => OrganizationPlanType::Integer(*value),
                PlanType::String(value) => OrganizationPlanType::String(value),
            },
        }
    }
    pub fn billing_error(&self) -> String {
        format!(
            "BillingEmail {} is not a valid email address",
            self.billing_email.to_lowercase().escape_debug()
        )
    }
}

pub struct Record {
    id: String,
    name: String,
    billing_email: String,
    has_keys: bool,
}
impl Record {
    fn view(&self) -> OrganizationRecord<'_> {
        OrganizationRecord {
            id: &self.id,
            name: &self.name,
            billing_email: &self.billing_email,
            has_public_and_private_keys: self.has_keys,
            features: OrganizationFeatures::default(),
        }
    }
}
fn record(row: &rusqlite::Row<'_>) -> rusqlite::Result<Record> {
    Ok(Record {
        id: row.get(0)?,
        name: row.get(1)?,
        billing_email: row.get(2)?,
        has_keys: row.get(3)?,
    })
}
pub struct Membership {
    user: String,
    organization: String,
    role: i32,
    status: i32,
}
impl Membership {
    fn view(&self) -> OrganizationMembership<'_> {
        OrganizationMembership {
            user_id: &self.user,
            organization_id: &self.organization,
            role: self.role,
            status: self.status,
        }
    }
}
fn membership(
    db: &Connection,
    owner: &str,
    organization: &str,
) -> rusqlite::Result<Option<Membership>> {
    db.query_row("SELECT user_id,organization_id,role,status FROM organization_memberships WHERE user_id=?1 AND organization_id=?2",
        params![owner,organization], |row| Ok(Membership { user:row.get(0)?, organization:row.get(1)?, role:row.get(2)?, status:row.get(3)? })).optional()
}

/// Match the owner request guard before the route's own UUID parameter guard.
/// A successfully parsed path wins over query values, retaining exact spelling.
pub fn owner_path(
    db: &Connection,
    owner: &str,
    raw: &str,
    query: Option<&str>,
) -> Result<String, Failure> {
    let parsed = crate::auth_requests::path_id(raw);
    let fallback;
    let selected = match &parsed {
        Ok(path) => path.as_str(),
        Err(_) => {
            fallback = query.and_then(|query| {
                url::form_urlencoded::parse(query.as_bytes())
                    .find(|(name, _)| query_root(name) == "organizationId")
                    .map(|(_, value)| value.into_owned())
            });
            fallback.as_deref().ok_or_else(crate::unauthorized)?
        }
    };
    let member = membership(db, owner, selected)?.ok_or_else(crate::unauthorized)?;
    if member.role != 0 || member.status != 2 {
        return Err(crate::unauthorized());
    }
    parsed.map_err(|_| Failure(StatusCode::UNPROCESSABLE_ENTITY, "Invalid organization ID"))
}
fn query_root(name: &str) -> &str {
    if let Some(rest) = name.strip_prefix('[') {
        return rest.split(']').next().unwrap_or_default();
    }
    name.strip_prefix('.')
        .unwrap_or(name)
        .split(['.', '['])
        .next()
        .unwrap_or_default()
}

pub struct Collection {
    id: String,
    organization: String,
    name: String,
    external_id: Option<String>,
    member: Membership,
}
#[derive(Default)]
pub struct Collections(Vec<Collection>);
impl UserCollectionListData for Collections {
    fn len(&self) -> usize {
        self.0.len()
    }
    fn get(&self, index: usize) -> Option<UserCollectionRecord<'_>> {
        self.0.get(index).map(|row| UserCollectionRecord {
            collection: CollectionRecord {
                id: &row.id,
                organization_id: &row.organization,
                name: &row.name,
                external_id: row.external_id.as_deref(),
            },
            membership: row.member.view(),
            readable: true,
            read_only: false,
            hide_passwords: false,
            manage: true,
        })
    }
}
pub struct Profile {
    org: Record,
    member: Membership,
    id: String,
    key: String,
    access_all: bool,
}
#[derive(Default)]
pub struct Profiles(Vec<Profile>);
impl OrganizationProfileListData for Profiles {
    fn len(&self) -> usize {
        self.0.len()
    }
    fn get(&self, index: usize) -> Option<OrganizationProfileRecord<'_>> {
        self.0.get(index).map(|row| OrganizationProfileRecord {
            organization: row.org.view(),
            membership: row.member.view(),
            membership_id: &row.id,
            key: &row.key,
            access_all: row.access_all,
            reset_password_enrolled: false,
        })
    }
}

pub fn last_owner(db: &Connection, owner: &str) -> rusqlite::Result<bool> {
    db.query_row("SELECT EXISTS(SELECT 1 FROM organization_memberships m WHERE m.user_id=?1 AND m.role=0 AND m.status=2 AND NOT EXISTS(SELECT 1 FROM organization_memberships other WHERE other.organization_id=m.organization_id AND other.user_id<>?1 AND other.role=0 AND other.status=2))", [owner], |row| row.get(0))
}

impl OrganizationStorage for Store {
    type Collections<'a> = &'a Collections;
    type Profiles<'a> = &'a Profiles;
    fn creation_policy(
        &mut self,
        _owner: &str,
        email: &str,
    ) -> rusqlite::Result<OrganizationCreationPolicy> {
        // This local host has default unrestricted creation and no SingleOrg
        // policy administration. Embedders supply their own policy provider.
        Ok(OrganizationCreationPolicy {
            allowed: true,
            single_org_blocked: false,
            billing_email_valid: registration::valid_storage_email(&email.to_lowercase()),
        })
    }
    fn create_organization(
        &mut self,
        owner: &str,
        plan: &ValidatedOrganizationCreate<'_, '_>,
    ) -> rusqlite::Result<OrganizationRecord<'_>> {
        let request = plan.request();
        let record = Record {
            id: uuid::Uuid::new_v4().to_string(),
            name: request.name.to_owned(),
            billing_email: request.billing_email.to_lowercase(),
            has_keys: request.keys.is_some(),
        };
        let member_id = uuid::Uuid::new_v4().to_string();
        let collection_id = uuid::Uuid::new_v4().to_string();
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let revision = store::next_revision(&tx, owner)?;
        tx.execute(
            "INSERT INTO organizations VALUES(?1,?2,?3,?4,?5)",
            params![
                record.id,
                record.name,
                record.billing_email,
                request.keys.map(|keys| keys.public_key),
                request.keys.map(|keys| keys.encrypted_private_key)
            ],
        )?;
        tx.execute(
            "INSERT INTO organization_memberships VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                member_id,
                record.id,
                owner,
                request.key.expose_secret(),
                plan.membership_role(),
                plan.membership_status(),
                plan.access_all()
            ],
        )?;
        tx.execute(
            "INSERT INTO organization_collections VALUES(?1,?2,?3,NULL)",
            params![collection_id, record.id, request.collection_name],
        )?;
        store::bump(&tx, owner, &revision)?;
        tx.commit()?;
        // The complete response cache was staged before any write; no fallible
        // work remains after persistence has succeeded.
        self.organization_cache = Some(record);
        Ok(self
            .organization_cache
            .as_ref()
            .expect("Staged organization")
            .view())
    }
    fn organization_membership(
        &mut self,
        owner: &str,
        org: &str,
    ) -> rusqlite::Result<Option<OrganizationMembership<'_>>> {
        self.organization_membership_cache = membership(&self.db, owner, org)?;
        Ok(self
            .organization_membership_cache
            .as_ref()
            .map(Membership::view))
    }
    fn organization(&mut self, org: &str) -> rusqlite::Result<Option<OrganizationRecord<'_>>> {
        self.organization_cache = self.db.query_row("SELECT id,name,billing_email,public_key IS NOT NULL AND encrypted_private_key IS NOT NULL FROM organizations WHERE id=?1", [org], record).optional()?;
        Ok(self.organization_cache.as_ref().map(Record::view))
    }
    fn user_collections(&mut self, owner: &str) -> rusqlite::Result<Self::Collections<'_>> {
        // The adapter currently creates confirmed full-access owners only.
        // Do not invent permissions for roles whose ACL lifecycle is not implemented.
        let mut statement = self.db.prepare("SELECT c.id,c.organization_id,c.name,c.external_id,m.user_id,m.role,m.status FROM organization_collections c JOIN organization_memberships m ON m.organization_id=c.organization_id WHERE m.user_id=?1 AND m.role=0 AND m.status=2 AND m.access_all=1 ORDER BY c.rowid")?;
        self.organization_collections_cache = Collections(
            statement
                .query_map([owner], |row| {
                    Ok(Collection {
                        id: row.get(0)?,
                        organization: row.get(1)?,
                        name: row.get(2)?,
                        external_id: row.get(3)?,
                        member: Membership {
                            user: row.get(4)?,
                            organization: row.get(1)?,
                            role: row.get(5)?,
                            status: row.get(6)?,
                        },
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?,
        );
        Ok(&self.organization_collections_cache)
    }
    fn profile_organizations(&mut self, owner: &str) -> rusqlite::Result<Self::Profiles<'_>> {
        let mut statement = self.db.prepare("SELECT o.id,o.name,o.billing_email,o.public_key IS NOT NULL AND o.encrypted_private_key IS NOT NULL,m.user_id,m.role,m.status,m.id,m.key,m.access_all FROM organizations o JOIN organization_memberships m ON m.organization_id=o.id WHERE m.user_id=?1 ORDER BY m.rowid")?;
        self.organization_profiles_cache = Profiles(
            statement
                .query_map([owner], |row| {
                    Ok(Profile {
                        org: record(row)?,
                        member: Membership {
                            user: row.get(4)?,
                            organization: row.get(0)?,
                            role: row.get(5)?,
                            status: row.get(6)?,
                        },
                        id: row.get(7)?,
                        key: row.get(8)?,
                        access_all: row.get(9)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?,
        );
        Ok(&self.organization_profiles_cache)
    }
}

#[cfg(test)]
mod tests;
