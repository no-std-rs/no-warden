//! No-SMTP organization invitations; independently authored protocol adapter.
use crate::{Failure, Store, organization_collections, password_login, registration, store};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use no_warden::{
    ErrorKind, VaultService,
    organization_invitations::{
        InvitationPolicy, InvitationTarget, InviteCommit, OrganizationInvitationStorage,
        OrganizationInviteData, OrganizationInviteError, OrganizationInviteErrorKind,
        ValidatedOrganizationInvite,
    },
    wire::{OrganizationInviteCollection, OrganizationInvitePermissions, OrganizationInviteRole},
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS organization_member_inviters(membership_id TEXT PRIMARY KEY REFERENCES organization_memberships(id) ON DELETE CASCADE,email TEXT NOT NULL);";

#[derive(Deserialize)]
#[serde(untagged)]
enum Role {
    Integer(i64),
    String(String),
}
// This tuple order differs from collection mutation selection objects. All four
// flags/ID fields are required, and string IDs reach reference validation intact.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Collection {
    id: String,
    read_only: bool,
    hide_passwords: bool,
    manage: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Input {
    emails: Vec<String>,
    groups: Vec<String>,
    #[serde(rename = "type")]
    role: Role,
    collections: Option<Vec<Collection>>,
    #[serde(default)]
    permissions: BTreeMap<String, Value>,
}
impl Input {
    pub fn parse(body: &[u8]) -> Result<Self, Failure> {
        let body = std::str::from_utf8(body).map_err(|_| crate::invalid())?;
        serde_json::from_str(body).map_err(crate::json_guard_error)
    }
}
impl OrganizationInviteData for Input {
    fn emails_len(&self) -> usize {
        self.emails.len()
    }
    fn email(&self, index: usize) -> Option<&str> {
        self.emails.get(index).map(String::as_str)
    }
    fn groups_len(&self) -> usize {
        self.groups.len()
    }
    fn group(&self, index: usize) -> Option<&str> {
        self.groups.get(index).map(String::as_str)
    }
    fn collections_len(&self) -> usize {
        self.collections.as_ref().map_or(0, Vec::len)
    }
    fn collection(&self, index: usize) -> Option<OrganizationInviteCollection<'_>> {
        self.collections
            .as_ref()?
            .get(index)
            .map(|c| OrganizationInviteCollection {
                id: &c.id,
                read_only: c.read_only,
                hide_passwords: c.hide_passwords,
                manage: c.manage,
            })
    }
    fn role(&self) -> OrganizationInviteRole<'_> {
        match &self.role {
            Role::Integer(v) => OrganizationInviteRole::Integer(*v),
            Role::String(v) => OrganizationInviteRole::String(v),
        }
    }
    fn permissions(&self) -> OrganizationInvitePermissions {
        OrganizationInvitePermissions {
            create_new_collections: self.permissions.get("createNewCollections")
                == Some(&Value::Bool(true)),
            edit_any_collection: self.permissions.get("editAnyCollection")
                == Some(&Value::Bool(true)),
            delete_any_collection: self.permissions.get("deleteAnyCollection")
                == Some(&Value::Bool(true)),
        }
    }
}

pub fn path(
    store: &mut Store,
    owner: &str,
    raw: &str,
    query: Option<&str>,
) -> Result<String, Failure> {
    let (parsed, selected) = organization_collections::selected(raw, query, "organizationId")?;
    VaultService::new(store).authorize_org_member_admin(owner, &selected)?;
    parsed.map_err(|_| Failure(StatusCode::UNPROCESSABLE_ENTITY, "Invalid organization ID"))
}
pub fn error_response(error: OrganizationInviteError<'_>) -> Response {
    let cause = error.cause();
    let status =
        StatusCode::from_u16(cause.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    if cause.kind != ErrorKind::InvalidRequest {
        return Failure(status, cause.message).into_response();
    }
    let normalized = matches!(
        error.kind(),
        OrganizationInviteErrorKind::InvalidEmail
            | OrganizationInviteErrorKind::InvalidInvitationEmail
    )
    .then(|| error.email().unwrap_or_default().to_lowercase());
    let mut message = String::new();
    error
        .write_message(&mut message, normalized.as_deref())
        .expect("String formatting cannot fail");
    password_login::error_response(status, &message)
}
fn account(db: &Connection, email: &str) -> rusqlite::Result<Option<(String, bool)>> {
    db.query_row(
        "SELECT id,password<>'' FROM accounts WHERE email=?1",
        [email],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .optional()
}
fn member_exists(db: &Connection, organization: &str, account: &str) -> rusqlite::Result<bool> {
    db.query_row("SELECT EXISTS(SELECT 1 FROM organization_memberships WHERE organization_id=?1 AND user_id=?2)",params![organization,account],|r|r.get(0))
}
fn collection_exists(
    db: &Connection,
    organization: &str,
    collection: &str,
) -> rusqlite::Result<bool> {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM organization_collections WHERE organization_id=?1 AND id=?2)",
        params![organization, collection],
        |r| r.get(0),
    )
}
impl OrganizationInvitationStorage for Store {
    type AccountId = String;
    fn invitation_policy(
        &mut self,
        _owner: &str,
        _organization: &str,
    ) -> rusqlite::Result<InvitationPolicy> {
        Ok(InvitationPolicy {
            mail_enabled: false,
            invitations_allowed: true,
        })
    }
    fn invitation_collection_exists(
        &mut self,
        organization: &str,
        collection: &str,
    ) -> rusqlite::Result<bool> {
        collection_exists(&self.db, organization, collection)
    }
    fn invitation_target(
        &mut self,
        organization: &str,
        raw_email: &str,
    ) -> rusqlite::Result<InvitationTarget<String>> {
        let email = raw_email.to_lowercase();
        Ok(match account(&self.db, &email)? {
            Some((id, has_password)) => InvitationTarget::Existing {
                already_member: member_exists(&self.db, organization, &id)?,
                account_id: id,
                has_master_password: has_password,
            },
            None => InvitationTarget::Missing {
                // Even the empty domain whitelist first requires both parts
                // of the LAST @ split. Mailbox validation follows this policy.
                domain_allowed: email
                    .rsplit_once('@')
                    .is_some_and(|(local, domain)| !local.is_empty() && !domain.is_empty()),
                email_valid: registration::valid_storage_email(&email),
            },
        })
    }
    fn commit_organization_invitation<D: OrganizationInviteData + ?Sized>(
        &mut self,
        owner: &str,
        organization: &str,
        plan: &ValidatedOrganizationInvite<'_, D, String>,
    ) -> rusqlite::Result<InviteCommit> {
        if plan.mail_enabled() {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let email = plan.email().to_lowercase();
        let tx = self.db.savepoint()?;
        let actor:Option<(i32,i32,String)>=tx.query_row("SELECT m.role,m.status,a.email FROM organization_memberships m JOIN accounts a ON a.id=m.user_id WHERE m.user_id=?1 AND m.organization_id=?2",params![owner,organization],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        let Some((role, 2, inviter)) = actor else {
            return Err(rusqlite::Error::InvalidQuery);
        };
        if !matches!(role, 0 | 1)
            || (plan.role() != 2 && role != 0)
            || plan.request().groups_len() != 0
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        for index in 0..plan.request().collections_len() {
            let selection = plan
                .request()
                .collection(index)
                .ok_or(rusqlite::Error::InvalidQuery)?;
            if !collection_exists(&tx, organization, selection.id)? {
                return Err(rusqlite::Error::InvalidQuery);
            }
        }
        let current = account(&tx, &email)?;
        if let Some((id, _)) = &current
            && member_exists(&tx, organization, id)?
        {
            return Ok(InviteCommit::AlreadyMember);
        }
        let id = match current {
            Some((id, has_password)) => {
                if plan.account_id() != Some(id.as_str())
                    || plan.creates_account()
                    || plan.membership_status() != i32::from(has_password)
                    || plan.requires_invitation() == has_password
                {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                id
            }
            None => {
                if !plan.creates_account()
                    || plan.account_id().is_some()
                    || !plan.requires_invitation()
                    || !registration::valid_storage_email(&email)
                {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                uuid::Uuid::new_v4().to_string()
            }
        };
        if plan.requires_invitation() {
            if !registration::valid_storage_email(&email) {
                return Err(rusqlite::Error::InvalidQuery);
            }
            tx.execute("INSERT INTO organization_invitations(email) VALUES(?1) ON CONFLICT(email) DO NOTHING",[&email])?;
        }
        if plan.creates_account() {
            let revision = store::now();
            let document = json!({"id":id,"email":email,"name":email,"key":"","keys":null,"masterPasswordHint":null,"kdf":0,"kdfIterations":600000,"kdfMemory":null,"kdfParallelism":null,"avatarColor":null,"userKeyId":null,"creationDate":revision,"revisionDate":revision});
            tx.execute(
                "INSERT INTO accounts(id,email,document,password,revision) VALUES(?1,?2,?3,'',?4)",
                params![id, email, document.to_string(), revision],
            )?;
        }
        let member = uuid::Uuid::new_v4().to_string();
        tx.execute("INSERT INTO organization_memberships(id,organization_id,user_id,key,role,status,access_all) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![member,organization,id,plan.key(),plan.role(),plan.membership_status(),plan.access_all()])?;
        tx.execute(
            "INSERT INTO organization_member_inviters(membership_id,email) VALUES(?1,?2)",
            params![member, inviter],
        )?;
        if !plan.access_all() {
            for index in 0..plan.request().collections_len() {
                let selection = plan
                    .request()
                    .collection(index)
                    .ok_or(rusqlite::Error::InvalidQuery)?;
                tx.execute("INSERT INTO organization_collection_users(collection_id,user_id,read_only,hide_passwords,manage) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(collection_id,user_id) DO UPDATE SET read_only=excluded.read_only,hide_passwords=excluded.hide_passwords,manage=excluded.manage",params![selection.id,id,selection.read_only,selection.hide_passwords,selection.manage])?;
            }
        }
        let revision = store::next_revision(&tx, &id)?;
        store::bump(&tx, &id, &revision)?;
        tx.commit()?;
        Ok(InviteCommit::Created)
    }
}

#[cfg(test)]
mod tests;
