use super::*;
use crate::{
    organization_cipher_sharing::{
        CipherCollectionAccessRecord, CipherSharingCollection, resolve_cipher_access,
    },
    service::ItemMetadata,
    wire::{CipherRequest, FolderRequest, OrganizationCipherUpdateRequest, RegisterRequest},
};
use std::{
    format,
    string::{String, ToString},
    vec::Vec,
};

// Owned provider handles deliberately do not implement Clone, Debug or Serialize.
struct Id(String);
impl AsRef<str> for Id {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
fn id(value: &str) -> Id {
    Id(value.to_string())
}
struct Access {
    outer: String,
    user: String,
    org: String,
    len: usize,
    assigned: bool,
    readonly: bool,
    manage: bool,
    wrong_outer: bool,
    wrong_user: bool,
    hole: bool,
}
impl CipherCollectionAccessData for Access {
    fn len(&self) -> usize {
        self.len
    }
    fn get(&self, index: usize) -> Option<CipherCollectionAccessRecord<'_>> {
        if index >= self.len || self.hole {
            return None;
        }
        Some(CipherCollectionAccessRecord {
            cipher_organization_id: Some(if self.wrong_outer {
                "foreign"
            } else {
                &self.outer
            }),
            collection: CipherSharingCollection {
                id: "associated",
                user_id: if self.wrong_user {
                    "foreign"
                } else {
                    &self.user
                },
                organization_id: &self.org,
                assigned: self.assigned && index + 1 == self.len,
                read_only: self.readonly,
                hide_passwords: false,
                manage: self.manage,
            },
        })
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct State {
    payload: String,
    favorite: bool,
    folder: Option<String>,
    other_favorite: bool,
    other_folder: Option<String>,
    cipher_revision: u32,
    account_revisions: [u32; 3],
    organization: String,
    associations: Vec<String>,
    keys: String,
}
struct Memory {
    calls: Vec<&'static str>,
    cache: String,
    cipher: String,
    source_present: bool,
    source_owner: Option<&'static str>,
    source_org: Option<&'static str>,
    bad_source_id: bool,
    empty_revision: bool,
    member: Option<(i32, i32, bool)>,
    wrong_member_user: bool,
    wrong_member_org: bool,
    readonly: bool,
    manage: bool,
    assigned: bool,
    rows: usize,
    wrong_outer: bool,
    wrong_collection_user: bool,
    access_hole: bool,
    folder_owner: Option<&'static str>,
    failure: Option<&'static str>,
    live_allowed: bool,
    live_revision: &'static str,
    fail_late: bool,
    pending_payload: String,
    pending_favorite: Option<bool>,
    state: State,
    commits: usize,
}
impl Memory {
    fn new() -> Self {
        Self {
            calls: Vec::new(),
            cache: String::new(),
            cipher: "cipher".to_string(),
            source_present: true,
            source_owner: None,
            source_org: Some("org"),
            bad_source_id: false,
            empty_revision: false,
            member: Some((2, 2, false)),
            wrong_member_user: false,
            wrong_member_org: false,
            readonly: false,
            manage: false,
            assigned: true,
            rows: 1,
            wrong_outer: false,
            wrong_collection_user: false,
            access_hole: false,
            folder_owner: Some("actor"),
            failure: None,
            live_allowed: true,
            live_revision: "r1",
            fail_late: false,
            pending_payload: "opaque replacement with retained key and extensions".to_string(),
            pending_favorite: None,
            state: State {
                payload: "opaque original".to_string(),
                favorite: true,
                folder: Some("old actor folder".to_string()),
                other_favorite: true,
                other_folder: Some("other viewer folder".to_string()),
                cipher_revision: 1,
                account_revisions: [1, 1, 1],
                organization: "org".to_string(),
                associations: std::vec!["existing".to_string()],
                keys: "unchanged account keys".to_string(),
            },
            commits: 0,
        }
    }
    fn call(&mut self, step: &'static str) -> Result<(), ()> {
        self.calls.push(step);
        self.cache = step.repeat(10_000);
        if self.failure == Some(step) {
            Err(())
        } else {
            Ok(())
        }
    }
}
impl Storage for Memory {
    type Error = ();
    fn account_exists(&mut self, _: &str) -> Result<bool, ()> {
        unreachable!()
    }
    fn insert_account(&mut self, _: &str, _: &RegisterRequest<'_>) -> Result<(), ()> {
        unreachable!()
    }
    fn folder_metadata(&mut self, _: &str) -> Result<Option<ItemMetadata<'_>>, ()> {
        self.call("folder")?;
        Ok(self.folder_owner.map(|owner_id| ItemMetadata {
            owner_id,
            deleted: false,
        }))
    }
    fn save_folder(&mut self, _: &str, _: &str, _: &FolderRequest<'_>) -> Result<(), ()> {
        unreachable!()
    }
    fn delete_folder(&mut self, _: &str, _: &str) -> Result<(), ()> {
        unreachable!()
    }
    fn cipher_metadata(&mut self, _: &str) -> Result<Option<ItemMetadata<'_>>, ()> {
        unreachable!()
    }
    fn save_cipher(&mut self, _: &str, _: &str, _: &CipherRequest<'_>) -> Result<(), ()> {
        unreachable!()
    }
    fn set_cipher_deleted(&mut self, _: &str, _: &str, _: bool) -> Result<(), ()> {
        unreachable!()
    }
    fn delete_cipher(&mut self, _: &str, _: &str) -> Result<(), ()> {
        unreachable!()
    }
}
impl OrganizationCipherUpdateStorage for Memory {
    type UpdateId = Id;
    type UpdateAccess = Access;
    fn organization_cipher_update_source(
        &mut self,
        path: &str,
    ) -> Result<Option<CipherSharingSource<Id>>, ()> {
        self.call("source")?;
        Ok(self.source_present.then(|| CipherSharingSource {
            id: id(if self.bad_source_id { "foreign" } else { path }),
            owner_id: self.source_owner.map(id),
            organization_id: self.source_org.map(id),
            revision: id(if self.empty_revision { "" } else { "r1" }),
        }))
    }
    fn organization_cipher_update_membership(
        &mut self,
        user: &str,
        organization: &str,
    ) -> Result<Option<CipherSharingMembership<Id>>, ()> {
        self.call("membership")?;
        Ok(self
            .member
            .map(|(role, status, access_all)| CipherSharingMembership {
                user_id: id(if self.wrong_member_user {
                    "foreign"
                } else {
                    user
                }),
                organization_id: id(if self.wrong_member_org {
                    "foreign"
                } else {
                    organization
                }),
                role,
                status,
                access_all,
            }))
    }
    fn organization_cipher_update_collections(
        &mut self,
        user: &str,
        source: &CipherSharingSource<Id>,
    ) -> Result<Access, ()> {
        self.call("access")?;
        Ok(Access {
            outer: source
                .organization_id
                .as_ref()
                .unwrap()
                .as_ref()
                .to_string(),
            user: user.to_string(),
            org: "org".to_string(),
            len: self.rows,
            assigned: self.assigned,
            readonly: self.readonly,
            manage: self.manage,
            wrong_outer: self.wrong_outer,
            wrong_user: self.wrong_collection_user,
            hole: self.access_hole,
        })
    }
    fn organization_cipher_update_revision_is_older(
        &mut self,
        source: &CipherSharingSource<Id>,
        requested: Option<&str>,
    ) -> Result<bool, ()> {
        self.call("revision")?;
        assert_eq!(source.id.as_ref(), self.cipher);
        assert_eq!(source.revision.as_ref(), "r1");
        // Comparison stands in for adapter date parsing; the core sees no clock.
        Ok(requested == Some("older"))
    }
    fn commit_organization_cipher_update<D: OrganizationCipherUpdateData + ?Sized>(
        &mut self,
        plan: &ValidatedOrganizationCipherUpdate<'_, D>,
    ) -> Result<(), ()> {
        self.call("commit")?;
        assert_eq!(
            format!("{plan:?}"),
            "ValidatedOrganizationCipherUpdate([REDACTED])"
        );
        assert_eq!(plan.owner(), "actor");
        assert_eq!(plan.cipher_id(), self.cipher);
        assert_eq!(plan.organization_id(), "org");
        assert_eq!(plan.source_revision(), "r1");
        assert_eq!(plan.view().organization_id, Some("org"));
        assert_eq!(plan.request().update_view().folder_id, plan.folder_id());
        assert_eq!(
            plan.request().update_view().last_known_revision_date,
            plan.last_known_revision_date()
        );
        if !self.live_allowed || self.live_revision != plan.source_revision() {
            return Err(());
        }
        let mut staged = self.state.clone();
        staged.payload = self.pending_payload.clone();
        if let Some(value) = self.pending_favorite {
            staged.favorite = value;
        }
        staged.folder = plan.folder_id().map(ToString::to_string);
        staged.cipher_revision += 1;
        staged.account_revisions[0] += 1;
        staged.account_revisions[1] += 1;
        if self.fail_late {
            return Err(());
        }
        self.state = staged;
        self.commits += 1;
        Ok(())
    }
}
fn request() -> OrganizationCipherUpdateRequest<'static> {
    OrganizationCipherUpdateRequest {
        kind: 2,
        name: "opaque",
        encrypted_for: "actor",
        favorite: None,
        organization_id: Some("org"),
        folder_id: Some("folder"),
        last_known_revision_date: Some("same"),
        secure_note: Some(serde::de::IgnoredAny),
    }
}
fn run(memory: &mut Memory, request: &impl OrganizationCipherUpdateData) -> Result<(), ApiError> {
    let path = memory.cipher.clone();
    VaultService::new(memory).update_organization_cipher("actor", &path, request)
}

#[test]
fn readonly_manage_updates_without_changing_get_edit_flags() {
    let mut m = Memory::new();
    m.readonly = true;
    m.manage = true;
    let source = m
        .organization_cipher_update_source("cipher")
        .unwrap()
        .unwrap();
    let facts = m
        .organization_cipher_update_collections("actor", &source)
        .unwrap();
    let member = CipherSharingMembership {
        user_id: "actor",
        organization_id: "org",
        role: 2,
        status: 2,
        access_all: false,
    };
    let get = resolve_cipher_access(
        "actor",
        CipherOwnership::Organization {
            organization_id: "org",
        },
        Some(member),
        &facts,
    )
    .unwrap();
    assert!(get.readable());
    assert!(!get.writable());
    assert!(!get.delete());
    m.calls.clear();
    run(&mut m, &request()).unwrap();
    assert_eq!(m.commits, 1);
    assert_eq!(
        m.calls,
        [
            "source",
            "membership",
            "access",
            "revision",
            "folder",
            "commit"
        ]
    );
}
#[test]
fn measured_full_and_direct_grant_roles_require_confirmation() {
    for (role, status, full, assigned, readonly, manage, allowed) in [
        (0, 2, false, false, true, false, true),
        (1, 2, false, false, true, false, true),
        (4, 2, true, false, true, false, true),
        (2, 2, false, true, false, false, true),
        (2, 2, false, true, true, true, true),
        (2, 2, false, true, true, false, false),
        (2, 2, false, false, false, false, false),
        (2, 1, false, true, false, true, false),
        (2, -1, false, true, false, true, false),
    ] {
        let mut m = Memory::new();
        m.member = Some((role, status, full));
        m.assigned = assigned;
        m.readonly = readonly;
        m.manage = manage;
        let before = m.state.clone();
        assert_eq!(run(&mut m, &request()).is_ok(), allowed);
        if !allowed {
            assert_eq!(m.state, before);
            assert_eq!(m.commits, 0);
            assert!(!m.calls.contains(&"revision"));
        }
    }
    let mut m = Memory::new();
    m.member = None;
    assert!(run(&mut m, &request()).is_err());
    assert_eq!(m.commits, 0);
}
#[test]
fn authority_precedes_revision_and_organization_precedes_folder() {
    let mut r = request();
    r.last_known_revision_date = Some("older");
    r.organization_id = Some("foreign");
    r.folder_id = Some("foreign");
    let mut m = Memory::new();
    m.readonly = true;
    assert_eq!(run(&mut m, &r).unwrap_err().field, Some("cipher"));
    assert!(!m.calls.contains(&"revision"));
    let mut m = Memory::new();
    assert_eq!(
        run(&mut m, &r).unwrap_err().field,
        Some("lastKnownRevisionDate")
    );
    assert!(!m.calls.contains(&"folder"));
    r.last_known_revision_date = Some("malformed");
    let mut m = Memory::new();
    assert_eq!(run(&mut m, &r).unwrap_err().field, Some("organizationId"));
    assert!(!m.calls.contains(&"folder"));
    r.organization_id = Some("org");
    let mut m = Memory::new();
    m.folder_owner = Some("foreign");
    assert_eq!(run(&mut m, &r).unwrap_err().field, Some("folderId"));
    assert_eq!(m.commits, 0);
}
#[test]
fn absent_revision_skips_comparison_and_adapter_accepted_values_are_not_cas() {
    for revision in [None, Some("malformed"), Some("future"), Some("same")] {
        let mut m = Memory::new();
        let mut r = request();
        r.last_known_revision_date = revision;
        run(&mut m, &r).unwrap();
        assert_eq!(m.calls.contains(&"revision"), revision.is_some());
        assert_eq!(m.commits, 1);
    }
}
#[test]
fn source_scope_and_private_api_boundary_fail_closed() {
    let mut m = Memory::new();
    let e = VaultService::new(&mut m)
        .update_organization_cipher("", "cipher", &request())
        .unwrap_err();
    assert_eq!(e.kind, ErrorKind::Unauthorized);
    assert!(m.calls.is_empty());
    for variant in 0..6 {
        let mut m = Memory::new();
        match variant {
            0 => m.source_present = false,
            1 => {
                m.source_owner = Some("actor");
                m.source_org = None
            }
            2 => m.source_owner = Some("actor"),
            3 => m.source_org = None,
            4 => m.bad_source_id = true,
            _ => m.empty_revision = true,
        }
        let before = m.state.clone();
        assert!(run(&mut m, &request()).is_err());
        assert_eq!(m.state, before);
        assert_eq!(m.commits, 0);
        assert_eq!(m.calls, ["source"]);
    }
}
#[test]
fn membership_and_association_snapshot_scope_is_validated() {
    for variant in 0..5 {
        let mut m = Memory::new();
        match variant {
            0 => m.wrong_member_user = true,
            1 => m.wrong_member_org = true,
            2 => m.wrong_outer = true,
            3 => m.wrong_collection_user = true,
            _ => m.access_hole = true,
        }
        let e = run(&mut m, &request()).unwrap_err();
        assert_eq!(e.kind, ErrorKind::Storage);
        assert_eq!(m.commits, 0);
        assert!(!m.calls.contains(&"revision"));
    }
}
#[test]
fn missing_and_foreign_folders_never_reach_commit() {
    for owner in [None, Some("foreign")] {
        let mut m = Memory::new();
        m.folder_owner = owner;
        let before = m.state.clone();
        let e = run(&mut m, &request()).unwrap_err();
        assert_eq!(e.field, Some("folderId"));
        assert_eq!(m.state, before);
        assert_eq!(m.commits, 0);
    }
}
#[test]
fn provider_failures_propagate_before_mutation() {
    for failure in [
        "source",
        "membership",
        "access",
        "revision",
        "folder",
        "commit",
    ] {
        let mut m = Memory::new();
        m.failure = Some(failure);
        let before = m.state.clone();
        assert_eq!(
            run(&mut m, &request()).unwrap_err().kind,
            ErrorKind::Storage
        );
        assert_eq!(m.state, before);
        assert_eq!(m.commits, 0);
        assert_eq!(m.calls.last(), Some(&failure));
    }
}
#[test]
fn atomic_commit_rechecks_live_facts_and_rolls_back_late_failure() {
    for variant in 0..3 {
        let mut m = Memory::new();
        match variant {
            0 => m.live_allowed = false,
            1 => m.live_revision = "changed",
            _ => m.fail_late = true,
        }
        let before = m.state.clone();
        assert!(run(&mut m, &request()).is_err());
        assert_eq!(m.calls.last(), Some(&"commit"));
        assert_eq!(m.state, before);
        assert_eq!(m.commits, 0);
    }
}
#[test]
fn successful_commit_preserves_other_viewers_links_keys_and_optional_favorite() {
    for favorite in [None, Some(false), Some(true)] {
        let mut m = Memory::new();
        m.pending_favorite = favorite;
        let before = m.state.clone();
        let mut r = request();
        r.folder_id = None;
        run(&mut m, &r).unwrap();
        assert_eq!(m.state.payload, m.pending_payload);
        assert_eq!(m.state.favorite, favorite.unwrap_or(true));
        assert_eq!(m.state.folder, None);
        assert_eq!(m.state.other_favorite, before.other_favorite);
        assert_eq!(m.state.other_folder, before.other_folder);
        assert_eq!(m.state.keys, before.keys);
        assert_eq!(m.state.associations, before.associations);
        assert_eq!(m.state.organization, before.organization);
        assert_eq!(m.state.account_revisions, [2, 2, 1]);
        assert_eq!(m.state.cipher_revision, 2);
    }
}
#[test]
fn owned_snapshots_survive_cache_reuse_and_unbounded_indexed_access() {
    let mut m = Memory::new();
    m.cipher = "c".repeat(10_000);
    m.rows = 10_001;
    m.readonly = true;
    m.manage = true;
    run(&mut m, &request()).unwrap();
    assert_eq!(m.commits, 1);
    assert_eq!(m.cache, "commit".repeat(10_000));
}
#[test]
fn reused_service_does_not_reuse_prior_authority() {
    let mut m = Memory::new();
    let mut service = VaultService::new(&mut m);
    service
        .update_organization_cipher("actor", "cipher", &request())
        .unwrap();
    let before = service.storage().state.clone();
    service.storage_mut().member = Some((2, -1, false));
    assert!(
        service
            .update_organization_cipher("actor", "cipher", &request())
            .is_err()
    );
    assert_eq!(service.storage().state, before);
    assert_eq!(service.storage().commits, 1);
}
#[test]
fn borrowed_decoder_requires_schema_and_redacts_without_round_trip_claim() {
    let raw = r#"{"type":2,"name":"opaque","encryptedFor":"actor","organizationId":"org","folderId":"folder","lastKnownRevisionDate":"future","id":"ignored","collectionIds":["forged"]}"#;
    let r: OrganizationCipherUpdateRequest<'_> = serde_json::from_str(raw).unwrap();
    assert_eq!(
        format!("{r:?}"),
        "OrganizationCipherUpdateRequest([REDACTED])"
    );
    assert_eq!(
        format!("{:?}", r.update_view()),
        "OrganizationCipherUpdateView([REDACTED])"
    );
    assert!(r.favorite.is_none());
    for value in [
        r.name,
        r.encrypted_for,
        r.organization_id.unwrap(),
        r.folder_id.unwrap(),
        r.last_known_revision_date.unwrap(),
    ] {
        let offset = value.as_ptr() as usize - raw.as_ptr() as usize;
        assert!(offset + value.len() <= raw.len());
    }
    for invalid in [
        r#"{}"#,
        r#"{"type":2,"name":"opaque"}"#,
        r#"{"type":2,"name":"opaque","encryptedFor":null}"#,
        r#"{"type":"wrong","name":"opaque","encryptedFor":"actor"}"#,
    ] {
        assert!(serde_json::from_str::<OrganizationCipherUpdateRequest<'_>>(invalid).is_err());
    }
}

#[test]
fn required_note_semantics_follow_authority_revision_organization_and_folder() {
    let mut r = request();
    r.secure_note = None;
    let mut m = Memory::new();
    assert_eq!(run(&mut m, &r).unwrap_err().field, Some("secureNote"));
    assert_eq!(m.calls.last(), Some(&"folder"));
    assert_eq!(m.commits, 0);
    let mut m = Memory::new();
    m.readonly = true;
    assert_eq!(run(&mut m, &r).unwrap_err().field, Some("cipher"));
    let mut m = Memory::new();
    r.last_known_revision_date = Some("older");
    assert_eq!(
        run(&mut m, &r).unwrap_err().field,
        Some("lastKnownRevisionDate")
    );
    let mut m = Memory::new();
    r.last_known_revision_date = None;
    r.organization_id = Some("foreign");
    assert_eq!(run(&mut m, &r).unwrap_err().field, Some("organizationId"));
    let mut m = Memory::new();
    r.organization_id = Some("org");
    m.folder_owner = None;
    assert_eq!(run(&mut m, &r).unwrap_err().field, Some("folderId"));
    for value in ["null", "{}", r#""opaque""#, "17"] {
        let raw = format!(
            r#"{{"type":2,"name":"","encryptedFor":"","organizationId":"org","secureNote":{value}}}"#
        );
        let decoded: OrganizationCipherUpdateRequest<'_> = serde_json::from_str(&raw).unwrap();
        assert_eq!(decoded.update_view().secure_note_present, value != "null");
    }
}
