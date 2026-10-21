use super::*;
use crate::{
    organization_cipher_sharing::CipherSharingCollection,
    service::ItemMetadata,
    wire::{CipherIdsRequest, CipherRequest, FolderRequest, RegisterRequest},
};
use std::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec::Vec,
};

// Provider handles intentionally do not implement Clone/Debug/Serialize.
struct Id(String);
impl AsRef<str> for Id {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
fn id(s: &str) -> Id {
    Id(s.to_string())
}
#[derive(Clone)]
struct Source {
    id: &'static str,
    owner: Option<&'static str>,
    org: Option<&'static str>,
    revision: &'static str,
}
impl Source {
    fn owned(&self) -> CipherSharingSource<Id> {
        CipherSharingSource {
            id: id(self.id),
            owner_id: self.owner.map(id),
            organization_id: self.org.map(id),
            revision: id(self.revision),
        }
    }
}
#[derive(Clone)]
struct Facts {
    canonical: &'static str,
    user: String,
    assigned: bool,
    readonly: bool,
    manage: bool,
    hole: bool,
}
impl CipherCollectionAccessData for Facts {
    fn len(&self) -> usize {
        1
    }
    fn get(&self, _: usize) -> Option<CipherCollectionAccessRecord<'_>> {
        (!self.hole).then_some(CipherCollectionAccessRecord {
            cipher_organization_id: Some(self.canonical),
            collection: CipherSharingCollection {
                id: "linked",
                user_id: &self.user,
                organization_id: "org",
                assigned: self.assigned,
                read_only: self.readonly,
                hide_passwords: false,
                manage: self.manage,
            },
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct State {
    archives: BTreeMap<String, Option<usize>>,
    account_revisions: [usize; 5],
    clock: usize,
    other_archive: Option<usize>,
    other_private: &'static str,
    favorite: bool,
    folder: &'static str,
    ciphertext: &'static str,
    key: &'static str,
    cipher_revision: &'static str,
    collection_ids: &'static str,
    deleted: bool,
}
#[derive(Clone, Copy)]
enum Live {
    Same,
    WrongId,
    Revision,
    Ownership,
    Revoke,
    NoGrant,
    WrongMember,
    WrongAssociation,
}
struct Probe {
    state: State,
    sources: BTreeMap<&'static str, Source>,
    role: i32,
    status: i32,
    full: bool,
    member_user: &'static str,
    member_org: &'static str,
    facts: Facts,
    fail: Option<&'static str>,
    fail_after_first_write: bool,
    live: Live,
    live_target: &'static str,
    calls: Vec<String>,
    cache: String,
    commits: usize,
    last_live_error: Option<ApiError>,
    observed_effect: Option<CipherArchiveRevisionEffect>,
    observed_ids: Vec<String>,
}
impl Probe {
    fn new() -> Self {
        Self {
            state: State {
                archives: BTreeMap::new(),
                account_revisions: [10, 20, 30, 40, 50],
                clock: 100,
                other_archive: Some(7),
                other_private: "other-viewer-private",
                favorite: true,
                folder: "actor-private-folder",
                ciphertext: "opaque common and nested extensions",
                key: "opaque wrapped key",
                cipher_revision: "source-revision",
                collection_ids: "unchanged links",
                deleted: false,
            },
            sources: [
                (
                    "a",
                    Source {
                        id: "a",
                        owner: None,
                        org: Some("org"),
                        revision: "source-revision",
                    },
                ),
                (
                    "z",
                    Source {
                        id: "z",
                        owner: None,
                        org: Some("org"),
                        revision: "source-revision",
                    },
                ),
                (
                    "personal",
                    Source {
                        id: "personal",
                        owner: Some("actor"),
                        org: None,
                        revision: "source-revision",
                    },
                ),
                (
                    "foreign",
                    Source {
                        id: "foreign",
                        owner: Some("someone-else"),
                        org: None,
                        revision: "source-revision",
                    },
                ),
            ]
            .into_iter()
            .collect(),
            role: 2,
            status: 2,
            full: false,
            member_user: "actor",
            member_org: "org",
            facts: Facts {
                canonical: "org",
                user: "actor".to_string(),
                assigned: true,
                readonly: true,
                manage: false,
                hole: false,
            },
            fail: None,
            fail_after_first_write: false,
            live: Live::Same,
            live_target: "a",
            calls: Vec::new(),
            cache: String::new(),
            commits: 0,
            last_live_error: None,
            observed_effect: None,
            observed_ids: Vec::new(),
        }
    }
    fn touch(&mut self, name: &'static str, key: &str) -> Result<(), ()> {
        self.cache = format!("{name} overwrites lookup cache {key}");
        self.calls.push(format!("{name}:{key}"));
        if self.fail == Some(name) {
            Err(())
        } else {
            Ok(())
        }
    }
    fn member(&self) -> CipherSharingMembership<Id> {
        CipherSharingMembership {
            user_id: id(self.member_user),
            organization_id: id(self.member_org),
            role: self.role,
            status: self.status,
            access_all: self.full,
        }
    }
    fn single(&mut self, cipher: &str, op: CipherArchiveOperation) -> Result<(), ApiError> {
        VaultService::new(self).archive_cipher("actor", cipher, op)
    }
    fn selected(&mut self, ids: &[&str], op: CipherArchiveOperation) -> Result<usize, ApiError> {
        let mut scratch = [""; 8];
        let mut sources = [const { None }; 8];
        VaultService::new(self).archive_selected_ciphers(
            "actor",
            op,
            ids.iter().copied(),
            &mut scratch,
            &mut sources,
        )
    }
}
impl Storage for Probe {
    type Error = ();
    fn map_error(_: ()) -> ApiError {
        ApiError::new(ErrorKind::Storage, "Archive provider failure")
    }
    fn account_exists(&mut self, _: &str) -> Result<bool, ()> {
        unreachable!()
    }
    fn insert_account(&mut self, _: &str, _: &RegisterRequest<'_>) -> Result<(), ()> {
        unreachable!()
    }
    fn folder_metadata(&mut self, _: &str) -> Result<Option<ItemMetadata<'_>>, ()> {
        unreachable!()
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
impl CipherArchiveStorage for Probe {
    type ArchiveId = Id;
    type ArchiveAccess = Facts;
    fn cipher_archive_source(
        &mut self,
        cipher: &str,
    ) -> Result<Option<CipherSharingSource<Id>>, ()> {
        self.touch("source", cipher)?;
        Ok(self.sources.get(cipher).map(Source::owned))
    }
    fn cipher_archive_membership(
        &mut self,
        _: &str,
        org: &str,
    ) -> Result<Option<CipherSharingMembership<Id>>, ()> {
        self.touch("member", org)?;
        Ok(Some(self.member()))
    }
    fn cipher_archive_collections(
        &mut self,
        actor: &str,
        _: &CipherSharingSource<Id>,
    ) -> Result<Facts, ()> {
        self.touch("collections", actor)?;
        Ok(self.facts.clone())
    }
    fn commit_cipher_archive(&mut self, plan: &ValidatedCipherArchive<'_, Id>) -> Result<(), ()> {
        self.touch("commit", plan.actor())?;
        self.commits += 1;
        self.observed_effect = Some(plan.revision_effect());
        self.observed_ids = (0..plan.len())
            .map(|i| plan.target(i).unwrap().cipher_id().to_string())
            .collect();
        assert!(plan.target(plan.len()).is_none());
        assert!(!plan.is_empty());
        // Complete live admission before any staged writes. No request body or clock
        // participates in core authority; mutation and fanout stay provider-owned.
        for i in 0..plan.len() {
            let target = plan.target(i).unwrap();
            let mut source = self.sources[target.cipher_id()].owned();
            let mut member = self.member();
            let mut access = self.facts.clone();
            if target.cipher_id() == self.live_target {
                match self.live {
                    Live::Same => {}
                    Live::WrongId => source.id = id("different"),
                    Live::Revision => source.revision = id("new-revision"),
                    Live::Ownership => {
                        source.owner_id = Some(id("actor"));
                        source.organization_id = None;
                    }
                    Live::Revoke => member.status = -1,
                    Live::NoGrant => access.assigned = false,
                    Live::WrongMember => member.organization_id = id("other-org"),
                    Live::WrongAssociation => access.canonical = "other-org",
                }
            }
            let empty: &[CipherCollectionAccessRecord<'_>] = &[];
            let live_result = if source.organization_id.is_some() {
                target.validate_live(&source, Some(member.view()), &access)
            } else {
                target.validate_live(&source, None, empty)
            };
            if let Err(error) = live_result {
                self.last_live_error = Some(error);
                return Err(());
            }
        }
        let mut staged = self.state.clone();
        for i in 0..plan.len() {
            let target = plan.target(i).unwrap();
            staged.clock += 1;
            staged.archives.insert(
                target.cipher_id().to_string(),
                match plan.operation() {
                    CipherArchiveOperation::Archive => Some(staged.clock),
                    CipherArchiveOperation::Unarchive => None,
                },
            );
            if self.fail_after_first_write {
                return Err(());
            }
        }
        // In this measured-shaped fixture only the Owner and acting readonly User
        // are current readers; confirmed no-grant/Accepted/Revoked do not fan out.
        staged.account_revisions[0] += 1;
        if plan.revision_effect() == CipherArchiveRevisionEffect::CurrentReaders
            && plan.target(0).unwrap().organization_id().is_some()
        {
            staged.account_revisions[1] += 1;
        }
        self.state = staged;
        Ok(())
    }
}

#[test]
fn single_readonly_archive_and_repeated_unarchive_refresh_current_readers_only() {
    let mut p = Probe::new();
    let before = p.state.clone();
    p.single("a", CipherArchiveOperation::Archive).unwrap();
    let first = p.state.archives["a"];
    p.single("a", CipherArchiveOperation::Archive).unwrap();
    assert!(p.state.archives["a"] > first);
    p.single("a", CipherArchiveOperation::Unarchive).unwrap();
    p.single("a", CipherArchiveOperation::Unarchive).unwrap();
    assert_eq!(p.state.archives["a"], None);
    let mut expected = before;
    expected.archives.insert("a".to_string(), None);
    expected.clock += 4;
    expected.account_revisions[0] += 4;
    expected.account_revisions[1] += 4;
    assert_eq!(p.state, expected);
    assert_eq!(
        p.observed_effect,
        Some(CipherArchiveRevisionEffect::CurrentReaders)
    );
}
#[test]
fn one_selected_cipher_refreshes_actor_only_and_preserves_all_common_private_state() {
    let mut p = Probe::new();
    let mut expected = p.state.clone();
    assert_eq!(
        p.selected(&["a"], CipherArchiveOperation::Archive).unwrap(),
        1
    );
    expected.clock += 1;
    expected
        .archives
        .insert("a".to_string(), Some(expected.clock));
    expected.account_revisions[0] += 1;
    assert_eq!(p.state, expected);
    assert_eq!(
        p.observed_effect,
        Some(CipherArchiveRevisionEffect::ActorOnly)
    );
}
#[test]
fn selection_deduplicates_exact_ids_and_empty_never_calls_provider() {
    let mut p = Probe::new();
    assert_eq!(p.selected(&[], CipherArchiveOperation::Archive).unwrap(), 0);
    assert!(p.calls.is_empty());
    assert_eq!(
        p.selected(&["z", "a", "z", "a"], CipherArchiveOperation::Unarchive)
            .unwrap(),
        2
    );
    assert_eq!(p.observed_ids, ["a", "z"]);
    assert_eq!(p.commits, 1);
    assert_eq!(p.state.account_revisions, [11, 20, 30, 40, 50]);
    let before = p.state.clone();
    assert!(p.selected(&["A"], CipherArchiveOperation::Archive).is_err());
    assert_eq!(p.state, before);
}
#[test]
fn complete_selection_admission_rejects_late_missing_or_foreign_before_commit() {
    for ids in [["a", "zz-missing"], ["a", "foreign"], ["zz-missing", "a"]] {
        let mut p = Probe::new();
        let before = p.state.clone();
        assert!(p.selected(&ids, CipherArchiveOperation::Archive).is_err());
        assert_eq!(p.commits, 0);
        assert_eq!(p.state, before);
    }
}
#[test]
fn confirmed_roles_and_readonly_manage_do_not_require_write_permission() {
    for (role, full, readonly, manage) in [
        (0, false, true, false),
        (1, false, true, false),
        (4, true, true, false),
        (3, false, true, false),
        (2, false, true, false),
        (2, false, true, true),
        (2, false, false, false),
    ] {
        let mut p = Probe::new();
        p.role = role;
        p.full = full;
        p.facts.readonly = readonly;
        p.facts.manage = manage;
        p.single("a", CipherArchiveOperation::Archive).unwrap();
    }
}
#[test]
fn no_grant_accepted_revoked_and_foreign_personal_deny_without_mutation() {
    for status in [0, 1, -1] {
        let mut p = Probe::new();
        p.status = status;
        p.role = 1;
        let before = p.state.clone();
        assert!(p.single("a", CipherArchiveOperation::Archive).is_err());
        assert_eq!(p.state, before);
        assert_eq!(p.commits, 0);
    }
    let mut p = Probe::new();
    p.facts.assigned = false;
    assert!(p.single("a", CipherArchiveOperation::Unarchive).is_err());
    assert!(
        p.single("foreign", CipherArchiveOperation::Archive)
            .is_err()
    );
    assert_eq!(p.commits, 0);
}
#[test]
fn personal_owner_uses_no_shared_provider_facts_and_keeps_cipher_revision() {
    let mut p = Probe::new();
    let before = p.state.clone();
    p.single("personal", CipherArchiveOperation::Archive)
        .unwrap();
    assert_eq!(p.calls, ["source:personal", "commit:actor"]);
    assert_eq!(p.state.cipher_revision, before.cipher_revision);
    assert_eq!(p.state.account_revisions, [11, 20, 30, 40, 50]);
}
#[test]
fn inconsistent_source_id_ownership_or_revision_is_storage_error() {
    for mode in 0..4 {
        let mut p = Probe::new();
        let row = p.sources.get_mut("a").unwrap();
        match mode {
            0 => row.id = "other",
            1 => row.revision = "",
            2 => row.owner = Some("actor"),
            _ => row.org = None,
        };
        let before = p.state.clone();
        assert_eq!(
            p.single("a", CipherArchiveOperation::Archive)
                .unwrap_err()
                .kind,
            ErrorKind::Storage
        );
        assert_eq!(p.state, before);
        assert_eq!(p.commits, 0);
    }
}
#[test]
fn membership_and_association_identity_scope_and_holes_fail_closed() {
    for mode in 0..5 {
        let mut p = Probe::new();
        match mode {
            0 => p.member_user = "other",
            1 => p.member_org = "other",
            2 => p.facts.canonical = "other",
            3 => p.facts.user = "other".to_string(),
            _ => p.facts.hole = true,
        };
        assert_eq!(
            p.single("a", CipherArchiveOperation::Archive)
                .unwrap_err()
                .kind,
            ErrorKind::Storage
        );
        assert_eq!(p.commits, 0);
    }
}
#[test]
fn provider_lookup_and_commit_failures_preserve_persistent_state() {
    for call in ["source", "member", "collections", "commit"] {
        let mut p = Probe::new();
        p.fail = Some(call);
        let before = p.state.clone();
        assert_eq!(
            p.single("a", CipherArchiveOperation::Archive)
                .unwrap_err()
                .kind,
            ErrorKind::Storage
        );
        assert_eq!(p.state, before);
    }
}
#[test]
fn live_exact_source_and_read_rechecks_reject_each_race_before_annotations() {
    for live in [
        Live::WrongId,
        Live::Revision,
        Live::Ownership,
        Live::Revoke,
        Live::NoGrant,
        Live::WrongMember,
        Live::WrongAssociation,
    ] {
        let mut p = Probe::new();
        p.live = live;
        p.live_target = "z";
        let before = p.state.clone();
        assert!(
            p.selected(&["z", "a"], CipherArchiveOperation::Archive)
                .is_err()
        );
        assert!(p.last_live_error.is_some());
        assert_eq!(p.state, before);
    }
}
#[test]
fn transaction_failure_after_annotation_write_rolls_back_every_selected_target() {
    let mut p = Probe::new();
    p.fail_after_first_write = true;
    let before = p.state.clone();
    assert!(
        p.selected(&["a", "z"], CipherArchiveOperation::Archive)
            .is_err()
    );
    assert_eq!(p.state, before);
    p.fail_after_first_write = false;
    assert_eq!(
        p.selected(&["a", "z"], CipherArchiveOperation::Archive)
            .unwrap(),
        2
    );
}
#[test]
fn caller_raw_id_capacity_and_unique_owned_slots_fail_before_provider_lookups() {
    let mut p = Probe::new();
    let mut ids = [""; 1];
    let mut sources = [const { None }; 2];
    assert!(
        VaultService::new(&mut p)
            .archive_selected_ciphers(
                "actor",
                CipherArchiveOperation::Archive,
                ["a", "a"],
                &mut ids,
                &mut sources
            )
            .is_err()
    );
    assert!(p.calls.is_empty());
    let mut ids = [""; 2];
    let mut sources = [];
    assert!(
        VaultService::new(&mut p)
            .archive_selected_ciphers(
                "actor",
                CipherArchiveOperation::Archive,
                ["a"],
                &mut ids,
                &mut sources
            )
            .is_err()
    );
    assert!(p.calls.is_empty());
}
#[test]
fn cache_reusing_owned_nonclone_snapshots_bind_all_targets_through_commit() {
    let mut p = Probe::new();
    p.selected(&["z", "a"], CipherArchiveOperation::Archive)
        .unwrap();
    assert_eq!(p.observed_ids, ["a", "z"]);
    assert!(p.cache.contains("commit overwrites"));
    assert_eq!(
        p.calls.iter().filter(|x| x.starts_with("source:")).count(),
        2
    );
}
#[test]
fn existing_borrowed_ids_body_decodes_and_reaches_real_archive_service() {
    let body = serde_json::from_str::<CipherIdsRequest<'_, 4>>(r#"{"ids":["z","a","z"]}"#).unwrap();
    let mut p = Probe::new();
    let mut ids = [""; 4];
    let mut sources = [const { None }; 2];
    assert_eq!(
        VaultService::new(&mut p)
            .archive_selected_ciphers(
                "actor",
                CipherArchiveOperation::Archive,
                body.ids.iter().copied(),
                &mut ids,
                &mut sources
            )
            .unwrap(),
        2
    );
}
#[test]
fn unauthenticated_actor_precedes_provider_and_plan_debug_redacts_snapshots() {
    let mut p = Probe::new();
    assert!(
        VaultService::new(&mut p)
            .archive_cipher("", "a", CipherArchiveOperation::Archive)
            .is_err()
    );
    assert!(p.calls.is_empty());
    let source = p.sources["a"].owned();
    let plan = ValidatedCipherArchive {
        actor: "actor",
        operation: CipherArchiveOperation::Archive,
        targets: Targets::Single(&source),
    };
    assert_eq!(format!("{plan:?}"), "ValidatedCipherArchive([REDACTED])");
    assert_eq!(
        format!("{:?}", plan.target(0).unwrap()),
        "CipherArchiveTarget([REDACTED])"
    );
}
