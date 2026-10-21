use super::*;
use crate::{
    organization_cipher_sharing::{CipherSharingCollection, resolve_cipher_access},
    service::ItemMetadata,
    wire::{CipherRequest, FolderRequest, RegisterRequest},
};
use std::{
    format,
    string::{String, ToString},
    vec::Vec,
};

// No Clone/Debug/serde: source and membership handles cannot borrow reused caches.
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
struct Facts {
    user: String,
    canonical: &'static str,
    actual: &'static str,
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
                organization_id: self.actual,
                assigned: self.assigned,
                read_only: self.readonly,
                hide_passwords: false,
                manage: self.manage,
            },
        })
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct State {
    present: bool,
    revision: u64,
    deleted: Option<u64>,
    clock: u64,
    ciphertext: &'static str,
    key: &'static str,
    archives: [Option<u64>; 3],
    folders: [Option<&'static str>; 3],
    favorites: [bool; 3],
    links: usize,
    account_revisions: [u64; 6],
    unrelated: &'static str,
}
#[derive(Clone, Copy)]
enum Live {
    Same,
    Identity,
    Revision,
    Ownership,
    Revoke,
    RemoveGrant,
    RemoveManage,
    WrongMember,
    WrongAssociation,
}
struct Probe {
    state: State,
    source_id: &'static str,
    owner: Option<&'static str>,
    org: Option<&'static str>,
    revision_override: Option<&'static str>,
    member_present: bool,
    member_user: &'static str,
    member_org: &'static str,
    role: i32,
    status: i32,
    full: bool,
    facts: Facts,
    fail: Option<&'static str>,
    late_failure: bool,
    live: Live,
    live_error: Option<ApiError>,
    cache: String,
    calls: Vec<&'static str>,
    commits: usize,
    operation: Option<CipherLifecycleOperation>,
}
impl Probe {
    fn new() -> Self {
        Self {
            state: State {
                present: true,
                revision: 10,
                deleted: None,
                clock: 20,
                ciphertext: "opaque encrypted nested payload",
                key: "opaque wrapped key",
                archives: [Some(1), Some(2), Some(3)],
                folders: [
                    Some("actor-folder"),
                    Some("owner-folder"),
                    Some("readonly-folder"),
                ],
                favorites: [false, true, true],
                links: 2,
                account_revisions: [10, 20, 30, 40, 50, 60],
                unrelated: "other cipher and account keys",
            },
            source_id: "cipher",
            owner: None,
            org: Some("org"),
            revision_override: None,
            member_present: true,
            member_user: "actor",
            member_org: "org",
            role: 2,
            status: 2,
            full: false,
            facts: Facts {
                user: "actor".to_string(),
                canonical: "org",
                actual: "org",
                assigned: true,
                readonly: true,
                manage: true,
                hole: false,
            },
            fail: None,
            late_failure: false,
            live: Live::Same,
            live_error: None,
            cache: String::new(),
            calls: Vec::new(),
            commits: 0,
            operation: None,
        }
    }
    fn source(&self) -> CipherSharingSource<Id> {
        CipherSharingSource {
            id: id(self.source_id),
            owner_id: self.owner.map(id),
            organization_id: self.org.map(id),
            revision: id(self
                .revision_override
                .unwrap_or(&self.state.revision.to_string())),
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
    fn touch(&mut self, call: &'static str) -> Result<(), ()> {
        self.calls.push(call);
        self.cache = format!("reused cache {call}");
        if self.fail == Some(call) {
            Err(())
        } else {
            Ok(())
        }
    }
    fn apply(&mut self, operation: CipherLifecycleOperation) -> Result<(), ApiError> {
        VaultService::new(self).mutate_cipher_lifecycle("actor", "cipher", operation)
    }
}
impl Storage for Probe {
    type Error = ();
    fn map_error(_: ()) -> ApiError {
        ApiError::new(ErrorKind::Storage, "Lifecycle provider failure")
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
impl CipherLifecycleStorage for Probe {
    type LifecycleId = Id;
    type LifecycleAccess = Facts;
    fn cipher_lifecycle_source(&mut self, _: &str) -> Result<Option<CipherSharingSource<Id>>, ()> {
        self.touch("source")?;
        Ok(self.state.present.then(|| self.source()))
    }
    fn cipher_lifecycle_membership(
        &mut self,
        _: &str,
        _: &str,
    ) -> Result<Option<CipherSharingMembership<Id>>, ()> {
        self.touch("member")?;
        Ok(self.member_present.then(|| self.member()))
    }
    fn cipher_lifecycle_collections(
        &mut self,
        _: &str,
        _: &CipherSharingSource<Id>,
    ) -> Result<Facts, ()> {
        self.touch("collections")?;
        Ok(self.facts.clone())
    }
    fn commit_cipher_lifecycle(&mut self, plan: &ValidatedCipherLifecycle<'_>) -> Result<(), ()> {
        self.touch("commit")?;
        self.commits += 1;
        self.operation = Some(plan.operation());
        let mut source = self.source();
        let mut member = self.member();
        let mut access = self.facts.clone();
        match self.live {
            Live::Same => {}
            Live::Identity => source.id = id("another"),
            Live::Revision => source.revision = id("new-revision"),
            Live::Ownership => {
                source.owner_id = Some(id("actor"));
                source.organization_id = None;
            }
            Live::Revoke => member.status = -1,
            Live::RemoveGrant => access.assigned = false,
            Live::RemoveManage => access.manage = false,
            Live::WrongMember => member.organization_id = id("another"),
            Live::WrongAssociation => access.canonical = "another",
        }
        let empty: &[CipherCollectionAccessRecord<'_>] = &[];
        let checked = if source.organization_id.is_some() {
            plan.validate_live(&source, Some(member.view()), &access)
        } else {
            plan.validate_live(&source, None, empty)
        };
        if let Err(error) = checked {
            self.live_error = Some(error);
            return Err(());
        }
        assert_eq!(plan.actor(), "actor");
        assert_eq!(plan.cipher_id(), "cipher");
        assert_eq!(plan.personal_owner_id(), self.owner);
        assert_eq!(plan.organization_id(), self.org);
        assert_eq!(plan.source_revision(), source.revision.as_ref());
        // Save READ recipients before deletion; readonly receives fanout even
        // though only the actor's manage grant supplies WRITE authority.
        let users = [
            "actor", "owner", "readonly", "nogrant", "accepted", "revoked",
        ];
        let mut readers = [false; 6];
        for (i, user) in users.iter().enumerate() {
            let owned_member = if i == 0 {
                self.member()
            } else {
                CipherSharingMembership {
                    user_id: id(user),
                    organization_id: id("org"),
                    role: if i == 1 || i >= 4 { 1 } else { 2 },
                    status: if i == 4 {
                        1
                    } else if i == 5 {
                        -1
                    } else {
                        2
                    },
                    access_all: false,
                }
            };
            let mut facts = self.facts.clone();
            facts.user = user.to_string();
            facts.assigned = i < 3;
            facts.manage = i == 0;
            readers[i] = if source.organization_id.is_some() {
                resolve_cipher_access(
                    user,
                    source.ownership().map_err(|_| ())?,
                    Some(owned_member.view()),
                    &facts,
                )
            } else {
                resolve_cipher_access(user, source.ownership().map_err(|_| ())?, None, empty)
            }
            .map_err(|_| ())?
            .readable();
        }
        let mut staged = self.state.clone();
        staged.clock += 1;
        match plan.operation() {
            CipherLifecycleOperation::Trash => {
                staged.deleted = Some(staged.clock);
                staged.revision = staged.clock;
            }
            CipherLifecycleOperation::Restore => {
                staged.deleted = None;
                staged.revision = staged.clock;
            }
            CipherLifecycleOperation::PermanentDelete => {
                staged.present = false;
                staged.archives = [None; 3];
                staged.folders = [None; 3];
                staged.favorites = [false; 3];
                staged.links = 0;
                staged.ciphertext = "";
                staged.key = "";
            }
        }
        for (i, readable) in readers.iter().enumerate() {
            if *readable {
                staged.account_revisions[i] += 1;
            }
        }
        if self.late_failure {
            return Err(());
        }
        self.state = staged;
        Ok(())
    }
}
const OPERATIONS: [CipherLifecycleOperation; 3] = [
    CipherLifecycleOperation::Trash,
    CipherLifecycleOperation::Restore,
    CipherLifecycleOperation::PermanentDelete,
];
#[test]
fn readonly_manage_admits_all_operations_without_changing_get_flags() {
    for op in OPERATIONS {
        let mut p = Probe::new();
        let member = p.member();
        let source = p.source();
        let flags = resolve_cipher_access(
            "actor",
            source.ownership().unwrap(),
            Some(member.view()),
            &p.facts,
        )
        .unwrap();
        assert!(flags.readable());
        assert!(!flags.writable());
        assert!(!flags.delete());
        assert!(!flags.restore());
        p.apply(op).unwrap();
        assert_eq!(p.operation, Some(op));
        assert_eq!(p.commits, 1);
    }
}
#[test]
fn owner_admin_and_writable_grants_use_existing_write_predicate() {
    for (role, readonly, manage) in [(0, true, false), (1, true, false), (2, false, false)] {
        for op in OPERATIONS {
            let mut p = Probe::new();
            p.role = role;
            p.facts.readonly = readonly;
            p.facts.manage = manage;
            p.apply(op).unwrap();
        }
    }
}
#[test]
fn readonly_without_manage_and_no_grant_deny_every_operation() {
    for assigned in [true, false] {
        for op in OPERATIONS {
            let mut p = Probe::new();
            p.facts.assigned = assigned;
            p.facts.manage = false;
            let before = p.state.clone();
            assert!(p.apply(op).is_err());
            assert_eq!(p.commits, 0);
            assert_eq!(p.state, before);
        }
    }
}
#[test]
fn accepted_invited_and_revoked_canonical_members_deny_even_admin() {
    for status in [0, 1, -1] {
        for op in OPERATIONS {
            let mut p = Probe::new();
            p.role = 1;
            p.status = status;
            let before = p.state.clone();
            assert!(p.apply(op).is_err());
            assert_eq!(p.state, before);
            assert_eq!(p.commits, 0);
        }
    }
}
#[test]
fn missing_membership_denies_with_assigned_manage_grant() {
    let mut p = Probe::new();
    p.member_present = false;
    let before = p.state.clone();
    assert!(p.apply(CipherLifecycleOperation::Trash).is_err());
    assert_eq!(p.state, before);
    assert_eq!(p.commits, 0);
}
#[test]
fn personal_owner_needs_no_shared_facts_and_foreign_personal_denies() {
    for owner in ["actor", "foreign"] {
        let mut p = Probe::new();
        p.owner = Some(owner);
        p.org = None;
        let before = p.state.clone();
        let result = p.apply(CipherLifecycleOperation::Trash);
        assert_eq!(result.is_ok(), owner == "actor");
        assert!(!p.calls.contains(&"member") && !p.calls.contains(&"collections"));
        if owner == "actor" {
            assert_eq!(p.state.account_revisions, [11, 20, 30, 40, 50, 60]);
        } else {
            assert_eq!(p.state, before);
        }
    }
}
#[test]
fn unauthenticated_actor_and_missing_source_never_commit() {
    let mut p = Probe::new();
    assert!(
        VaultService::new(&mut p)
            .mutate_cipher_lifecycle("", "cipher", CipherLifecycleOperation::Trash)
            .is_err()
    );
    assert!(p.calls.is_empty());
    p.state.present = false;
    assert!(p.apply(CipherLifecycleOperation::Restore).is_err());
    assert_eq!(p.commits, 0);
}
#[test]
fn corrupted_source_id_revision_and_canonical_ownership_fail_closed() {
    for mode in 0..5 {
        let mut p = Probe::new();
        match mode {
            0 => p.source_id = "different",
            1 => p.revision_override = Some(""),
            2 => p.owner = Some("actor"),
            3 => p.org = None,
            _ => p.org = Some(""),
        };
        let before = p.state.clone();
        assert_eq!(
            p.apply(CipherLifecycleOperation::Trash).unwrap_err().kind,
            ErrorKind::Storage
        );
        assert_eq!(p.state, before);
        assert_eq!(p.commits, 0);
    }
}
#[test]
fn membership_user_and_organization_are_bound_to_source_and_actor() {
    for mode in 0..2 {
        let mut p = Probe::new();
        if mode == 0 {
            p.member_user = "other";
        } else {
            p.member_org = "other";
        }
        assert_eq!(
            p.apply(CipherLifecycleOperation::Trash).unwrap_err().kind,
            ErrorKind::Storage
        );
        assert_eq!(p.commits, 0);
    }
}
#[test]
fn associated_scope_user_and_indexed_holes_cannot_supply_authority() {
    for mode in 0..3 {
        let mut p = Probe::new();
        match mode {
            0 => p.facts.canonical = "other",
            1 => p.facts.user = "other".to_string(),
            _ => p.facts.hole = true,
        };
        assert_eq!(
            p.apply(CipherLifecycleOperation::Trash).unwrap_err().kind,
            ErrorKind::Storage
        );
        assert_eq!(p.commits, 0);
    }
}
#[test]
fn historical_fact_shape_reuses_scoped_predicate_without_new_native_claim() {
    let mut p = Probe::new();
    p.facts.actual = "historical-org";
    p.apply(CipherLifecycleOperation::Trash).unwrap();
    let mut p = Probe::new();
    p.facts.actual = "historical-org";
    p.status = -1;
    assert!(p.apply(CipherLifecycleOperation::Trash).is_err());
}
#[test]
fn every_lookup_and_commit_error_preserves_persistent_state() {
    for step in ["source", "member", "collections", "commit"] {
        let mut p = Probe::new();
        p.fail = Some(step);
        let before = p.state.clone();
        assert_eq!(
            p.apply(CipherLifecycleOperation::Trash).unwrap_err().kind,
            ErrorKind::Storage
        );
        assert_eq!(p.state, before);
    }
}
#[test]
fn nonclone_owned_source_membership_survive_cache_reuse_until_commit() {
    let mut p = Probe::new();
    p.apply(CipherLifecycleOperation::Restore).unwrap();
    assert_eq!(p.calls, ["source", "member", "collections", "commit"]);
    assert_eq!(p.cache, "reused cache commit");
}
#[test]
fn live_exact_identity_revision_and_owner_changes_are_rejected() {
    for live in [Live::Identity, Live::Revision, Live::Ownership] {
        for op in OPERATIONS {
            let mut p = Probe::new();
            p.live = live;
            let before = p.state.clone();
            assert!(p.apply(op).is_err());
            assert_eq!(p.state, before);
            assert!(p.live_error.is_some());
        }
    }
}
#[test]
fn live_revoke_grant_manage_and_scope_changes_cannot_commit() {
    for live in [
        Live::Revoke,
        Live::RemoveGrant,
        Live::RemoveManage,
        Live::WrongMember,
        Live::WrongAssociation,
    ] {
        let mut p = Probe::new();
        p.live = live;
        let before = p.state.clone();
        assert!(p.apply(CipherLifecycleOperation::PermanentDelete).is_err());
        assert_eq!(p.state, before);
        assert!(p.live_error.is_some());
    }
}
#[test]
fn repeated_trash_and_active_restore_preserve_all_archives_and_other_fields() {
    let mut p = Probe::new();
    let mut expected = p.state.clone();
    for op in [
        CipherLifecycleOperation::Trash,
        CipherLifecycleOperation::Trash,
        CipherLifecycleOperation::Restore,
        CipherLifecycleOperation::Restore,
    ] {
        p.apply(op).unwrap();
        expected.clock += 1;
        expected.revision = expected.clock;
        expected.deleted = if op == CipherLifecycleOperation::Trash {
            Some(expected.clock)
        } else {
            None
        };
        for i in 0..3 {
            expected.account_revisions[i] += 1;
        }
        assert_eq!(p.state, expected);
    }
}
#[test]
fn permanent_active_and_trashed_cleanup_save_read_fanout_and_keep_unrelated_state() {
    for deleted in [None, Some(7)] {
        let mut p = Probe::new();
        p.state.deleted = deleted;
        p.apply(CipherLifecycleOperation::PermanentDelete).unwrap();
        assert!(!p.state.present);
        assert_eq!(p.state.links, 0);
        assert_eq!(p.state.archives, [None; 3]);
        assert_eq!(p.state.folders, [None; 3]);
        assert_eq!(p.state.account_revisions, [11, 21, 31, 40, 50, 60]);
        assert_eq!(p.state.unrelated, "other cipher and account keys");
        assert!(p.apply(CipherLifecycleOperation::PermanentDelete).is_err());
    }
}
#[test]
fn late_provider_failure_rolls_back_mutation_and_all_reader_revisions() {
    for op in OPERATIONS {
        let mut p = Probe::new();
        p.late_failure = true;
        let before = p.state.clone();
        assert!(p.apply(op).is_err());
        assert_eq!(p.state, before);
        p.late_failure = false;
        p.apply(op).unwrap();
    }
}
#[test]
fn sealed_plan_debug_redacts_all_source_and_actor_identifiers() {
    let p = Probe::new();
    let plan = ValidatedCipherLifecycle {
        actor: "private-actor",
        cipher: "private-source",
        owner: None,
        organization: Some("private-org"),
        revision: "private-token",
        operation: CipherLifecycleOperation::Restore,
    };
    assert_eq!(format!("{plan:?}"), "ValidatedCipherLifecycle([REDACTED])");
    assert!(p.state.present);
}
