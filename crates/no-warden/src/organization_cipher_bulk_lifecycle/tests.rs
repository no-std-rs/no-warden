use super::*;
use crate::{
    Storage,
    organization_cipher_lifecycle::ValidatedCipherLifecycle,
    organization_cipher_sharing::{
        CipherCollectionAccessData, CipherCollectionAccessRecord, CipherSharingCollection,
        CipherSharingMembership, CipherSharingSource,
    },
    service::ItemMetadata,
    wire::{CipherRequest, FolderRequest, RegisterRequest},
};
use std::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

// Owned snapshots/order intentionally implement neither Clone nor Debug.
struct Id(String);
impl AsRef<str> for Id {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
fn id(value: &str) -> Id {
    Id(value.to_string())
}
struct Order(Vec<usize>);
impl AsRef<[usize]> for Order {
    fn as_ref(&self) -> &[usize] {
        &self.0
    }
}
struct Facts {
    user: String,
    writable: bool,
}
impl CipherCollectionAccessData for Facts {
    fn len(&self) -> usize {
        1
    }
    fn get(&self, index: usize) -> Option<CipherCollectionAccessRecord<'_>> {
        (index == 0).then_some(CipherCollectionAccessRecord {
            cipher_organization_id: Some("org"),
            collection: CipherSharingCollection {
                id: "linked",
                user_id: &self.user,
                organization_id: "org",
                assigned: true,
                read_only: true,
                hide_passwords: false,
                manage: self.writable,
            },
        })
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Row {
    name: &'static str,
    owner: Option<&'static str>,
    org: Option<&'static str>,
    present: bool,
    revision: u64,
    deleted: bool,
    archives: [u64; 3],
    favorites: [bool; 3],
    folders: [&'static str; 3],
    opaque: &'static str,
}
struct Probe {
    rows: [Row; 2],
    revisions: [u64; 6],
    order: Vec<usize>,
    ordered_ids: Vec<String>,
    writable: [bool; 2],
    status: i32,
    cache: String,
    calls: Vec<String>,
    commits: Vec<String>,
    order_error: bool,
    lookup_failure: Option<usize>,
    late_failure: Option<usize>,
    live_revoke: Option<usize>,
    lose_after_first: bool,
    wrong_source: Option<usize>,
}
impl Probe {
    fn new() -> Self {
        Self {
            rows: ["a", "b"].map(|name| Row {
                name,
                owner: None,
                org: Some("org"),
                present: true,
                revision: 10,
                deleted: false,
                archives: [1, 2, 3],
                favorites: [true, false, true],
                folders: ["actor-folder", "owner-folder", "readonly-folder"],
                opaque: "opaque nested key and payload",
            }),
            revisions: [10, 20, 30, 40, 50, 60],
            order: vec![0, 1],
            ordered_ids: Vec::new(),
            writable: [true, true],
            status: 2,
            cache: String::new(),
            calls: Vec::new(),
            commits: Vec::new(),
            order_error: false,
            lookup_failure: None,
            late_failure: None,
            live_revoke: None,
            lose_after_first: false,
            wrong_source: None,
        }
    }
    fn touch(&mut self, value: &str) {
        self.cache = format!("reused {value}");
        self.calls.push(value.to_string());
    }
    fn index(&self, name: &str) -> Option<usize> {
        self.rows.iter().position(|r| r.name == name)
    }
    fn source(&self, index: usize) -> CipherSharingSource<Id> {
        let r = &self.rows[index];
        CipherSharingSource {
            id: id(r.name),
            owner_id: r.owner.map(id),
            organization_id: r.org.map(id),
            revision: id(&r.revision.to_string()),
        }
    }
    fn member(&self, actor: &str) -> CipherSharingMembership<Id> {
        CipherSharingMembership {
            user_id: id(actor),
            organization_id: id("org"),
            role: 2,
            status: self.status,
            access_all: false,
        }
    }
    fn apply(
        &mut self,
        operation: CipherLifecycleOperation,
        selected: &[&str],
    ) -> Result<usize, ApiError> {
        let mut ids = [""; 8];
        let mut seen = [true; 8];
        VaultService::new(self).mutate_selected_cipher_lifecycle(
            "actor",
            operation,
            selected.iter().copied(),
            &mut ids,
            &mut seen,
        )
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
    fn cipher_lifecycle_source(
        &mut self,
        cipher: &str,
    ) -> Result<Option<CipherSharingSource<Id>>, ()> {
        self.touch(&format!("source {cipher}"));
        let Some(index) = self.index(cipher) else {
            return Ok(None);
        };
        if self.lookup_failure == Some(index) {
            return Err(());
        }
        if !self.rows[index].present {
            return Ok(None);
        }
        let mut source = self.source(index);
        if self.wrong_source == Some(index) {
            source.id = id("wrong")
        };
        Ok(Some(source))
    }
    fn cipher_lifecycle_membership(
        &mut self,
        actor: &str,
        _: &str,
    ) -> Result<Option<CipherSharingMembership<Id>>, ()> {
        self.touch("member");
        Ok(Some(self.member(actor)))
    }
    fn cipher_lifecycle_collections(
        &mut self,
        actor: &str,
        source: &CipherSharingSource<Id>,
    ) -> Result<Facts, ()> {
        self.touch("collections");
        Ok(Facts {
            user: actor.to_string(),
            writable: self.writable[self.index(source.id.as_ref()).unwrap()],
        })
    }
    fn commit_cipher_lifecycle(&mut self, plan: &ValidatedCipherLifecycle<'_>) -> Result<(), ()> {
        self.touch(&format!("commit {}", plan.cipher_id()));
        let index = self.index(plan.cipher_id()).ok_or(())?;
        let source = self.source(index);
        let mut member = self.member(plan.actor());
        if self.live_revoke == Some(index) {
            member.status = -1
        }
        let facts = Facts {
            user: plan.actor().to_string(),
            writable: self.writable[index],
        };
        let empty: &[CipherCollectionAccessRecord<'_>] = &[];
        if source.organization_id.is_some() {
            plan.validate_live(&source, Some(member.view()), &facts)
                .map_err(|_| ())?
        } else {
            plan.validate_live(&source, None, empty).map_err(|_| ())?
        }
        let before = self.rows[index].clone();
        let revisions = self.revisions;
        match plan.operation() {
            CipherLifecycleOperation::Trash => self.rows[index].deleted = true,
            CipherLifecycleOperation::Restore => self.rows[index].deleted = false,
            CipherLifecycleOperation::PermanentDelete => self.rows[index].present = false,
        }
        self.rows[index].revision += 1;
        // Provider models the existing single contract: CURRENT READERS, not actor-only.
        for r in &mut self.revisions[..if source.organization_id.is_some() {
            3
        } else {
            1
        }] {
            *r += 1
        }
        if self.late_failure == Some(index) {
            self.rows[index] = before;
            self.revisions = revisions;
            return Err(());
        }
        self.commits.push(plan.cipher_id().to_string());
        if self.lose_after_first && self.commits.len() == 1 {
            self.status = -1
        }
        Ok(())
    }
}
impl CipherLifecycleSelectionStorage for Probe {
    type LifecycleOrder = Order;
    fn cipher_lifecycle_order(
        &mut self,
        actor: &str,
        operation: CipherLifecycleOperation,
        selected: &[&str],
    ) -> Result<Order, ()> {
        assert_eq!(actor, "actor");
        self.touch(&format!("order {operation:?}"));
        self.ordered_ids = selected.iter().map(|v| v.to_string()).collect();
        if self.order_error {
            return Err(());
        }
        Ok(Order(self.order.to_vec()))
    }
}
fn operations() -> [CipherLifecycleOperation; 3] {
    [
        CipherLifecycleOperation::Trash,
        CipherLifecycleOperation::Restore,
        CipherLifecycleOperation::PermanentDelete,
    ]
}
#[test]
fn all_operations_follow_owned_order_and_fanout_each_success_to_current_readers() {
    for operation in operations() {
        let mut p = Probe::new();
        p.order = vec![1, 0];
        let before = p.rows.clone();
        assert_eq!(p.apply(operation, &["b", "a"]), Ok(2));
        assert_eq!(p.commits, ["b", "a"]);
        assert_eq!(p.revisions, [12, 22, 32, 40, 50, 60]);
        for (after, before) in p.rows.iter().zip(before) {
            assert_eq!(after.archives, before.archives);
            assert_eq!(after.favorites, before.favorites);
            assert_eq!(after.folders, before.folders);
            assert_eq!(after.opaque, before.opaque);
            assert_eq!(after.revision, 11);
            assert_eq!(
                after.present,
                operation != CipherLifecycleOperation::PermanentDelete
            );
            assert_eq!(after.deleted, operation == CipherLifecycleOperation::Trash)
        }
    }
}
#[test]
fn empty_input_performs_no_observational_or_mutation_provider_calls() {
    for op in operations() {
        let mut p = Probe::new();
        assert_eq!(p.apply(op, &[]), Ok(0));
        assert!(p.calls.is_empty());
        assert!(p.commits.is_empty())
    }
}
#[test]
fn duplicates_are_removed_sorted_response_ids_and_seen_need_only_unique_capacity() {
    for op in operations() {
        let mut p = Probe::new();
        let mut scratch = [""; 5];
        let mut seen = [true; 2];
        assert_eq!(
            VaultService::new(&mut p).mutate_selected_cipher_lifecycle(
                "actor",
                op,
                ["b", "a", "b", "a", "a"],
                &mut scratch,
                &mut seen
            ),
            Ok(2)
        );
        assert_eq!(&scratch[..2], ["a", "b"]);
        assert_eq!(p.ordered_ids, ["a", "b"]);
        assert_eq!(p.commits, ["a", "b"]);
        assert_eq!(p.revisions, [12, 22, 32, 40, 50, 60])
    }
}
#[test]
fn raw_scratch_capacity_covers_duplicates_before_any_provider_call() {
    let mut p = Probe::new();
    let mut scratch = [""; 1];
    let mut seen = [false; 1];
    assert!(
        VaultService::new(&mut p)
            .mutate_selected_cipher_lifecycle(
                "actor",
                CipherLifecycleOperation::Trash,
                ["a", "a"],
                &mut scratch,
                &mut seen
            )
            .is_err()
    );
    assert!(p.calls.is_empty());
}
#[test]
fn unique_seen_capacity_error_precedes_order_and_all_mutations() {
    let mut p = Probe::new();
    let mut scratch = [""; 2];
    let mut seen = [false; 1];
    assert!(
        VaultService::new(&mut p)
            .mutate_selected_cipher_lifecycle(
                "actor",
                CipherLifecycleOperation::Trash,
                ["b", "a"],
                &mut scratch,
                &mut seen
            )
            .is_err()
    );
    assert!(p.calls.is_empty());
}
#[test]
fn every_malformed_permutation_is_rejected_before_any_source_lookup() {
    for order in [
        vec![],
        vec![0],
        vec![0, 1, 0],
        vec![0, 0],
        vec![1, 1],
        vec![0, 2],
        vec![usize::MAX, 1],
    ] {
        let mut p = Probe::new();
        let before = p.rows.clone();
        p.order = order;
        let error = p
            .apply(CipherLifecycleOperation::Trash, &["a", "b"])
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Storage);
        assert_eq!(p.calls.len(), 1);
        assert_eq!(p.rows, before);
        assert_eq!(p.revisions, [10, 20, 30, 40, 50, 60]);
        assert!(p.commits.is_empty())
    }
}
#[test]
fn observational_order_failure_is_mapped_without_target_calls() {
    let mut p = Probe::new();
    p.order_error = true;
    assert_eq!(
        p.apply(CipherLifecycleOperation::Trash, &["a", "b"])
            .unwrap_err()
            .kind,
        ErrorKind::Storage
    );
    assert_eq!(p.calls.len(), 1);
    assert!(p.commits.is_empty());
}
#[test]
fn unauthenticated_actor_is_rejected_before_consuming_the_iterator() {
    let mut p = Probe::new();
    let mut scratch = [""; 2];
    let mut seen = [false; 2];
    let input = core::iter::from_fn(|| -> Option<&str> {
        panic!("must not consume unauthenticated input")
    });
    assert!(
        VaultService::new(&mut p)
            .mutate_selected_cipher_lifecycle(
                "",
                CipherLifecycleOperation::Trash,
                input,
                &mut scratch,
                &mut seen
            )
            .is_err()
    );
    assert!(p.calls.is_empty());
}
#[test]
fn exact_ids_are_not_normalized_or_prevalidated_as_uuids() {
    let mut p = Probe::new();
    p.rows[0].name = "A";
    p.rows[1].name = "a";
    assert_eq!(
        p.apply(CipherLifecycleOperation::Trash, &["a", "A", "A"]),
        Ok(2)
    );
    assert_eq!(p.ordered_ids, ["A", "a"]);
    assert_eq!(p.commits, ["A", "a"]);
}
#[test]
fn provider_order_controls_whether_missing_target_follows_a_durable_success() {
    for op in operations() {
        let mut first = Probe::new();
        first.order = vec![1, 0];
        assert!(first.apply(op, &["a", "missing"]).is_err());
        assert!(first.commits.is_empty());
        let mut later = Probe::new();
        assert!(later.apply(op, &["a", "missing"]).is_err());
        assert_eq!(later.commits, ["a"]);
        assert_eq!(later.revisions, [11, 21, 31, 40, 50, 60]);
        assert_eq!(later.rows[0].revision, 11);
        assert_eq!(later.rows[1].revision, 10)
    }
}
#[test]
fn readonly_without_manage_is_freshly_denied_after_the_first_success() {
    for op in operations() {
        let mut p = Probe::new();
        p.writable[1] = false;
        assert!(p.apply(op, &["a", "b"]).is_err());
        assert_eq!(p.commits, ["a"]);
        assert_eq!(p.revisions, [11, 21, 31, 40, 50, 60]);
        assert_eq!(p.rows[1].revision, 10);
        assert!(!p.calls.iter().any(|x| x == "commit b"))
    }
}
#[test]
fn authority_loss_after_success_is_seen_by_next_admission_without_cached_batch_authority() {
    let mut p = Probe::new();
    p.lose_after_first = true;
    assert!(
        p.apply(CipherLifecycleOperation::Restore, &["a", "b"])
            .is_err()
    );
    assert_eq!(p.commits, ["a"]);
    assert_eq!(p.rows[0].revision, 11);
    assert_eq!(p.rows[1].revision, 10);
    assert_eq!(p.revisions, [11, 21, 31, 40, 50, 60]);
    assert!(!p.calls.iter().any(|x| x == "commit b"));
    assert!(p.calls.iter().any(|x| x == "source b"));
}
#[test]
fn late_failure_rolls_back_only_its_step_and_retains_prior_success() {
    for op in operations() {
        let mut p = Probe::new();
        p.late_failure = Some(1);
        let before = p.rows[1].clone();
        assert!(p.apply(op, &["a", "b"]).is_err());
        assert_eq!(p.rows[1], before);
        assert_eq!(p.rows[0].revision, 11);
        assert_eq!(p.commits, ["a"]);
        assert_eq!(p.revisions, [11, 21, 31, 40, 50, 60]);
    }
}
#[test]
fn later_lookup_and_live_validation_failures_retain_the_completed_step() {
    for live in [false, true] {
        let mut p = Probe::new();
        if live {
            p.live_revoke = Some(1)
        } else {
            p.lookup_failure = Some(1)
        };
        assert!(
            p.apply(CipherLifecycleOperation::Trash, &["a", "b"])
                .is_err()
        );
        assert_eq!(p.commits, ["a"]);
        assert_eq!(p.rows[1].revision, 10);
        assert_eq!(p.revisions, [11, 21, 31, 40, 50, 60]);
    }
}
#[test]
fn exact_source_identity_guard_remains_active_for_each_step() {
    let mut p = Probe::new();
    p.wrong_source = Some(1);
    assert!(
        p.apply(CipherLifecycleOperation::Trash, &["a", "b"])
            .is_err()
    );
    assert_eq!(p.commits, ["a"]);
    assert!(!p.calls.iter().any(|x| x == "commit b"));
}
#[test]
fn personal_owner_step_then_foreign_personal_target_never_borrows_shared_authority() {
    let mut p = Probe::new();
    p.rows[0].org = None;
    p.rows[0].owner = Some("actor");
    p.rows[1].org = None;
    p.rows[1].owner = Some("foreign");
    assert!(
        p.apply(CipherLifecycleOperation::Trash, &["a", "b"])
            .is_err()
    );
    assert_eq!(p.commits, ["a"]);
    assert_eq!(p.revisions, [11, 20, 30, 40, 50, 60]);
    assert_eq!(p.rows[1].revision, 10);
    assert!(!p.calls.iter().any(|x| x == "member" || x == "collections"));
}
#[test]
fn owned_nonclone_order_and_source_snapshots_survive_reused_provider_cache() {
    let mut p = Probe::new();
    p.order = vec![1, 0];
    assert_eq!(p.apply(CipherLifecycleOperation::Trash, &["a", "b"]), Ok(2));
    assert_eq!(p.commits, ["b", "a"]);
    assert_eq!(p.cache, "reused commit a");
}

#[test]
fn repeated_single_id_commits_once_even_for_permanent_delete() {
    for operation in operations() {
        let mut p = Probe::new();
        p.order = vec![0];
        assert_eq!(p.apply(operation, &["a", "a", "a"]), Ok(1));
        assert_eq!(p.ordered_ids, ["a"]);
        assert_eq!(p.commits, ["a"]);
        assert_eq!(p.rows[0].revision, 11);
        assert_eq!(p.rows[1].revision, 10);
        assert_eq!(p.revisions, [11, 21, 31, 40, 50, 60]);
    }
}
