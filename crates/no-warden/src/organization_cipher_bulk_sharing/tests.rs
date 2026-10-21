use super::*;
use crate::{
    organization_cipher_sharing::CipherCollectionAccessRecord,
    service::ItemMetadata,
    wire::{CipherBulkShareRequest, CipherRequest, FolderRequest, RegisterRequest},
};
use std::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

// Provider identifiers intentionally have no Clone, Debug or serialization bound.
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
struct Fact {
    canonical: Option<String>,
    id: String,
    user: String,
    org: String,
    assigned: bool,
    ro: bool,
    manage: bool,
}
struct Facts(Vec<Fact>);
impl CipherCollectionAccessData for Facts {
    fn len(&self) -> usize {
        self.0.len()
    }
    fn get(&self, i: usize) -> Option<CipherCollectionAccessRecord<'_>> {
        self.0.get(i).map(|r| CipherCollectionAccessRecord {
            cipher_organization_id: r.canonical.as_deref(),
            collection: CipherSharingCollection {
                id: &r.id,
                user_id: &r.user,
                organization_id: &r.org,
                assigned: r.assigned,
                read_only: r.ro,
                hide_passwords: false,
                manage: r.manage,
            },
        })
    }
}
fn fact(canonical: Option<&str>, org: &str, ro: bool, manage: bool) -> Fact {
    Fact {
        canonical: canonical.map(str::to_string),
        id: "linked".into(),
        user: "actor".into(),
        org: org.into(),
        assigned: true,
        ro,
        manage,
    }
}
struct Input<'a> {
    items: Vec<CipherBulkShareItem<'a>>,
    selections: Vec<&'a str>,
    hole: Option<usize>,
    collection_hole: bool,
}
impl CipherBulkSharingData for Input<'_> {
    fn ciphers_len(&self) -> usize {
        self.items.len()
    }
    fn cipher(&self, i: usize) -> Option<CipherBulkShareItem<'_>> {
        if self.hole == Some(i) {
            None
        } else {
            self.items.get(i).copied()
        }
    }
    fn collections_len(&self) -> usize {
        self.selections.len()
    }
    fn collection(&self, i: usize) -> Option<&str> {
        if self.collection_hole {
            None
        } else {
            self.selections.get(i).copied()
        }
    }
}
fn item(id: Option<&str>) -> CipherBulkShareItem<'_> {
    CipherBulkShareItem {
        id,
        cipher_type: 2,
        name: "",
        organization_id: Some("org"),
        folder_id: None,
    }
}
fn input<'a>(ids: &[Option<&'a str>], selections: &[&'a str]) -> Input<'a> {
    Input {
        items: ids.iter().map(|s| item(*s)).collect(),
        selections: selections.to_vec(),
        hole: None,
        collection_hole: false,
    }
}
struct Stored {
    id: String,
    owner: Option<String>,
    org: Option<String>,
    revision: usize,
    name: String,
    applied: Option<usize>,
    other_annotation: bool,
}
struct Memory {
    sources: Vec<Stored>,
    calls: Vec<&'static str>,
    commits: Vec<usize>,
    associations: Vec<(String, String)>,
    role: i32,
    status: i32,
    all: bool,
    facts: Vec<Fact>,
    folder_owner: Option<&'static str>,
    wrong_source: bool,
    invalid_ownership: bool,
    empty_revision: bool,
    wrong_member: bool,
    wrong_collection: bool,
    failure: Option<&'static str>,
    fail_association: Option<usize>,
    fail_commit: Option<usize>,
    revoke_after_association: bool,
    cache: String,
}
impl Memory {
    fn new() -> Self {
        Self {
            sources: ["one", "two", "three"]
                .iter()
                .map(|s| Stored {
                    id: (*s).into(),
                    owner: Some("actor".into()),
                    org: None,
                    revision: 1,
                    name: "original".into(),
                    applied: None,
                    other_annotation: true,
                })
                .collect(),
            calls: vec![],
            commits: vec![],
            associations: vec![],
            role: 0,
            status: 2,
            all: false,
            facts: vec![],
            folder_owner: Some("actor"),
            wrong_source: false,
            invalid_ownership: false,
            empty_revision: false,
            wrong_member: false,
            wrong_collection: false,
            failure: None,
            fail_association: None,
            fail_commit: None,
            revoke_after_association: false,
            cache: String::new(),
        }
    }
    fn call(&mut self, name: &'static str) -> Result<(), ApiError> {
        self.calls.push(name);
        self.cache = format!("replaced cache {name}");
        if self.failure == Some(name) {
            Err(ApiError::new(ErrorKind::Storage, "provider"))
        } else {
            Ok(())
        }
    }
    fn source(&self, name: &str) -> &Stored {
        self.sources.iter().find(|s| s.id == name).unwrap()
    }
    fn shared(&mut self) {
        self.sources[0].owner = None;
        self.sources[0].org = Some("org".into());
    }
    fn live(
        &self,
        source: &str,
        revision: &str,
        owner: Option<&str>,
        org: Option<&str>,
    ) -> Result<(), ApiError> {
        let s = self.source(source);
        if s.revision.to_string() != revision
            || s.owner.as_deref() != owner
            || s.org.as_deref() != org
            || self.status != 2
        {
            return Err(ApiError::new(ErrorKind::Conflict, "live authority changed"));
        }
        Ok(())
    }
}
impl Storage for Memory {
    type Error = ApiError;
    fn map_error(e: ApiError) -> ApiError {
        e
    }
    fn account_exists(&mut self, _: &str) -> Result<bool, ApiError> {
        unreachable!()
    }
    fn insert_account(&mut self, _: &str, _: &RegisterRequest<'_>) -> Result<(), ApiError> {
        unreachable!()
    }
    fn folder_metadata(&mut self, _: &str) -> Result<Option<ItemMetadata<'_>>, ApiError> {
        self.call("folder")?;
        Ok(self.folder_owner.map(|owner_id| ItemMetadata {
            owner_id,
            deleted: false,
        }))
    }
    fn save_folder(&mut self, _: &str, _: &str, _: &FolderRequest<'_>) -> Result<(), ApiError> {
        unreachable!()
    }
    fn delete_folder(&mut self, _: &str, _: &str) -> Result<(), ApiError> {
        unreachable!()
    }
    fn cipher_metadata(&mut self, _: &str) -> Result<Option<ItemMetadata<'_>>, ApiError> {
        unreachable!()
    }
    fn save_cipher(&mut self, _: &str, _: &str, _: &CipherRequest<'_>) -> Result<(), ApiError> {
        unreachable!()
    }
    fn set_cipher_deleted(&mut self, _: &str, _: &str, _: bool) -> Result<(), ApiError> {
        unreachable!()
    }
    fn delete_cipher(&mut self, _: &str, _: &str) -> Result<(), ApiError> {
        unreachable!()
    }
}
impl OrganizationCipherBulkSharingStorage for Memory {
    type BulkId = Id;
    type SourceAccess = Facts;
    fn bulk_sharing_source(
        &mut self,
        name: &str,
    ) -> Result<Option<CipherSharingSource<Id>>, ApiError> {
        self.call("source")?;
        Ok(self
            .sources
            .iter()
            .find(|s| s.id == name)
            .map(|s| CipherSharingSource {
                id: id(if self.wrong_source { "wrong" } else { name }),
                owner_id: s.owner.as_deref().map(id),
                organization_id: if self.invalid_ownership {
                    Some(id("wrong"))
                } else {
                    s.org.as_deref().map(id)
                },
                revision: Id(if self.empty_revision {
                    String::new()
                } else {
                    s.revision.to_string()
                }),
            }))
    }
    fn bulk_sharing_membership(
        &mut self,
        user: &str,
        org: &str,
    ) -> Result<Option<CipherSharingMembership<Id>>, ApiError> {
        self.call("membership")?;
        Ok(Some(CipherSharingMembership {
            user_id: id(if self.wrong_member { "wrong" } else { user }),
            organization_id: id(org),
            role: self.role,
            status: self.status,
            access_all: self.all,
        }))
    }
    fn bulk_source_collections(
        &mut self,
        _: &str,
        _: &CipherSharingSource<Id>,
    ) -> Result<Facts, ApiError> {
        self.call("access")?;
        Ok(Facts(self.facts.clone()))
    }
    fn bulk_sharing_collection(
        &mut self,
        user: &str,
        org: &str,
        selected: &str,
    ) -> Result<Option<CipherSharingCollection<Id>>, ApiError> {
        self.call("collection")?;
        Ok((selected != "missing").then(|| CipherSharingCollection {
            id: id(selected),
            user_id: id(user),
            organization_id: id(if self.wrong_collection { "wrong" } else { org }),
            assigned: selected != "unassigned",
            read_only: matches!(selected, "readonly" | "manage"),
            hide_passwords: false,
            manage: selected == "manage",
        }))
    }
    fn associate_bulk_sharing_collection<D: CipherBulkSharingData + ?Sized>(
        &mut self,
        p: &ValidatedCipherBulkShareAssociation<'_, D>,
    ) -> Result<(), ApiError> {
        self.call("associate")?;
        assert_eq!(p.owner(), "actor");
        assert_eq!(
            p.request().cipher(p.index()).unwrap().id,
            Some(p.cipher_id())
        );
        assert_eq!(p.target_organization(), "org");
        self.live(
            p.cipher_id(),
            p.source_revision(),
            p.source_owner(),
            p.source_organization(),
        )?;
        if self.fail_association == Some(self.associations.len()) {
            return Err(ApiError::new(ErrorKind::Storage, "association failure"));
        }
        self.associations
            .push((p.cipher_id().into(), p.collection_id().into()));
        if self.revoke_after_association {
            self.status = -1;
        }
        Ok(())
    }
    fn commit_cipher_bulk_share<D: CipherBulkSharingData + ?Sized>(
        &mut self,
        p: &ValidatedCipherBulkShare<'_, D>,
    ) -> Result<(), ApiError> {
        self.call("commit")?;
        self.live(
            p.cipher_id(),
            p.source_revision(),
            p.source_owner(),
            p.source_organization(),
        )?;
        if self.fail_commit == Some(self.commits.len()) {
            return Err(ApiError::new(ErrorKind::Storage, "commit failure"));
        }
        let row = p.request().cipher(p.index()).unwrap();
        let s = self
            .sources
            .iter_mut()
            .find(|s| s.id == p.cipher_id())
            .unwrap();
        s.org = p.target_organization().map(str::to_string);
        s.owner = if s.org.is_some() {
            None
        } else {
            Some(p.owner().into())
        };
        s.revision += 1;
        s.name = row.name.into();
        s.applied = Some(p.index());
        self.commits.push(p.index());
        Ok(())
    }
}
#[test]
fn global_presence_and_index_preflight_precedes_every_provider_call() {
    for missing in 0..3 {
        let mut d = input(&[Some("one"), Some("two"), Some("three")], &["valid"]);
        d.items[missing].id = None;
        let mut s = Memory::new();
        let error = VaultService::new(&mut s)
            .bulk_share_ciphers("actor", &d)
            .unwrap_err();
        assert_eq!(error.message, "Request missing ids field");
        assert!(s.calls.is_empty());
        d.items[missing].id = Some("one");
        d.hole = Some(missing);
        assert_eq!(
            VaultService::new(&mut s)
                .bulk_share_ciphers("actor", &d)
                .unwrap_err()
                .kind,
            ErrorKind::Storage
        );
        assert!(s.calls.is_empty());
    }
    let mut d = input(&[Some("one")], &["valid"]);
    d.collection_hole = true;
    let mut s = Memory::new();
    assert!(
        VaultService::new(&mut s)
            .bulk_share_ciphers("actor", &d)
            .is_err()
    );
    assert!(s.calls.is_empty());
}
#[test]
fn reverse_lookup_keeps_exact_successful_suffix_and_no_global_existence_check() {
    for missing in 0..3 {
        let mut d = input(&[Some("one"), Some("two"), Some("three")], &["valid"]);
        d.items[missing].id = Some("missing");
        let mut s = Memory::new();
        assert_eq!(
            VaultService::new(&mut s)
                .bulk_share_ciphers("actor", &d)
                .unwrap_err()
                .message,
            "Cipher doesn't exist"
        );
        assert_eq!(s.commits, ((missing + 1)..3).rev().collect::<Vec<_>>());
        for (i, name) in ["one", "two", "three"].iter().enumerate() {
            assert_eq!(
                s.source(name).applied,
                if i > missing { Some(i) } else { None }
            );
        }
    }
}
#[test]
fn duplicate_ids_reload_new_ownership_revision_and_first_body_wins() {
    let mut d = input(
        &[Some("one"), Some("one"), Some("one")],
        &["valid", "valid"],
    );
    d.items[0].name = "first";
    d.items[1].name = "middle";
    d.items[2].name = "last";
    let mut s = Memory::new();
    VaultService::new(&mut s)
        .bulk_share_ciphers("actor", &d)
        .unwrap();
    assert_eq!(s.commits, vec![2, 1, 0]);
    assert_eq!(s.source("one").name, "first");
    assert_eq!(s.source("one").revision, 4);
    assert_eq!(s.associations.len(), 6);
    assert!(s.source("one").other_annotation);
}
#[test]
fn forward_collection_failure_preserves_current_prefix_without_applying_payload() {
    let d = input(&[Some("one"), Some("two")], &["valid", "missing", "valid"]);
    let mut s = Memory::new();
    assert_eq!(
        VaultService::new(&mut s)
            .bulk_share_ciphers("actor", &d)
            .unwrap_err()
            .message,
        "Invalid collection ID provided"
    );
    assert_eq!(s.associations, vec![("two".into(), "valid".into())]);
    assert!(s.commits.is_empty());
    assert_eq!(s.source("two").owner.as_deref(), Some("actor"));
    assert_eq!(s.source("two").revision, 1);
}
#[test]
fn folder_validation_follows_associations_and_retains_prefix_on_error() {
    for folder_owner in [None, Some("foreign")] {
        let mut s = Memory::new();
        s.folder_owner = folder_owner;
        let mut d = input(&[Some("one")], &["valid"]);
        d.items[0].folder_id = Some("folder");
        assert_eq!(
            VaultService::new(&mut s)
                .bulk_share_ciphers("actor", &d)
                .unwrap_err()
                .message,
            "Invalid folder"
        );
        assert_eq!(s.associations.len(), 1);
        assert!(s.commits.is_empty());
        assert_eq!(&s.calls[s.calls.len() - 2..], &["associate", "folder"]);
    }
}
#[test]
fn personal_null_target_skips_selections_but_preserves_required_wrapper_nonemptiness() {
    let mut d = input(&[Some("one")], &["missing"]);
    d.items[0].organization_id = None;
    d.items[0].name = "plain name accepted";
    let mut s = Memory::new();
    VaultService::new(&mut s)
        .bulk_share_ciphers("actor", &d)
        .unwrap();
    assert_eq!(s.commits, vec![0]);
    assert!(!s.calls.contains(&"collection"));
    assert_eq!(s.source("one").owner.as_deref(), Some("actor"));
    assert_eq!(s.source("one").name, "plain name accepted");
    d.selections.clear();
    let mut s = Memory::new();
    assert_eq!(
        VaultService::new(&mut s)
            .bulk_share_ciphers("actor", &d)
            .unwrap_err()
            .message,
        "You must select at least one collection."
    );
    assert!(s.calls.is_empty());
    d.items.clear();
    assert_eq!(
        VaultService::new(&mut s)
            .bulk_share_ciphers("actor", &d)
            .unwrap_err()
            .message,
        "You must select at least one cipher."
    );
}
#[test]
fn shared_source_requires_same_nonnull_target_after_source_write_authority() {
    for target in [None, Some("different")] {
        let mut s = Memory::new();
        s.shared();
        let mut d = input(&[Some("one")], &["valid"]);
        d.items[0].organization_id = target;
        assert!(
            VaultService::new(&mut s)
                .bulk_share_ciphers("actor", &d)
                .unwrap_err()
                .message
                .starts_with("Organization mismatch.")
        );
        assert!(s.associations.is_empty());
    }
    let mut s = Memory::new();
    s.shared();
    s.role = 2;
    s.facts = vec![fact(Some("org"), "org", true, false)];
    let mut d = input(&[Some("one")], &["valid"]);
    d.items[0].organization_id = None;
    assert_eq!(
        VaultService::new(&mut s)
            .bulk_share_ciphers("actor", &d)
            .unwrap_err()
            .message,
        "Cipher is not write accessible"
    );
}
#[test]
fn bulk_source_manage_authority_does_not_change_read_flags_or_new_selection_permission() {
    let f = Facts(vec![fact(Some("org"), "historical", true, true)]);
    let membership = || {
        Some(CipherSharingMembership {
            user_id: "actor",
            organization_id: "org",
            role: 2,
            status: 2,
            access_all: false,
        })
    };
    let ownership = CipherOwnership::Organization {
        organization_id: "org",
    };
    assert!(
        !resolve_cipher_access("actor", ownership, membership(), &f)
            .unwrap()
            .writable()
    );
    assert!(resolve_bulk_cipher_source_write_access("actor", ownership, membership(), &f).unwrap());
    for selected in ["readonly", "manage"] {
        let mut s = Memory::new();
        s.shared();
        s.role = 2;
        s.facts = f.0.clone();
        let d = input(&[Some("one")], &[selected]);
        assert_eq!(
            VaultService::new(&mut s)
                .bulk_share_ciphers("actor", &d)
                .unwrap_err()
                .message,
            "No rights to modify the collection"
        );
        assert!(s.associations.is_empty());
    }
    let mut s = Memory::new();
    s.shared();
    s.role = 2;
    s.facts = f.0;
    VaultService::new(&mut s)
        .bulk_share_ciphers("actor", &input(&[Some("one")], &["valid"]))
        .unwrap();
}
#[test]
fn historical_grants_require_canonical_confirmed_membership_and_exact_scope() {
    for status in [-1, 0, 1, 2] {
        let mut s = Memory::new();
        s.shared();
        s.role = 2;
        s.status = status;
        s.facts = vec![fact(Some("org"), "old-org", false, false)];
        let r = VaultService::new(&mut s)
            .bulk_share_ciphers("actor", &input(&[Some("one")], &["valid"]));
        assert_eq!(r.is_ok(), status == 2);
    }
    for bad in ["canonical", "user", "empty-org", "hole"] {
        let mut f = Facts(vec![fact(Some("org"), "old-org", false, true)]);
        match bad {
            "canonical" => f.0[0].canonical = Some("wrong".into()),
            "user" => f.0[0].user = "foreign".into(),
            "empty-org" => f.0[0].org.clear(),
            _ => f.0[0].id.clear(),
        };
        assert_eq!(
            resolve_bulk_cipher_source_write_access(
                "actor",
                CipherOwnership::Organization {
                    organization_id: "org"
                },
                Some(CipherSharingMembership {
                    user_id: "actor",
                    organization_id: "org",
                    role: 2,
                    status: 2,
                    access_all: false
                }),
                &f
            )
            .unwrap_err()
            .kind,
            ErrorKind::Storage
        );
    }
}
#[test]
fn foreign_personal_and_unconfirmed_or_restricted_destination_fail_closed() {
    let mut s = Memory::new();
    s.sources[0].owner = Some("foreign".into());
    assert_eq!(
        VaultService::new(&mut s)
            .bulk_share_ciphers("actor", &input(&[Some("one")], &["valid"]))
            .unwrap_err()
            .message,
        "Cipher is not write accessible"
    );
    for (role, status, all, selected, ok) in [
        (2, 1, false, "valid", false),
        (2, -1, false, "valid", false),
        (2, 2, false, "unassigned", false),
        (3, 2, false, "unassigned", false),
        (4, 2, true, "unassigned", true),
        (0, 2, false, "readonly", true),
        (2, 2, false, "valid", true),
    ] {
        let mut s = Memory::new();
        s.role = role;
        s.status = status;
        s.all = all;
        assert_eq!(
            VaultService::new(&mut s)
                .bulk_share_ciphers("actor", &input(&[Some("one")], &[selected]))
                .is_ok(),
            ok
        );
    }
}
#[test]
fn provider_owned_snapshots_survive_cache_reuse_and_bad_snapshots_fail_before_writes() {
    for bad in ["source", "ownership", "revision", "member", "collection"] {
        let mut s = Memory::new();
        s.wrong_source = bad == "source";
        s.invalid_ownership = bad == "ownership";
        s.empty_revision = bad == "revision";
        s.wrong_member = bad == "member";
        s.wrong_collection = bad == "collection";
        assert_eq!(
            VaultService::new(&mut s)
                .bulk_share_ciphers("actor", &input(&[Some("one")], &["valid"]))
                .unwrap_err()
                .kind,
            ErrorKind::Storage
        );
        assert!(s.associations.is_empty());
    }
    let mut s = Memory::new();
    VaultService::new(&mut s)
        .bulk_share_ciphers("actor", &input(&[Some("one"), Some("two")], &["valid"]))
        .unwrap();
    assert_eq!(s.commits, vec![1, 0]);
    assert_eq!(s.cache, "replaced cache commit");
}
#[test]
fn provider_phase_failures_and_live_revocation_retain_only_completed_phases() {
    let d = input(&[Some("one"), Some("two")], &["valid", "valid"]);
    let mut s = Memory::new();
    s.fail_association = Some(1);
    assert!(
        VaultService::new(&mut s)
            .bulk_share_ciphers("actor", &d)
            .is_err()
    );
    assert_eq!(s.associations.len(), 1);
    assert!(s.commits.is_empty());
    let mut s = Memory::new();
    s.fail_commit = Some(1);
    assert!(
        VaultService::new(&mut s)
            .bulk_share_ciphers("actor", &d)
            .is_err()
    );
    assert_eq!(s.commits, vec![1]);
    assert_eq!(s.associations.len(), 4);
    assert!(s.source("one").applied.is_none());
    let mut s = Memory::new();
    s.revoke_after_association = true;
    assert_eq!(
        VaultService::new(&mut s)
            .bulk_share_ciphers("actor", &input(&[Some("one")], &["valid"]))
            .unwrap_err()
            .kind,
        ErrorKind::Conflict
    );
    assert_eq!(s.associations.len(), 1);
    assert!(s.commits.is_empty());
    for step in [
        "source",
        "access",
        "membership",
        "collection",
        "associate",
        "folder",
        "commit",
    ] {
        let mut s = Memory::new();
        s.failure = Some(step);
        let mut d = input(&[Some("one")], &["valid"]);
        d.items[0].folder_id = Some("folder");
        assert_eq!(
            VaultService::new(&mut s)
                .bulk_share_ciphers("actor", &d)
                .unwrap_err()
                .kind,
            ErrorKind::Storage
        );
    }
}
#[test]
fn indexed_service_accepts_more_items_than_any_example_wire_capacity() {
    let d = input(&vec![Some("one"); 1025], &["valid"]);
    let mut s = Memory::new();
    VaultService::new(&mut s)
        .bulk_share_ciphers("actor", &d)
        .unwrap();
    assert_eq!(s.commits.len(), 1025);
    assert_eq!(s.source("one").applied, Some(0));
}
#[derive(serde::Deserialize, serde::Serialize)]
struct WireItem<'a> {
    id: Option<&'a str>,
    #[serde(rename = "type")]
    kind: i32,
    name: &'a str,
}
impl CipherBulkShareItemData for WireItem<'_> {
    fn bulk_share_item(&self) -> CipherBulkShareItem<'_> {
        CipherBulkShareItem {
            id: self.id,
            cipher_type: self.kind,
            name: self.name,
            organization_id: None,
            folder_id: None,
        }
    }
}
#[test]
fn bounded_borrowed_wrapper_matches_native_required_case_order_and_capacity() {
    type Body<'a> = CipherBulkShareRequest<'a, WireItem<'a>, 2, 2>;
    for raw in [
        r#"{"ciphers":[{"id":"one","type":2,"name":""}],"collectionIds":["exact"],"encryptedFor":"ignored"}"#,
        r#"[[{"id":"one","type":2,"name":"plain"}],["exact"]]"#,
    ] {
        let d: Body<'_> = serde_json::from_str(raw).unwrap();
        assert_eq!(d.cipher(0).unwrap().id, Some("one"));
        assert_eq!(d.collection(0), Some("exact"));
        assert_eq!(format!("{d:?}"), "CipherBulkShareRequest([REDACTED])");
    }
    for raw in [
        r#"{}"#,
        r#"{"ciphers":[],"CollectionIds":[]}"#,
        r#"{"Ciphers":[],"collectionIds":[]}"#,
        r#"{"ciphers":null,"collectionIds":[]}"#,
        r#"{"ciphers":[],"collectionIds":null}"#,
        r#"{"ciphers":[{"id":"one","type":2}],"collectionIds":[]}"#,
        r#"{"ciphers":[],"collectionIds":["1","2","3"]}"#,
        r#"[[],[],null]"#,
    ] {
        assert!(serde_json::from_str::<Body<'_>>(raw).is_err());
    }
    let raw = r#"{"ciphers":[{"id":"one","type":2,"name":"plain"}],"collectionIds":["exact"]}"#;
    let d: Body<'_> = serde_json::from_str(raw).unwrap();
    let name = d.cipher(0).unwrap().name;
    assert!(
        name.as_ptr() as usize >= raw.as_ptr() as usize
            && (name.as_ptr() as usize) < raw.as_ptr() as usize + raw.len()
    );
}
