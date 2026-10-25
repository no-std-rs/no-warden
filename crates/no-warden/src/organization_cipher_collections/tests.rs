use super::*;
use crate::{
    organization_cipher_sharing::CipherCollectionAccessRecord,
    service::ItemMetadata,
    wire::{CipherCollectionsRequest, CipherRequest, FolderRequest, RegisterRequest},
};
use std::{
    string::{String, ToString},
    vec,
    vec::Vec,
};

// IDs deliberately do not implement Clone, Debug, Serialize or Deref.
struct Id(String);
impl AsRef<str> for Id {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
fn id(s: &str) -> Id {
    Id(s.to_string())
}
#[derive(Clone, Copy)]
struct Row {
    id: &'static str,
    user: &'static str,
    org: &'static str,
    canonical: &'static str,
    assigned: bool,
    readonly: bool,
    manage: bool,
}
impl Row {
    fn view(&self) -> CipherSharingCollection<&str> {
        CipherSharingCollection {
            id: self.id,
            user_id: self.user,
            organization_id: self.org,
            assigned: self.assigned,
            read_only: self.readonly,
            hide_passwords: false,
            manage: self.manage,
        }
    }
}
struct Facts {
    rows: Vec<Row>,
    hole: bool,
}
impl CipherCollectionAccessData for Facts {
    fn len(&self) -> usize {
        self.rows.len()
    }
    fn get(&self, i: usize) -> Option<CipherCollectionAccessRecord<'_>> {
        if self.hole {
            return None;
        }
        self.rows.get(i).map(|r| CipherCollectionAccessRecord {
            cipher_organization_id: Some(r.canonical),
            collection: r.view(),
        })
    }
}
struct Probe {
    rows: Vec<Row>,
    links: Vec<&'static str>,
    role: i32,
    status: i32,
    access_all: bool,
    personal: bool,
    source_id: &'static str,
    revision: &'static str,
    member_user: &'static str,
    cache: String,
    reads: usize,
    adds: Vec<&'static str>,
    finishes: usize,
    account_revision: usize,
    payload: &'static str,
    favorite: bool,
    folder: &'static str,
    fail_add: Option<&'static str>,
    fail_finish: bool,
    live_add_revoke: bool,
    live_finish_protect: bool,
    bad_facts: bool,
}
impl Probe {
    fn new() -> Self {
        let mut rows = Vec::new();
        for (name, assigned, readonly, manage) in [
            ("old", true, false, false),
            ("new", true, false, false),
            ("second", true, false, false),
            ("readonly", true, true, false),
            ("manage", true, true, true),
            ("unassigned", false, false, false),
        ] {
            rows.push(Row {
                id: name,
                user: "actor",
                org: "org",
                canonical: "org",
                assigned,
                readonly,
                manage,
            });
        }
        Self {
            rows,
            links: vec!["old"],
            role: 2,
            status: 2,
            access_all: false,
            personal: false,
            source_id: "cipher",
            revision: "revision",
            member_user: "actor",
            cache: String::new(),
            reads: 0,
            adds: Vec::new(),
            finishes: 0,
            account_revision: 0,
            payload: "opaque unchanged bytes",
            favorite: true,
            folder: "private folder",
            fail_add: None,
            fail_finish: false,
            live_add_revoke: false,
            live_finish_protect: false,
            bad_facts: false,
        }
    }
    fn touch(&mut self) {
        self.reads += 1;
        self.cache = std::format!("overwritten provider cache {}", self.reads);
    }
    fn source(&self) -> CipherSharingSource<Id> {
        CipherSharingSource {
            id: id(self.source_id),
            owner_id: self.personal.then(|| id("actor")),
            organization_id: (!self.personal).then(|| id("org")),
            revision: id(self.revision),
        }
    }
    fn member(&self) -> CipherSharingMembership<Id> {
        CipherSharingMembership {
            user_id: id(self.member_user),
            organization_id: id("org"),
            role: self.role,
            status: self.status,
            access_all: self.access_all,
        }
    }
    fn facts(&self) -> Facts {
        Facts {
            rows: self
                .links
                .iter()
                .filter_map(|id| self.rows.iter().find(|r| r.id == *id).copied())
                .collect(),
            hole: self.bad_facts,
        }
    }
    fn unchanged(&self) {
        assert_eq!(self.revision, "revision");
        assert_eq!(self.payload, "opaque unchanged bytes");
        assert!(self.favorite);
        assert_eq!(self.folder, "private folder");
    }
}
impl Storage for Probe {
    type Error = ();
    fn account_exists(&mut self, _: &str) -> Result<bool, ()> {
        Ok(false)
    }
    fn insert_account(&mut self, _: &str, _: &RegisterRequest<'_>) -> Result<(), ()> {
        Ok(())
    }
    fn folder_metadata(&mut self, _: &str) -> Result<Option<ItemMetadata<'_>>, ()> {
        Ok(None)
    }
    fn save_folder(&mut self, _: &str, _: &str, _: &FolderRequest<'_>) -> Result<(), ()> {
        Ok(())
    }
    fn delete_folder(&mut self, _: &str, _: &str) -> Result<(), ()> {
        Ok(())
    }
    fn cipher_metadata(&mut self, _: &str) -> Result<Option<ItemMetadata<'_>>, ()> {
        Ok(None)
    }
    fn save_cipher(&mut self, _: &str, _: &str, _: &CipherRequest<'_>) -> Result<(), ()> {
        panic!("association service must never write cipher payload")
    }
    fn set_cipher_deleted(&mut self, _: &str, _: &str, _: bool) -> Result<(), ()> {
        panic!("association service must never write lifecycle")
    }
    fn delete_cipher(&mut self, _: &str, _: &str) -> Result<(), ()> {
        panic!("association service must never delete cipher")
    }
}
impl OrganizationCipherCollectionsStorage for Probe {
    type CollectionId = Id;
    type CollectionAccess = Facts;
    fn collection_reassignment_source(
        &mut self,
        _: &str,
    ) -> Result<Option<CipherSharingSource<Id>>, ()> {
        self.touch();
        let mut source = self.source();
        self.cache = self.source_id.to_string();
        source.id = Id(self.cache.clone());
        Ok(Some(source))
    }
    fn collection_reassignment_membership(
        &mut self,
        _: &str,
        _: &str,
    ) -> Result<Option<CipherSharingMembership<Id>>, ()> {
        self.touch();
        Ok(Some(self.member()))
    }
    fn collection_reassignment_associations(
        &mut self,
        _: &str,
        _: &CipherSharingSource<Id>,
    ) -> Result<Facts, ()> {
        self.touch();
        Ok(self.facts())
    }
    fn collection_reassignment_target(
        &mut self,
        _: &str,
        _: &str,
        wanted: &str,
    ) -> Result<Option<CipherSharingCollection<Id>>, ()> {
        self.touch();
        Ok(self
            .rows
            .iter()
            .find(|r| r.id == wanted)
            .map(|r| CipherSharingCollection {
                id: id(r.id),
                user_id: id(r.user),
                organization_id: id(r.org),
                assigned: r.assigned,
                read_only: r.readonly,
                hide_passwords: false,
                manage: r.manage,
            }))
    }
    fn add_cipher_collection(&mut self, plan: &ValidatedCipherCollectionAdd<'_>) -> Result<(), ()> {
        if self.live_add_revoke {
            self.status = 3;
        }
        let target = self
            .rows
            .iter()
            .find(|r| r.id == plan.collection_id())
            .ok_or(())?
            .view();
        plan.validate_live(
            &self.source(),
            Some(self.member().view()),
            &self.facts(),
            target,
        )
        .map_err(|_| ())?;
        if self.fail_add == Some(plan.collection_id()) {
            return Err(());
        }
        let selected = self
            .rows
            .iter()
            .find(|r| r.id == plan.collection_id())
            .ok_or(())?
            .id;
        if !self.links.contains(&selected) {
            self.links.push(selected);
        }
        self.adds.push(selected);
        self.account_revision += 1;
        Ok(())
    }
    fn finish_cipher_collections<D: CipherShareIdsData + ?Sized>(
        &mut self,
        plan: &ValidatedCipherCollectionsFinish<'_, D, Facts>,
    ) -> Result<(), ()> {
        if self.live_finish_protect {
            self.rows
                .iter_mut()
                .find(|r| r.id == "old")
                .ok_or(())?
                .readonly = true;
        }
        plan.validate_live(&self.source(), Some(self.member().view()), &self.facts())
            .map_err(|_| ())?;
        if self.fail_finish {
            return Err(());
        }
        let mut removals = Vec::new();
        for index in 0..plan.associated_len() {
            if let Some(id) = plan.removal(index).map_err(|_| ())? {
                removals.push(id);
            }
        }
        self.links.retain(|id| !removals.contains(id));
        self.finishes += 1;
        self.account_revision += 1;
        Ok(())
    }
}
fn run(
    p: &mut Probe,
    ids: &[&str],
    order: &[usize],
) -> Result<CipherCollectionsResponseScope<'static, Id>, ApiError> {
    VaultService::new(p).reassign_cipher_collections("actor", "cipher", ids, order)
}

#[test]
fn borrowed_required_alias_tuple_capacity_and_redaction() {
    for text in [
        r#"{"collectionIds":["secret雪","secret雪"]}"#,
        r#"{"CollectionIds":["secret雪","secret雪"],"organizationId":"ignored","cipher":{"name":"ignored"}}"#,
        r#"[["secret雪","secret雪"]]"#,
    ] {
        let d: CipherCollectionsRequest<'_, 2> = serde_json::from_str(text).unwrap();
        assert_eq!(d.len(), 2);
        assert_eq!(d.get(0), Some("secret雪"));
        let ptr = d.get(0).unwrap().as_ptr() as usize;
        assert!((text.as_ptr() as usize..text.as_ptr() as usize + text.len()).contains(&ptr));
        assert!(!std::format!("{d:?}").contains("secret"));
        validate_collection_selection_order(&d, [1].as_slice()).unwrap();
    }
    for text in [
        r#"{}"#,
        r#"{"collectionIds":null}"#,
        r#"{"collectionids":[]}"#,
        r#"{"collectionIds":["a",7]}"#,
        r#"{"collectionIds":["a","b","c"]}"#,
        r#"[]"#,
        r#"null"#,
        r#"[["a"],0]"#,
    ] {
        assert!(serde_json::from_str::<CipherCollectionsRequest<'_, 2>>(text).is_err());
    }
    let empty: CipherCollectionsRequest<'_, 0> =
        serde_json::from_str(r#"{"collectionIds":[]}"#).unwrap();
    assert!(empty.is_empty());
}
#[test]
fn invalid_permutations_fail_before_provider_calls_or_mutations() {
    for (ids, order) in [
        (vec!["new", "second"], vec![0]),
        (vec!["new", "second"], vec![0, 0]),
        (vec!["new"], vec![1]),
        (vec!["new", "new"], vec![0, 1]),
        (vec![], vec![0]),
    ] {
        let mut p = Probe::new();
        assert!(run(&mut p, &ids, &order).is_err());
        assert_eq!(p.reads, 0);
        assert!(p.adds.is_empty());
        assert_eq!(p.finishes, 0);
    }
    struct Hole;
    impl CipherShareIdsData for Hole {
        fn len(&self) -> usize {
            1
        }
        fn get(&self, _: usize) -> Option<&str> {
            None
        }
    }
    struct MissingOrder;
    impl CipherCollectionSelectionOrder for MissingOrder {
        fn len(&self) -> usize {
            1
        }
        fn get(&self, _: usize) -> Option<usize> {
            None
        }
    }
    let mut p = Probe::new();
    assert!(
        VaultService::new(&mut p)
            .reassign_cipher_collections("actor", "cipher", &Hole, [0].as_slice())
            .is_err()
    );
    assert!(
        VaultService::new(&mut p)
            .reassign_cipher_collections("actor", "cipher", ["new"].as_slice(), &MissingOrder)
            .is_err()
    );
    assert_eq!(p.reads, 0);
}
#[test]
fn operation_order_deduplicates_and_does_not_claim_input_prefix() {
    let mut p = Probe::new();
    run(&mut p, &["new", "second", "new"], &[1, 2]).unwrap();
    assert_eq!(p.adds, ["second", "new"]);
    assert_eq!(p.links, ["second", "new"]);
    assert_eq!(p.finishes, 1);
    assert!(p.cache.starts_with("overwritten"));
    p.unchanged();
}
#[test]
fn late_missing_target_retains_committed_subset_and_old_links_without_finish() {
    for (order, expected) in [(vec![0, 1], vec!["old", "new"]), (vec![1, 0], vec!["old"])] {
        let mut p = Probe::new();
        assert!(run(&mut p, &["new", "missing"], &order).is_err());
        assert_eq!(p.links, expected);
        assert_eq!(p.finishes, 0);
        assert_eq!(p.account_revision, p.adds.len());
        p.unchanged();
    }
}
#[test]
fn protected_old_links_survive_while_omitted_writable_links_are_removed() {
    let mut p = Probe::new();
    p.links = vec!["old", "readonly", "manage", "unassigned"];
    run(&mut p, &["new"], &[0]).unwrap();
    assert_eq!(p.links, ["readonly", "manage", "unassigned", "new"]);
    p.unchanged();
    let mut p = Probe::new();
    p.links = vec!["old", "readonly", "manage", "unassigned"];
    run(&mut p, &[], &[]).unwrap();
    assert_eq!(p.links, ["readonly", "manage", "unassigned"]);
    assert_eq!(p.account_revision, 1);
}
#[test]
fn full_roles_can_select_unassigned_and_clear_all_but_remain_confirmed() {
    for (role, access_all) in [(0, false), (1, false), (4, true)] {
        let mut p = Probe::new();
        p.role = role;
        p.access_all = access_all;
        run(&mut p, &["unassigned"], &[0]).unwrap();
        assert_eq!(p.links, ["unassigned"]);
        run(&mut p, &[], &[]).unwrap();
        assert!(p.links.is_empty());
        p.unchanged();
    }
    for status in [0, 1, 3] {
        let mut p = Probe::new();
        p.role = 0;
        p.status = status;
        assert!(run(&mut p, &[], &[]).is_err());
        assert_eq!(p.finishes, 0);
    }
}
#[test]
fn source_readonly_manage_is_allowed_but_reselecting_readonly_manage_is_denied() {
    let mut p = Probe::new();
    p.links = vec!["manage"];
    run(&mut p, &["new"], &[0]).unwrap();
    assert_eq!(p.links, ["manage", "new"]);
    for selected in ["manage", "readonly", "unassigned"] {
        let mut p = Probe::new();
        p.links = vec!["manage"];
        assert!(run(&mut p, &[selected], &[0]).is_err());
        assert_eq!(p.links, ["manage"]);
        assert!(p.adds.is_empty());
    }
    for source in ["readonly", "unassigned"] {
        let mut p = Probe::new();
        p.links = vec![source];
        assert!(run(&mut p, &["new"], &[0]).is_err());
        assert!(p.adds.is_empty());
    }
}
#[test]
fn noop_finish_bumps_account_revision_and_preserves_every_cipher_field() {
    let mut p = Probe::new();
    run(&mut p, &["old"], &[0]).unwrap();
    assert_eq!(p.links, ["old"]);
    assert_eq!(p.finishes, 1);
    let previous = p.account_revision;
    run(&mut p, &["old"], &[0]).unwrap();
    assert!(p.account_revision > previous);
    assert_eq!(p.finishes, 2);
    p.unchanged();
}
#[test]
fn response_scope_survives_loss_of_read_and_rejects_other_source_binding() {
    let mut p = Probe::new();
    let response = run(&mut p, &[], &[]).unwrap();
    assert!(p.links.is_empty());
    response.validate_source(&p.source()).unwrap();
    let access = response
        .response_access(Some(p.member().view()), &p.facts())
        .unwrap();
    assert!(!access.readable() && !access.writable() && !access.view_password());
    assert_eq!(response.cipher_id(), "cipher");
    assert_eq!(response.organization_id(), "org");
    assert_eq!(response.actor(), "actor");
    assert!(run(&mut p, &[], &[]).is_err());
    p.source_id = "other";
    assert!(response.validate_source(&p.source()).is_err());
    assert!(!std::format!("{response:?}").contains("actor"));
    p.unchanged();
}
#[test]
fn provider_add_and_final_failures_preserve_earlier_durable_adds() {
    let mut p = Probe::new();
    p.fail_add = Some("second");
    assert!(run(&mut p, &["new", "second"], &[0, 1]).is_err());
    assert_eq!(p.links, ["old", "new"]);
    assert_eq!(p.adds, ["new"]);
    assert_eq!(p.finishes, 0);
    p.unchanged();
    let mut p = Probe::new();
    p.fail_finish = true;
    assert!(run(&mut p, &["new"], &[0]).is_err());
    assert_eq!(p.links, ["old", "new"]);
    assert_eq!(p.finishes, 0);
    assert_eq!(p.account_revision, 1);
    p.unchanged();
}
#[test]
fn live_transaction_rechecks_reject_revocation_and_new_protected_link_permissions() {
    let mut p = Probe::new();
    p.live_add_revoke = true;
    assert!(run(&mut p, &["new"], &[0]).is_err());
    assert_eq!(p.links, ["old"]);
    assert_eq!(p.account_revision, 0);
    let mut p = Probe::new();
    p.live_finish_protect = true;
    assert!(run(&mut p, &["new"], &[0]).is_err());
    assert_eq!(p.links, ["old", "new"]);
    assert_eq!(p.finishes, 0);
    assert_eq!(p.account_revision, 1);
    p.unchanged();
}
#[test]
fn provider_source_membership_and_association_scope_errors_never_mutate() {
    for variant in 0..6 {
        let mut p = Probe::new();
        match variant {
            0 => p.personal = true,
            1 => p.source_id = "other",
            2 => p.member_user = "other",
            3 => p.rows[0].canonical = "other",
            4 => p.bad_facts = true,
            _ => p.revision = "",
        };
        assert!(run(&mut p, &["new"], &[0]).is_err());
        assert!(p.adds.is_empty());
        assert_eq!(p.finishes, 0);
    }
    let mut p = Probe::new();
    p.rows.iter_mut().find(|r| r.id == "new").unwrap().org = "foreign";
    assert!(run(&mut p, &["new"], &[0]).is_err());
    assert_eq!(p.links, ["old"]);
}

#[test]
fn owned_source_snapshot_survives_cache_reuse_without_clone_id_bounds() {
    let mut p = Probe::new();
    let scope = run(&mut p, &["new"], &[0]).unwrap();
    assert_eq!(scope.cipher_id(), "cipher");
    assert_eq!(scope.source_revision(), "revision");
    assert_ne!(p.cache, "cipher");
    assert!(p.reads > 8);
    scope.validate_source(&p.source()).unwrap();
}
