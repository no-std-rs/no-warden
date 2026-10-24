use super::*;
use crate::{
    service::ItemMetadata,
    wire::{FolderRequest, RegisterRequest},
};
use std::{
    format,
    string::{String, ToString},
    vec::Vec,
};

const ENCRYPTED: &str = "2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
// Intentionally lacks Clone/Debug/Serialize: the provider contract must not need them.
struct Id(String);
impl AsRef<str> for Id {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
fn id(value: &str) -> Id {
    Id(value.to_string())
}
fn request() -> CipherRequest<'static> {
    serde_json::from_str(r#"{"type":2,"organizationId":"org","encryptedFor":"actor","name":"2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","notes":"2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","secureNote":{"type":0},"favorite":true,"key":null,"lastKnownRevisionDate":"r1"}"#).unwrap()
}
fn member(role: i32, status: i32, all: bool) -> CipherSharingMembership<&'static str> {
    CipherSharingMembership {
        user_id: "actor",
        organization_id: "org",
        role,
        status,
        access_all: all,
    }
}
fn collection(read_only: bool, hide: bool, manage: bool) -> CipherSharingCollection<&'static str> {
    CipherSharingCollection {
        id: "valid",
        user_id: "actor",
        organization_id: "org",
        assigned: true,
        read_only,
        hide_passwords: hide,
        manage,
    }
}
struct Memory {
    calls: Vec<&'static str>,
    associations: Vec<String>,
    target: Option<String>,
    payload: Option<String>,
    source_owner: Option<&'static str>,
    source_org: Option<&'static str>,
    source_present: bool,
    source_bad_id: bool,
    source_empty_revision: bool,
    membership: Option<(i32, i32, bool)>,
    member_bad_user: bool,
    member_bad_org: bool,
    collection_bad_scope: Option<&'static str>,
    provider_failure: Option<&'static str>,
    fail_association: Option<usize>,
    association_calls: usize,
    folder_owner: Option<&'static str>,
    cache: String,
}
impl Memory {
    fn new() -> Self {
        Self {
            calls: Vec::new(),
            associations: Vec::new(),
            target: None,
            payload: None,
            source_owner: Some("actor"),
            source_org: None,
            source_present: true,
            source_bad_id: false,
            source_empty_revision: false,
            membership: Some((2, 2, false)),
            member_bad_user: false,
            member_bad_org: false,
            collection_bad_scope: None,
            provider_failure: None,
            fail_association: None,
            association_calls: 0,
            folder_owner: Some("actor"),
            cache: String::new(),
        }
    }
    fn call(&mut self, step: &'static str) -> Result<(), ()> {
        self.calls.push(step);
        self.cache = step.to_string();
        if self.provider_failure == Some(step) {
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
        Ok(self.folder_owner.map(|owner| ItemMetadata {
            owner_id: owner,
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
impl OrganizationCipherSharingStorage for Memory {
    type ShareId = Id;
    fn sharing_revision_is_older(
        &mut self,
        source: &CipherSharingSource<Id>,
        requested: &str,
    ) -> Result<bool, ()> {
        self.call("revision")?;
        assert_eq!(source.id.as_ref(), "source");
        assert_eq!(source.revision.as_ref(), "r1");
        Ok(requested == "r0")
    }
    fn sharing_source(&mut self, source: &str) -> Result<Option<CipherSharingSource<Id>>, ()> {
        self.call("source")?;
        Ok(self.source_present.then(|| CipherSharingSource {
            id: id(if self.source_bad_id { "wrong" } else { source }),
            owner_id: self.source_owner.map(id),
            organization_id: self.source_org.map(id),
            revision: id(if self.source_empty_revision { "" } else { "r1" }),
        }))
    }
    fn sharing_membership(
        &mut self,
        _: &str,
        _: &str,
    ) -> Result<Option<CipherSharingMembership<Id>>, ()> {
        self.call("membership")?;
        Ok(self
            .membership
            .map(|(role, status, access_all)| CipherSharingMembership {
                user_id: id(if self.member_bad_user {
                    "foreign"
                } else {
                    "actor"
                }),
                organization_id: id(if self.member_bad_org {
                    "foreign"
                } else {
                    "org"
                }),
                role,
                status,
                access_all,
            }))
    }
    fn sharing_collection(
        &mut self,
        _: &str,
        _: &str,
        selected: &str,
    ) -> Result<Option<CipherSharingCollection<Id>>, ()> {
        self.call("collection")?;
        if selected == "missing" || selected == "foreign" {
            return Ok(None);
        }
        Ok(Some(CipherSharingCollection {
            id: id(if self.collection_bad_scope == Some("id") {
                "different"
            } else {
                selected
            }),
            user_id: id(if self.collection_bad_scope == Some("user") {
                "different"
            } else {
                "actor"
            }),
            organization_id: id(if self.collection_bad_scope == Some("org") {
                "different"
            } else {
                "org"
            }),
            assigned: selected != "unassigned",
            read_only: matches!(selected, "readonly" | "managed-readonly"),
            hide_passwords: selected == "hidden",
            manage: selected == "managed-readonly",
        }))
    }
    fn associate_sharing_collection(
        &mut self,
        plan: &ValidatedCipherShareAssociation<'_>,
    ) -> Result<(), ()> {
        self.call("association")?;
        self.association_calls += 1;
        if self.fail_association == Some(self.association_calls) {
            return Err(());
        }
        assert_eq!(plan.owner(), "actor");
        assert_eq!(plan.cipher_id(), "source");
        assert_eq!(plan.source_revision(), "r1");
        assert_eq!(plan.target_organization(), "org");
        if !self
            .associations
            .iter()
            .any(|entry| entry == plan.collection_id())
        {
            self.associations.push(plan.collection_id().to_string());
        }
        Ok(())
    }
    fn commit_cipher_share(&mut self, plan: &ValidatedCipherShare<'_, '_>) -> Result<(), ()> {
        self.call("payload")?;
        assert_eq!(plan.owner(), "actor");
        assert_eq!(plan.cipher_id(), "source");
        assert_eq!(plan.source_revision(), "r1");
        self.target = plan.target_organization().map(ToString::to_string);
        self.payload = plan.request().notes.map(ToString::to_string);
        self.source_org = plan.target_organization().map(|_| "org");
        self.source_owner = self.source_org.is_none().then_some("actor");
        Ok(())
    }
}

#[test]
fn sharing_authentication_and_incomplete_views_precede_provider_access() {
    struct Broken;
    impl CipherShareIdsData for Broken {
        fn len(&self) -> usize {
            2
        }
        fn get(&self, index: usize) -> Option<&str> {
            (index == 0).then_some("valid")
        }
    }
    let mut service = VaultService::new(Memory::new());
    assert_eq!(
        service
            .share_cipher("", "source", &request(), &Broken)
            .unwrap_err()
            .status_code(),
        401
    );
    assert!(service.storage().calls.is_empty());
    assert_eq!(
        service
            .share_cipher("actor", "source", &request(), &Broken)
            .unwrap_err()
            .kind,
        ErrorKind::Storage
    );
    assert!(service.storage().calls.is_empty());
}

#[test]
fn sharing_owned_snapshots_survive_cache_replacement_and_ordered_duplicate_steps() {
    let mut state = Memory::new();
    let ids = ["valid", "hidden", "valid"];
    VaultService::new(&mut state)
        .share_cipher("actor", "source", &request(), ids.as_slice())
        .unwrap();
    assert_eq!(
        state.calls,
        [
            "source",
            "membership",
            "collection",
            "association",
            "collection",
            "association",
            "collection",
            "association",
            "revision",
            "payload"
        ]
    );
    assert_eq!(state.associations, ["valid", "hidden"]);
    assert_eq!(state.association_calls, 3);
    assert_eq!(state.target.as_deref(), Some("org"));
    assert_eq!(state.payload.as_deref(), Some(ENCRYPTED));
}

#[test]
fn sharing_late_missing_or_denied_selection_retains_only_successful_prefix() {
    for rejected in [
        "missing",
        "foreign",
        "readonly",
        "managed-readonly",
        "unassigned",
    ] {
        let mut state = Memory::new();
        let ids = ["valid", rejected, "hidden"];
        assert_eq!(
            VaultService::new(&mut state)
                .share_cipher("actor", "source", &request(), ids.as_slice())
                .unwrap_err()
                .status_code(),
            400
        );
        assert_eq!(state.associations, ["valid"]);
        assert!(state.payload.is_none());
        assert!(state.source_org.is_none());
        assert_eq!(state.source_owner, Some("actor"));
        assert_eq!(state.association_calls, 1);
    }
    let mut state = Memory::new();
    assert!(
        VaultService::new(&mut state)
            .share_cipher(
                "actor",
                "source",
                &request(),
                ["foreign", "valid"].as_slice()
            )
            .is_err()
    );
    assert!(state.associations.is_empty());
}

#[test]
fn sharing_membership_states_grants_and_empty_selection_have_independent_rules() {
    for status in [0, 1, -1] {
        let mut state = Memory::new();
        state.membership = Some((0, status, true));
        assert_eq!(
            VaultService::new(&mut state)
                .share_cipher("actor", "source", &request(), ["valid"].as_slice())
                .unwrap_err()
                .status_code(),
            400
        );
        assert_eq!(state.calls, ["source", "membership"]);
    }
    for membership in [None, Some((2, 2, false)), Some((3, 2, false))] {
        let mut state = Memory::new();
        state.membership = membership;
        assert!(
            VaultService::new(&mut state)
                .share_cipher("actor", "source", &request(), [].as_slice())
                .is_err()
        );
        assert!(state.associations.is_empty());
        assert!(state.payload.is_none());
    }
    for membership in [Some((0, 2, true)), Some((1, 2, false)), Some((3, 2, true))] {
        let mut state = Memory::new();
        state.membership = membership;
        VaultService::new(&mut state)
            .share_cipher("actor", "source", &request(), [].as_slice())
            .unwrap();
        assert!(state.associations.is_empty());
        assert!(state.payload.is_some());
    }
    let mut state = Memory::new();
    state.membership = Some((3, 2, true));
    VaultService::new(&mut state)
        .share_cipher("actor", "source", &request(), ["unassigned"].as_slice())
        .unwrap();
    assert_eq!(state.associations, ["unassigned"]);
}

#[test]
fn sharing_personal_target_ignores_collection_lookups_but_checks_own_folder_and_payload() {
    let mut state = Memory::new();
    state.membership = None;
    let mut payload = request();
    payload.organization_id = None;
    payload.folder_id = Some("folder");
    VaultService::new(&mut state)
        .share_cipher(
            "actor",
            "source",
            &payload,
            ["foreign", "missing"].as_slice(),
        )
        .unwrap();
    assert_eq!(state.calls, ["source", "folder", "revision", "payload"]);
    assert!(state.target.is_none());
    assert!(state.associations.is_empty());
    let mut state = Memory::new();
    state.folder_owner = Some("foreign");
    assert_eq!(
        VaultService::new(&mut state)
            .share_cipher("actor", "source", &payload, [].as_slice())
            .unwrap_err()
            .field,
        Some("folderId")
    );
    assert!(state.payload.is_none());
    let mut state = Memory::new();
    payload.encrypted_for = Some("foreign");
    assert_eq!(
        VaultService::new(&mut state)
            .share_cipher("actor", "source", &payload, [].as_slice())
            .unwrap_err()
            .field,
        Some("encryptedFor")
    );
    assert_eq!(state.calls, ["source"]);
    assert_eq!(
        validation::validate_cipher(&request()).unwrap_err().field,
        Some("organizationId")
    );
}

#[test]
fn sharing_older_revision_rejects_final_payload_after_retaining_associations() {
    let mut state = Memory::new();
    let mut payload = request();
    payload.last_known_revision_date = Some("r0");
    assert_eq!(
        VaultService::new(&mut state)
            .share_cipher("actor", "source", &payload, ["valid"].as_slice())
            .unwrap_err()
            .status_code(),
        400
    );
    assert_eq!(state.associations, ["valid"]);
    assert!(state.payload.is_none());

    // A later selection failure wins before the final revision guard.
    let mut state = Memory::new();
    VaultService::new(&mut state)
        .share_cipher("actor", "source", &payload, ["valid", "missing"].as_slice())
        .unwrap_err();
    assert_eq!(state.associations, ["valid"]);
    assert!(!state.calls.contains(&"revision"));
    assert!(state.payload.is_none());

    // Null organization is a personal update: no association steps precede
    // the same final payload guard, even when IDs were supplied.
    let mut state = Memory::new();
    payload.organization_id = None;
    assert_eq!(
        VaultService::new(&mut state)
            .share_cipher("actor", "source", &payload, ["valid"].as_slice())
            .unwrap_err()
            .status_code(),
        400
    );
    assert!(state.associations.is_empty() && state.payload.is_none());
}

#[test]
fn sharing_revision_comparison_is_provider_owned_and_missing_is_unconditional() {
    for revision in [Some("r1"), Some("r2"), Some("malformed"), None] {
        let mut state = Memory::new();
        let mut payload = request();
        payload.last_known_revision_date = revision;
        VaultService::new(&mut state)
            .share_cipher("actor", "source", &payload, ["valid"].as_slice())
            .unwrap();
        assert!(state.payload.is_some());
        assert_eq!(state.calls.contains(&"revision"), revision.is_some());
    }
}

#[test]
fn sharing_provider_failures_are_safe_and_do_not_undo_prior_individual_steps() {
    for step in [
        "source",
        "membership",
        "collection",
        "association",
        "revision",
        "payload",
    ] {
        let mut state = Memory::new();
        state.provider_failure = Some(step);
        let error = VaultService::new(&mut state)
            .share_cipher("actor", "source", &request(), ["valid"].as_slice())
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Storage);
        assert_eq!(error.message, "Storage operation failed.");
        assert!(state.payload.is_none());
        assert_eq!(
            state.associations.len(),
            usize::from(matches!(step, "revision" | "payload"))
        );
    }
    let mut state = Memory::new();
    state.fail_association = Some(2);
    assert!(
        VaultService::new(&mut state)
            .share_cipher(
                "actor",
                "source",
                &request(),
                ["valid", "hidden"].as_slice()
            )
            .is_err()
    );
    assert_eq!(state.associations, ["valid"]);
    assert!(state.payload.is_none());
}

#[test]
fn sharing_scope_misassociation_is_rejected_even_when_full_access_would_allow_addition() {
    for corrupt in [
        "source-id",
        "source-revision",
        "source-owners",
        "member-user",
        "member-org",
        "collection-id",
        "collection-user",
        "collection-org",
    ] {
        let mut state = Memory::new();
        state.membership = Some((0, 2, true));
        match corrupt {
            "source-id" => state.source_bad_id = true,
            "source-revision" => state.source_empty_revision = true,
            "source-owners" => state.source_org = Some("org"),
            "member-user" => state.member_bad_user = true,
            "member-org" => state.member_bad_org = true,
            "collection-id" => state.collection_bad_scope = Some("id"),
            "collection-user" => state.collection_bad_scope = Some("user"),
            "collection-org" => state.collection_bad_scope = Some("org"),
            _ => unreachable!(),
        }
        assert_eq!(
            VaultService::new(&mut state)
                .share_cipher("actor", "source", &request(), ["valid"].as_slice())
                .unwrap_err()
                .kind,
            ErrorKind::Storage
        );
        assert!(state.associations.is_empty());
        assert!(state.payload.is_none());
    }
    for (owner, org, present) in [
        (Some("foreign"), None, true),
        (None, Some("org"), true),
        (Some("actor"), None, false),
    ] {
        let mut state = Memory::new();
        state.source_owner = owner;
        state.source_org = org;
        state.source_present = present;
        assert_eq!(
            VaultService::new(&mut state)
                .share_cipher("actor", "source", &request(), ["valid"].as_slice())
                .unwrap_err()
                .status_code(),
            400
        );
        assert_eq!(state.calls, ["source"]);
    }
}

#[test]
fn sharing_indexed_input_has_no_intrinsic_sixty_four_or_one_thousand_item_cap() {
    let mut state = Memory::new();
    let ids = ["valid"; 1025];
    VaultService::new(&mut state)
        .share_cipher("actor", "source", &request(), ids.as_slice())
        .unwrap();
    assert_eq!(state.association_calls, 1025);
    assert_eq!(state.associations, ["valid"]);
}

fn access_record(collection: CipherSharingCollection<&str>) -> CipherCollectionAccessRecord<'_> {
    CipherCollectionAccessRecord {
        cipher_organization_id: Some("org"),
        collection,
    }
}

#[test]
fn pure_shared_access_separates_readonly_hidden_and_full_access_flags() {
    let org = CipherOwnership::Organization {
        organization_id: "org",
    };
    let readonly = [access_record(collection(true, false, true))];
    let access =
        resolve_cipher_access("actor", org, Some(member(2, 2, false)), readonly.as_slice())
            .unwrap();
    assert!(access.readable());
    assert!(!access.writable());
    assert!(access.view_password());
    assert!(!access.delete());
    assert!(!access.restore());
    let hidden = [access_record(collection(false, true, false))];
    let access =
        resolve_cipher_access("actor", org, Some(member(2, 2, false)), hidden.as_slice()).unwrap();
    assert!(access.readable());
    assert!(access.writable());
    assert!(!access.view_password());
    assert!(access.delete());
    assert!(access.restore());
    let mut unassigned = collection(false, false, true);
    unassigned.assigned = false;
    let rows = [access_record(unassigned)];
    assert!(
        !resolve_cipher_access("actor", org, Some(member(3, 2, false)), rows.as_slice())
            .unwrap()
            .readable()
    );
    for m in [member(0, 2, true), member(1, 2, false), member(3, 2, true)] {
        let access = resolve_cipher_access("actor", org, Some(m), readonly.as_slice()).unwrap();
        assert!(access.readable() && access.writable() && access.view_password());
    }
    for status in [0, 1, -1] {
        assert!(
            !resolve_cipher_access(
                "actor",
                org,
                Some(member(0, status, true)),
                readonly.as_slice()
            )
            .unwrap()
            .readable()
        );
    }
    assert!(
        !resolve_cipher_access("actor", org, None, readonly.as_slice())
            .unwrap()
            .readable()
    );
}

#[test]
fn pure_access_validates_every_positive_snapshot_row_and_exact_viewer_scope() {
    let empty: &[CipherCollectionAccessRecord<'_>] = &[];
    let org = CipherOwnership::Organization {
        organization_id: "org",
    };
    for wrong in ["user", "org", "empty collection", "empty organization"] {
        let mut row = access_record(collection(false, false, false));
        match wrong {
            "user" => row.collection.user_id = "foreign",
            "org" => row.cipher_organization_id = Some("foreign"),
            "empty collection" => row.collection.id = "",
            _ => row.collection.organization_id = "",
        }
        assert_eq!(
            resolve_cipher_access("actor", org, Some(member(0, 2, true)), [row].as_slice())
                .unwrap_err()
                .kind,
            ErrorKind::Storage
        );
    }
    for wrong in ["user", "org"] {
        let mut m = member(0, 2, true);
        if wrong == "user" {
            m.user_id = "foreign"
        } else {
            m.organization_id = "foreign"
        }
        assert_eq!(
            resolve_cipher_access("actor", org, Some(m), empty)
                .unwrap_err()
                .kind,
            ErrorKind::Storage
        );
    }
    struct Broken;
    impl CipherCollectionAccessData for Broken {
        fn len(&self) -> usize {
            1
        }
        fn get(&self, _: usize) -> Option<CipherCollectionAccessRecord<'_>> {
            None
        }
    }
    assert_eq!(
        resolve_cipher_access("actor", org, Some(member(0, 2, true)), &Broken)
            .unwrap_err()
            .kind,
        ErrorKind::Storage
    );
    let personal = CipherOwnership::Personal { user_id: "actor" };
    let associated = [access_record(collection(false, false, false))];
    assert_eq!(
        resolve_cipher_access("actor", personal, None, associated.as_slice())
            .unwrap_err()
            .kind,
        ErrorKind::Storage
    );
    let unassociated = [CipherCollectionAccessRecord {
        cipher_organization_id: None,
        collection: collection(false, false, false),
    }];
    assert_eq!(
        resolve_cipher_access(
            "actor",
            org,
            Some(member(0, 2, true)),
            unassociated.as_slice()
        )
        .unwrap_err()
        .kind,
        ErrorKind::Storage
    );
    assert!(
        resolve_cipher_access("actor", personal, None, empty)
            .unwrap()
            .writable()
    );
    assert!(
        !resolve_cipher_access("foreign", personal, None, empty)
            .unwrap()
            .readable()
    );
    assert_eq!(
        resolve_cipher_access("", personal, None, &Broken)
            .unwrap_err()
            .status_code(),
        401
    );
}

#[test]
fn historical_associated_grant_requires_confirmed_canonical_membership() {
    let org = CipherOwnership::Organization {
        organization_id: "org",
    };
    let mut historical = collection(false, false, false);
    historical.organization_id = "historical-org";
    let mut current_without_grant = collection(false, false, false);
    current_without_grant.assigned = false;
    let historical = access_record(historical);
    let fresh = [access_record(current_without_grant)];
    for role in [2, 3] {
        let membership = Some(member(role, 2, false));
        assert!(
            !resolve_cipher_access("actor", org, membership, fresh.as_slice())
                .unwrap()
                .readable()
        );
        let rows = [
            CipherCollectionAccessRecord {
                cipher_organization_id: historical.cipher_organization_id,
                collection: historical.collection.view(),
            },
            CipherCollectionAccessRecord {
                cipher_organization_id: fresh[0].cipher_organization_id,
                collection: fresh[0].collection.view(),
            },
        ];
        let access =
            resolve_cipher_access("actor", org, Some(member(role, 2, false)), rows.as_slice())
                .unwrap();
        assert!(access.readable() && access.writable() && access.view_password());
        assert!(access.delete() && access.restore());
        for status in [0, 1, -1] {
            assert!(
                !resolve_cipher_access(
                    "actor",
                    org,
                    Some(member(role, status, false)),
                    rows.as_slice()
                )
                .unwrap()
                .readable()
            );
        }
        assert!(
            !resolve_cipher_access("actor", org, None, rows.as_slice())
                .unwrap()
                .readable()
        );
        let mut historical_membership = member(role, 2, false);
        historical_membership.organization_id = "historical-org";
        assert_eq!(
            resolve_cipher_access("actor", org, Some(historical_membership), rows.as_slice())
                .unwrap_err()
                .kind,
            ErrorKind::Storage
        );
    }
}

#[test]
fn sharing_sensitive_handles_and_authority_debug_output_are_redacted() {
    let source = CipherSharingSource {
        id: id("source-secret"),
        owner_id: Some(id("owner-secret")),
        organization_id: None,
        revision: id("revision-secret"),
    };
    assert_eq!(format!("{source:?}"), "CipherSharingSource([REDACTED])");
    assert_eq!(
        format!("{:?}", access_record(collection(false, false, false))),
        "CipherCollectionAccessRecord([REDACTED])"
    );
    assert_eq!(
        format!("{:?}", member(0, 2, true)),
        "CipherSharingMembership([REDACTED])"
    );
    assert_eq!(
        format!("{:?}", collection(false, false, false)),
        "CipherSharingCollection([REDACTED])"
    );
}
