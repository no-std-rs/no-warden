use super::*;
use crate::{
    Storage,
    organization_collections::{
        CollectionAccessEntry, CollectionCreateData, OrganizationCollectionMembership,
        ValidatedCollectionCreate,
    },
    organizations::{
        CollectionRecord, OrganizationCreationPolicy, OrganizationMembership,
        OrganizationProfileRecord, OrganizationRecord, OrganizationStorage, UserCollectionRecord,
        ValidatedOrganizationCreate,
    },
    service::ItemMetadata,
    wire::{CipherRequest, FolderRequest, RegisterRequest},
};
use std::{format, vec, vec::Vec};
struct CipherView {
    rows: Vec<OrganizationCipherReadRecord<'static>>,
    hole: bool,
}
impl OrganizationCipherReadData for CipherView {
    fn len(&self) -> usize {
        self.rows.len()
    }
    fn get(&self, i: usize) -> Option<OrganizationCipherReadRecord<'_>> {
        if self.hole {
            None
        } else {
            self.rows.get(i).copied()
        }
    }
}
struct Details {
    row: UserCollectionRecord<'static>,
    users: Vec<CollectionAccessEntry<'static>>,
    groups: Vec<CollectionAccessEntry<'static>>,
    hole: bool,
}
impl CollectionAccessData for Details {
    fn collection(&self) -> UserCollectionRecord<'_> {
        self.row
    }
    fn assigned(&self) -> bool {
        true
    }
    fn users_len(&self) -> usize {
        self.users.len()
    }
    fn user(&self, i: usize) -> Option<CollectionAccessEntry<'_>> {
        if self.hole {
            None
        } else {
            self.users.get(i).copied()
        }
    }
    fn groups_enabled(&self) -> bool {
        true
    }
    fn groups_len(&self) -> usize {
        self.groups.len()
    }
    fn group(&self, i: usize) -> Option<CollectionAccessEntry<'_>> {
        if self.hole {
            None
        } else {
            self.groups.get(i).copied()
        }
    }
}
struct DetailsRows {
    rows: Vec<Details>,
    hole: bool,
}
impl OrganizationCollectionDetailsData for DetailsRows {
    type Details<'a> = &'a Details;
    fn len(&self) -> usize {
        self.rows.len()
    }
    fn get(&self, i: usize) -> Option<Self::Details<'_>> {
        if self.hole { None } else { self.rows.get(i) }
    }
}
struct Memory {
    actor: Option<OrganizationCollectionMembership<'static>>,
    ciphers: CipherView,
    details: DetailsRows,
    groups: OrganizationGroupPresence,
    calls: Vec<&'static str>,
    fail: Option<&'static str>,
}
fn member() -> OrganizationMembership<'static> {
    OrganizationMembership {
        user_id: "actor",
        organization_id: "org",
        role: 0,
        status: 2,
    }
}
fn selection() -> CollectionAccessEntry<'static> {
    CollectionAccessEntry {
        id: "selected-member",
        organization_id: "org",
        read_only: true,
        hide_passwords: false,
        manage: false,
    }
}
impl Memory {
    fn new() -> Self {
        Self {
            actor: Some(OrganizationCollectionMembership {
                membership: member(),
                access_all: false,
            }),
            ciphers: CipherView {
                rows: vec![OrganizationCipherReadRecord {
                    id: "opaque-id",
                    organization_id: "org",
                }],
                hole: false,
            },
            details: DetailsRows {
                rows: vec![Details {
                    row: UserCollectionRecord {
                        collection: CollectionRecord {
                            id: "collection",
                            organization_id: "org",
                            name: "opaque encrypted name",
                            external_id: None,
                        },
                        membership: member(),
                        readable: true,
                        read_only: false,
                        hide_passwords: false,
                        manage: true,
                    },
                    users: vec![selection()],
                    groups: Vec::new(),
                    hole: false,
                }],
                hole: false,
            },
            groups: OrganizationGroupPresence::NoCreatedGroups,
            calls: Vec::new(),
            fail: None,
        }
    }
    fn step(&mut self, name: &'static str) -> Result<(), ()> {
        self.calls.push(name);
        if self.fail == Some(name) {
            Err(())
        } else {
            Ok(())
        }
    }
}
impl Storage for Memory {
    type Error = ();
    fn map_error(_: ()) -> ApiError {
        ApiError::new(
            ErrorKind::Conflict,
            "Organization read provider unavailable",
        )
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
impl OrganizationStorage for Memory {
    type Collections<'a> = &'a [UserCollectionRecord<'static>];
    type Profiles<'a> = &'a [OrganizationProfileRecord<'static>];
    fn creation_policy(&mut self, _: &str, _: &str) -> Result<OrganizationCreationPolicy, ()> {
        unreachable!()
    }
    fn create_organization(
        &mut self,
        _: &str,
        _: &ValidatedOrganizationCreate<'_, '_>,
    ) -> Result<OrganizationRecord<'_>, ()> {
        unreachable!()
    }
    fn organization_membership(
        &mut self,
        _: &str,
        _: &str,
    ) -> Result<Option<OrganizationMembership<'_>>, ()> {
        unreachable!()
    }
    fn organization(&mut self, _: &str) -> Result<Option<OrganizationRecord<'_>>, ()> {
        unreachable!()
    }
    fn user_collections(&mut self, _: &str) -> Result<Self::Collections<'_>, ()> {
        unreachable!()
    }
    fn profile_organizations(&mut self, _: &str) -> Result<Self::Profiles<'_>, ()> {
        unreachable!()
    }
}
struct Unused;
impl CollectionAccessData for Unused {
    fn collection(&self) -> UserCollectionRecord<'_> {
        unreachable!()
    }
    fn assigned(&self) -> bool {
        unreachable!()
    }
    fn users_len(&self) -> usize {
        unreachable!()
    }
    fn user(&self, _: usize) -> Option<CollectionAccessEntry<'_>> {
        unreachable!()
    }
    fn groups_enabled(&self) -> bool {
        unreachable!()
    }
    fn groups_len(&self) -> usize {
        unreachable!()
    }
    fn group(&self, _: usize) -> Option<CollectionAccessEntry<'_>> {
        unreachable!()
    }
}
impl OrganizationCollectionStorage for Memory {
    type OrgCollections<'a> = &'a [CollectionRecord<'static>];
    type AccessDetails<'a> = Unused;
    fn collection_membership(
        &mut self,
        _: &str,
        _: &str,
    ) -> Result<Option<OrganizationCollectionMembership<'_>>, ()> {
        self.step("actor")?;
        Ok(self.actor)
    }
    fn org_collections(&mut self, _: &str) -> Result<Self::OrgCollections<'_>, ()> {
        unreachable!()
    }
    fn can_manage_collection(&mut self, _: &str, _: &str) -> Result<bool, ()> {
        unreachable!()
    }
    fn collection_access_details(
        &mut self,
        _: &str,
        _: &str,
    ) -> Result<Option<Self::AccessDetails<'_>>, ()> {
        unreachable!()
    }
    fn collection_group_exists(&mut self, _: &str, _: &str) -> Result<bool, ()> {
        unreachable!()
    }
    fn collection_member_exists(&mut self, _: &str, _: &str) -> Result<bool, ()> {
        unreachable!()
    }
    fn create_collection<D: CollectionCreateData + ?Sized>(
        &mut self,
        _: &str,
        _: &str,
        _: &ValidatedCollectionCreate<'_, D>,
    ) -> Result<UserCollectionRecord<'_>, ()> {
        unreachable!()
    }
}

impl OrganizationWebReadsStorage for Memory {
    type CipherReads<'a> = &'a CipherView;
    type CollectionDetails<'a> = &'a DetailsRows;
    fn organization_cipher_reads(&mut self, org: &str) -> Result<Self::CipherReads<'_>, ()> {
        assert_eq!(org, "org");
        self.step("ciphers")?;
        Ok(&self.ciphers)
    }
    fn organization_collection_details(
        &mut self,
        owner: &str,
        org: &str,
    ) -> Result<Self::CollectionDetails<'_>, ()> {
        assert_eq!((owner, org), ("actor", "org"));
        self.step("collections")?;
        Ok(&self.details)
    }
    fn organization_group_presence(&mut self, org: &str) -> Result<OrganizationGroupPresence, ()> {
        assert_eq!(org, "org");
        self.step("groups")?;
        Ok(self.groups)
    }
}
#[test]
fn web_reads_keep_manager_admission_distinct_from_full_access() {
    for role in [0, 1, 3] {
        for all in [false, true] {
            let mut m = Memory::new();
            m.actor.as_mut().unwrap().membership.role = role;
            m.actor.as_mut().unwrap().access_all = all;
            let ok = role != 3 || all;
            let error = VaultService::new(&mut m)
                .authorize_org_cipher_list("actor", "org")
                .err();
            assert_eq!(
                error.map(|e| e.status_code()),
                if ok { None } else { Some(404) }
            );
            m.calls.clear();
            let groups = VaultService::new(&mut m).list_empty_org_groups("actor", "org");
            assert_eq!(groups.is_ok(), ok);
            m.calls.clear();
            assert!(
                VaultService::new(&mut m)
                    .list_org_collection_details("actor", "org")
                    .is_ok()
            );
            assert_eq!(m.calls, ["actor", "collections"]);
        }
    }
    for (role, status) in [(2, 2), (4, 2), (0, 0), (1, 1), (3, -1)] {
        let mut m = Memory::new();
        m.actor.as_mut().unwrap().membership.role = role;
        m.actor.as_mut().unwrap().membership.status = status;
        assert_eq!(
            VaultService::new(&mut m)
                .authorize_org_cipher_list("actor", "org")
                .unwrap_err()
                .status_code(),
            401
        );
        assert_eq!(m.calls, ["actor"]);
    }
    let mut m = Memory::new();
    assert_eq!(
        VaultService::new(&mut m)
            .list_empty_org_groups("", "org")
            .unwrap_err()
            .status_code(),
        401
    );
    assert!(m.calls.is_empty());
    m.actor = None;
    assert_eq!(
        VaultService::new(&mut m)
            .list_org_collection_details("actor", "org")
            .unwrap_err()
            .status_code(),
        401
    );
    assert_eq!(m.calls, ["actor"]);
}
#[test]
fn cipher_grants_preserve_uncapped_order_and_reject_incomplete_or_foreign_views() {
    let mut m = Memory::new();
    m.ciphers.rows = vec![
        OrganizationCipherReadRecord {
            id: "retained-id",
            organization_id: "org"
        };
        1025
    ];
    let mut service = VaultService::new(&mut m);
    let grant = service.authorize_org_cipher_list("actor", "org").unwrap();
    assert_eq!(grant.len(), 1025);
    assert!(!grant.is_empty());
    assert_eq!(grant.get(1024).unwrap().id, "retained-id");
    assert!(grant.get(1025).is_none());
    for problem in ["hole", "foreign", "empty"] {
        let mut m = Memory::new();
        match problem {
            "hole" => m.ciphers.hole = true,
            "foreign" => m.ciphers.rows[0].organization_id = "foreign",
            _ => m.ciphers.rows[0].id = "",
        };
        assert_eq!(
            VaultService::new(&mut m)
                .authorize_org_cipher_list("actor", "org")
                .unwrap_err()
                .kind,
            ErrorKind::Storage
        );
    }
}
#[test]
fn collection_list_adds_only_unmanaged_to_the_individual_thirteen_fields() {
    let mut m = Memory::new();
    let individual =
        serde_json::to_value(CollectionAccessDetailsResponse::new(&m.details.rows[0])).unwrap();
    assert_eq!(individual.as_object().unwrap().len(), 13);
    assert!(individual.get("unmanaged").is_none());
    let value = serde_json::to_value(
        VaultService::new(&mut m)
            .list_org_collection_details("actor", "org")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(value.as_object().unwrap().len(), 3);
    assert_eq!(value["object"], "list");
    assert!(value["continuationToken"].is_null());
    let mut row = value["data"][0].clone();
    assert_eq!(row.as_object().unwrap().len(), 14);
    assert_eq!(row["unmanaged"], false);
    assert!(row.get("managed").is_none());
    row.as_object_mut().unwrap().remove("unmanaged");
    assert_eq!(row, individual);
    assert_eq!(row["users"][0].as_object().unwrap().len(), 4);
}
#[test]
fn collection_scope_membership_and_nested_selection_defects_fail_closed() {
    for problem in [
        "hole",
        "nested-hole",
        "collection-org",
        "member-org",
        "member-user",
        "member-state",
        "unreadable",
        "user-org",
        "group-org",
    ] {
        let mut m = Memory::new();
        match problem {
            "hole" => m.details.hole = true,
            "nested-hole" => m.details.rows[0].hole = true,
            "collection-org" => m.details.rows[0].row.collection.organization_id = "foreign",
            "member-org" => m.details.rows[0].row.membership.organization_id = "foreign",
            "member-user" => m.details.rows[0].row.membership.user_id = "foreign",
            "member-state" => m.details.rows[0].row.membership.status = 1,
            "unreadable" => m.details.rows[0].row.readable = false,
            "user-org" => m.details.rows[0].users[0].organization_id = "foreign",
            _ => {
                let mut group = selection();
                group.organization_id = "foreign";
                m.details.rows[0].groups.push(group)
            }
        };
        assert_eq!(
            VaultService::new(&mut m)
                .list_org_collection_details("actor", "org")
                .unwrap_err()
                .kind,
            ErrorKind::Storage
        );
    }
}
#[test]
fn empty_groups_need_provider_proof_and_provider_errors_are_not_empty_success() {
    let mut m = Memory::new();
    let value = serde_json::to_value(
        VaultService::new(&mut m)
            .list_empty_org_groups("actor", "org")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        value,
        serde_json::json!({"object":"list","data":[],"continuationToken":null})
    );
    m.groups = OrganizationGroupPresence::ConfiguredOrUnknown;
    assert_eq!(
        VaultService::new(&mut m)
            .list_empty_org_groups("actor", "org")
            .unwrap_err()
            .kind,
        ErrorKind::Forbidden
    );
    for step in ["actor", "ciphers", "collections", "groups"] {
        let mut m = Memory::new();
        m.fail = Some(step);
        let error = match step {
            "actor" | "ciphers" => VaultService::new(&mut m)
                .authorize_org_cipher_list("actor", "org")
                .unwrap_err(),
            "collections" => VaultService::new(&mut m)
                .list_org_collection_details("actor", "org")
                .unwrap_err(),
            _ => VaultService::new(&mut m)
                .list_empty_org_groups("actor", "org")
                .unwrap_err(),
        };
        assert_eq!(error.kind, ErrorKind::Conflict);
    }
}
#[test]
fn public_scoped_handles_redact_debug_output() {
    let m = Memory::new();
    assert!(!format!("{:?}", m.ciphers.rows[0]).contains("opaque-id"));
    let mut m = Memory::new();
    let mut service = VaultService::new(&mut m);
    let grant = service.authorize_org_cipher_list("actor", "org").unwrap();
    assert_eq!(
        format!("{grant:?}"),
        "OrganizationCipherListGrant([REDACTED])"
    );
}
