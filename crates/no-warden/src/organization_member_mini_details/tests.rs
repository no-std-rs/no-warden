use super::*;
use crate::{
    Storage,
    organization_collections::{
        CollectionAccessData, CollectionAccessEntry, CollectionCreateData,
        OrganizationCollectionMembership, ValidatedCollectionCreate,
    },
    organizations::{
        CollectionRecord, OrganizationCreationPolicy, OrganizationMembership,
        OrganizationProfileRecord, OrganizationRecord, OrganizationStorage, UserCollectionRecord,
        ValidatedOrganizationCreate,
    },
    service::ItemMetadata,
    wire::{CipherRequest, FolderRequest, RegisterRequest},
};
use std::{format, vec::Vec};
struct View {
    rows: Vec<OrganizationMemberMiniRecord<'static>>,
    hole: bool,
}
impl OrganizationMemberMiniData for View {
    fn len(&self) -> usize {
        self.rows.len()
    }
    fn get(&self, index: usize) -> Option<OrganizationMemberMiniRecord<'_>> {
        if self.hole {
            None
        } else {
            self.rows.get(index).copied()
        }
    }
}
struct Memory {
    actor: Option<OrganizationCollectionMembership<'static>>,
    view: View,
    calls: Vec<&'static str>,
    fail: Option<&'static str>,
}
impl Memory {
    fn new() -> Self {
        Self {
            actor: Some(OrganizationCollectionMembership {
                membership: OrganizationMembership {
                    user_id: "actor",
                    organization_id: "org",
                    role: 0,
                    status: 2,
                },
                access_all: false,
            }),
            view: View {
                rows: std::vec![row()],
                hole: false,
            },
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
fn row() -> OrganizationMemberMiniRecord<'static> {
    OrganizationMemberMiniRecord {
        membership_id: "member",
        organization_id: "org",
        user_id: "recipient",
        email: "recipient@example.test",
        name: "opaque name 雪\0",
        role: 2,
        status: 1,
    }
}
impl Storage for Memory {
    type Error = ();
    fn map_error(_: ()) -> ApiError {
        ApiError::new(ErrorKind::Conflict, "Mini-member provider unavailable")
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

impl OrganizationMemberMiniStorage for Memory {
    type MiniMembers<'a> = &'a View;
    fn organization_member_mini_details(
        &mut self,
        organization: &str,
    ) -> Result<Self::MiniMembers<'_>, ()> {
        assert_eq!(organization, "org");
        self.step("read")?;
        Ok(&self.view)
    }
}
#[test]
fn mini_details_authenticates_confirmed_managers_without_requiring_full_access() {
    for role in [0, 1, 3] {
        for access_all in [false, true] {
            let mut memory = Memory::new();
            let actor = memory.actor.as_mut().unwrap();
            actor.membership.role = role;
            actor.access_all = access_all;
            let value = serde_json::to_value(
                VaultService::new(&mut memory)
                    .list_org_member_mini_details("actor", "org")
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(value["data"].as_array().unwrap().len(), 1);
            assert_eq!(memory.calls, ["actor", "read"]);
        }
    }
    for (role, status) in [(2, 2), (4, 2), (-7, 2), (0, 0), (1, 1), (3, -126)] {
        let mut memory = Memory::new();
        let actor = memory.actor.as_mut().unwrap();
        actor.membership.role = role;
        actor.membership.status = status;
        let error = VaultService::new(&mut memory)
            .list_org_member_mini_details("actor", "org")
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Unauthorized);
        assert_eq!(memory.calls, ["actor"]);
    }
    let mut memory = Memory::new();
    assert_eq!(
        VaultService::new(&mut memory)
            .list_org_member_mini_details("", "org")
            .unwrap_err()
            .kind,
        ErrorKind::Unauthorized
    );
    assert!(memory.calls.is_empty());
    for user_mismatch in [false, true] {
        let mut memory = Memory::new();
        let actor = &mut memory.actor.as_mut().unwrap().membership;
        if user_mismatch {
            actor.user_id = "foreign"
        } else {
            actor.organization_id = "foreign"
        };
        assert_eq!(
            VaultService::new(&mut memory)
                .list_org_member_mini_details("actor", "org")
                .unwrap_err()
                .kind,
            ErrorKind::Unauthorized
        );
        assert_eq!(memory.calls, ["actor"]);
    }
}
#[test]
fn mini_details_seven_field_projection_keeps_names_all_states_role_mapping_and_provider_order() {
    let mut memory = Memory::new();
    memory.view.rows.clear();
    for (index, (role, status, name)) in [
        (0, 0, ""),
        (1, 1, "accepted"),
        (3, 2, "manager"),
        (2, -126, "revoked"),
    ]
    .into_iter()
    .enumerate()
    {
        let ids = ["invited", "accepted", "confirmed", "revoked"];
        let mut r = row();
        r.membership_id = ids[index];
        r.role = role;
        r.status = status;
        r.name = name;
        memory.view.rows.push(r);
    }
    let mut service = VaultService::new(&mut memory);
    let response = service
        .list_org_member_mini_details("actor", "org")
        .unwrap();
    assert_eq!(
        format!("{response:?}"),
        "OrganizationMemberMiniDetailsResponse([REDACTED])"
    );
    let value = serde_json::to_value(response).unwrap();
    assert_eq!(value["object"], "list");
    assert_eq!(value["continuationToken"], serde_json::Value::Null);
    assert_eq!(value.as_object().unwrap().len(), 3);
    for (index, (id, role, status, name)) in [
        ("invited", 0, 0, ""),
        ("accepted", 1, 1, "accepted"),
        ("confirmed", 4, 2, "manager"),
        ("revoked", 2, -1, "revoked"),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(
            value["data"][index],
            serde_json::json!({"id":id,"userId":"recipient","email":"recipient@example.test","name":name,"type":role,"status":status,"object":"organizationUserUserMiniDetails"})
        );
    }
    assert_eq!(
        format!("{:?}", memory.view.rows[0]),
        "OrganizationMemberMiniRecord([REDACTED])"
    );
}
#[test]
fn mini_details_rejects_foreign_incomplete_and_provider_error_views_before_projection() {
    for hole in [true, false] {
        let mut memory = Memory::new();
        if hole {
            memory.view.hole = true;
        } else {
            memory.view.rows[0].organization_id = "foreign";
        }
        let error = VaultService::new(&mut memory)
            .list_org_member_mini_details("actor", "org")
            .unwrap_err();
        assert_eq!(
            error.kind,
            if hole {
                ErrorKind::Storage
            } else {
                ErrorKind::Unauthorized
            }
        );
        assert_eq!(memory.calls, ["actor", "read"]);
    }
    for stage in ["actor", "read"] {
        let mut memory = Memory::new();
        memory.fail = Some(stage);
        let error = VaultService::new(&mut memory)
            .list_org_member_mini_details("actor", "org")
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Conflict);
        assert_eq!(error.message, "Mini-member provider unavailable");
    }
}
#[test]
fn mini_details_empty_large_and_forwarded_views_require_no_core_batch_allocation() {
    let mut memory = Memory::new();
    memory.view.rows.clear();
    let mut service = VaultService::new(&mut memory);
    let response = service
        .list_org_member_mini_details("actor", "org")
        .unwrap();
    assert_eq!(
        serde_json::to_value(response).unwrap(),
        serde_json::json!({"data":[],"object":"list","continuationToken":null})
    );
    memory.view.rows = std::vec![row();513];
    let mut forward = &mut memory;
    let value = serde_json::to_value(
        VaultService::new(&mut forward)
            .list_org_member_mini_details("actor", "org")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(value["data"].as_array().unwrap().len(), 513);
    let rows = [row()];
    let borrowed: &[OrganizationMemberMiniRecord<'_>] = &rows;
    assert_eq!(OrganizationMemberMiniData::len(&borrowed), 1);
    assert!(!OrganizationMemberMiniData::is_empty(&borrowed));
    assert!(OrganizationMemberMiniData::get(&borrowed, 1).is_none());
}
