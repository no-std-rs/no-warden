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
    wire::{CipherRequest, FolderRequest, OrganizationMemberPublicKeysRequest, RegisterRequest},
};
use std::{
    format,
    string::{String, ToString},
    vec::Vec,
};
struct Id(String);
impl AsRef<str> for Id {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
struct Key(String);
impl AsRef<str> for Key {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
struct Memory {
    actor: Option<OrganizationCollectionMembership<'static>>,
    calls: Vec<&'static str>,
    lookups: usize,
    fail_actor: bool,
    fail_lookup: Option<usize>,
    corrupt_lookup: Option<(usize, bool)>,
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
            calls: Vec::new(),
            lookups: 0,
            fail_actor: false,
            fail_lookup: None,
            corrupt_lookup: None,
        }
    }
    fn step(&mut self, name: &'static str) -> Result<(), ()> {
        self.calls.push(name);
        if name == "actor" && self.fail_actor {
            Err(())
        } else {
            Ok(())
        }
    }
}
impl Storage for Memory {
    type Error = ();
    fn map_error(_: ()) -> ApiError {
        ApiError::new(ErrorKind::Conflict, "Public-key provider unavailable")
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

impl OrganizationMemberPublicKeyStorage for Memory {
    type Id = Id;
    type PublicKey = Key;
    fn member_public_key(
        &mut self,
        org: &str,
        member: &str,
    ) -> Result<Option<OrganizationMemberPublicKeyRecord<Id, Key>>, ()> {
        assert_eq!(org, "org");
        self.step("lookup")?;
        self.lookups += 1;
        if self.fail_lookup == Some(self.lookups) {
            return Err(());
        }
        let (user, key) = match member {
            "member" => ("recipient", Some("future-public-key\0雪")),
            "null" => ("placeholder", None),
            "empty" => ("empty-account", Some("")),
            "actor-member" => ("actor", Some("actor-public-key")),
            _ => return Ok(None),
        };
        let (record_org, record_id) = match self.corrupt_lookup {
            Some((index, true)) if index == self.lookups => ("foreign", member),
            Some((index, false)) if index == self.lookups => (org, "wrong-member"),
            _ => (org, member),
        };
        Ok(Some(OrganizationMemberPublicKeyRecord {
            membership_id: Id(record_id.to_string()),
            organization_id: Id(record_org.to_string()),
            user_id: Id(user.to_string()),
            public_key: key.map(|key| Key(key.to_string())),
        }))
    }
}
fn slots<const N: usize>() -> [Option<OrganizationMemberPublicKeyRecord<Id, Key>>; N] {
    core::array::from_fn(|_| None)
}
#[test]
fn public_keys_join_omits_missing_rows_preserves_duplicates_and_nullable_opaque_keys() {
    let mut memory = Memory::new();
    let ids = [
        "missing",
        "member",
        "foreign",
        "member",
        "recipient",
        "null",
        "empty",
        "actor-member",
    ];
    let mut scratch = slots::<9>();
    let response = VaultService::new(&mut memory)
        .get_org_member_public_keys("actor", "org", ids.as_slice(), &mut scratch)
        .unwrap();
    assert_eq!(response.len(), 5);
    assert!(!response.is_empty());
    assert!(response.get(5).is_none());
    assert_eq!(response.get(0).unwrap().membership_id(), "member");
    assert_eq!(response.get(1).unwrap().membership_id(), "member");
    assert!(response.get(2).unwrap().public_key().is_none());
    assert!(response.get(3).unwrap().public_key() == Some(""));
    assert_eq!(response.get(4).unwrap().user_id(), "actor");
    let value = serde_json::to_value(&response).unwrap();
    let expected = serde_json::json!({"object":"list","continuationToken":null,"data":[
        {"object":"organizationUserPublicKeyResponseModel","id":"member","userId":"recipient","key":"future-public-key\0雪"},
        {"object":"organizationUserPublicKeyResponseModel","id":"member","userId":"recipient","key":"future-public-key\0雪"},
        {"object":"organizationUserPublicKeyResponseModel","id":"null","userId":"placeholder","key":null},
        {"object":"organizationUserPublicKeyResponseModel","id":"empty","userId":"empty-account","key":""},
        {"object":"organizationUserPublicKeyResponseModel","id":"actor-member","userId":"actor","key":"actor-public-key"}
    ]});
    assert!(value == expected, "Public-key projection differed");
    assert_eq!(memory.lookups, 8);
    assert_eq!(memory.calls.iter().filter(|&&s| s == "actor").count(), 1);
}
#[test]
fn public_keys_authorization_precedes_capacity_and_target_access_even_for_empty_input() {
    for (role, status) in [(2, 2), (3, 2), (4, 2), (0, 0), (0, 1), (1, -126), (-1, 2)] {
        let mut memory = Memory::new();
        let actor = &mut memory.actor.as_mut().unwrap().membership;
        actor.role = role;
        actor.status = status;
        let mut scratch = slots::<0>();
        let error = VaultService::new(&mut memory)
            .get_org_member_public_keys("actor", "org", ["member"].as_slice(), &mut scratch)
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Unauthorized);
        assert_eq!(memory.calls, ["actor"]);
    }
    for foreign_user in [true, false] {
        let mut memory = Memory::new();
        let actor = &mut memory.actor.as_mut().unwrap().membership;
        if foreign_user {
            actor.user_id = "foreign";
        } else {
            actor.organization_id = "foreign";
        }
        let error = VaultService::new(&mut memory)
            .get_org_member_public_keys("actor", "org", [].as_slice(), &mut [])
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Unauthorized);
        assert_eq!(memory.calls, ["actor"]);
    }
    let mut memory = Memory::new();
    assert_eq!(
        VaultService::new(&mut memory)
            .get_org_member_public_keys("", "org", [].as_slice(), &mut [])
            .unwrap_err()
            .kind,
        ErrorKind::Unauthorized
    );
    assert!(memory.calls.is_empty());
    for role in [0, 1] {
        let mut memory = Memory::new();
        memory.actor.as_mut().unwrap().membership.role = role;
        let response = VaultService::new(&mut memory)
            .get_org_member_public_keys("actor", "org", [].as_slice(), &mut [])
            .unwrap();
        assert!(response.is_empty());
        assert_eq!(
            serde_json::to_value(response).unwrap(),
            serde_json::json!({"object":"list","data":[],"continuationToken":null})
        );
        assert_eq!(memory.calls, ["actor"]);
    }
}
#[test]
fn public_keys_complete_views_and_capacity_are_checked_before_lookup() {
    struct Hole;
    impl OrganizationMemberPublicKeysData for Hole {
        fn len(&self) -> usize {
            2
        }
        fn get(&self, i: usize) -> Option<&str> {
            (i == 0).then_some("member")
        }
    }
    let mut memory = Memory::new();
    let mut scratch = slots::<2>();
    let error = VaultService::new(&mut memory)
        .get_org_member_public_keys(
            "actor",
            "org",
            ["member", "member"].as_slice(),
            &mut scratch[..1],
        )
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Storage);
    assert_eq!(memory.lookups, 0);
    let error = VaultService::new(&mut memory)
        .get_org_member_public_keys("actor", "org", &Hole, &mut scratch)
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Storage);
    assert_eq!(memory.lookups, 0);
    assert!(scratch.iter().all(Option::is_none));
}
#[test]
fn public_keys_provider_failure_and_cross_scope_snapshots_discard_partial_output() {
    for foreign_org in [true, false] {
        let mut memory = Memory::new();
        memory.corrupt_lookup = Some((2, foreign_org));
        let mut scratch = slots::<3>();
        let error = VaultService::new(&mut memory)
            .get_org_member_public_keys(
                "actor",
                "org",
                ["member", "member", "empty"].as_slice(),
                &mut scratch,
            )
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Storage);
        assert_eq!(memory.lookups, 2);
        assert!(scratch.iter().all(Option::is_none));
    }
    let mut memory = Memory::new();
    memory.fail_lookup = Some(2);
    let mut scratch = slots::<3>();
    let error = VaultService::new(&mut memory)
        .get_org_member_public_keys(
            "actor",
            "org",
            ["member", "member", "empty"].as_slice(),
            &mut scratch,
        )
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Conflict);
    assert_eq!(error.message, "Public-key provider unavailable");
    assert!(scratch.iter().all(Option::is_none));
    assert_eq!(memory.lookups, 2);
    let mut memory = Memory::new();
    memory.fail_actor = true;
    assert_eq!(
        VaultService::new(&mut memory)
            .get_org_member_public_keys("actor", "org", [].as_slice(), &mut [])
            .unwrap_err()
            .kind,
        ErrorKind::Conflict
    );
    assert_eq!(memory.lookups, 0);
}
#[test]
fn public_keys_nonclone_handles_forwarding_and_debug_never_expose_key_values_or_ids() {
    let mut memory = Memory::new();
    let mut scratch = slots::<1>();
    let mut forward = &mut memory;
    let response = VaultService::new(&mut forward)
        .get_org_member_public_keys("actor", "org", ["member"].as_slice(), &mut scratch)
        .unwrap();
    assert_eq!(
        format!("{response:?}"),
        "OrganizationMemberPublicKeysResponse([REDACTED])"
    );
    assert_eq!(
        format!("{:?}", response.get(0).unwrap()),
        "OrganizationMemberPublicKeyResponse([REDACTED])"
    );
    assert_eq!(
        format!("{:?}", scratch[0].as_ref().unwrap()),
        "OrganizationMemberPublicKeyRecord([REDACTED])"
    );
}
#[test]
fn public_keys_host_input_and_caller_snapshots_have_no_intrinsic_batch_limit() {
    let mut memory = Memory::new();
    let ids = std::vec!["null";513];
    let mut scratch = Vec::new();
    scratch.resize_with(ids.len(), || None);
    let response = VaultService::new(&mut memory)
        .get_org_member_public_keys("actor", "org", ids.as_slice(), &mut scratch)
        .unwrap();
    assert_eq!(response.len(), 513);
    assert!(response.get(512).unwrap().public_key().is_none());
    assert_eq!(memory.lookups, 513);
}
#[test]
fn public_keys_wire_requires_canonical_ids_with_caller_capacity_and_preserves_order() {
    for valid in [r#"{"ids":[]}"#, "[[]]"] {
        let request: OrganizationMemberPublicKeysRequest<'_, 0> =
            serde_json::from_str(valid).unwrap();
        assert!(request.is_empty());
    }
    let input = r#"{"ids":["bad.id","","bad.id"],"ignored":true}"#;
    let request: OrganizationMemberPublicKeysRequest<'_, 3> = serde_json::from_str(input).unwrap();
    assert_eq!(request.len(), 3);
    assert_eq!(request.get(0), Some("bad.id"));
    assert_eq!(request.get(1), Some(""));
    assert_eq!(request.get(2), Some("bad.id"));
    let forwarded = &request;
    assert_eq!(
        OrganizationMemberPublicKeysData::get(&forwarded, 0),
        Some("bad.id")
    );
    assert_eq!(
        format!("{request:?}"),
        "OrganizationMemberPublicKeysRequest([REDACTED])"
    );
    assert!(serde_json::from_str::<OrganizationMemberPublicKeysRequest<'_, 2>>(input).is_err());
    for invalid in [
        "{}",
        r#"{"ids":null}"#,
        r#"{"Ids":[]}"#,
        r#"{"ids":[],"ids":[]}"#,
        r#"{"ids":[null]}"#,
        r#"{"ids":[42]}"#,
        r#"{"ids":"member"}"#,
        "[]",
        "[null]",
    ] {
        assert!(
            serde_json::from_str::<OrganizationMemberPublicKeysRequest<'_, 3>>(invalid).is_err(),
            "{invalid}"
        );
    }
}
