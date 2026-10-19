//! Organization collection update/deletion over caller-owned storage and views.
//!
//! Payload decoding, HTTP guards, clocks, events and notifications belong to adapters.
//! These operations do not implement membership administration or shared cipher writes.

use crate::{
    ApiError, ErrorKind, VaultService,
    organization_collections::{CollectionCreateData, OrganizationCollectionStorage},
    organizations::{CollectionRecord, UserCollectionRecord},
    wire::CollectionDetailsResponse,
};

/// A complete update admitted after manager, reference and scoped-record checks.
/// Optional external IDs are cleared only when all characters are Unicode whitespace;
/// otherwise the original borrowed string is retained without trimming.
pub struct ValidatedCollectionUpdate<'a, D: ?Sized> {
    request: &'a D,
    external_id: Option<&'a str>,
}
impl<'a, D: ?Sized> ValidatedCollectionUpdate<'a, D> {
    pub const fn request(&self) -> &'a D {
        self.request
    }
    pub const fn external_id(&self) -> Option<&'a str> {
        self.external_id
    }
}
impl<D: ?Sized> core::fmt::Debug for ValidatedCollectionUpdate<'_, D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ValidatedCollectionUpdate([REDACTED])")
    }
}

/// Sealed deletion authority, borrowing only the verified caller's operation context.
/// A provider must still recheck mutable authorization within its transaction.
pub struct ValidatedCollectionDelete<'a> {
    owner: &'a str,
    organization: &'a str,
    collection: &'a str,
}
impl<'a> ValidatedCollectionDelete<'a> {
    pub const fn owner(&self) -> &'a str {
        self.owner
    }
    pub const fn organization(&self) -> &'a str {
        self.organization
    }
    pub const fn collection(&self) -> &'a str {
        self.collection
    }
}
impl core::fmt::Debug for ValidatedCollectionDelete<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ValidatedCollectionDelete([REDACTED])")
    }
}

/// Opt-in mutation provider; existing collection providers gain no required methods.
/// Hold the verified operation's lock/context through authorization and serialization.
///
/// `mutation_collection` looks up an exact collection within the supplied organization,
/// independently of the actor's readable/assigned view. Global manager permission can
/// be valid even when a configuration hides the corresponding group from read views.
/// The adapter runs `authorize_org_collection_details` before HTTP path/JSON guards.
/// Services repeat that authorization before examining references or committing writes.
///
/// An update replaces the entire group/direct-user assignment set. Validate all group
/// IDs even when group projection is disabled; use membership IDs for user selections,
/// and validate but skip direct writes for access_all members. Preserve input order and
/// duplicate upsert semantics. Recheck permission, references and scoped existence in
/// the write transaction; prepare the returned owned cache before committing. Losing
/// the actor's own last grant is valid: return the resulting flags even if unreadable.
///
/// Atomically persist name/external ID, ACL replacement and affected OLD/NEW account
/// revisions. Deletion removes the collection, its ACLs and cipher/collection links,
/// advances affected account revisions, and preserves cipher rows, revisions and opaque
/// bytes. Preserve organization/membership/key/session/account/foreign state. Provider
/// errors leave all state unchanged. This failure boundary is stronger than upstream's
/// sequential persistence; notification/event delivery remains outside this interface.
pub trait OrganizationCollectionMutationStorage: OrganizationCollectionStorage {
    fn mutation_collection(
        &mut self,
        organization: &str,
        collection: &str,
    ) -> Result<Option<CollectionRecord<'_>>, Self::Error>;
    fn update_collection<D: CollectionCreateData + ?Sized>(
        &mut self,
        owner: &str,
        organization: &str,
        collection: &str,
        plan: &ValidatedCollectionUpdate<'_, D>,
    ) -> Result<UserCollectionRecord<'_>, Self::Error>;
    fn delete_collection(
        &mut self,
        plan: &ValidatedCollectionDelete<'_>,
    ) -> Result<(), Self::Error>;
}
impl<T: OrganizationCollectionMutationStorage + ?Sized> OrganizationCollectionMutationStorage
    for &mut T
{
    fn mutation_collection(
        &mut self,
        org: &str,
        col: &str,
    ) -> Result<Option<CollectionRecord<'_>>, Self::Error> {
        (**self).mutation_collection(org, col)
    }
    fn update_collection<D: CollectionCreateData + ?Sized>(
        &mut self,
        owner: &str,
        org: &str,
        col: &str,
        plan: &ValidatedCollectionUpdate<'_, D>,
    ) -> Result<UserCollectionRecord<'_>, Self::Error> {
        (**self).update_collection(owner, org, col, plan)
    }
    fn delete_collection(
        &mut self,
        plan: &ValidatedCollectionDelete<'_>,
    ) -> Result<(), Self::Error> {
        (**self).delete_collection(plan)
    }
}

fn missing_collection() -> ApiError {
    ApiError::invalid("collection", "Collection not found")
}
fn inconsistent_view() -> ApiError {
    ApiError::new(ErrorKind::Storage, "Collection view is incomplete")
}
fn invalid_response() -> ApiError {
    ApiError::new(
        ErrorKind::Unauthorized,
        "Collection response is not owned by user",
    )
}

impl<S: OrganizationCollectionMutationStorage> VaultService<S> {
    pub fn update_org_collection<D: CollectionCreateData + ?Sized>(
        &mut self,
        owner: &str,
        organization: &str,
        collection: &str,
        request: &D,
    ) -> Result<CollectionDetailsResponse<'_>, ApiError> {
        self.authorize_org_collection_details(owner, organization, collection)?;
        for index in 0..request.groups_len() {
            let selection = request.group(index).ok_or_else(inconsistent_view)?;
            if !self
                .storage_mut()
                .collection_group_exists(organization, selection.id)
                .map_err(S::map_error)?
            {
                return Err(ApiError::invalid("groups", "Invalid group"));
            }
        }
        for index in 0..request.users_len() {
            let selection = request.user(index).ok_or_else(inconsistent_view)?;
            if !self
                .storage_mut()
                .collection_member_exists(organization, selection.id)
                .map_err(S::map_error)?
            {
                return Err(ApiError::invalid("users", "Invalid member"));
            }
        }
        if self
            .storage_mut()
            .organization(organization)
            .map_err(S::map_error)?
            .is_none()
        {
            return Err(ApiError::invalid(
                "organization",
                "Can't find organization details",
            ));
        }
        let existing = self
            .storage_mut()
            .mutation_collection(organization, collection)
            .map_err(S::map_error)?
            .ok_or_else(missing_collection)?;
        if existing.id != collection || existing.organization_id != organization {
            return Err(missing_collection());
        }
        let plan = ValidatedCollectionUpdate {
            request,
            external_id: request
                .external_id()
                .filter(|value| !value.trim().is_empty()),
        };
        let record = self
            .storage_mut()
            .update_collection(owner, organization, collection, &plan)
            .map_err(S::map_error)?;
        // Updating selections can intentionally revoke the acting manager's own access.
        if record.collection.id != collection
            || record.collection.organization_id != organization
            || record.membership.user_id != owner
            || record.membership.organization_id != organization
            || record.membership.status != 2
        {
            return Err(invalid_response());
        }
        Ok(CollectionDetailsResponse::new(record))
    }

    pub fn delete_org_collection(
        &mut self,
        owner: &str,
        organization: &str,
        collection: &str,
    ) -> Result<(), ApiError> {
        self.authorize_org_collection_details(owner, organization, collection)?;
        let existing = self
            .storage_mut()
            .mutation_collection(organization, collection)
            .map_err(S::map_error)?
            .ok_or_else(missing_collection)?;
        if existing.id != collection || existing.organization_id != organization {
            return Err(missing_collection());
        }
        self.storage_mut()
            .delete_collection(&ValidatedCollectionDelete {
                owner,
                organization,
                collection,
            })
            .map_err(S::map_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Storage,
        organization_collections::{
            CollectionAccessData, CollectionAccessEntry, OrganizationCollectionMembership,
            ValidatedCollectionCreate,
        },
        organizations::{
            OrganizationCreationPolicy, OrganizationFeatures, OrganizationMembership,
            OrganizationProfileRecord, OrganizationRecord, OrganizationStorage,
            ValidatedOrganizationCreate,
        },
        service::ItemMetadata,
        wire::{
            CipherRequest, CollectionSelectionRequest, FolderRequest,
            OrganizationCollectionCreateRequest, RegisterRequest,
        },
    };
    use serde_json::json;
    use std::{
        string::{String, ToString},
        vec,
        vec::Vec,
    };

    fn membership() -> OrganizationMembership<'static> {
        OrganizationMembership {
            user_id: "owner",
            organization_id: "org",
            role: 3,
            status: 2,
        }
    }
    fn collection() -> CollectionRecord<'static> {
        CollectionRecord {
            id: "collection",
            organization_id: "org",
            name: "before",
            external_id: Some("before"),
        }
    }
    fn returned() -> UserCollectionRecord<'static> {
        UserCollectionRecord {
            collection: collection(),
            membership: membership(),
            readable: true,
            read_only: false,
            hide_passwords: false,
            manage: true,
        }
    }
    struct UnusedReadView;
    impl CollectionAccessData for UnusedReadView {
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
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct State {
        present: bool,
        name: String,
        external: Option<String>,
        groups: Vec<String>,
        users: Vec<String>,
        revisions: [u64; 3],
        cipher: Vec<u8>,
        foreign: [u64; 3],
    }
    struct Memory {
        calls: Vec<&'static str>,
        fail: Option<&'static str>,
        member: Option<OrganizationCollectionMembership<'static>>,
        manageable: bool,
        org_exists: bool,
        lookup: Option<CollectionRecord<'static>>,
        response: UserCollectionRecord<'static>,
        self_remove: bool,
        state: State,
    }
    impl Memory {
        fn new() -> Self {
            Self {
                calls: Vec::new(),
                fail: None,
                member: Some(OrganizationCollectionMembership {
                    membership: membership(),
                    access_all: false,
                }),
                manageable: true,
                org_exists: true,
                lookup: Some(collection()),
                response: returned(),
                self_remove: false,
                state: State {
                    present: true,
                    name: "before".into(),
                    external: Some("before".into()),
                    groups: vec!["old-group".into()],
                    users: vec!["old-member".into()],
                    revisions: [3, 5, 7],
                    cipher: vec![0, 255, 1, 254],
                    foreign: [11, 13, 17],
                },
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
            ApiError::new(ErrorKind::Conflict, "Concurrent collection mutation")
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
            self.step("organization")?;
            Ok(self.org_exists.then_some(OrganizationRecord {
                id: "org",
                name: "opaque",
                billing_email: "opaque",
                has_public_and_private_keys: false,
                features: OrganizationFeatures::default(),
            }))
        }
        fn user_collections(&mut self, _: &str) -> Result<Self::Collections<'_>, ()> {
            unreachable!()
        }
        fn profile_organizations(&mut self, _: &str) -> Result<Self::Profiles<'_>, ()> {
            unreachable!()
        }
    }
    impl OrganizationCollectionStorage for Memory {
        type OrgCollections<'a> = &'a [CollectionRecord<'static>];
        type AccessDetails<'a> = UnusedReadView;
        fn collection_membership(
            &mut self,
            _: &str,
            _: &str,
        ) -> Result<Option<OrganizationCollectionMembership<'_>>, ()> {
            self.step("membership")?;
            Ok(self.member)
        }
        fn org_collections(&mut self, _: &str) -> Result<Self::OrgCollections<'_>, ()> {
            unreachable!()
        }
        fn can_manage_collection(&mut self, _: &str, _: &str) -> Result<bool, ()> {
            self.step("manage")?;
            Ok(self.manageable)
        }
        fn collection_access_details(
            &mut self,
            _: &str,
            _: &str,
        ) -> Result<Option<Self::AccessDetails<'_>>, ()> {
            panic!("Mutation lookup must not require an actor read view")
        }
        fn collection_group_exists(&mut self, _: &str, id: &str) -> Result<bool, ()> {
            self.step("group")?;
            Ok(id != "bad-group")
        }
        fn collection_member_exists(&mut self, _: &str, id: &str) -> Result<bool, ()> {
            self.step("member")?;
            Ok(id != "bad-member")
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
    impl OrganizationCollectionMutationStorage for Memory {
        fn mutation_collection(
            &mut self,
            _: &str,
            _: &str,
        ) -> Result<Option<CollectionRecord<'_>>, ()> {
            self.step("lookup")?;
            Ok(self.lookup.filter(|_| self.state.present))
        }
        fn update_collection<D: CollectionCreateData + ?Sized>(
            &mut self,
            owner: &str,
            org: &str,
            id: &str,
            plan: &ValidatedCollectionUpdate<'_, D>,
        ) -> Result<UserCollectionRecord<'_>, ()> {
            self.step("update")?;
            assert_eq!((owner, org, id), ("owner", "org", "collection"));
            let mut next = self.state.clone();
            next.name = plan.request().name().to_string();
            next.external = plan.external_id().map(ToString::to_string);
            next.groups = (0..plan.request().groups_len())
                .map(|i| plan.request().group(i).unwrap().id.to_string())
                .collect();
            next.users = (0..plan.request().users_len())
                .map(|i| plan.request().user(i).unwrap().id.to_string())
                .collect();
            for revision in &mut next.revisions {
                *revision += 1;
            }
            self.step("update-commit")?;
            self.state = next;
            let mut response = self.response;
            if self.self_remove {
                self.manageable = false;
                response.readable = false;
                response.read_only = true;
                response.hide_passwords = false;
                response.manage = false;
            }
            Ok(UserCollectionRecord {
                collection: CollectionRecord {
                    name: &self.state.name,
                    external_id: self.state.external.as_deref(),
                    ..response.collection
                },
                ..response
            })
        }
        fn delete_collection(&mut self, plan: &ValidatedCollectionDelete<'_>) -> Result<(), ()> {
            self.step("delete")?;
            assert_eq!(
                (plan.owner(), plan.organization(), plan.collection()),
                ("owner", "org", "collection")
            );
            let mut next = self.state.clone();
            next.present = false;
            next.groups.clear();
            next.users.clear();
            for revision in &mut next.revisions {
                *revision += 1;
            }
            self.step("delete-commit")?;
            self.state = next;
            Ok(())
        }
    }
    struct Input {
        name: String,
        external: Option<String>,
        groups: Vec<CollectionSelectionRequest<'static>>,
        users: Vec<CollectionSelectionRequest<'static>>,
    }
    impl CollectionCreateData for Input {
        fn name(&self) -> &str {
            &self.name
        }
        fn external_id(&self) -> Option<&str> {
            self.external.as_deref()
        }
        fn groups_len(&self) -> usize {
            self.groups.len()
        }
        fn group(&self, i: usize) -> Option<CollectionSelectionRequest<'_>> {
            self.groups.get(i).copied()
        }
        fn users_len(&self) -> usize {
            self.users.len()
        }
        fn user(&self, i: usize) -> Option<CollectionSelectionRequest<'_>> {
            self.users.get(i).copied()
        }
    }
    fn selection(id: &'static str) -> CollectionSelectionRequest<'static> {
        CollectionSelectionRequest {
            hide_passwords: false,
            id,
            read_only: false,
            manage: true,
        }
    }
    fn request() -> Input {
        Input {
            name: "opaque\0雪".into(),
            external: None,
            groups: vec![],
            users: vec![],
        }
    }

    #[test]
    fn collection_mutations_require_verified_owner_and_strict_global_management() {
        for deleting in [false, true] {
            let mut memory = Memory::new();
            let error = if deleting {
                VaultService::new(&mut memory)
                    .delete_org_collection("", "org", "collection")
                    .unwrap_err()
            } else {
                VaultService::new(&mut memory)
                    .update_org_collection("", "org", "collection", &request())
                    .unwrap_err()
            };
            assert_eq!(error.status_code(), 401);
            assert!(memory.calls.is_empty());
            memory.manageable = false;
            let error = if deleting {
                VaultService::new(&mut memory)
                    .delete_org_collection("owner", "org", "collection")
                    .unwrap_err()
            } else {
                VaultService::new(&mut memory)
                    .update_org_collection("owner", "org", "collection", &request())
                    .unwrap_err()
            };
            assert_eq!(error.status_code(), 401);
            assert_eq!(memory.calls, ["membership", "manage"]);
        }
    }
    #[test]
    fn collection_update_validates_groups_then_members_before_scoped_existence() {
        let mut memory = Memory::new();
        let before = memory.state.clone();
        memory.org_exists = false;
        memory.lookup = None;
        let mut input = request();
        input.groups = vec![selection("group"), selection("bad-group")];
        input.users = vec![selection("bad-member")];
        assert_eq!(
            VaultService::new(&mut memory)
                .update_org_collection("owner", "org", "collection", &input)
                .unwrap_err()
                .message,
            "Invalid group"
        );
        assert_eq!(memory.calls, ["membership", "manage", "group", "group"]);
        assert_eq!(memory.state, before);
        input.groups.pop();
        memory.calls.clear();
        assert_eq!(
            VaultService::new(&mut memory)
                .update_org_collection("owner", "org", "collection", &input)
                .unwrap_err()
                .message,
            "Invalid member"
        );
        assert_eq!(memory.calls, ["membership", "manage", "group", "member"]);
        input.users[0] = selection("member");
        memory.calls.clear();
        assert_eq!(
            VaultService::new(&mut memory)
                .update_org_collection("owner", "org", "collection", &input)
                .unwrap_err()
                .message,
            "Can't find organization details"
        );
        assert_eq!(
            memory.calls,
            ["membership", "manage", "group", "member", "organization"]
        );
        memory.org_exists = true;
        memory.calls.clear();
        assert_eq!(
            VaultService::new(&mut memory)
                .update_org_collection("owner", "org", "collection", &input)
                .unwrap_err()
                .message,
            "Collection not found"
        );
        assert_eq!(
            memory.calls,
            [
                "membership",
                "manage",
                "group",
                "member",
                "organization",
                "lookup"
            ]
        );
        assert_eq!(memory.state, before);
    }
    #[test]
    fn collection_mutation_scoped_lookup_rejects_missing_cross_org_or_wrong_id() {
        for deleting in [false, true] {
            for variant in 0..3 {
                let mut memory = Memory::new();
                let before = memory.state.clone();
                match variant {
                    0 => memory.lookup = None,
                    1 => memory.lookup.as_mut().unwrap().organization_id = "foreign",
                    _ => memory.lookup.as_mut().unwrap().id = "different",
                }
                let error = if deleting {
                    VaultService::new(&mut memory)
                        .delete_org_collection("owner", "org", "collection")
                        .unwrap_err()
                } else {
                    VaultService::new(&mut memory)
                        .update_org_collection("owner", "org", "collection", &request())
                        .unwrap_err()
                };
                assert_eq!(
                    (error.status_code(), error.message),
                    (400, "Collection not found")
                );
                assert_eq!(memory.state, before);
                assert!(!memory.calls.contains(&"update"));
                assert!(!memory.calls.contains(&"delete"));
            }
        }
    }
    #[test]
    fn collection_update_uses_mutation_lookup_and_allows_actor_self_removal() {
        let mut memory = Memory::new();
        memory.self_remove = true;
        let wire = serde_json::to_value(
            VaultService::new(&mut memory)
                .update_org_collection("owner", "org", "collection", &request())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(wire.as_object().unwrap().len(), 10);
        assert_eq!(
            (
                wire["readOnly"].as_bool(),
                wire["hidePasswords"].as_bool(),
                wire["manage"].as_bool()
            ),
            (Some(true), Some(false), Some(false))
        );
        assert_eq!(wire["object"], "collectionDetails");
        assert_eq!(memory.state.name, "opaque\0雪");
        assert!(memory.state.users.is_empty());
        assert_eq!(
            VaultService::new(&mut memory)
                .delete_org_collection("owner", "org", "collection")
                .unwrap_err()
                .status_code(),
            401
        );
    }
    #[test]
    fn collection_update_preserves_nonblank_external_bytes_and_clears_unicode_whitespace() {
        for (external, expected) in [
            (None, None),
            (Some(""), None),
            (Some("\u{2003}\u{a0}\t"), None),
            (Some(" \u{2003}name\0雪 \t"), Some(" \u{2003}name\0雪 \t")),
        ] {
            let mut memory = Memory::new();
            let mut input = request();
            input.external = external.map(ToString::to_string);
            VaultService::new(&mut memory)
                .update_org_collection("owner", "org", "collection", &input)
                .unwrap();
            assert_eq!(memory.state.external.as_deref(), expected);
        }
    }
    #[test]
    fn collection_update_replaces_all_acl_entries_preserving_duplicate_order_and_payloads() {
        let mut memory = Memory::new();
        let before = memory.state.clone();
        let mut input = request();
        input.name = "future\0雪".repeat(20_000);
        input.groups = vec![selection("new-group"); 7];
        input.users = vec![selection("new-member"); 9];
        let borrowed: &dyn CollectionCreateData = &input;
        VaultService::new(&mut memory)
            .update_org_collection("owner", "org", "collection", &borrowed)
            .unwrap();
        assert_eq!(memory.state.name, input.name);
        assert_eq!(memory.state.groups, vec!["new-group"; 7]);
        assert_eq!(memory.state.users, vec!["new-member"; 9]);
        assert_eq!(memory.state.cipher, before.cipher);
        assert_eq!(memory.state.foreign, before.foreign);
        assert_eq!(memory.state.revisions, [4, 6, 8]);
    }
    #[test]
    fn collection_update_response_is_bound_to_target_and_membership_without_readability_requirement()
     {
        for variant in 0..5 {
            let mut memory = Memory::new();
            match variant {
                0 => memory.response.collection.id = "foreign",
                1 => memory.response.collection.organization_id = "foreign",
                2 => memory.response.membership.user_id = "foreign",
                3 => memory.response.membership.organization_id = "foreign",
                _ => memory.response.membership.status = 1,
            }
            assert_eq!(
                VaultService::new(&mut memory)
                    .update_org_collection("owner", "org", "collection", &request())
                    .unwrap_err()
                    .status_code(),
                401
            );
        }
        let mut memory = Memory::new();
        memory.response.readable = false;
        memory.response.manage = false;
        assert!(
            VaultService::new(&mut memory)
                .update_org_collection("owner", "org", "collection", &request())
                .is_ok()
        );
    }
    #[test]
    fn collection_mutation_provider_errors_propagate_without_partial_state() {
        for (deleting, calls) in [
            (
                false,
                &[
                    "membership",
                    "manage",
                    "group",
                    "member",
                    "organization",
                    "lookup",
                    "update",
                    "update-commit",
                ][..],
            ),
            (
                true,
                &["membership", "manage", "lookup", "delete", "delete-commit"][..],
            ),
        ] {
            for call in calls {
                let mut memory = Memory::new();
                memory.fail = Some(call);
                let before = memory.state.clone();
                let mut input = request();
                input.groups.push(selection("group"));
                input.users.push(selection("member"));
                let error = if deleting {
                    VaultService::new(&mut memory)
                        .delete_org_collection("owner", "org", "collection")
                        .unwrap_err()
                } else {
                    VaultService::new(&mut memory)
                        .update_org_collection("owner", "org", "collection", &input)
                        .unwrap_err()
                };
                assert_eq!(error.status_code(), 409);
                assert_eq!(memory.state, before);
                assert_eq!(memory.calls.last(), Some(call));
            }
        }
    }
    #[test]
    fn collection_delete_removes_only_collection_links_and_grants_and_preserves_cipher_bytes() {
        let mut memory = Memory::new();
        let before = memory.state.clone();
        VaultService::new(&mut memory)
            .delete_org_collection("owner", "org", "collection")
            .unwrap();
        assert!(!memory.state.present);
        assert!(memory.state.groups.is_empty());
        assert!(memory.state.users.is_empty());
        assert_eq!(memory.state.cipher, before.cipher);
        assert_eq!(memory.state.foreign, before.foreign);
        assert_eq!(memory.state.revisions, [4, 6, 8]);
        assert_eq!(
            memory.calls,
            ["membership", "manage", "lookup", "delete", "delete-commit"]
        );
    }
    #[test]
    fn collection_mutation_plans_are_redacted_and_reuse_borrowed_positional_decoder() {
        let text = r#"["opaque",[[false,"group",true,false]],[[true,"member",false,true]],"   "]"#;
        let request: OrganizationCollectionCreateRequest<'_, 1, 1> =
            serde_json::from_str(text).unwrap();
        let plan = ValidatedCollectionUpdate {
            request: &request,
            external_id: None,
        };
        assert_eq!(plan.request().name, "opaque");
        assert_eq!(
            std::format!("{plan:?}"),
            "ValidatedCollectionUpdate([REDACTED])"
        );
        let deletion = ValidatedCollectionDelete {
            owner: "private-owner",
            organization: "private-org",
            collection: "private-col",
        };
        assert_eq!(
            std::format!("{deletion:?}"),
            "ValidatedCollectionDelete([REDACTED])"
        );
        let mut memory = Memory::new();
        assert_eq!(
            serde_json::to_value(
                VaultService::new(&mut memory)
                    .update_org_collection("owner", "org", "collection", &request)
                    .unwrap()
            )
            .unwrap()["externalId"],
            json!(null)
        );
    }
}
