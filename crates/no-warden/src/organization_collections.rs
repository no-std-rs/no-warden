//! Organization-scoped collection discovery and creation without allocation.
//!
//! HTTP/path guards, ACL joins, storage transactions, clocks and notification delivery
//! remain outside the core. Membership IDs in selections are not account IDs.

use crate::{
    ApiError, ErrorKind, VaultService,
    organizations::{
        CollectionRecord, OrganizationMembership, OrganizationStorage, UserCollectionRecord,
    },
    service::require_owner,
    wire::{
        CollectionAccessDetailsResponse, CollectionDetailsResponse, CollectionSelectionRequest,
        OrganizationCollectionCreateRequest, OrganizationCollectionListResponse,
    },
};

/// Extends existing membership metadata without changing its public field constructors.
#[derive(Clone, Copy, Debug)]
pub struct OrganizationCollectionMembership<'a> {
    pub membership: OrganizationMembership<'a>,
    pub access_all: bool,
}

/// Uncapped borrowed creation view. Transport limits and bounded decoders are caller policy.
/// Every index below its reported length must exist. Preserve ordering and duplicates.
pub trait CollectionCreateData {
    fn name(&self) -> &str;
    fn external_id(&self) -> Option<&str>;
    fn groups_len(&self) -> usize;
    fn group(&self, index: usize) -> Option<CollectionSelectionRequest<'_>>;
    fn users_len(&self) -> usize;
    fn user(&self, index: usize) -> Option<CollectionSelectionRequest<'_>>;
}
impl<T: CollectionCreateData + ?Sized> CollectionCreateData for &T {
    fn name(&self) -> &str {
        (**self).name()
    }
    fn external_id(&self) -> Option<&str> {
        (**self).external_id()
    }
    fn groups_len(&self) -> usize {
        (**self).groups_len()
    }
    fn group(&self, index: usize) -> Option<CollectionSelectionRequest<'_>> {
        (**self).group(index)
    }
    fn users_len(&self) -> usize {
        (**self).users_len()
    }
    fn user(&self, index: usize) -> Option<CollectionSelectionRequest<'_>> {
        (**self).user(index)
    }
}
impl<const G: usize, const U: usize> CollectionCreateData
    for OrganizationCollectionCreateRequest<'_, G, U>
{
    fn name(&self) -> &str {
        self.name
    }
    fn external_id(&self) -> Option<&str> {
        self.external_id
    }
    fn groups_len(&self) -> usize {
        self.groups.len()
    }
    fn group(&self, index: usize) -> Option<CollectionSelectionRequest<'_>> {
        self.groups.get(index).copied()
    }
    fn users_len(&self) -> usize {
        self.users.len()
    }
    fn user(&self, index: usize) -> Option<CollectionSelectionRequest<'_>> {
        self.users.get(index).copied()
    }
}

pub trait CollectionListData {
    fn len(&self) -> usize;
    fn get(&self, index: usize) -> Option<CollectionRecord<'_>>;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
impl<T: CollectionListData + ?Sized> CollectionListData for &T {
    fn len(&self) -> usize {
        (**self).len()
    }
    fn get(&self, index: usize) -> Option<CollectionRecord<'_>> {
        (**self).get(index)
    }
}
impl CollectionListData for [CollectionRecord<'_>] {
    fn len(&self) -> usize {
        <[CollectionRecord<'_>]>::len(self)
    }
    fn get(&self, index: usize) -> Option<CollectionRecord<'_>> {
        <[CollectionRecord<'_>]>::get(self, index).copied()
    }
}

/// Effective selection flags for a response, not necessarily raw persisted flags.
/// User IDs here are membership IDs. The organization association is internal only.
#[derive(Clone, Copy)]
pub struct CollectionAccessEntry<'a> {
    pub id: &'a str,
    pub organization_id: &'a str,
    pub read_only: bool,
    pub hide_passwords: bool,
    pub manage: bool,
}
impl core::fmt::Debug for CollectionAccessEntry<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CollectionAccessEntry([REDACTED])")
    }
}

/// Stable detail view. Every index exists through serialization. The provider resolves
/// source-compatible effective user/group manage flags and the assigned decision.
pub trait CollectionAccessData {
    fn collection(&self) -> UserCollectionRecord<'_>;
    fn assigned(&self) -> bool;
    fn users_len(&self) -> usize;
    fn user(&self, index: usize) -> Option<CollectionAccessEntry<'_>>;
    fn groups_enabled(&self) -> bool;
    fn groups_len(&self) -> usize;
    fn group(&self, index: usize) -> Option<CollectionAccessEntry<'_>>;
}
impl<T: CollectionAccessData + ?Sized> CollectionAccessData for &T {
    fn collection(&self) -> UserCollectionRecord<'_> {
        (**self).collection()
    }
    fn assigned(&self) -> bool {
        (**self).assigned()
    }
    fn users_len(&self) -> usize {
        (**self).users_len()
    }
    fn user(&self, index: usize) -> Option<CollectionAccessEntry<'_>> {
        (**self).user(index)
    }
    fn groups_enabled(&self) -> bool {
        (**self).groups_enabled()
    }
    fn groups_len(&self) -> usize {
        (**self).groups_len()
    }
    fn group(&self, index: usize) -> Option<CollectionAccessEntry<'_>> {
        (**self).group(index)
    }
}

/// A manager request guard, borrowing only caller-owned verified identity/context.
/// This does not authorize a particular collection or a creation mutation on its own.
#[derive(Clone, Copy)]
pub struct AuthorizedCollectionManager<'a> {
    owner: &'a str,
    organization: &'a str,
    role: i32,
    access_all: bool,
}
impl<'a> AuthorizedCollectionManager<'a> {
    pub const fn owner(&self) -> &'a str {
        self.owner
    }
    pub const fn organization(&self) -> &'a str {
        self.organization
    }
    pub const fn role(&self) -> i32 {
        self.role
    }
    pub const fn access_all(&self) -> bool {
        self.access_all
    }
}
impl core::fmt::Debug for AuthorizedCollectionManager<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AuthorizedCollectionManager([REDACTED])")
    }
}

/// Complete prevalidation before the provider's atomic collection/ACL write.
pub struct ValidatedCollectionCreate<'a, D: ?Sized> {
    request: &'a D,
    external_id: Option<&'a str>,
}
impl<'a, D: ?Sized> ValidatedCollectionCreate<'a, D> {
    pub const fn request(&self) -> &'a D {
        self.request
    }
    pub const fn external_id(&self) -> Option<&'a str> {
        self.external_id
    }
}
impl<D: ?Sized> core::fmt::Debug for ValidatedCollectionCreate<'_, D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ValidatedCollectionCreate([REDACTED])")
    }
}

/// Opt-in organization collection provider; existing OrganizationStorage implementers
/// do not gain mandatory methods. Hold the authenticated operation's lock/context.
///
/// Membership lookup is scoped to the requested organization. Global manageability is
/// deliberately scoped only to the verified user and collection: a manageable collection
/// from another organization must pass that guard before the handler rejects its association.
/// Resolve full/direct/group ACLs according to configured source policy. Ordinary User role
/// 2 is not a manager; stored Manager role 3 represents custom roles, never raw role 4.
/// Do not infer permission ordering from numeric comparison.
///
/// Validate group IDs against organization groups even when group response projection is
/// disabled, and validate user IDs against organization MEMBERSHIPS of any status. After
/// prevalidation, atomically create a fresh-ID collection, requested group/direct-user
/// assignments, and affected account revisions. Validate access_all user selections, but
/// skip their direct assignment writes. Preserve selection ordering/duplicate upsert
/// behavior; do not silently deduplicate or grant unrelated users access. Empty external
/// IDs become absent; whitespace is preserved at creation. Names/IDs/flags remain opaque.
///
/// Recheck mutable membership/reference policy within the write transaction as needed.
/// Prepare the owned response cache before commit; an error leaves prior collection,
/// grants/revisions and foreign state unchanged. This is stronger than upstream sequential
/// persistence; notifications and events remain adapter responsibilities.
///
/// Details must expose only the single collection's direct selections, not synthesized
/// manage-all memberships from the separate aggregate endpoint. User effective manage
/// depends on role/persisted grants; group effective manage includes unrestricted read/write
/// access. Groups-disabled configurations still persist/validate groups but project [].
pub trait OrganizationCollectionStorage: OrganizationStorage {
    type OrgCollections<'a>: CollectionListData
    where
        Self: 'a;
    type AccessDetails<'a>: CollectionAccessData
    where
        Self: 'a;
    fn collection_membership(
        &mut self,
        owner: &str,
        organization: &str,
    ) -> Result<Option<OrganizationCollectionMembership<'_>>, Self::Error>;
    fn org_collections(
        &mut self,
        organization: &str,
    ) -> Result<Self::OrgCollections<'_>, Self::Error>;
    fn can_manage_collection(&mut self, owner: &str, collection: &str)
    -> Result<bool, Self::Error>;
    fn collection_access_details(
        &mut self,
        owner: &str,
        collection: &str,
    ) -> Result<Option<Self::AccessDetails<'_>>, Self::Error>;
    fn collection_group_exists(
        &mut self,
        organization: &str,
        group: &str,
    ) -> Result<bool, Self::Error>;
    fn collection_member_exists(
        &mut self,
        organization: &str,
        membership: &str,
    ) -> Result<bool, Self::Error>;
    fn create_collection<D: CollectionCreateData + ?Sized>(
        &mut self,
        owner: &str,
        organization: &str,
        plan: &ValidatedCollectionCreate<'_, D>,
    ) -> Result<UserCollectionRecord<'_>, Self::Error>;
}
impl<T: OrganizationCollectionStorage + ?Sized> OrganizationCollectionStorage for &mut T {
    type OrgCollections<'a>
        = T::OrgCollections<'a>
    where
        Self: 'a;
    type AccessDetails<'a>
        = T::AccessDetails<'a>
    where
        Self: 'a;
    fn collection_membership(
        &mut self,
        owner: &str,
        org: &str,
    ) -> Result<Option<OrganizationCollectionMembership<'_>>, Self::Error> {
        (**self).collection_membership(owner, org)
    }
    fn org_collections(&mut self, org: &str) -> Result<Self::OrgCollections<'_>, Self::Error> {
        (**self).org_collections(org)
    }
    fn can_manage_collection(
        &mut self,
        owner: &str,
        collection: &str,
    ) -> Result<bool, Self::Error> {
        (**self).can_manage_collection(owner, collection)
    }
    fn collection_access_details(
        &mut self,
        owner: &str,
        collection: &str,
    ) -> Result<Option<Self::AccessDetails<'_>>, Self::Error> {
        (**self).collection_access_details(owner, collection)
    }
    fn collection_group_exists(&mut self, org: &str, group: &str) -> Result<bool, Self::Error> {
        (**self).collection_group_exists(org, group)
    }
    fn collection_member_exists(&mut self, org: &str, member: &str) -> Result<bool, Self::Error> {
        (**self).collection_member_exists(org, member)
    }
    fn create_collection<D: CollectionCreateData + ?Sized>(
        &mut self,
        owner: &str,
        org: &str,
        plan: &ValidatedCollectionCreate<'_, D>,
    ) -> Result<UserCollectionRecord<'_>, Self::Error> {
        (**self).create_collection(owner, org, plan)
    }
}
fn denied() -> ApiError {
    ApiError::new(
        ErrorKind::Unauthorized,
        "You need to be a Manager, Admin or Owner to call this endpoint",
    )
}
fn invalid_view() -> ApiError {
    ApiError::new(ErrorKind::Storage, "Collection view is incomplete")
}

impl<S: OrganizationCollectionStorage> VaultService<S> {
    pub fn authorize_org_collection_manager<'a>(
        &mut self,
        owner: &'a str,
        organization: &'a str,
    ) -> Result<AuthorizedCollectionManager<'a>, ApiError> {
        require_owner(owner)?;
        let access = self
            .storage_mut()
            .collection_membership(owner, organization)
            .map_err(S::map_error)?
            .ok_or_else(denied)?;
        let member = access.membership;
        if member.user_id != owner
            || member.organization_id != organization
            || member.status != 2
            || !matches!(member.role, 0 | 1 | 3)
        {
            return Err(denied());
        }
        Ok(AuthorizedCollectionManager {
            owner,
            organization,
            role: member.role,
            access_all: access.access_all,
        })
    }
    pub fn authorize_org_collection_details<'a>(
        &mut self,
        owner: &'a str,
        organization: &'a str,
        collection: &str,
    ) -> Result<AuthorizedCollectionManager<'a>, ApiError> {
        let authority = self.authorize_org_collection_manager(owner, organization)?;
        if !self
            .storage_mut()
            .can_manage_collection(owner, collection)
            .map_err(S::map_error)?
        {
            return Err(ApiError::new(
                ErrorKind::Unauthorized,
                "The current user isn't a manager for this collection",
            ));
        }
        Ok(authority)
    }
    pub fn list_org_collections(
        &mut self,
        owner: &str,
        organization: &str,
    ) -> Result<OrganizationCollectionListResponse<S::OrgCollections<'_>>, ApiError> {
        let authority = self.authorize_org_collection_manager(owner, organization)?;
        if !authority.access_all && !matches!(authority.role, 0 | 1) {
            return Err(ApiError::new(ErrorKind::NotFound, "Resource not found."));
        }
        let records = self
            .storage_mut()
            .org_collections(organization)
            .map_err(S::map_error)?;
        for index in 0..records.len() {
            if records.get(index).ok_or_else(invalid_view)?.organization_id != organization {
                return Err(denied());
            }
        }
        Ok(OrganizationCollectionListResponse::new(records))
    }
    pub fn create_org_collection<D: CollectionCreateData + ?Sized>(
        &mut self,
        owner: &str,
        organization: &str,
        request: &D,
    ) -> Result<CollectionDetailsResponse<'_>, ApiError> {
        let authority = self.authorize_org_collection_manager(owner, organization)?;
        for index in 0..request.groups_len() {
            let group = request.group(index).ok_or_else(invalid_view)?;
            if !self
                .storage_mut()
                .collection_group_exists(organization, group.id)
                .map_err(S::map_error)?
            {
                return Err(ApiError::invalid("groups", "Invalid group"));
            }
        }
        for index in 0..request.users_len() {
            let member = request.user(index).ok_or_else(invalid_view)?;
            if !self
                .storage_mut()
                .collection_member_exists(organization, member.id)
                .map_err(S::map_error)?
            {
                return Err(ApiError::invalid("users", "Invalid member"));
            }
        }
        if authority.role == 3 && !authority.access_all {
            return Err(ApiError::invalid(
                "collection",
                "You don't have permission to create collections",
            ));
        }
        let plan = ValidatedCollectionCreate {
            request,
            external_id: request.external_id().filter(|value| !value.is_empty()),
        };
        let record = self
            .storage_mut()
            .create_collection(owner, organization, &plan)
            .map_err(S::map_error)?;
        if record.collection.organization_id != organization
            || record.membership.organization_id != organization
            || record.membership.user_id != owner
            || record.membership.status != 2
            || !record.readable
        {
            return Err(denied());
        }
        Ok(CollectionDetailsResponse::new(record))
    }
    pub fn get_org_collection_details(
        &mut self,
        owner: &str,
        organization: &str,
        collection: &str,
    ) -> Result<CollectionAccessDetailsResponse<S::AccessDetails<'_>>, ApiError> {
        self.authorize_org_collection_details(owner, organization, collection)?;
        let details = self
            .storage_mut()
            .collection_access_details(owner, collection)
            .map_err(S::map_error)?
            .ok_or_else(|| ApiError::invalid("collection", "Collection not found"))?;
        let row = details.collection();
        if row.collection.organization_id != organization {
            return Err(ApiError::invalid(
                "collection",
                "Collection is not owned by organization",
            ));
        }
        if row.collection.id != collection
            || row.membership.organization_id != organization
            || row.membership.user_id != owner
            || row.membership.status != 2
            || !row.readable
        {
            return Err(denied());
        }
        for index in 0..details.users_len() {
            if details
                .user(index)
                .ok_or_else(invalid_view)?
                .organization_id
                != organization
            {
                return Err(denied());
            }
        }
        if details.groups_enabled() {
            for index in 0..details.groups_len() {
                if details
                    .group(index)
                    .ok_or_else(invalid_view)?
                    .organization_id
                    != organization
                {
                    return Err(denied());
                }
            }
        }
        Ok(CollectionAccessDetailsResponse::new(details))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Storage,
        organizations::{
            OrganizationCreationPolicy, OrganizationProfileRecord, OrganizationRecord,
            ValidatedOrganizationCreate,
        },
        service::ItemMetadata,
        wire::{CipherRequest, FolderRequest, RegisterRequest},
    };
    use serde_json::{Value, json};
    use std::{
        string::{String, ToString},
        vec,
        vec::Vec,
    };

    fn member() -> OrganizationMembership<'static> {
        OrganizationMembership {
            user_id: "owner",
            organization_id: "org",
            role: 0,
            status: 2,
        }
    }
    fn collection() -> CollectionRecord<'static> {
        CollectionRecord {
            id: "collection",
            organization_id: "org",
            name: "opaque",
            external_id: None,
        }
    }
    fn row() -> UserCollectionRecord<'static> {
        UserCollectionRecord {
            collection: collection(),
            membership: member(),
            readable: true,
            read_only: false,
            hide_passwords: false,
            manage: true,
        }
    }
    fn entry(id: &'static str) -> CollectionAccessEntry<'static> {
        CollectionAccessEntry {
            id,
            organization_id: "org",
            read_only: true,
            hide_passwords: false,
            manage: true,
        }
    }
    struct Details {
        row: UserCollectionRecord<'static>,
        users: Vec<CollectionAccessEntry<'static>>,
        groups: Vec<CollectionAccessEntry<'static>>,
        enabled: bool,
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
            self.users.get(i).copied()
        }
        fn groups_enabled(&self) -> bool {
            self.enabled
        }
        fn groups_len(&self) -> usize {
            self.groups.len()
        }
        fn group(&self, i: usize) -> Option<CollectionAccessEntry<'_>> {
            self.groups.get(i).copied()
        }
    }
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct State {
        name: String,
        external: Option<String>,
        groups: Vec<String>,
        users: Vec<String>,
        revision: u64,
        foreign: [u64; 3],
    }
    struct Memory {
        membership: Option<OrganizationCollectionMembership<'static>>,
        manageable: bool,
        rows: [CollectionRecord<'static>; 1],
        details: Details,
        present: bool,
        calls: Vec<&'static str>,
        fail: Option<&'static str>,
        state: State,
        returned: UserCollectionRecord<'static>,
    }
    impl Memory {
        fn new() -> Self {
            Self {
                membership: Some(OrganizationCollectionMembership {
                    membership: member(),
                    access_all: true,
                }),
                manageable: true,
                rows: [collection()],
                details: Details {
                    row: row(),
                    users: vec![entry("member")],
                    groups: vec![entry("group")],
                    enabled: true,
                },
                present: true,
                calls: Vec::new(),
                fail: None,
                state: State {
                    name: "before".into(),
                    external: None,
                    groups: Vec::new(),
                    users: Vec::new(),
                    revision: 5,
                    foreign: [3, 5, 7],
                },
                returned: row(),
            }
        }
        fn check(&mut self, call: &'static str) -> Result<(), ()> {
            self.calls.push(call);
            if self.fail == Some(call) {
                Err(())
            } else {
                Ok(())
            }
        }
    }
    impl Storage for Memory {
        type Error = ();
        fn map_error(_: ()) -> ApiError {
            ApiError::new(ErrorKind::Conflict, "Collection provider conflict")
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
    impl OrganizationCollectionStorage for Memory {
        type OrgCollections<'a> = &'a [CollectionRecord<'static>];
        type AccessDetails<'a> = &'a Details;
        fn collection_membership(
            &mut self,
            _: &str,
            _: &str,
        ) -> Result<Option<OrganizationCollectionMembership<'_>>, ()> {
            self.check("membership")?;
            Ok(self.membership)
        }
        fn org_collections(&mut self, _: &str) -> Result<Self::OrgCollections<'_>, ()> {
            self.check("list")?;
            Ok(&self.rows)
        }
        fn can_manage_collection(&mut self, _: &str, _: &str) -> Result<bool, ()> {
            self.check("manageable")?;
            Ok(self.manageable)
        }
        fn collection_access_details(
            &mut self,
            _: &str,
            _: &str,
        ) -> Result<Option<Self::AccessDetails<'_>>, ()> {
            self.check("details")?;
            Ok(self.present.then_some(&self.details))
        }
        fn collection_group_exists(&mut self, _: &str, id: &str) -> Result<bool, ()> {
            self.check("group")?;
            Ok(id != "bad-group")
        }
        fn collection_member_exists(&mut self, _: &str, id: &str) -> Result<bool, ()> {
            self.check("member")?;
            Ok(id != "bad-member")
        }
        fn create_collection<D: CollectionCreateData + ?Sized>(
            &mut self,
            _: &str,
            _: &str,
            plan: &ValidatedCollectionCreate<'_, D>,
        ) -> Result<UserCollectionRecord<'_>, ()> {
            self.check("create")?;
            let request = plan.request();
            let mut next = self.state.clone();
            next.name = request.name().to_string();
            next.external = plan.external_id().map(ToString::to_string);
            next.groups = (0..request.groups_len())
                .map(|i| request.group(i).unwrap().id.to_string())
                .collect();
            next.users = (0..request.users_len())
                .map(|i| request.user(i).unwrap().id.to_string())
                .collect();
            next.revision += 1;
            self.state = next;
            Ok(UserCollectionRecord {
                collection: CollectionRecord {
                    name: &self.state.name,
                    external_id: self.state.external.as_deref(),
                    ..self.returned.collection
                },
                ..self.returned
            })
        }
    }
    // An unbounded embedding view: decoder capacities do not constrain service APIs.
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
            read_only: true,
            manage: false,
        }
    }
    fn input() -> Input {
        Input {
            name: "opaque\0名".into(),
            external: Some("".into()),
            groups: vec![],
            users: vec![],
        }
    }

    #[test]
    fn collection_owner_and_confirmed_manager_guards_precede_provider_reads() {
        let mut memory = Memory::new();
        assert_eq!(
            VaultService::new(&mut memory)
                .list_org_collections("", "org")
                .unwrap_err()
                .status_code(),
            401
        );
        assert!(memory.calls.is_empty());
        for (role, status, permitted) in [
            (0, 2, true),
            (1, 2, true),
            (3, 2, true),
            (2, 2, false),
            (4, 2, false),
            (99, 2, false),
            (0, 1, false),
            (0, -1, false),
        ] {
            let mut memory = Memory::new();
            memory.membership.as_mut().unwrap().membership.role = role;
            memory.membership.as_mut().unwrap().membership.status = status;
            assert_eq!(
                VaultService::new(&mut memory)
                    .authorize_org_collection_manager("owner", "org")
                    .is_ok(),
                permitted
            );
            assert_eq!(memory.calls, ["membership"]);
        }
        for foreign in [true, false] {
            let mut memory = Memory::new();
            if foreign {
                memory.membership.as_mut().unwrap().membership.user_id = "foreign";
            } else {
                memory
                    .membership
                    .as_mut()
                    .unwrap()
                    .membership
                    .organization_id = "foreign";
            }
            assert_eq!(
                VaultService::new(&mut memory)
                    .authorize_org_collection_manager("owner", "org")
                    .unwrap_err()
                    .status_code(),
                401
            );
        }
    }
    #[test]
    fn collection_list_requires_direct_full_access_and_rejects_foreign_rows() {
        for role in [0, 1, 3] {
            let mut memory = Memory::new();
            memory.membership.as_mut().unwrap().membership.role = role;
            memory.membership.as_mut().unwrap().access_all = false;
            let actual = VaultService::new(&mut memory)
                .list_org_collections("owner", "org")
                .map(|v| serde_json::to_value(v).unwrap());
            if role == 3 {
                assert_eq!(actual.unwrap_err().status_code(), 404);
                assert_eq!(memory.calls, ["membership"]);
            } else {
                assert_eq!(actual.unwrap()["data"][0]["id"], "collection");
            }
        }
        let mut memory = Memory::new();
        memory.rows[0].organization_id = "foreign";
        assert_eq!(
            VaultService::new(&mut memory)
                .list_org_collections("owner", "org")
                .unwrap_err()
                .status_code(),
            401
        );
    }
    #[test]
    fn collection_creation_checks_all_groups_then_members_then_manager_creation_policy() {
        let mut memory = Memory::new();
        memory.membership.as_mut().unwrap().membership.role = 3;
        memory.membership.as_mut().unwrap().access_all = false;
        let mut request = input();
        request.groups = vec![selection("group"), selection("bad-group")];
        request.users = vec![selection("bad-member")];
        let before = memory.state.clone();
        assert_eq!(
            VaultService::new(&mut memory)
                .create_org_collection("owner", "org", &request)
                .unwrap_err()
                .message,
            "Invalid group"
        );
        assert_eq!(memory.calls, ["membership", "group", "group"]);
        assert_eq!(memory.state, before);
        memory.calls.clear();
        request.groups.pop();
        assert_eq!(
            VaultService::new(&mut memory)
                .create_org_collection("owner", "org", &request)
                .unwrap_err()
                .message,
            "Invalid member"
        );
        assert_eq!(memory.calls, ["membership", "group", "member"]);
        assert_eq!(memory.state, before);
        memory.calls.clear();
        request.users[0] = selection("member");
        assert_eq!(
            VaultService::new(&mut memory)
                .create_org_collection("owner", "org", &request)
                .unwrap_err()
                .status_code(),
            400
        );
        assert_eq!(memory.calls, ["membership", "group", "member"]);
        assert_eq!(memory.state, before);
    }
    #[test]
    fn collection_creation_preserves_uncapped_opaque_data_and_duplicate_reference_order() {
        let mut memory = Memory::new();
        let mut request = input();
        request.name = "\0名 future opaque ".repeat(100_000);
        request.groups = vec![selection("group"); 9];
        request.users = vec![selection("member"); 11];
        let foreign = memory.state.foreign;
        {
            let mut service = VaultService::new(&mut memory);
            let response = service
                .create_org_collection("owner", "org", &&request)
                .unwrap();
            let wire = serde_json::to_value(response).unwrap();
            assert_eq!(wire["name"], request.name);
            assert!(wire["externalId"].is_null());
            assert_eq!(wire.as_object().unwrap().len(), 10);
        }
        assert_eq!(memory.state.groups, vec!["group"; 9]);
        assert_eq!(memory.state.users, vec!["member"; 11]);
        assert_eq!(memory.state.foreign, foreign);
        assert_eq!(memory.state.revision, 6);
        request.external = Some(" \t ".into());
        VaultService::new(&mut memory)
            .create_org_collection("owner", "org", &request)
            .unwrap();
        assert_eq!(memory.state.external.as_deref(), Some(" \t "));
    }
    #[test]
    fn collection_provider_errors_preserve_state_and_typed_error_mapping() {
        for call in ["membership", "group", "member", "create"] {
            let mut memory = Memory::new();
            memory.fail = Some(call);
            let before = memory.state.clone();
            let mut request = input();
            request.groups.push(selection("group"));
            request.users.push(selection("member"));
            assert_eq!(
                VaultService::new(&mut memory)
                    .create_org_collection("owner", "org", &request)
                    .unwrap_err()
                    .status_code(),
                409
            );
            assert_eq!(memory.state, before);
            assert_eq!(memory.calls.last(), Some(&call));
        }
    }
    #[test]
    fn collection_created_response_is_bound_to_owner_organization_and_readability() {
        for which in 0..5 {
            let mut memory = Memory::new();
            match which {
                0 => memory.returned.collection.organization_id = "foreign",
                1 => memory.returned.membership.organization_id = "foreign",
                2 => memory.returned.membership.user_id = "foreign",
                3 => memory.returned.membership.status = 1,
                _ => memory.returned.readable = false,
            }
            assert_eq!(
                VaultService::new(&mut memory)
                    .create_org_collection("owner", "org", &input())
                    .unwrap_err()
                    .status_code(),
                401
            );
        }
    }
    #[test]
    fn collection_global_manageability_precedes_lookup_and_organization_association() {
        let mut memory = Memory::new();
        memory.manageable = false;
        assert_eq!(
            VaultService::new(&mut memory)
                .get_org_collection_details("owner", "org", "collection")
                .unwrap_err()
                .status_code(),
            401
        );
        assert_eq!(memory.calls, ["membership", "manageable"]);
        memory.manageable = true;
        memory.details.row.collection.organization_id = "another-org";
        memory.calls.clear();
        assert_eq!(
            VaultService::new(&mut memory)
                .get_org_collection_details("owner", "org", "collection")
                .unwrap_err()
                .message,
            "Collection is not owned by organization"
        );
        assert_eq!(memory.calls, ["membership", "manageable", "details"]);
        memory.details.row.collection.organization_id = "org";
        memory.present = false;
        assert_eq!(
            VaultService::new(&mut memory)
                .get_org_collection_details("owner", "org", "collection")
                .unwrap_err()
                .status_code(),
            400
        );
    }
    #[test]
    fn collection_single_response_rejects_inconsistent_provider_identity_and_acl_joins() {
        for which in 0..8 {
            let mut memory = Memory::new();
            match which {
                0 => memory.details.row.collection.id = "different",
                1 => memory.details.row.membership.organization_id = "foreign",
                2 => memory.details.row.membership.user_id = "foreign",
                3 => memory.details.row.membership.status = 1,
                4 => memory.details.users[0].organization_id = "foreign",
                5 => memory.details.groups[0].organization_id = "foreign",
                6 => memory.details.row.readable = false,
                _ => memory.fail = Some("details"),
            }
            let error = VaultService::new(&mut memory)
                .get_org_collection_details("owner", "org", "collection")
                .unwrap_err();
            assert_eq!(error.status_code(), if which == 7 { 409 } else { 401 });
        }
    }
    #[test]
    fn collection_responses_project_exact_basic_details_and_access_shapes() {
        let mut memory = Memory::new();
        let before = memory.state.clone();
        let list = serde_json::to_value(
            VaultService::new(&mut memory)
                .list_org_collections("owner", "org")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(list.as_object().unwrap().len(), 3);
        assert_eq!(list["object"], "list");
        assert!(list["continuationToken"].is_null());
        assert_eq!(list["data"][0].as_object().unwrap().len(), 7);
        let detail = serde_json::to_value(
            VaultService::new(&mut memory)
                .get_org_collection_details("owner", "org", "collection")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(detail.as_object().unwrap().len(), 13);
        assert_eq!(detail["object"], "collectionAccessDetails");
        assert_eq!(detail["assigned"], true);
        assert!(detail.get("unmanaged").is_none());
        assert_eq!(
            detail["users"][0],
            json!({"id":"member","readOnly":true,"hidePasswords":false,"manage":true})
        );
        assert_eq!(detail["groups"][0].as_object().unwrap().len(), 4);
        assert_eq!(memory.state, before);
    }
    #[test]
    fn collection_disabled_group_projection_does_not_disable_creation_validation() {
        let mut memory = Memory::new();
        memory.details.enabled = false;
        let wire = serde_json::to_value(
            VaultService::new(&mut memory)
                .get_org_collection_details("owner", "org", "collection")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(wire["groups"], json!([]));
        let mut request = input();
        request.groups.push(selection("bad-group"));
        assert_eq!(
            VaultService::new(&mut memory)
                .create_org_collection("owner", "org", &request)
                .unwrap_err()
                .message,
            "Invalid group"
        );
        assert!(!memory.calls.contains(&"create"));
    }
    #[test]
    fn collection_bounded_wire_decoder_matches_required_object_and_positional_fields() {
        type Request<'a> = OrganizationCollectionCreateRequest<'a, 1, 1>;
        for text in [
            r#"{"name":"","groups":[],"users":[]}"#,
            r#"["",[],[],null]"#,
        ] {
            let request: Request<'_> = serde_json::from_str(text).unwrap();
            assert_eq!(request.name, "");
            assert_eq!(request.external_id, None);
        }
        let tuple: Request<'_> = serde_json::from_str(
            r#"["opaque",[[false,"group",true,false]],[[true,"member",false,true]]," "]"#,
        )
        .unwrap();
        assert_eq!(tuple.group(0).unwrap().id, "group");
        assert!(tuple.user(0).unwrap().manage);
        assert_eq!(tuple.external_id, Some(" "));
        for text in [
            r#"{}"#,
            r#"{"name":"a","groups":[]}"#,
            r#"["a",[],[]]"#,
            r#"["a",[],[],null,0]"#,
            r#"{"name":"a","groups":[],"users":null}"#,
            r#"{"name":"a","groups":[[false,"a",false,false],[false,"b",false,false]],"users":[]}"#,
            r#"{"name":"a","groups":[[false,"a",false]],"users":[]}"#,
            r#"{"name":"a","groups":[],"users":[[false,1,false,false]]}"#,
            r#"{"name":"a","groups":[],"users":[],"externalId":false}"#,
        ] {
            assert!(serde_json::from_str::<Request<'_>>(text).is_err(), "{text}");
        }
        let serialized: Value = serde_json::to_value(tuple).unwrap();
        assert_eq!(serialized["groups"][0].as_object().unwrap().len(), 4);
    }
    #[test]
    fn collection_authority_request_plan_and_response_debug_are_redacted() {
        let mut memory = Memory::new();
        let request = input();
        let authority = VaultService::new(&mut memory)
            .authorize_org_collection_manager("owner", "org")
            .unwrap();
        assert_eq!(
            (
                authority.owner(),
                authority.organization(),
                authority.role(),
                authority.access_all()
            ),
            ("owner", "org", 0, true)
        );
        let plan = ValidatedCollectionCreate {
            request: &request,
            external_id: None,
        };
        assert_eq!(
            std::format!("{authority:?}"),
            "AuthorizedCollectionManager([REDACTED])"
        );
        assert_eq!(
            std::format!("{plan:?}"),
            "ValidatedCollectionCreate([REDACTED])"
        );
        assert_eq!(
            std::format!("{:?}", entry("secret-member")),
            "CollectionAccessEntry([REDACTED])"
        );
    }
}
