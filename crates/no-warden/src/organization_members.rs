//! Public organization-member discovery through allocation-free provider views.
//!
//! This API lists membership metadata, not organization keys. HTTP query parsing,
//! UUID guards, authentication, membership administration and storage remain external.

use crate::{
    ApiError, ErrorKind, VaultService, organization_collections::OrganizationCollectionStorage,
};
use serde::{
    Serialize,
    ser::{SerializeMap, SerializeSeq},
};

/// Semantic query options. The adapter decodes its protocol's optional boolean fields.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OrganizationMemberQuery {
    pub include_collections: bool,
    pub include_groups: bool,
}

/// Optional semantic query values for the single-member endpoint. An adapter maps
/// absent, malformed or duplicated HTTP Option<bool> fields to None. Explicit false
/// remains distinct: only None inherits the resolved include_groups value.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OrganizationMemberDetailQuery {
    pub include_collections: Option<bool>,
    pub include_groups: Option<bool>,
}
impl OrganizationMemberDetailQuery {
    pub const fn resolved(self) -> OrganizationMemberQuery {
        let groups = matches!(self.include_groups, Some(true));
        OrganizationMemberQuery {
            include_groups: groups,
            include_collections: match self.include_collections {
                Some(value) => value,
                None => groups,
            },
        }
    }
}

/// Joined public member/account metadata. Status and role are the stored values;
/// the explicit serializer handles revoked status and the Manager/custom wire mapping.
/// The organization ID is an internal association and never serialized here.
#[derive(Clone, Copy)]
pub struct OrganizationMemberRecord<'a> {
    pub membership_id: &'a str,
    pub user_id: &'a str,
    pub organization_id: &'a str,
    pub name: Option<&'a str>,
    pub email: &'a str,
    pub external_id: Option<&'a str>,
    pub avatar_color: Option<&'a str>,
    pub status: i32,
    pub role: i32,
    pub access_all: bool,
    pub two_factor_enabled: bool,
    pub reset_password_enrolled: bool,
    pub has_master_password: bool,
    pub full_access_group: bool,
}
#[derive(Clone, Copy)]
pub struct OrganizationMemberGroup<'a> {
    pub id: &'a str,
    pub organization_id: &'a str,
}
/// A direct collection assignment. `manage` is the persisted grant; the serializer
/// adds the source-compatible unrestricted Manager permission for that member.
#[derive(Clone, Copy)]
pub struct OrganizationMemberCollection<'a> {
    pub id: &'a str,
    pub organization_id: &'a str,
    pub read_only: bool,
    pub hide_passwords: bool,
    pub manage: bool,
}
macro_rules! redacted {
    ($($name:ident),+ $(,)?) => {$(
        impl core::fmt::Debug for $name<'_> {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    )+};
}
redacted!(
    OrganizationMemberRecord,
    OrganizationMemberGroup,
    OrganizationMemberCollection
);

/// Caller-owned stable indexed view without an intrinsic member/group/collection cap.
/// Every reported index must exist until serialization finishes. Nested IDs must be
/// joined to the same organization, and collections are direct grants, not group-derived
/// collections or automatically synthesized full-access assignments. Resolve full-group
/// access independently of membership status and query flags. Group configuration is
/// trusted provider state, never client input. Do not log this view or attach key material.
pub trait OrganizationMemberListData {
    fn len(&self) -> usize;
    fn get(&self, member: usize) -> Option<OrganizationMemberRecord<'_>>;
    fn groups_enabled(&self) -> bool;
    fn groups_len(&self, member: usize) -> usize;
    fn group(&self, member: usize, index: usize) -> Option<OrganizationMemberGroup<'_>>;
    fn collections_len(&self, member: usize) -> usize;
    fn collection(&self, member: usize, index: usize) -> Option<OrganizationMemberCollection<'_>>;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
impl<T: OrganizationMemberListData + ?Sized> OrganizationMemberListData for &T {
    fn len(&self) -> usize {
        (**self).len()
    }
    fn get(&self, member: usize) -> Option<OrganizationMemberRecord<'_>> {
        (**self).get(member)
    }
    fn groups_enabled(&self) -> bool {
        (**self).groups_enabled()
    }
    fn groups_len(&self, member: usize) -> usize {
        (**self).groups_len(member)
    }
    fn group(&self, member: usize, index: usize) -> Option<OrganizationMemberGroup<'_>> {
        (**self).group(member, index)
    }
    fn collections_len(&self, member: usize) -> usize {
        (**self).collections_len(member)
    }
    fn collection(&self, member: usize, index: usize) -> Option<OrganizationMemberCollection<'_>> {
        (**self).collection(member, index)
    }
}

/// Opt-in discovery provider. Existing organization/collection providers are unchanged.
/// Return all memberships in this organization, including invited, accepted and revoked
/// members; the authenticated requesting actor still requires a confirmed manager role
/// and direct full access. Group-derived full access alone does not admit the actor.
///
/// Account name/email/avatar, 2FA/master-password presence and enrollment flags must
/// come from trusted joined records. Include only organization-scoped direct collection
/// grants. Read operations may update caches, but must preserve all persisted revisions,
/// grants, account state, credentials, keys, ciphertext and foreign records. Hold the
/// operation's lock/snapshot across authorization, view construction and serialization.
pub trait OrganizationMemberStorage: OrganizationCollectionStorage {
    type Members<'a>: OrganizationMemberListData
    where
        Self: 'a;
    fn organization_members(
        &mut self,
        organization: &str,
    ) -> Result<Self::Members<'_>, Self::Error>;
}
impl<T: OrganizationMemberStorage + ?Sized> OrganizationMemberStorage for &mut T {
    type Members<'a>
        = T::Members<'a>
    where
        Self: 'a;
    fn organization_members(
        &mut self,
        organization: &str,
    ) -> Result<Self::Members<'_>, Self::Error> {
        (**self).organization_members(organization)
    }
}

/// Opt-in single-member discovery, reusing the existing indexed response view.
/// A successful provider result contains exactly one membership, scoped by BOTH
/// organization and membership ID; missing/foreign members return None. Do not load
/// or expose another organization's member metadata. Preserve the same stable-view,
/// nested-join and read-only guarantees as OrganizationMemberStorage.
pub trait OrganizationMemberDetailStorage: OrganizationMemberStorage {
    fn organization_member(
        &mut self,
        organization: &str,
        member: &str,
    ) -> Result<Option<Self::Members<'_>>, Self::Error>;
}
impl<T: OrganizationMemberDetailStorage + ?Sized> OrganizationMemberDetailStorage for &mut T {
    fn organization_member(
        &mut self,
        organization: &str,
        member: &str,
    ) -> Result<Option<Self::Members<'_>>, Self::Error> {
        (**self).organization_member(organization, member)
    }
}

/// A sealed single public membership projection, using the list's nineteen fields.
/// It is not a list envelope and cannot authorize membership mutation.
pub struct OrganizationMemberResponse<L> {
    records: L,
    query: OrganizationMemberQuery,
}
impl<L> core::fmt::Debug for OrganizationMemberResponse<L> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OrganizationMemberResponse([REDACTED])")
    }
}

/// Sealed three-field list envelope, with nineteen-field public member projections.
/// No organization/account keys or provider-only organization associations are emitted.
pub struct OrganizationMemberListResponse<L> {
    records: L,
    query: OrganizationMemberQuery,
}
impl<L> core::fmt::Debug for OrganizationMemberListResponse<L> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OrganizationMemberListResponse([REDACTED])")
    }
}
fn collections_visible(
    row: OrganizationMemberRecord<'_>,
    groups_enabled: bool,
    query: OrganizationMemberQuery,
) -> bool {
    query.include_collections && !row.access_all && !(groups_enabled && row.full_access_group)
}
fn incomplete() -> ApiError {
    ApiError::new(ErrorKind::Storage, "Organization member view is incomplete")
}
fn foreign() -> ApiError {
    ApiError::new(
        ErrorKind::Unauthorized,
        "Organization member view belongs to another organization",
    )
}
fn validate_member<'a, L: OrganizationMemberListData + ?Sized>(
    records: &'a L,
    index: usize,
    organization: &str,
    query: OrganizationMemberQuery,
) -> Result<OrganizationMemberRecord<'a>, ApiError> {
    let row = records.get(index).ok_or_else(incomplete)?;
    if row.organization_id != organization {
        return Err(foreign());
    }
    if query.include_groups && records.groups_enabled() {
        for index2 in 0..records.groups_len(index) {
            if records
                .group(index, index2)
                .ok_or_else(incomplete)?
                .organization_id
                != organization
            {
                return Err(foreign());
            }
        }
    }
    if collections_visible(row, records.groups_enabled(), query) {
        for index2 in 0..records.collections_len(index) {
            if records
                .collection(index, index2)
                .ok_or_else(incomplete)?
                .organization_id
                != organization
            {
                return Err(foreign());
            }
        }
    }
    Ok(row)
}
fn missing_member() -> ApiError {
    ApiError::invalid(
        "member",
        "The specified user isn't a member of the organization",
    )
}
fn admin_required() -> ApiError {
    ApiError::new(
        ErrorKind::Unauthorized,
        "You need to be Admin or Owner to call this endpoint",
    )
}
impl<S: OrganizationMemberDetailStorage> VaultService<S> {
    /// Run this request guard before adapter UUID/query guards, then retain the
    /// authenticated lock/snapshot through get_org_member and serialization.
    pub fn authorize_org_member_admin(
        &mut self,
        owner: &str,
        organization: &str,
    ) -> Result<(), ApiError> {
        crate::service::require_owner(owner)?;
        let member = self
            .storage_mut()
            .collection_membership(owner, organization)
            .map_err(S::map_error)?
            .ok_or_else(admin_required)?
            .membership;
        if member.user_id != owner
            || member.organization_id != organization
            || member.status != 2
            || !matches!(member.role, 0 | 1)
        {
            return Err(admin_required());
        }
        Ok(())
    }
    pub fn get_org_member(
        &mut self,
        owner: &str,
        organization: &str,
        member: &str,
        query: &OrganizationMemberDetailQuery,
    ) -> Result<OrganizationMemberResponse<S::Members<'_>>, ApiError> {
        self.authorize_org_member_admin(owner, organization)?;
        let records = self
            .storage_mut()
            .organization_member(organization, member)
            .map_err(S::map_error)?
            .ok_or_else(missing_member)?;
        if records.len() != 1 {
            return Err(incomplete());
        }
        let row = records.get(0).ok_or_else(incomplete)?;
        if row.membership_id != member || row.organization_id != organization {
            return Err(missing_member());
        }
        let query = query.resolved();
        validate_member(&records, 0, organization, query)?;
        Ok(OrganizationMemberResponse { records, query })
    }
}
impl<L: OrganizationMemberListData> Serialize for OrganizationMemberResponse<L> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let row = self
            .records
            .get(0)
            .ok_or_else(|| serde::ser::Error::custom("Incomplete organization member view"))?;
        Member {
            records: &self.records,
            index: 0,
            row,
            query: self.query,
        }
        .serialize(serializer)
    }
}

impl<S: OrganizationMemberStorage> VaultService<S> {
    pub fn list_org_members(
        &mut self,
        owner: &str,
        organization: &str,
        query: &OrganizationMemberQuery,
    ) -> Result<OrganizationMemberListResponse<S::Members<'_>>, ApiError> {
        let authority = self.authorize_org_collection_manager(owner, organization)?;
        if !authority.access_all() && !matches!(authority.role(), 0 | 1) {
            return Err(ApiError::new(ErrorKind::NotFound, "Resource not found."));
        }
        let records = self
            .storage_mut()
            .organization_members(organization)
            .map_err(S::map_error)?;
        for index in 0..records.len() {
            validate_member(&records, index, organization, *query)?;
        }
        Ok(OrganizationMemberListResponse {
            records,
            query: *query,
        })
    }
}

impl<L: OrganizationMemberListData> Serialize for OrganizationMemberListResponse<L> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry(
            "data",
            &Members {
                records: &self.records,
                query: self.query,
            },
        )?;
        map.serialize_entry("object", "list")?;
        map.serialize_entry("continuationToken", &Option::<&str>::None)?;
        map.end()
    }
}
struct Members<'a, L> {
    records: &'a L,
    query: OrganizationMemberQuery,
}
impl<L: OrganizationMemberListData> Serialize for Members<'_, L> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.records.len()))?;
        for index in 0..self.records.len() {
            let row = self
                .records
                .get(index)
                .ok_or_else(|| serde::ser::Error::custom("Incomplete organization member view"))?;
            seq.serialize_element(&Member {
                records: self.records,
                index,
                row,
                query: self.query,
            })?;
        }
        seq.end()
    }
}
struct Member<'a, L> {
    records: &'a L,
    index: usize,
    row: OrganizationMemberRecord<'a>,
    query: OrganizationMemberQuery,
}
impl<L: OrganizationMemberListData> Serialize for Member<'_, L> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let row = self.row;
        let restored_status = if row.status <= -1 {
            row.status + 128
        } else {
            row.status
        };
        let mut map = serializer.serialize_map(Some(19))?;
        map.serialize_entry("id", row.membership_id)?;
        map.serialize_entry("userId", row.user_id)?;
        map.serialize_entry("name", &row.name.filter(|_| restored_status >= 1))?;
        map.serialize_entry("email", row.email)?;
        map.serialize_entry("externalId", &row.external_id)?;
        map.serialize_entry("avatarColor", &row.avatar_color)?;
        map.serialize_entry(
            "groups",
            &Groups {
                records: self.records,
                index: self.index,
                visible: self.query.include_groups && self.records.groups_enabled(),
            },
        )?;
        map.serialize_entry(
            "collections",
            &Collections {
                records: self.records,
                index: self.index,
                role: row.role,
                visible: collections_visible(row, self.records.groups_enabled(), self.query),
            },
        )?;
        map.serialize_entry("status", &row.status.max(-1))?;
        map.serialize_entry("type", &if row.role == 3 { 4 } else { row.role })?;
        map.serialize_entry("twoFactorEnabled", &row.two_factor_enabled)?;
        map.serialize_entry("resetPasswordEnrolled", &row.reset_password_enrolled)?;
        map.serialize_entry("hasMasterPassword", &row.has_master_password)?;
        map.serialize_entry(
            "permissions",
            &if matches!(row.role, 3 | 4) && row.access_all {
                Some(ManagerPermissions)
            } else {
                None
            },
        )?;
        for field in [
            "ssoBound",
            "claimedByOrganization",
            "usesKeyConnector",
            "accessSecretsManager",
        ] {
            map.serialize_entry(field, &false)?;
        }
        map.serialize_entry("object", "organizationUserUserDetails")?;
        map.end()
    }
}
struct ManagerPermissions;
impl Serialize for ManagerPermissions {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(12))?;
        for field in [
            "accessEventLogs",
            "accessImportExport",
            "accessReports",
            "manageGroups",
            "managePolicies",
            "manageSso",
            "manageUsers",
            "manageResetPassword",
            "manageScim",
        ] {
            map.serialize_entry(field, &false)?;
        }
        for field in [
            "createNewCollections",
            "editAnyCollection",
            "deleteAnyCollection",
        ] {
            map.serialize_entry(field, &true)?;
        }
        map.end()
    }
}
struct Groups<'a, L> {
    records: &'a L,
    index: usize,
    visible: bool,
}
impl<L: OrganizationMemberListData> Serialize for Groups<'_, L> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let len = if self.visible {
            self.records.groups_len(self.index)
        } else {
            0
        };
        let mut seq = serializer.serialize_seq(Some(len))?;
        for index in 0..len {
            let group = self.records.group(self.index, index).ok_or_else(|| {
                serde::ser::Error::custom("Incomplete organization member group view")
            })?;
            seq.serialize_element(group.id)?;
        }
        seq.end()
    }
}
struct Collections<'a, L> {
    records: &'a L,
    index: usize,
    role: i32,
    visible: bool,
}
impl<L: OrganizationMemberListData> Serialize for Collections<'_, L> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let len = if self.visible {
            self.records.collections_len(self.index)
        } else {
            0
        };
        let mut seq = serializer.serialize_seq(Some(len))?;
        for index in 0..len {
            let row = self.records.collection(self.index, index).ok_or_else(|| {
                serde::ser::Error::custom("Incomplete organization member collection view")
            })?;
            seq.serialize_element(&CollectionSelection {
                row,
                role: self.role,
            })?;
        }
        seq.end()
    }
}
struct CollectionSelection<'a> {
    row: OrganizationMemberCollection<'a>,
    role: i32,
}
impl Serialize for CollectionSelection<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(4))?;
        map.serialize_entry("id", self.row.id)?;
        map.serialize_entry("readOnly", &self.row.read_only)?;
        map.serialize_entry("hidePasswords", &self.row.hide_passwords)?;
        map.serialize_entry(
            "manage",
            &(self.row.manage
                || (self.role == 3 && !self.row.read_only && !self.row.hide_passwords)),
        )?;
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Storage,
        organization_collections::{
            CollectionCreateData, OrganizationCollectionMembership, ValidatedCollectionCreate,
        },
        organizations::{
            CollectionRecord, OrganizationCreationPolicy, OrganizationMembership,
            OrganizationProfileRecord, OrganizationRecord, OrganizationStorage,
            UserCollectionRecord, ValidatedOrganizationCreate,
        },
        service::ItemMetadata,
        wire::{CipherRequest, FolderRequest, RegisterRequest},
    };
    use serde_json::{Value, json};
    use std::{vec, vec::Vec};
    fn actor() -> OrganizationMembership<'static> {
        OrganizationMembership {
            user_id: "actor",
            organization_id: "org",
            role: 0,
            status: 2,
        }
    }
    fn row() -> OrganizationMemberRecord<'static> {
        OrganizationMemberRecord {
            membership_id: "member",
            user_id: "subject",
            organization_id: "org",
            name: Some("雪\0public name"),
            email: "member@example.test",
            external_id: Some("opaque external"),
            avatar_color: Some("opaque"),
            status: 2,
            role: 2,
            access_all: false,
            two_factor_enabled: true,
            reset_password_enrolled: true,
            has_master_password: true,
            full_access_group: false,
        }
    }
    fn grant() -> OrganizationMemberCollection<'static> {
        OrganizationMemberCollection {
            id: "collection",
            organization_id: "org",
            read_only: false,
            hide_passwords: false,
            manage: false,
        }
    }
    struct View {
        rows: Vec<OrganizationMemberRecord<'static>>,
        groups: Vec<OrganizationMemberGroup<'static>>,
        collections: Vec<OrganizationMemberCollection<'static>>,
        enabled: bool,
        hole: u8,
    }
    impl OrganizationMemberListData for View {
        fn len(&self) -> usize {
            self.rows.len()
        }
        fn get(&self, i: usize) -> Option<OrganizationMemberRecord<'_>> {
            if self.hole == 1 {
                None
            } else {
                self.rows.get(i).copied()
            }
        }
        fn groups_enabled(&self) -> bool {
            self.enabled
        }
        fn groups_len(&self, _: usize) -> usize {
            self.groups.len()
        }
        fn group(&self, _: usize, i: usize) -> Option<OrganizationMemberGroup<'_>> {
            if self.hole == 2 {
                None
            } else {
                self.groups.get(i).copied()
            }
        }
        fn collections_len(&self, _: usize) -> usize {
            self.collections.len()
        }
        fn collection(&self, _: usize, i: usize) -> Option<OrganizationMemberCollection<'_>> {
            if self.hole == 3 {
                None
            } else {
                self.collections.get(i).copied()
            }
        }
    }
    struct Memory {
        actor: Option<OrganizationCollectionMembership<'static>>,
        view: View,
        calls: Vec<&'static str>,
        fail: Option<&'static str>,
        persisted: [u64; 6],
        detail_missing: bool,
    }
    impl Memory {
        fn new() -> Self {
            Self {
                actor: Some(OrganizationCollectionMembership {
                    membership: actor(),
                    access_all: true,
                }),
                view: View {
                    rows: vec![row()],
                    groups: vec![OrganizationMemberGroup {
                        id: "group",
                        organization_id: "org",
                    }],
                    collections: vec![grant()],
                    enabled: true,
                    hole: 0,
                },
                calls: Vec::new(),
                fail: None,
                persisted: [2, 3, 5, 7, 11, 13],
                detail_missing: false,
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
            ApiError::new(ErrorKind::Conflict, "Member provider conflict")
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
        type AccessDetails<'a> = Unused;
        fn collection_membership(
            &mut self,
            _: &str,
            _: &str,
        ) -> Result<Option<OrganizationCollectionMembership<'_>>, ()> {
            self.step("membership")?;
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
    struct Unused;
    impl crate::organization_collections::CollectionAccessData for Unused {
        fn collection(&self) -> UserCollectionRecord<'_> {
            unreachable!()
        }
        fn assigned(&self) -> bool {
            unreachable!()
        }
        fn users_len(&self) -> usize {
            unreachable!()
        }
        fn user(
            &self,
            _: usize,
        ) -> Option<crate::organization_collections::CollectionAccessEntry<'_>> {
            unreachable!()
        }
        fn groups_enabled(&self) -> bool {
            unreachable!()
        }
        fn groups_len(&self) -> usize {
            unreachable!()
        }
        fn group(
            &self,
            _: usize,
        ) -> Option<crate::organization_collections::CollectionAccessEntry<'_>> {
            unreachable!()
        }
    }
    impl OrganizationMemberStorage for Memory {
        type Members<'a> = &'a View;
        fn organization_members(&mut self, organization: &str) -> Result<Self::Members<'_>, ()> {
            self.step("members")?;
            assert_eq!(organization, "org");
            Ok(&self.view)
        }
    }
    impl OrganizationMemberDetailStorage for Memory {
        fn organization_member(
            &mut self,
            organization: &str,
            member: &str,
        ) -> Result<Option<Self::Members<'_>>, ()> {
            self.step("member")?;
            assert_eq!((organization, member), ("org", "member"));
            Ok((!self.detail_missing).then_some(&self.view))
        }
    }
    fn detail_query() -> OrganizationMemberDetailQuery {
        OrganizationMemberDetailQuery {
            include_collections: Some(true),
            include_groups: Some(true),
        }
    }
    fn single(memory: &mut Memory, query: OrganizationMemberDetailQuery) -> Value {
        serde_json::to_value(
            VaultService::new(memory)
                .get_org_member("actor", "org", "member", &query)
                .unwrap(),
        )
        .unwrap()
    }

    fn both() -> OrganizationMemberQuery {
        OrganizationMemberQuery {
            include_collections: true,
            include_groups: true,
        }
    }
    fn serialize(memory: &mut Memory, query: OrganizationMemberQuery) -> Value {
        serde_json::to_value(
            VaultService::new(memory)
                .list_org_members("actor", "org", &query)
                .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn member_discovery_authentication_and_confirmed_manager_checks_precede_listing() {
        let mut memory = Memory::new();
        assert_eq!(
            VaultService::new(&mut memory)
                .list_org_members("", "org", &both())
                .unwrap_err()
                .status_code(),
            401
        );
        assert!(memory.calls.is_empty());
        for (role, status) in [(2, 2), (4, 2), (0, 1), (0, -126)] {
            let mut memory = Memory::new();
            memory.actor.as_mut().unwrap().membership.role = role;
            memory.actor.as_mut().unwrap().membership.status = status;
            assert_eq!(
                VaultService::new(&mut memory)
                    .list_org_members("actor", "org", &both())
                    .unwrap_err()
                    .status_code(),
                401
            );
            assert_eq!(memory.calls, ["membership"]);
        }
        for foreign in [true, false] {
            let mut memory = Memory::new();
            if foreign {
                memory.actor.as_mut().unwrap().membership.user_id = "foreign";
            } else {
                memory.actor.as_mut().unwrap().membership.organization_id = "foreign";
            }
            assert_eq!(
                VaultService::new(&mut memory)
                    .list_org_members("actor", "org", &both())
                    .unwrap_err()
                    .status_code(),
                401
            );
            assert!(!memory.calls.contains(&"members"));
        }
    }
    #[test]
    fn member_discovery_requires_direct_full_access_but_owner_and_admin_are_full() {
        for role in [0, 1, 3] {
            let mut memory = Memory::new();
            memory.actor.as_mut().unwrap().membership.role = role;
            memory.actor.as_mut().unwrap().access_all = false;
            memory.view.rows[0].full_access_group = true;
            let result = VaultService::new(&mut memory)
                .list_org_members("actor", "org", &both())
                .map(|v| serde_json::to_value(v).unwrap());
            if role == 3 {
                assert_eq!(
                    (result.unwrap_err().status_code(), memory.calls),
                    (404, vec!["membership"])
                );
            } else {
                assert_eq!(result.unwrap()["data"].as_array().unwrap().len(), 1);
            }
        }
        let mut memory = Memory::new();
        memory.actor.as_mut().unwrap().membership.role = 3;
        assert_eq!(serialize(&mut memory, both())["data"][0]["id"], "member");
    }
    #[test]
    fn member_discovery_exact_public_projection_preserves_opaque_metadata_without_keys() {
        let mut memory = Memory::new();
        let before = memory.persisted;
        let value = serialize(&mut memory, both());
        assert_eq!(value.as_object().unwrap().len(), 3);
        assert_eq!(value["object"], "list");
        assert!(value["continuationToken"].is_null());
        assert_eq!(
            value["data"][0],
            json!({"id":"member","userId":"subject","name":"雪\0public name","email":"member@example.test","externalId":"opaque external","avatarColor":"opaque","groups":["group"],"collections":[{"id":"collection","readOnly":false,"hidePasswords":false,"manage":false}],"status":2,"type":2,"twoFactorEnabled":true,"resetPasswordEnrolled":true,"hasMasterPassword":true,"permissions":null,"ssoBound":false,"claimedByOrganization":false,"usesKeyConnector":false,"accessSecretsManager":false,"object":"organizationUserUserDetails"})
        );
        assert_eq!(value["data"][0].as_object().unwrap().len(), 19);
        assert_eq!(memory.persisted, before);
        assert_eq!(memory.calls, ["membership", "members"]);
    }
    #[test]
    fn member_discovery_lists_all_statuses_and_hides_only_unaccepted_names() {
        let mut memory = Memory::new();
        memory.view.rows = vec![row(); 7];
        for (r, status) in memory
            .view
            .rows
            .iter_mut()
            .zip([0, 1, 2, -128, -127, -126, -1])
        {
            r.status = status;
        }
        let value = serialize(&mut memory, both());
        for (index, (status, visible)) in [
            (0, false),
            (1, true),
            (2, true),
            (-1, false),
            (-1, true),
            (-1, true),
            (-1, true),
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(value["data"][index]["status"], status);
            assert_eq!(!value["data"][index]["name"].is_null(), visible);
            // These are administrative metadata, including grants on revoked/invited rows.
            assert_eq!(
                value["data"][index]["collections"]
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
        }
    }
    #[test]
    fn member_discovery_query_flags_and_group_configuration_control_nested_arrays() {
        for enabled in [false, true] {
            for query in [
                OrganizationMemberQuery::default(),
                OrganizationMemberQuery {
                    include_groups: true,
                    include_collections: false,
                },
                OrganizationMemberQuery {
                    include_groups: false,
                    include_collections: true,
                },
                both(),
            ] {
                let mut memory = Memory::new();
                memory.view.enabled = enabled;
                let value = serialize(&mut memory, query);
                assert_eq!(
                    value["data"][0]["groups"].as_array().unwrap().len(),
                    usize::from(query.include_groups && enabled)
                );
                assert_eq!(
                    value["data"][0]["collections"].as_array().unwrap().len(),
                    usize::from(query.include_collections)
                );
            }
        }
    }
    #[test]
    fn member_discovery_suppresses_direct_collections_for_access_all_or_enabled_full_group() {
        for enabled in [false, true] {
            for access_all in [false, true] {
                for full_group in [false, true] {
                    let mut memory = Memory::new();
                    memory.view.enabled = enabled;
                    memory.view.rows[0].access_all = access_all;
                    memory.view.rows[0].full_access_group = full_group;
                    let value = serialize(
                        &mut memory,
                        OrganizationMemberQuery {
                            include_collections: true,
                            include_groups: false,
                        },
                    );
                    assert_eq!(
                        value["data"][0]["collections"].as_array().unwrap().len(),
                        usize::from(!access_all && !(enabled && full_group))
                    );
                }
            }
        }
    }
    #[test]
    fn member_discovery_custom_permissions_are_nullable_and_have_exact_manager_flags() {
        for role in [0, 1, 2, 3, 4] {
            for access_all in [false, true] {
                let mut memory = Memory::new();
                memory.view.rows[0].role = role;
                memory.view.rows[0].access_all = access_all;
                let value = serialize(&mut memory, both());
                assert_eq!(value["data"][0]["type"], if role == 3 { 4 } else { role });
                let permissions = &value["data"][0]["permissions"];
                if matches!(role, 3 | 4) && access_all {
                    let fields = permissions.as_object().unwrap();
                    assert_eq!(fields.len(), 12);
                    for (key, value) in fields {
                        assert_eq!(
                            *value,
                            json!(matches!(
                                key.as_str(),
                                "createNewCollections"
                                    | "editAnyCollection"
                                    | "deleteAnyCollection"
                            ))
                        );
                    }
                } else {
                    assert!(permissions.is_null());
                }
            }
        }
    }
    #[test]
    fn member_discovery_direct_collection_manage_uses_listed_member_role_and_persisted_flags() {
        for role in [0, 1, 2, 3, 4] {
            for read_only in [false, true] {
                for hide_passwords in [false, true] {
                    for manage in [false, true] {
                        let mut memory = Memory::new();
                        memory.view.rows[0].role = role;
                        memory.view.collections[0].read_only = read_only;
                        memory.view.collections[0].hide_passwords = hide_passwords;
                        memory.view.collections[0].manage = manage;
                        let value = serialize(&mut memory, both());
                        assert_eq!(
                            value["data"][0]["collections"][0]["manage"],
                            manage || (role == 3 && !read_only && !hide_passwords)
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn member_discovery_rejects_foreign_joins_and_incomplete_projected_views() {
        for foreign in 0..3 {
            let mut memory = Memory::new();
            match foreign {
                0 => memory.view.rows[0].organization_id = "foreign",
                1 => memory.view.groups[0].organization_id = "foreign",
                _ => memory.view.collections[0].organization_id = "foreign",
            }
            assert_eq!(
                VaultService::new(&mut memory)
                    .list_org_members("actor", "org", &both())
                    .unwrap_err()
                    .status_code(),
                401
            );
        }
        for hole in 1..=3 {
            let mut memory = Memory::new();
            memory.view.hole = hole;
            assert_eq!(
                VaultService::new(&mut memory)
                    .list_org_members("actor", "org", &both())
                    .unwrap_err()
                    .status_code(),
                500
            );
        }
        let mut memory = Memory::new();
        memory.view.groups[0].organization_id = "foreign";
        memory.view.collections[0].organization_id = "foreign";
        let value = serialize(&mut memory, OrganizationMemberQuery::default());
        assert_eq!(value["data"][0]["groups"], json!([]));
        assert_eq!(value["data"][0]["collections"], json!([]));
    }
    #[test]
    fn member_discovery_provider_failures_preserve_typed_errors_and_no_persistent_writes() {
        for step in ["membership", "members"] {
            let mut memory = Memory::new();
            memory.fail = Some(step);
            let before = memory.persisted;
            assert_eq!(
                VaultService::new(&mut memory)
                    .list_org_members("actor", "org", &both())
                    .unwrap_err()
                    .status_code(),
                409
            );
            assert_eq!(memory.persisted, before);
            assert_eq!(memory.calls.last(), Some(&step));
        }
        let mut memory = Memory::new();
        memory.view.rows.clear();
        let value = serialize(&mut memory, both());
        assert_eq!(
            value,
            json!({"data":[],"object":"list","continuationToken":null})
        );
    }
    #[test]
    fn member_discovery_preserves_view_order_duplicates_and_nullable_account_fields() {
        let mut memory = Memory::new();
        memory.view.rows = vec![row(); 17];
        memory.view.groups = vec![
            OrganizationMemberGroup {
                id: "opaque group\0雪",
                organization_id: "org"
            };
            9
        ];
        memory.view.collections = vec![grant(); 11];
        memory.view.rows[0].name = None;
        memory.view.rows[0].external_id = None;
        memory.view.rows[0].avatar_color = None;
        memory.view.rows[0].has_master_password = false;
        let value = serialize(&mut memory, both());
        assert_eq!(value["data"].as_array().unwrap().len(), 17);
        assert!(value["data"][0]["name"].is_null());
        assert!(value["data"][0]["externalId"].is_null());
        assert!(value["data"][0]["avatarColor"].is_null());
        assert_eq!(value["data"][0]["hasMasterPassword"], false);
        assert_eq!(
            value["data"][1]["groups"],
            serde_json::to_value(vec!["opaque group\0雪"; 9]).unwrap()
        );
        assert_eq!(
            value["data"][1]["collections"].as_array().unwrap().len(),
            11
        );
    }
    #[test]
    fn member_discovery_debug_redacts_rows_nested_views_and_sealed_response() {
        assert_eq!(
            std::format!("{:?}", row()),
            "OrganizationMemberRecord([REDACTED])"
        );
        assert_eq!(
            std::format!("{:?}", grant()),
            "OrganizationMemberCollection([REDACTED])"
        );
        let mut memory = Memory::new();
        let mut service = VaultService::new(&mut memory);
        let response = service.list_org_members("actor", "org", &both()).unwrap();
        assert_eq!(
            std::format!("{response:?}"),
            "OrganizationMemberListResponse([REDACTED])"
        );
    }
    #[test]
    fn single_member_admin_guard_accepts_owner_admin_without_access_all_and_rejects_manager() {
        let mut memory = Memory::new();
        assert_eq!(
            VaultService::new(&mut memory)
                .get_org_member("", "org", "member", &detail_query())
                .unwrap_err()
                .status_code(),
            401
        );
        assert!(memory.calls.is_empty());
        for role in [0, 1] {
            let mut memory = Memory::new();
            memory.actor.as_mut().unwrap().membership.role = role;
            memory.actor.as_mut().unwrap().access_all = false;
            assert_eq!(single(&mut memory, detail_query())["id"], "member");
            assert_eq!(memory.calls, ["membership", "member"]);
        }
        for role in [2, 3, 4] {
            for access_all in [false, true] {
                let mut memory = Memory::new();
                memory.actor.as_mut().unwrap().membership.role = role;
                memory.actor.as_mut().unwrap().access_all = access_all;
                let error = VaultService::new(&mut memory)
                    .get_org_member("actor", "org", "member", &detail_query())
                    .unwrap_err();
                assert_eq!(
                    (error.status_code(), error.message),
                    (401, "You need to be Admin or Owner to call this endpoint")
                );
                assert_eq!(memory.calls, ["membership"]);
            }
        }
    }
    #[test]
    fn single_member_admin_guard_binds_actor_organization_and_confirmed_status() {
        for variant in 0..5 {
            let mut memory = Memory::new();
            match variant {
                0 => memory.actor = None,
                1 => memory.actor.as_mut().unwrap().membership.user_id = "foreign",
                2 => memory.actor.as_mut().unwrap().membership.organization_id = "foreign",
                3 => memory.actor.as_mut().unwrap().membership.status = 1,
                _ => memory.actor.as_mut().unwrap().membership.status = -126,
            }
            assert_eq!(
                VaultService::new(&mut memory)
                    .authorize_org_member_admin("actor", "org")
                    .unwrap_err()
                    .status_code(),
                401
            );
            assert!(!memory.calls.contains(&"member"));
        }
    }
    #[test]
    fn single_member_missing_foreign_and_wrong_identity_have_same_scoped_error() {
        for variant in 0..3 {
            let mut memory = Memory::new();
            match variant {
                0 => memory.detail_missing = true,
                1 => memory.view.rows[0].organization_id = "foreign",
                _ => memory.view.rows[0].membership_id = "wrong-member",
            }
            let error = VaultService::new(&mut memory)
                .get_org_member("actor", "org", "member", &detail_query())
                .unwrap_err();
            assert_eq!(
                (error.status_code(), error.message),
                (400, "The specified user isn't a member of the organization")
            );
            assert_eq!(memory.calls, ["membership", "member"]);
        }
    }
    #[test]
    fn single_member_provider_must_return_one_complete_scoped_record() {
        for count in [0, 2] {
            let mut memory = Memory::new();
            memory.view.rows = vec![row(); count];
            assert_eq!(
                VaultService::new(&mut memory)
                    .get_org_member("actor", "org", "member", &detail_query())
                    .unwrap_err()
                    .status_code(),
                500
            );
        }
        for hole in 1..=3 {
            let mut memory = Memory::new();
            memory.view.hole = hole;
            assert_eq!(
                VaultService::new(&mut memory)
                    .get_org_member("actor", "org", "member", &detail_query())
                    .unwrap_err()
                    .status_code(),
                500
            );
        }
        for group in [true, false] {
            let mut memory = Memory::new();
            if group {
                memory.view.groups[0].organization_id = "foreign";
            } else {
                memory.view.collections[0].organization_id = "foreign";
            }
            assert_eq!(
                VaultService::new(&mut memory)
                    .get_org_member("actor", "org", "member", &detail_query())
                    .unwrap_err()
                    .status_code(),
                401
            );
        }
    }
    #[test]
    fn single_member_optional_collection_flag_inherits_groups_only_when_not_explicit() {
        for groups in [None, Some(false), Some(true)] {
            for collections in [None, Some(false), Some(true)] {
                for enabled in [false, true] {
                    let query = OrganizationMemberDetailQuery {
                        include_groups: groups,
                        include_collections: collections,
                    };
                    let resolved = query.resolved();
                    let expected_groups = groups.unwrap_or(false);
                    let expected_collections = collections.unwrap_or(expected_groups);
                    assert_eq!(
                        resolved,
                        OrganizationMemberQuery {
                            include_groups: expected_groups,
                            include_collections: expected_collections
                        }
                    );
                    let mut memory = Memory::new();
                    memory.view.enabled = enabled;
                    let response = single(&mut memory, query);
                    assert_eq!(
                        response["groups"].as_array().unwrap().len(),
                        usize::from(enabled && expected_groups)
                    );
                    assert_eq!(
                        response["collections"].as_array().unwrap().len(),
                        usize::from(expected_collections)
                    );
                }
            }
        }
        // Malformed/duplicate optional HTTP fields are represented as None by the adapter.
        assert!(
            OrganizationMemberDetailQuery {
                include_groups: Some(true),
                include_collections: None
            }
            .resolved()
            .include_collections
        );
        assert!(
            !OrganizationMemberDetailQuery {
                include_groups: Some(true),
                include_collections: Some(false)
            }
            .resolved()
            .include_collections
        );
    }
    #[test]
    fn single_member_reuses_exact_list_projection_for_all_listed_member_statuses() {
        for status in [-128, -127, -126, -1, 0, 1, 2] {
            for role in [0, 2, 3, 4] {
                let mut memory = Memory::new();
                memory.view.rows[0].status = status;
                memory.view.rows[0].role = role;
                let list = serialize(&mut memory, both());
                let response = single(&mut memory, detail_query());
                assert_eq!(response, list["data"][0]);
                assert_eq!(response.as_object().unwrap().len(), 19);
                assert!(response.get("data").is_none());
                assert!(response.get("organizationId").is_none());
                assert!(response.get("key").is_none());
            }
        }
    }
    #[test]
    fn single_member_provider_errors_are_typed_and_all_reads_preserve_state() {
        for step in ["membership", "member"] {
            let mut memory = Memory::new();
            memory.fail = Some(step);
            let before = memory.persisted;
            assert_eq!(
                VaultService::new(&mut memory)
                    .get_org_member("actor", "org", "member", &detail_query())
                    .unwrap_err()
                    .status_code(),
                409
            );
            assert_eq!(memory.persisted, before);
            assert_eq!(memory.calls.last(), Some(&step));
        }
        let mut memory = Memory::new();
        let before = memory.persisted;
        single(&mut memory, OrganizationMemberDetailQuery::default());
        assert_eq!(memory.persisted, before);
    }
    #[test]
    fn single_member_sealed_response_is_redacted_and_wire_alias_preserves_direct_shape() {
        let mut memory = Memory::new();
        let mut service = VaultService::new(&mut memory);
        let response: crate::wire::OrganizationMemberResponse<_> = service
            .get_org_member(
                "actor",
                "org",
                "member",
                &OrganizationMemberDetailQuery::default(),
            )
            .unwrap();
        assert_eq!(
            std::format!("{response:?}"),
            "OrganizationMemberResponse([REDACTED])"
        );
        let value = serde_json::to_value(response).unwrap();
        assert_eq!(value["id"], "member");
        assert_eq!(value["groups"], json!([]));
        assert_eq!(value["collections"], json!([]));
        assert_eq!(value.as_object().unwrap().len(), 19);
    }
}
