//! Allocation-free single and ordered bulk organization-member removal.
//!
//! HTTP authentication/path decoding, storage, clocks and notifications remain external.
//! This removes an organization membership, never the underlying personal account.

use crate::{
    ApiError, ErrorKind, VaultService, organization_collections::OrganizationCollectionStorage,
};

/// Owned target metadata, independent of a mutable storage borrow. Identifier handles
/// can use strings or caller-bounded storage without a Debug/Clone/Serialize bound.
/// Other invited memberships means exact raw status 0, in ANY organization, excluding
/// this membership. Resolve user existence and configured mail state from trusted data.
pub struct OrganizationMemberRemovalRecord<I> {
    pub membership_id: I,
    pub organization_id: I,
    pub user_id: I,
    pub role: i32,
    pub status: i32,
    pub mail_enabled: bool,
    pub user_exists: bool,
    pub other_invited_memberships: bool,
}
impl<I> core::fmt::Debug for OrganizationMemberRemovalRecord<I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OrganizationMemberRemovalRecord([REDACTED])")
    }
}

/// Sealed removal authority after role/hierarchy/last-owner checks. The invitation
/// decision is a snapshot: commit must recheck it as well as mutable authorization.
pub struct ValidatedOrganizationMemberRemoval<'a, I> {
    owner: &'a str,
    target: &'a OrganizationMemberRemovalRecord<I>,
    remove_invitation: bool,
}
impl<'a, I: AsRef<str>> ValidatedOrganizationMemberRemoval<'a, I> {
    pub const fn owner(&self) -> &'a str {
        self.owner
    }
    pub fn organization(&self) -> &str {
        self.target.organization_id.as_ref()
    }
    pub fn membership_id(&self) -> &str {
        self.target.membership_id.as_ref()
    }
    pub fn user_id(&self) -> &str {
        self.target.user_id.as_ref()
    }
    pub const fn role(&self) -> i32 {
        self.target.role
    }
    pub const fn status(&self) -> i32 {
        self.target.status
    }
    pub const fn remove_invitation(&self) -> bool {
        self.remove_invitation
    }
    pub const fn requires_other_confirmed_owner(&self) -> bool {
        self.target.role == 0 && self.target.status == 2
    }
}
impl<I> core::fmt::Debug for ValidatedOrganizationMemberRemoval<'_, I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ValidatedOrganizationMemberRemoval([REDACTED])")
    }
}

/// Opt-in removal storage; no existing provider must implement this trait.
/// Run authorize_org_member_admin before HTTP UUID guards and hold the authenticated
/// operation context through validation and commit. Target lookup scopes BOTH org and
/// membership ID, and returns owned metadata without loading unrelated private fields.
/// Count only role 0/status 2 memberships for the last-confirmed-owner safeguard.
///
/// Commit must atomically recheck the actor's confirmed Admin/Owner authority, target
/// identity/org/user/role/status, hierarchy and remaining confirmed Owner count. Recheck
/// mail/user/other-Invited state before conditional invitation cleanup; a stale snapshot
/// may fail safely without mutation rather than broadening this plan's authority.
///
/// Remove the selected membership, its inviter metadata, its group-membership links and
/// ALL direct collection grants for this user within this organization, regardless of
/// membership status. Remove the user's global pending invitation marker only when
/// remove_invitation() is true, using its trusted normalized email. Advance the recipient
/// account revision even when there were no collection/group links. Do not promise an
/// exact number of source revision updates. Preserve the personal account/placeholder,
/// credentials, asymmetric/client keys, access/refresh sessions, devices, personal vault,
/// organization/collection definitions and foreign membership/grant state. An error
/// rolls back this operation's entire write. This is stronger than upstream sequential
/// cleanup (including ignored invitation-take failures). Notifications/events, which
/// upstream attempts before removal, remain adapter responsibilities.
pub trait OrganizationMemberRemovalStorage: OrganizationCollectionStorage {
    type Id: AsRef<str>;
    fn removal_member(
        &mut self,
        organization: &str,
        member: &str,
    ) -> Result<Option<OrganizationMemberRemovalRecord<Self::Id>>, Self::Error>;
    fn confirmed_owner_count(&mut self, organization: &str) -> Result<u64, Self::Error>;
    fn remove_organization_member(
        &mut self,
        plan: &ValidatedOrganizationMemberRemoval<'_, Self::Id>,
    ) -> Result<(), Self::Error>;
}
impl<T: OrganizationMemberRemovalStorage + ?Sized> OrganizationMemberRemovalStorage for &mut T {
    type Id = T::Id;
    fn removal_member(
        &mut self,
        org: &str,
        member: &str,
    ) -> Result<Option<OrganizationMemberRemovalRecord<Self::Id>>, Self::Error> {
        (**self).removal_member(org, member)
    }
    fn confirmed_owner_count(&mut self, org: &str) -> Result<u64, Self::Error> {
        (**self).confirmed_owner_count(org)
    }
    fn remove_organization_member(
        &mut self,
        plan: &ValidatedOrganizationMemberRemoval<'_, Self::Id>,
    ) -> Result<(), Self::Error> {
        (**self).remove_organization_member(plan)
    }
}
fn invalid(message: &'static str) -> ApiError {
    ApiError::new(ErrorKind::InvalidRequest, message)
}
fn missing() -> ApiError {
    invalid("User to delete isn't member of the organization")
}

impl<S: OrganizationMemberRemovalStorage> VaultService<S> {
    /// Remove one scoped membership. Admins may remove only ordinary User role 2;
    /// only Owners may remove other roles, including Manager role 3. Invited, accepted
    /// and revoked targets are removable. Self-removal follows the same rules.
    pub fn remove_org_member(
        &mut self,
        owner: &str,
        organization: &str,
        member: &str,
    ) -> Result<(), ApiError> {
        let actor_role = self.org_member_admin_role(owner, organization)?;
        let target = self.removal_target_with_role(organization, member, actor_role)?;
        let remove_invitation =
            !target.mail_enabled && target.user_exists && !target.other_invited_memberships;
        let plan = ValidatedOrganizationMemberRemoval {
            owner,
            target: &target,
            remove_invitation,
        };
        self.storage_mut()
            .remove_organization_member(&plan)
            .map_err(S::map_error)
    }
    fn removal_target_with_role(
        &mut self,
        organization: &str,
        member: &str,
        actor_role: i32,
    ) -> Result<OrganizationMemberRemovalRecord<S::Id>, ApiError> {
        let target = self
            .storage_mut()
            .removal_member(organization, member)
            .map_err(S::map_error)?
            .ok_or_else(missing)?;
        if target.organization_id.as_ref() != organization
            || target.membership_id.as_ref() != member
        {
            return Err(missing());
        }
        if target.role != 2 && actor_role != 0 {
            return Err(invalid("Only Owners can delete Admins or Owners"));
        }
        if target.role == 0
            && target.status == 2
            && self
                .storage_mut()
                .confirmed_owner_count(organization)
                .map_err(S::map_error)?
                <= 1
        {
            return Err(invalid("Can't delete the last owner"));
        }
        Ok(target)
    }
}

/// Stable, completely decoded, caller-owned IDs. There is no intrinsic item limit.
/// A host can implement this over owned strings; borrowed bounded decoding is optional.
/// Preserve every string byte, input order and duplicates. All JSON must be decoded
/// before entering the service, so later schema failures cannot follow earlier writes.
pub trait OrganizationBulkMemberRemovalData {
    fn len(&self) -> usize;
    fn get(&self, index: usize) -> Option<&str>;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
impl<T: OrganizationBulkMemberRemovalData + ?Sized> OrganizationBulkMemberRemovalData for &T {
    fn len(&self) -> usize {
        (**self).len()
    }
    fn get(&self, index: usize) -> Option<&str> {
        (**self).get(index)
    }
}
impl<const N: usize> OrganizationBulkMemberRemovalData
    for crate::wire::OrganizationBulkMemberRemovalRequest<'_, N>
{
    fn len(&self) -> usize {
        self.ids.len()
    }
    fn get(&self, index: usize) -> Option<&str> {
        self.ids.get(index).copied()
    }
}

/// Sealed authorization for one invocation. It is neither clonable nor serializable,
/// and no response exposes it. Providers capture the original actor membership identity
/// in their owned Batch context rather than borrowing mutable storage through this value.
pub struct OrganizationMemberRemovalBatchAuthority<'a> {
    owner: &'a str,
    organization: &'a str,
    actor_role: i32,
}
impl<'a> OrganizationMemberRemovalBatchAuthority<'a> {
    pub const fn owner(&self) -> &'a str {
        self.owner
    }
    pub const fn organization(&self) -> &'a str {
        self.organization
    }
    pub const fn actor_role(&self) -> i32 {
        self.actor_role
    }
}
impl core::fmt::Debug for OrganizationMemberRemovalBatchAuthority<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OrganizationMemberRemovalBatchAuthority([REDACTED])")
    }
}

/// A batch-only write plan. Its underlying removal has the same target/count/marker
/// rules as a single removal, but cannot be sent through the single live-actor hook.
/// actor_removed_by_batch is set only after this invocation committed a self-removal.
pub struct ValidatedOrganizationBulkMemberRemoval<'a, I> {
    removal: ValidatedOrganizationMemberRemoval<'a, I>,
    actor_role: i32,
    actor_removed_by_batch: bool,
}
impl<I: AsRef<str>> ValidatedOrganizationBulkMemberRemoval<'_, I> {
    pub const fn removal(&self) -> &ValidatedOrganizationMemberRemoval<'_, I> {
        &self.removal
    }
    pub const fn actor_role(&self) -> i32 {
        self.actor_role
    }
    pub const fn actor_removed_by_batch(&self) -> bool {
        self.actor_removed_by_batch
    }
    pub fn removes_actor(&self) -> bool {
        self.removal.user_id() == self.removal.owner()
    }
}
impl<I> core::fmt::Debug for ValidatedOrganizationBulkMemberRemoval<'_, I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ValidatedOrganizationBulkMemberRemoval([REDACTED])")
    }
}

/// Optional batch capability, separate from single-operation authorization. Begin is
/// read-only and must capture the original confirmed actor membership ID, owner, org
/// and role. Hold a trusted operation context through the invocation. Each item has
/// its own atomic commit; errors must not undo successful earlier items, advance the
/// batch's self-removal state or leak provider diagnostics into public errors.
///
/// Before self-removal succeeds, recheck that original live actor identity/role/status.
/// After a successful self-removal in THIS context, require both the sealed plan flag
/// and provider's matching self-removal proof, and require that no replacement actor
/// membership exists. Never treat unrelated disappearance, revocation or reinvitation
/// as successful self-removal. Target identity/hierarchy, live last-confirmed-owner
/// count, invitation decision and all scoped cleanup/revision obligations of the
/// single removal provider still apply, using the captured actor role.
///
/// This deliberately preserves stronger local stale-actor/atomic-item checks than an
/// upstream request-snapshot loop. It does not weaken the existing single write hook.
/// Batch context must not escape this invocation or authorize another request. Build
/// any fallible result state before committing; do not report failure after a commit.
pub trait OrganizationBulkMemberRemovalStorage: OrganizationMemberRemovalStorage {
    type Batch;
    fn begin_member_removal_batch(
        &mut self,
        authority: &OrganizationMemberRemovalBatchAuthority<'_>,
    ) -> Result<Self::Batch, Self::Error>;
    fn remove_organization_member_in_batch(
        &mut self,
        batch: &mut Self::Batch,
        plan: &ValidatedOrganizationBulkMemberRemoval<'_, Self::Id>,
    ) -> Result<(), Self::Error>;
}
impl<T: OrganizationBulkMemberRemovalStorage + ?Sized> OrganizationBulkMemberRemovalStorage
    for &mut T
{
    type Batch = T::Batch;
    fn begin_member_removal_batch(
        &mut self,
        authority: &OrganizationMemberRemovalBatchAuthority<'_>,
    ) -> Result<Self::Batch, Self::Error> {
        (**self).begin_member_removal_batch(authority)
    }
    fn remove_organization_member_in_batch(
        &mut self,
        batch: &mut Self::Batch,
        plan: &ValidatedOrganizationBulkMemberRemoval<'_, Self::Id>,
    ) -> Result<(), Self::Error> {
        (**self).remove_organization_member_in_batch(batch, plan)
    }
}

/// Public, exact-ID outcome with only a safely mapped public error message.
/// Storage/notification Debug causes are intentionally not reproduced.
#[derive(Clone, Copy)]
pub struct OrganizationBulkMemberRemovalResult<'a> {
    id: &'a str,
    error: Option<ApiError>,
}
impl<'a> OrganizationBulkMemberRemovalResult<'a> {
    pub const fn id(&self) -> &'a str {
        self.id
    }
    pub const fn error(&self) -> Option<ApiError> {
        self.error
    }
}
impl core::fmt::Debug for OrganizationBulkMemberRemovalResult<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OrganizationBulkMemberRemovalResult([REDACTED])")
    }
}
impl serde::Serialize for OrganizationBulkMemberRemovalResult<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut row = serializer.serialize_map(Some(3))?;
        row.serialize_entry("object", "OrganizationBulkConfirmResponseModel")?;
        row.serialize_entry("id", self.id)?;
        row.serialize_entry("error", self.error.map_or("", |error| error.message))?;
        row.end()
    }
}
/// Complete ordered response borrowing both caller input and output storage.
/// Slots beyond the input length are not serialized.
pub struct OrganizationBulkMemberRemovalResponse<'out, 'data> {
    results: &'out [Option<OrganizationBulkMemberRemovalResult<'data>>],
}
impl<'data> OrganizationBulkMemberRemovalResponse<'_, 'data> {
    pub const fn len(&self) -> usize {
        self.results.len()
    }
    pub const fn is_empty(&self) -> bool {
        self.results.is_empty()
    }
    pub fn get(&self, index: usize) -> Option<&OrganizationBulkMemberRemovalResult<'data>> {
        self.results.get(index)?.as_ref()
    }
}
impl core::fmt::Debug for OrganizationBulkMemberRemovalResponse<'_, '_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OrganizationBulkMemberRemovalResponse([REDACTED])")
    }
}
impl serde::Serialize for OrganizationBulkMemberRemovalResponse<'_, '_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{SerializeMap, SerializeSeq};
        struct Rows<'a, 'b>(&'a [Option<OrganizationBulkMemberRemovalResult<'b>>]);
        impl serde::Serialize for Rows<'_, '_> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut rows = serializer.serialize_seq(Some(self.0.len()))?;
                for row in self.0 {
                    rows.serialize_element(row.as_ref().ok_or_else(|| {
                        serde::ser::Error::custom("Incomplete bulk member removal output")
                    })?)?;
                }
                rows.end()
            }
        }
        let mut result = serializer.serialize_map(Some(3))?;
        result.serialize_entry("data", &Rows(self.results))?;
        result.serialize_entry("object", "list")?;
        result.serialize_entry("continuationToken", &Option::<&str>::None)?;
        result.end()
    }
}
impl<S: OrganizationBulkMemberRemovalStorage> VaultService<S> {
    /// Authorize once, validate full input/output views, then commit independently in
    /// input order. All item domain/provider errors are rows, including empty or
    /// malformed opaque IDs; they do not abort or roll back the successful prefix.
    /// Empty batches return a list without invoking the begin hook. Insufficient
    /// caller scratch is a local capacity error, never an intrinsic HTTP item cap.
    pub fn bulk_remove_org_members<'data, 'out, D: OrganizationBulkMemberRemovalData + ?Sized>(
        &mut self,
        owner: &str,
        organization: &str,
        request: &'data D,
        scratch: &'out mut [Option<OrganizationBulkMemberRemovalResult<'data>>],
    ) -> Result<OrganizationBulkMemberRemovalResponse<'out, 'data>, ApiError> {
        let actor_role = self.org_member_admin_role(owner, organization)?;
        let count = request.len();
        if scratch.len() < count {
            return Err(ApiError::new(
                ErrorKind::Storage,
                "Bulk member removal output capacity is insufficient",
            ));
        }
        for index in 0..count {
            if request.get(index).is_none() {
                return Err(ApiError::new(
                    ErrorKind::Storage,
                    "Bulk member removal input view is incomplete",
                ));
            }
        }
        scratch[..count].fill(None);
        if count == 0 {
            return Ok(OrganizationBulkMemberRemovalResponse {
                results: &scratch[..0],
            });
        }
        let authority = OrganizationMemberRemovalBatchAuthority {
            owner,
            organization,
            actor_role,
        };
        let mut batch = self
            .storage_mut()
            .begin_member_removal_batch(&authority)
            .map_err(S::map_error)?;
        let mut actor_removed_by_batch = false;
        for (index, slot) in scratch[..count].iter_mut().enumerate() {
            let member = request.get(index).ok_or_else(|| {
                ApiError::new(
                    ErrorKind::Storage,
                    "Bulk member removal input view is incomplete",
                )
            })?;
            let result = (|| {
                let target = self.removal_target_with_role(organization, member, actor_role)?;
                let removal = ValidatedOrganizationMemberRemoval {
                    owner,
                    remove_invitation: !target.mail_enabled
                        && target.user_exists
                        && !target.other_invited_memberships,
                    target: &target,
                };
                let plan = ValidatedOrganizationBulkMemberRemoval {
                    removal,
                    actor_role,
                    actor_removed_by_batch,
                };
                self.storage_mut()
                    .remove_organization_member_in_batch(&mut batch, &plan)
                    .map_err(S::map_error)?;
                if plan.removes_actor() {
                    actor_removed_by_batch = true;
                }
                Ok(())
            })();
            *slot = Some(OrganizationBulkMemberRemovalResult {
                id: member,
                error: result.err(),
            });
        }
        Ok(OrganizationBulkMemberRemovalResponse {
            results: &scratch[..count],
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::{
        Storage,
        organization_collections::{
            CollectionAccessData, CollectionAccessEntry, CollectionCreateData,
            OrganizationCollectionMembership, ValidatedCollectionCreate,
        },
        organizations::{
            CollectionRecord, OrganizationCreationPolicy, OrganizationMembership,
            OrganizationProfileRecord, OrganizationRecord, OrganizationStorage,
            UserCollectionRecord, ValidatedOrganizationCreate,
        },
        service::ItemMetadata,
        wire::{CipherRequest, FolderRequest, RegisterRequest},
    };
    use std::{
        format,
        string::{String, ToString},
        vec::Vec,
    };

    // These owned identifiers intentionally need neither Clone nor Debug nor Serialize.
    struct Id(String);
    impl AsRef<str> for Id {
        fn as_ref(&self) -> &str {
            &self.0
        }
    }
    #[derive(Clone, Copy)]
    struct Target {
        member: &'static str,
        org: &'static str,
        user: &'static str,
        role: i32,
        status: i32,
    }
    struct Memory {
        actor: Option<OrganizationCollectionMembership<'static>>,
        target: Option<Target>,
        owners: u64,
        mail: bool,
        user_exists: bool,
        other_invited: bool,
        marker: bool,
        grants: u32,
        groups: u32,
        inviter: bool,
        revision: u64,
        preserved: [u64; 8],
        fail: Option<&'static str>,
        stale: bool,
        batch_targets: Option<Vec<Target>>,
        batch_flags: Vec<bool>,
        batch_lookups: Vec<String>,
        batch_fail_member: Option<&'static str>,
        batch_invalidate_at: Option<usize>,
        batch_reinvite_at: Option<usize>,
        actor_generation: u64,
        calls: Vec<&'static str>,
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
                target: Some(Target {
                    member: "member",
                    org: "org",
                    user: "recipient",
                    role: 2,
                    status: 2,
                }),
                owners: 1,
                mail: false,
                user_exists: true,
                other_invited: false,
                marker: true,
                grants: 3,
                groups: 2,
                inviter: true,
                revision: 7,
                preserved: [11, 22, 33, 44, 55, 66, 77, 88],
                fail: None,
                stale: false,
                batch_targets: None,
                batch_flags: Vec::new(),
                batch_lookups: Vec::new(),
                batch_fail_member: None,
                batch_invalidate_at: None,
                batch_reinvite_at: None,
                actor_generation: 0,
                calls: Vec::new(),
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
        fn state(&self) -> (bool, bool, u32, u32, bool, u64, [u64; 8]) {
            (
                self.target.is_some(),
                self.marker,
                self.grants,
                self.groups,
                self.inviter,
                self.revision,
                self.preserved,
            )
        }
    }
    impl Storage for Memory {
        type Error = ();
        fn map_error(_: ()) -> ApiError {
            ApiError::new(ErrorKind::Conflict, "Removal provider conflict")
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

    impl OrganizationMemberRemovalStorage for Memory {
        type Id = Id;
        fn removal_member(
            &mut self,
            org: &str,
            member: &str,
        ) -> Result<Option<OrganizationMemberRemovalRecord<Id>>, ()> {
            assert_eq!(org, "org");
            self.step("target")?;
            let target = if let Some(targets) = &self.batch_targets {
                self.batch_lookups.push(member.to_string());
                targets.iter().find(|row| row.member == member).copied()
            } else {
                assert_eq!(member, "member");
                self.target
            };
            Ok(target.map(|row| OrganizationMemberRemovalRecord {
                membership_id: Id(row.member.to_string()),
                organization_id: Id(row.org.to_string()),
                user_id: Id(row.user.to_string()),
                role: row.role,
                status: row.status,
                mail_enabled: self.mail,
                user_exists: self.user_exists,
                other_invited_memberships: self.other_invited,
            }))
        }
        fn confirmed_owner_count(&mut self, org: &str) -> Result<u64, ()> {
            assert_eq!(org, "org");
            self.step("owners")?;
            Ok(self.owners)
        }
        fn remove_organization_member(
            &mut self,
            plan: &ValidatedOrganizationMemberRemoval<'_, Id>,
        ) -> Result<(), ()> {
            self.step("commit")?;
            let target = self.target.ok_or(())?;
            let actor = self.actor.ok_or(())?.membership;
            if self.stale
                || actor.user_id != plan.owner()
                || actor.organization_id != plan.organization()
                || actor.status != 2
                || !matches!(actor.role, 0 | 1)
                || target.member != plan.membership_id()
                || target.org != plan.organization()
                || target.user != plan.user_id()
                || target.role != plan.role()
                || target.status != plan.status()
                || (target.role != 2 && actor.role != 0)
                || (plan.requires_other_confirmed_owner() && self.owners <= 1)
                || plan.remove_invitation()
                    != (!self.mail && self.user_exists && !self.other_invited)
            {
                return Err(());
            }
            assert_eq!(
                format!("{plan:?}"),
                "ValidatedOrganizationMemberRemoval([REDACTED])"
            );
            self.marker &= !plan.remove_invitation();
            self.grants = 0;
            self.groups = 0;
            self.inviter = false;
            self.target = None;
            self.revision += 1;
            Ok(())
        }
    }
    fn remove(memory: &mut Memory) -> Result<(), ApiError> {
        VaultService::new(memory).remove_org_member("actor", "org", "member")
    }
    fn error(memory: &mut Memory, message: &str) {
        let before = memory.state();
        let error = remove(memory).unwrap_err();
        assert_eq!((error.status_code(), error.message), (400, message));
        assert_eq!(memory.state(), before);
    }

    #[test]
    fn removal_requires_bound_confirmed_admin_before_target_lookup() {
        let mut memory = Memory::new();
        let error = VaultService::new(&mut memory)
            .remove_org_member("", "org", "member")
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Unauthorized);
        assert!(memory.calls.is_empty());
        let mut cases = Vec::new();
        for role in [2, 3, 4, -1] {
            let mut m = Memory::new();
            m.actor.as_mut().unwrap().membership.role = role;
            cases.push(m);
        }
        for status in [0, 1, -1, -126] {
            let mut m = Memory::new();
            m.actor.as_mut().unwrap().membership.status = status;
            cases.push(m);
        }
        let mut m = Memory::new();
        m.actor.as_mut().unwrap().membership.user_id = "foreign";
        cases.push(m);
        let mut m = Memory::new();
        m.actor.as_mut().unwrap().membership.organization_id = "foreign";
        cases.push(m);
        let mut m = Memory::new();
        m.actor = None;
        cases.push(m);
        for mut m in cases {
            let before = m.state();
            assert_eq!(remove(&mut m).unwrap_err().kind, ErrorKind::Unauthorized);
            assert_eq!(m.calls, ["actor"]);
            assert_eq!(m.state(), before);
        }
    }
    #[test]
    fn removal_rejects_missing_or_misbound_owned_target_without_side_effects() {
        for bad in [
            None,
            Some(Target {
                member: "other",
                org: "org",
                user: "recipient",
                role: 2,
                status: 2,
            }),
            Some(Target {
                member: "member",
                org: "foreign",
                user: "recipient",
                role: 2,
                status: 2,
            }),
        ] {
            let mut m = Memory::new();
            m.target = bad;
            error(&mut m, "User to delete isn't member of the organization");
            assert_eq!(m.calls, ["actor", "target"]);
        }
    }
    #[test]
    fn removal_admin_hierarchy_precedes_last_owner_and_owners_can_remove_managers() {
        for role in [0, 1, 3, 4, -1] {
            let mut m = Memory::new();
            m.actor.as_mut().unwrap().membership.role = 1;
            m.target.as_mut().unwrap().role = role;
            error(&mut m, "Only Owners can delete Admins or Owners");
            assert_eq!(m.calls, ["actor", "target"]);
        }
        let mut admin = Memory::new();
        admin.actor.as_mut().unwrap().membership.role = 1;
        remove(&mut admin).unwrap();
        assert_eq!(admin.calls, ["actor", "target", "commit"]);
        let mut owner = Memory::new();
        owner.target.as_mut().unwrap().role = 3;
        remove(&mut owner).unwrap();
        assert_eq!(owner.calls, ["actor", "target", "commit"]);
    }
    #[test]
    fn removal_last_owner_counts_only_confirmed_owner_targets() {
        for owners in [0, 1] {
            let mut m = Memory::new();
            m.owners = owners;
            m.target.as_mut().unwrap().role = 0;
            error(&mut m, "Can't delete the last owner");
            assert_eq!(m.calls, ["actor", "target", "owners"]);
        }
        let mut allowed = Memory::new();
        allowed.owners = 2;
        allowed.target.as_mut().unwrap().role = 0;
        remove(&mut allowed).unwrap();
        assert_eq!(allowed.calls, ["actor", "target", "owners", "commit"]);
        for status in [0, 1, -1, -126] {
            let mut m = Memory::new();
            m.owners = 0;
            m.target.as_mut().unwrap().role = 0;
            m.target.as_mut().unwrap().status = status;
            remove(&mut m).unwrap();
            assert_eq!(m.calls, ["actor", "target", "commit"]);
        }
    }
    #[test]
    fn removal_self_membership_preserves_personal_authority_and_other_state() {
        let mut m = Memory::new();
        m.owners = 2;
        let target = m.target.as_mut().unwrap();
        target.role = 0;
        target.user = "actor";
        let preserved = m.preserved;
        remove(&mut m).unwrap();
        assert!(m.target.is_none());
        assert_eq!(m.preserved, preserved);
        assert_eq!(m.revision, 8);
        assert_eq!((m.grants, m.groups, m.inviter), (0, 0, false));
    }
    #[test]
    fn removal_invitation_cleanup_obeys_mail_user_and_other_invited_snapshot() {
        for mail in [false, true] {
            for user_exists in [false, true] {
                for other in [false, true] {
                    let mut m = Memory::new();
                    m.mail = mail;
                    m.user_exists = user_exists;
                    m.other_invited = other;
                    m.target.as_mut().unwrap().status = 0;
                    remove(&mut m).unwrap();
                    assert_eq!(m.marker, mail || !user_exists || other);
                    assert_eq!(m.revision, 8);
                }
            }
        }
    }
    #[test]
    fn removal_advances_recipient_even_without_grants_and_keeps_foreign_state() {
        for status in [0, 1, 2, -1, -126] {
            let mut m = Memory::new();
            m.target.as_mut().unwrap().status = status;
            m.grants = 0;
            m.groups = 0;
            m.inviter = false;
            let preserved = m.preserved;
            remove(&mut m).unwrap();
            assert_eq!(m.revision, 8);
            assert_eq!(m.preserved, preserved);
            assert_eq!(m.calls, ["actor", "target", "commit"]);
        }
    }
    #[test]
    fn removal_provider_errors_and_stale_commit_are_typed_and_nonmutating() {
        for step in ["actor", "target", "owners", "commit"] {
            let mut m = Memory::new();
            m.target.as_mut().unwrap().role = 0;
            m.owners = 2;
            m.fail = Some(step);
            let before = m.state();
            let error = remove(&mut m).unwrap_err();
            assert_eq!(
                (error.kind, error.message),
                (ErrorKind::Conflict, "Removal provider conflict")
            );
            assert_eq!(m.state(), before);
            assert!(!format!("{error:?}").contains("recipient"));
        }
        let mut m = Memory::new();
        m.stale = true;
        let before = m.state();
        assert_eq!(remove(&mut m).unwrap_err().kind, ErrorKind::Conflict);
        assert_eq!(m.state(), before);
    }
    #[test]
    fn removal_owned_handles_redact_and_forward_through_mutable_storage() {
        let mut m = Memory::new();
        let row = m.removal_member("org", "member").unwrap().unwrap();
        assert_eq!(
            format!("{row:?}"),
            "OrganizationMemberRemovalRecord([REDACTED])"
        );
        let mut storage = &mut m;
        let mut service = VaultService::new(&mut storage);
        service.remove_org_member("actor", "org", "member").unwrap();
        assert!(service.storage_mut().target.is_none());
    }
    // The optional batch provider reuses the single-provider mock without forcing
    // single-operation implementers to carry any batch context or behavior.
    struct Batch {
        actor_generation: u64,
        actor_role: i32,
        removed: bool,
    }
    impl OrganizationBulkMemberRemovalStorage for Memory {
        type Batch = Batch;
        fn begin_member_removal_batch(
            &mut self,
            authority: &OrganizationMemberRemovalBatchAuthority<'_>,
        ) -> Result<Batch, ()> {
            self.step("begin")?;
            let actor = self.actor.ok_or(())?.membership;
            if actor.user_id != authority.owner()
                || actor.organization_id != authority.organization()
                || actor.status != 2
                || actor.role != authority.actor_role()
            {
                return Err(());
            }
            assert_eq!(
                format!("{authority:?}"),
                "OrganizationMemberRemovalBatchAuthority([REDACTED])"
            );
            Ok(Batch {
                actor_generation: self.actor_generation,
                actor_role: actor.role,
                removed: false,
            })
        }
        fn remove_organization_member_in_batch(
            &mut self,
            batch: &mut Batch,
            plan: &ValidatedOrganizationBulkMemberRemoval<'_, Id>,
        ) -> Result<(), ()> {
            self.step("batch_commit")?;
            self.batch_flags.push(plan.actor_removed_by_batch());
            let attempt = self.batch_flags.len();
            if self.batch_invalidate_at == Some(attempt) {
                self.actor = None;
            }
            if self.batch_reinvite_at == Some(attempt) {
                self.actor_generation += 1;
                self.actor = Some(OrganizationCollectionMembership {
                    membership: OrganizationMembership {
                        user_id: "actor",
                        organization_id: "org",
                        role: 0,
                        status: 2,
                    },
                    access_all: false,
                });
            }
            let removal = plan.removal();
            if batch.removed != plan.actor_removed_by_batch()
                || batch.actor_role != plan.actor_role()
                || removal.owner() != "actor"
                || removal.organization() != "org"
            {
                return Err(());
            }
            if batch.removed {
                if self.actor.is_some() {
                    return Err(());
                }
            } else {
                let actor = self.actor.ok_or(())?.membership;
                if actor.user_id != removal.owner()
                    || actor.organization_id != removal.organization()
                    || actor.status != 2
                    || actor.role != batch.actor_role
                    || self.actor_generation != batch.actor_generation
                {
                    return Err(());
                }
            }
            if self.batch_fail_member == Some(removal.membership_id()) {
                return Err(());
            }
            let targets = self.batch_targets.as_mut().ok_or(())?;
            let index = targets
                .iter()
                .position(|row| row.member == removal.membership_id())
                .ok_or(())?;
            let target = targets[index];
            if target.org != removal.organization()
                || target.user != removal.user_id()
                || target.role != removal.role()
                || target.status != removal.status()
                || (target.role != 2 && batch.actor_role != 0)
                || (removal.requires_other_confirmed_owner() && self.owners <= 1)
                || removal.remove_invitation()
                    != (!self.mail && self.user_exists && !self.other_invited)
            {
                return Err(());
            }
            assert_eq!(
                format!("{plan:?}"),
                "ValidatedOrganizationBulkMemberRemoval([REDACTED])"
            );
            targets.remove(index);
            if removal.requires_other_confirmed_owner() {
                self.owners -= 1;
            }
            if plan.removes_actor() {
                self.actor = None;
                batch.removed = true;
            }
            self.revision += 1;
            Ok(())
        }
    }
    struct Ids<'a>(&'a [&'a str]);
    impl OrganizationBulkMemberRemovalData for Ids<'_> {
        fn len(&self) -> usize {
            self.0.len()
        }
        fn get(&self, index: usize) -> Option<&str> {
            self.0.get(index).copied()
        }
    }
    fn batch_memory() -> Memory {
        let mut m = Memory::new();
        m.batch_targets = Some(std::vec![
            Target {
                member: "actor-member",
                org: "org",
                user: "actor",
                role: 0,
                status: 2
            },
            Target {
                member: "other-owner",
                org: "org",
                user: "other-owner-user",
                role: 0,
                status: 2
            },
            Target {
                member: "user",
                org: "org",
                user: "recipient",
                role: 2,
                status: 1
            },
            Target {
                member: "later",
                org: "org",
                user: "later-recipient",
                role: 2,
                status: 0
            },
            Target {
                member: "manager",
                org: "org",
                user: "manager-user",
                role: 3,
                status: 2
            },
            Target {
                member: "foreign",
                org: "elsewhere",
                user: "foreign-user",
                role: 2,
                status: 2
            },
        ]);
        m.owners = 2;
        m
    }
    fn remaining(m: &Memory) -> Vec<&'static str> {
        m.batch_targets
            .as_ref()
            .unwrap()
            .iter()
            .map(|row| row.member)
            .collect()
    }
    fn bulk_json(m: &mut Memory, ids: &[&str]) -> serde_json::Value {
        let mut slots = std::vec![None;ids.len()+1];
        let data = Ids(ids);
        let response = VaultService::new(m)
            .bulk_remove_org_members("actor", "org", &data, &mut slots)
            .unwrap();
        assert_eq!(response.len(), ids.len());
        serde_json::to_value(response).unwrap()
    }
    #[test]
    fn bulk_removal_self_success_continues_but_new_invocation_requires_live_actor() {
        let mut m = batch_memory();
        let before = m.preserved;
        let value = bulk_json(&mut m, &["actor-member", "user", "other-owner"]);
        assert_eq!(value["data"][0]["error"], "");
        assert_eq!(value["data"][1]["error"], "");
        assert_eq!(value["data"][2]["error"], "Can't delete the last owner");
        assert_eq!(m.batch_flags, [false, true]);
        assert_eq!(m.revision, 9);
        assert!(remaining(&m).contains(&"other-owner"));
        assert_eq!(m.preserved, before);
        let mut slots = [None];
        let error = VaultService::new(&mut m)
            .bulk_remove_org_members("actor", "org", &Ids(&["later"]), &mut slots)
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Unauthorized);
        assert!(remaining(&m).contains(&"later"));
    }
    #[test]
    fn bulk_removal_failed_self_never_enables_absent_actor_continuation() {
        let mut m = batch_memory();
        m.batch_fail_member = Some("actor-member");
        let value = bulk_json(&mut m, &["actor-member", "user"]);
        assert_eq!(value["data"][0]["error"], "Removal provider conflict");
        assert_eq!(value["data"][1]["error"], "");
        assert_eq!(m.batch_flags, [false, false]);
        assert!(m.actor.is_some());
        assert!(remaining(&m).contains(&"actor-member"));
        let mut m = batch_memory();
        m.batch_invalidate_at = Some(1);
        let value = bulk_json(&mut m, &["actor-member", "user"]);
        assert!(
            value["data"]
                .as_array()
                .unwrap()
                .iter()
                .all(|r| r["error"] == "Removal provider conflict")
        );
        assert_eq!(m.batch_flags, [false, false]);
        assert_eq!(m.revision, 7);
    }
    #[test]
    fn bulk_removal_reinvitation_cannot_reuse_completed_self_authority() {
        let mut m = batch_memory();
        m.batch_reinvite_at = Some(2);
        let value = bulk_json(&mut m, &["actor-member", "user", "later"]);
        assert_eq!(value["data"][0]["error"], "");
        for row in &value["data"].as_array().unwrap()[1..] {
            assert_eq!(row["error"], "Removal provider conflict");
        }
        assert_eq!(m.batch_flags, [false, true, true]);
        assert_eq!(m.revision, 8);
        assert!(remaining(&m).contains(&"user") && remaining(&m).contains(&"later"));
    }
    #[test]
    fn bulk_removal_order_duplicates_opaque_ids_and_scoped_rows_are_exact() {
        let mut m = batch_memory();
        let ids = ["foreign", "", "bad.id\0雪", "user", "user", "later"];
        let value = bulk_json(&mut m, &ids);
        assert_eq!(value.as_object().unwrap().len(), 3);
        assert_eq!(value["object"], "list");
        assert!(value["continuationToken"].is_null());
        for (index, row) in value["data"].as_array().unwrap().iter().enumerate() {
            assert_eq!(row.as_object().unwrap().len(), 3);
            assert_eq!(row["id"], ids[index]);
            assert_eq!(row["object"], "OrganizationBulkConfirmResponseModel");
            assert_eq!(
                row["error"],
                if matches!(index, 3 | 5) {
                    ""
                } else {
                    "User to delete isn't member of the organization"
                }
            );
        }
        assert_eq!(m.batch_lookups, ids);
        assert_eq!(m.revision, 9);
        assert!(remaining(&m).contains(&"foreign"));
    }
    #[test]
    fn bulk_removal_admin_errors_continue_without_role_or_owner_count_escalation() {
        let mut m = batch_memory();
        m.actor.as_mut().unwrap().membership.role = 1;
        m.batch_targets.as_mut().unwrap()[0].role = 1;
        let value = bulk_json(
            &mut m,
            &["manager", "actor-member", "user", "other-owner", "later"],
        );
        for index in [0, 1, 3] {
            assert_eq!(
                value["data"][index]["error"],
                "Only Owners can delete Admins or Owners"
            );
        }
        for index in [2, 4] {
            assert_eq!(value["data"][index]["error"], "");
        }
        assert!(!m.calls.contains(&"owners"));
        assert_eq!(m.batch_flags, [false, false]);
    }
    #[test]
    fn bulk_removal_empty_capacity_and_incomplete_views_have_no_begin_or_writes() {
        let mut m = batch_memory();
        let before = remaining(&m);
        let response = bulk_json(&mut m, &[]);
        assert_eq!(
            response,
            serde_json::json!({"data":[],"object":"list","continuationToken":null})
        );
        assert_eq!(m.calls, ["actor"]);
        let mut slots = [];
        assert!(
            VaultService::new(&mut m)
                .bulk_remove_org_members("actor", "org", &Ids(&["user"]), &mut slots)
                .is_err()
        );
        struct Incomplete;
        impl OrganizationBulkMemberRemovalData for Incomplete {
            fn len(&self) -> usize {
                2
            }
            fn get(&self, index: usize) -> Option<&str> {
                (index == 0).then_some("user")
            }
        }
        let mut slots = [None; 2];
        assert!(
            VaultService::new(&mut m)
                .bulk_remove_org_members("actor", "org", &Incomplete, &mut slots)
                .is_err()
        );
        assert!(!m.calls.contains(&"begin"));
        assert_eq!(remaining(&m), before);
        assert_eq!(m.revision, 7);
        m.actor = None;
        assert_eq!(
            VaultService::new(&mut m)
                .bulk_remove_org_members("actor", "org", &Ids(&[]), &mut slots)
                .unwrap_err()
                .kind,
            ErrorKind::Unauthorized
        );
    }
    #[test]
    fn bulk_removal_begin_failure_is_outer_and_item_backend_failure_keeps_prefix() {
        let mut m = batch_memory();
        m.fail = Some("begin");
        let before = remaining(&m);
        let mut slots = [None];
        let error = VaultService::new(&mut m)
            .bulk_remove_org_members("actor", "org", &Ids(&["user"]), &mut slots)
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Conflict);
        assert_eq!(remaining(&m), before);
        assert_eq!(m.calls, ["actor", "begin"]);
        let mut m = batch_memory();
        m.batch_fail_member = Some("user");
        let value = bulk_json(&mut m, &["manager", "user", "later"]);
        assert_eq!(value["data"][0]["error"], "");
        assert_eq!(value["data"][1]["error"], "Removal provider conflict");
        assert_eq!(value["data"][2]["error"], "");
        assert_eq!(m.revision, 9);
        assert!(remaining(&m).contains(&"user"));
        assert!(!remaining(&m).contains(&"manager") && !remaining(&m).contains(&"later"));
    }
    #[test]
    fn bulk_removal_uncapped_dynamic_view_forwards_and_borrows_output() {
        let mut m = batch_memory();
        let ids = std::vec!["missing";129];
        let view = Ids(&ids);
        let dynamic: &dyn OrganizationBulkMemberRemovalData = &view;
        let mut slots = std::vec![None;130];
        let mut forwarded = &mut m;
        let response = VaultService::new(&mut forwarded)
            .bulk_remove_org_members("actor", "org", &dynamic, &mut slots)
            .unwrap();
        assert_eq!(response.len(), 129);
        assert!(core::ptr::eq(
            response.get(0).unwrap().id().as_ptr(),
            ids[0].as_ptr()
        ));
        assert!(format!("{response:?}").contains("REDACTED"));
        assert!(!format!("{:?}", response.get(0).unwrap()).contains("missing"));
        assert!(response.get(129).is_none());
        assert_eq!(
            serde_json::to_value(&response).unwrap()["data"]
                .as_array()
                .unwrap()
                .len(),
            129
        );
        assert!(slots[129].is_none());
    }
    #[test]
    fn bulk_removal_bounded_schema_requires_complete_string_ids_and_redacts_debug() {
        type Input<'a> = crate::wire::OrganizationBulkMemberRemovalRequest<'a, 4>;
        for json in [
            r#"{"ids":[]}"#,
            r#"[[]]"#,
            r#"{"ids":["","bad.id","雪"],"ignored":true}"#,
        ] {
            let input: Input<'_> = serde_json::from_str(json).unwrap();
            assert_eq!(
                format!("{input:?}"),
                "OrganizationBulkMemberRemovalRequest([REDACTED])"
            );
        }
        for json in [
            r#"{}"#,
            r#"[]"#,
            r#"{"ids":null}"#,
            r#"{"ids":["user",null]}"#,
            r#"{"ids":["user",1]}"#,
            r#"{"Ids":[]}"#,
            r#"{"ids":[],"ids":[]}"#,
            r#"[[],0]"#,
            r#"{"ids":["1","2","3","4","5"]}"#,
        ] {
            assert!(serde_json::from_str::<Input<'_>>(json).is_err(), "{json}");
        }
    }
}
