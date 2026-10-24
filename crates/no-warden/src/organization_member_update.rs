//! Allocation-free native organization-member role and direct-grant edits.
//!
//! The measured operation has visible partial effects: clearing old direct grants
//! and adding an ordered prefix can survive a later rejected collection/group.
//! The new role is committed only after the supported selections succeed. HTTP,
//! storage, revision clocks, configuration and notifications remain adapters.

use crate::{
    ApiError, ErrorKind, VaultService,
    organization_collections::OrganizationCollectionStorage,
    wire::{OrganizationInviteCollection, OrganizationInvitePermissions, OrganizationInviteRole},
};

/// Stable complete decoded input. Adapters may own strings/vectors; bounded wire
/// decoding is an optional caller policy, never an intrinsic core item limit.
pub trait OrganizationMemberUpdateData {
    fn role(&self) -> OrganizationInviteRole<'_>;
    fn permissions(&self) -> OrganizationInvitePermissions;
    fn collections_len(&self) -> usize;
    fn collection(&self, index: usize) -> Option<OrganizationInviteCollection<'_>>;
    fn groups_len(&self) -> usize;
    fn group(&self, index: usize) -> Option<&str>;
}
impl<T: OrganizationMemberUpdateData + ?Sized> OrganizationMemberUpdateData for &T {
    fn role(&self) -> OrganizationInviteRole<'_> {
        (**self).role()
    }
    fn permissions(&self) -> OrganizationInvitePermissions {
        (**self).permissions()
    }
    fn collections_len(&self) -> usize {
        (**self).collections_len()
    }
    fn collection(&self, index: usize) -> Option<OrganizationInviteCollection<'_>> {
        (**self).collection(index)
    }
    fn groups_len(&self) -> usize {
        (**self).groups_len()
    }
    fn group(&self, index: usize) -> Option<&str> {
        (**self).group(index)
    }
}
impl<const G: usize, const C: usize> OrganizationMemberUpdateData
    for crate::wire::OrganizationMemberUpdateRequest<'_, G, C>
{
    fn role(&self) -> OrganizationInviteRole<'_> {
        self.role
    }
    fn permissions(&self) -> OrganizationInvitePermissions {
        self.permissions
    }
    fn collections_len(&self) -> usize {
        self.collections.as_ref().map_or(0, |v| v.len())
    }
    fn collection(&self, index: usize) -> Option<OrganizationInviteCollection<'_>> {
        self.collections.as_ref()?.get(index).copied()
    }
    fn groups_len(&self) -> usize {
        self.groups.as_ref().map_or(0, |v| v.len())
    }
    fn group(&self, index: usize) -> Option<&str> {
        self.groups.as_ref()?.get(index).copied()
    }
}

/// Owned scoped member facts, independent of caches reused by later provider calls.
/// No wrapped key, account document or untrusted request identity belongs here.
/// groups_configured means existing group definitions/membership/grant state that
/// this default no-created-groups subset cannot safely replace; it is NOT useGroups.
pub struct OrganizationMemberUpdateRecord<I> {
    pub membership_id: I,
    pub organization_id: I,
    pub user_id: I,
    pub role: i32,
    pub status: i32,
    pub access_all: bool,
    pub groups_configured: bool,
}
/// An actual collection scoped to the requested organization. Own handles so that
/// a lookup cannot invalidate the previously loaded member or selection facts.
pub struct OrganizationMemberUpdateCollection<I> {
    pub id: I,
    pub organization_id: I,
}

/// Sealed authorization for the destructive direct-grant reset/revision phase.
/// It does not authorize committing new role metadata before selections succeed.
pub struct ValidatedOrganizationMemberUpdateStart<'a, I> {
    owner: &'a str,
    target: &'a OrganizationMemberUpdateRecord<I>,
    actor_role: i32,
    new_role: i32,
    new_access_all: bool,
}
impl<'a, I: AsRef<str>> ValidatedOrganizationMemberUpdateStart<'a, I> {
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
    pub const fn actor_role(&self) -> i32 {
        self.actor_role
    }
    pub const fn previous_role(&self) -> i32 {
        self.target.role
    }
    pub const fn status(&self) -> i32 {
        self.target.status
    }
    pub const fn previous_access_all(&self) -> bool {
        self.target.access_all
    }
    pub const fn new_role(&self) -> i32 {
        self.new_role
    }
    pub const fn new_access_all(&self) -> bool {
        self.new_access_all
    }
    pub const fn requires_other_confirmed_owner(&self) -> bool {
        self.target.role == 0 && self.target.status == 2 && self.new_role != 0
    }
}
/// One checked direct-grant upsert. Existing successful prefix effects survive a
/// later rejected selection; duplicate IDs deliberately use last-write semantics.
pub struct ValidatedOrganizationMemberUpdateGrant<'a, 'data, I> {
    start: &'a ValidatedOrganizationMemberUpdateStart<'data, I>,
    selection: OrganizationInviteCollection<'data>,
}
impl<'a, 'data, I> ValidatedOrganizationMemberUpdateGrant<'a, 'data, I> {
    pub const fn start(&self) -> &'a ValidatedOrganizationMemberUpdateStart<'data, I> {
        self.start
    }
    pub const fn selection(&self) -> OrganizationInviteCollection<'data> {
        self.selection
    }
}
/// Final metadata authority exists only after every supported selection succeeds.
/// Preserve status and wrapped organization key; this is neither confirmation nor
/// restoration, and cannot transfer the membership to another account or org.
pub struct ValidatedOrganizationMemberUpdate<'a, 'data, I> {
    start: &'a ValidatedOrganizationMemberUpdateStart<'data, I>,
}
impl<'a, 'data, I> ValidatedOrganizationMemberUpdate<'a, 'data, I> {
    pub const fn start(&self) -> &'a ValidatedOrganizationMemberUpdateStart<'data, I> {
        self.start
    }
}

/// Opt-in storage for a default-policy organization with no configured group state.
/// Run authorize_org_member_admin before adapter path/body guards and hold the
/// operation lock/context through all phases. Recheck live confirmed Owner/Admin
/// actor, exact target identity/org/user/old role/status/access_all and applicable
/// last-confirmed-Owner count within each phase's transaction. Count role0/status2.
/// Never infer role ordering from numeric inequalities.
///
/// begin_member_update clears this user's existing direct grants within this org
/// and advances only the target account revision, including no-op/empty updates.
/// It preserves OLD role/access_all/status/key, groups and unrelated state.
/// append_member_update_grant upserts only the sealed exact collection/flags;
/// duplicate IDs overwrite flags. Each successful phase persists independently:
/// errors must not roll back earlier successful phases. An individual failed local
/// phase must not expose half a local write. Local failure rollback is not claimed
/// as upstream failure-injection/concurrency parity.
/// finish_member_update commits only new_role/new_access_all after rechecking live
/// authority. No additional revision bump is required by this core contract. Keep
/// membership IDs/status/wrapped key, account credentials/asymmetric/client keys,
/// sessions/devices, personal vault, collection definitions and foreign-org state.
/// Adapters must reject unsupported policies/configuration rather than silently
/// overwriting unknown state. Mail/events/configured groups remain unimplemented.
pub trait OrganizationMemberUpdateStorage: OrganizationCollectionStorage {
    type UpdateId: AsRef<str>;
    fn update_member(
        &mut self,
        organization: &str,
        member: &str,
    ) -> Result<Option<OrganizationMemberUpdateRecord<Self::UpdateId>>, Self::Error>;
    fn update_confirmed_owner_count(&mut self, organization: &str) -> Result<u64, Self::Error>;
    fn update_collection(
        &mut self,
        organization: &str,
        collection: &str,
    ) -> Result<Option<OrganizationMemberUpdateCollection<Self::UpdateId>>, Self::Error>;
    fn begin_member_update(
        &mut self,
        plan: &ValidatedOrganizationMemberUpdateStart<'_, Self::UpdateId>,
    ) -> Result<(), Self::Error>;
    fn append_member_update_grant(
        &mut self,
        plan: &ValidatedOrganizationMemberUpdateGrant<'_, '_, Self::UpdateId>,
    ) -> Result<(), Self::Error>;
    fn finish_member_update(
        &mut self,
        plan: &ValidatedOrganizationMemberUpdate<'_, '_, Self::UpdateId>,
    ) -> Result<(), Self::Error>;
}
impl<T: OrganizationMemberUpdateStorage + ?Sized> OrganizationMemberUpdateStorage for &mut T {
    type UpdateId = T::UpdateId;
    fn update_member(
        &mut self,
        org: &str,
        member: &str,
    ) -> Result<Option<OrganizationMemberUpdateRecord<Self::UpdateId>>, Self::Error> {
        (**self).update_member(org, member)
    }
    fn update_confirmed_owner_count(&mut self, org: &str) -> Result<u64, Self::Error> {
        (**self).update_confirmed_owner_count(org)
    }
    fn update_collection(
        &mut self,
        org: &str,
        collection: &str,
    ) -> Result<Option<OrganizationMemberUpdateCollection<Self::UpdateId>>, Self::Error> {
        (**self).update_collection(org, collection)
    }
    fn begin_member_update(
        &mut self,
        plan: &ValidatedOrganizationMemberUpdateStart<'_, Self::UpdateId>,
    ) -> Result<(), Self::Error> {
        (**self).begin_member_update(plan)
    }
    fn append_member_update_grant(
        &mut self,
        plan: &ValidatedOrganizationMemberUpdateGrant<'_, '_, Self::UpdateId>,
    ) -> Result<(), Self::Error> {
        (**self).append_member_update_grant(plan)
    }
    fn finish_member_update(
        &mut self,
        plan: &ValidatedOrganizationMemberUpdate<'_, '_, Self::UpdateId>,
    ) -> Result<(), Self::Error> {
        (**self).finish_member_update(plan)
    }
}
fn invalid_snapshot() -> ApiError {
    ApiError::new(
        ErrorKind::Storage,
        "Invalid organization member update provider snapshot",
    )
}
fn invalid(message: &'static str) -> ApiError {
    ApiError::new(ErrorKind::InvalidRequest, message)
}
fn resolved_role(
    input: OrganizationInviteRole<'_>,
    permissions: OrganizationInvitePermissions,
) -> Result<(i32, bool), ApiError> {
    use crate::wire::OrganizationPlanType::{Integer, String};
    let (role, custom) = match input {
        Integer(0) | String("0" | "Owner") => (0, false),
        Integer(1) | String("1" | "Admin") => (1, false),
        Integer(2) | String("2" | "User") => (2, false),
        Integer(3) | String("3" | "Manager" | "Custom") => (3, false),
        Integer(4) | String("4") => (3, true),
        _ => return Err(invalid("Invalid type")),
    };
    Ok((
        role,
        matches!(role, 0 | 1)
            || (custom
                && permissions.create_new_collections
                && permissions.edit_any_collection
                && permissions.delete_any_collection),
    ))
}
impl<S: OrganizationMemberUpdateStorage> VaultService<S> {
    pub fn update_org_member<D: OrganizationMemberUpdateData + ?Sized>(
        &mut self,
        owner: &str,
        organization: &str,
        member: &str,
        request: &D,
    ) -> Result<(), ApiError> {
        let actor_role = self.org_member_admin_role(owner, organization)?;
        // Validate the complete structural view before destructive provider work.
        for index in 0..request.collections_len() {
            request.collection(index).ok_or_else(invalid_snapshot)?;
        }
        for index in 0..request.groups_len() {
            request.group(index).ok_or_else(invalid_snapshot)?;
        }
        let (new_role, new_access_all) = resolved_role(request.role(), request.permissions())?;
        let target = self
            .storage_mut()
            .update_member(organization, member)
            .map_err(S::map_error)?
            .ok_or_else(|| invalid("The specified user isn't member of the organization"))?;
        if target.membership_id.as_ref() != member
            || target.organization_id.as_ref() != organization
            || target.user_id.as_ref().is_empty()
        {
            return Err(invalid_snapshot());
        }
        if actor_role != 0
            && new_role != target.role
            && (matches!(new_role, 0 | 1) || matches!(target.role, 0 | 1))
        {
            return Err(invalid(
                "Only Owners can grant and remove Admin or Owner privileges",
            ));
        }
        if actor_role != 0 && target.role == 0 {
            return Err(invalid("Only Owners can edit Owner users"));
        }
        let start = ValidatedOrganizationMemberUpdateStart {
            owner,
            target: &target,
            actor_role,
            new_role,
            new_access_all,
        };
        if start.requires_other_confirmed_owner()
            && self
                .storage_mut()
                .update_confirmed_owner_count(organization)
                .map_err(S::map_error)?
                <= 1
        {
            return Err(invalid("Can't delete the last owner"));
        }
        if target.groups_configured {
            return Err(invalid(
                "Configured organization member group updates are not supported",
            ));
        }
        self.storage_mut()
            .begin_member_update(&start)
            .map_err(S::map_error)?;
        if !new_access_all {
            for index in 0..request.collections_len() {
                let selection = request.collection(index).ok_or_else(invalid_snapshot)?;
                let collection = self
                    .storage_mut()
                    .update_collection(organization, selection.id)
                    .map_err(S::map_error)?
                    .ok_or_else(|| invalid("Collection not found in Organization"))?;
                if collection.id.as_ref() != selection.id
                    || collection.organization_id.as_ref() != organization
                {
                    return Err(invalid_snapshot());
                }
                self.storage_mut()
                    .append_member_update_grant(&ValidatedOrganizationMemberUpdateGrant {
                        start: &start,
                        selection,
                    })
                    .map_err(S::map_error)?;
            }
        }
        // In a proven group-free scope every requested group is absent. Preserve
        // the measured direct-grant prefix before the native missing-group error.
        if request.groups_len() != 0 {
            return Err(invalid("Group not found in Organization"));
        }
        self.storage_mut()
            .finish_member_update(&ValidatedOrganizationMemberUpdate { start: &start })
            .map_err(S::map_error)
    }
}
macro_rules! redacted {
    ($($name:ident),+ $(,)?) => {$ (
        impl<I> core::fmt::Debug for $name<I> {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result { f.write_str(concat!(stringify!($name), "([REDACTED])")) }
        }
    )+};
}
redacted!(
    OrganizationMemberUpdateRecord,
    OrganizationMemberUpdateCollection
);
impl<I> core::fmt::Debug for ValidatedOrganizationMemberUpdateStart<'_, I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ValidatedOrganizationMemberUpdateStart([REDACTED])")
    }
}
impl<I> core::fmt::Debug for ValidatedOrganizationMemberUpdateGrant<'_, '_, I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ValidatedOrganizationMemberUpdateGrant([REDACTED])")
    }
}
impl<I> core::fmt::Debug for ValidatedOrganizationMemberUpdate<'_, '_, I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ValidatedOrganizationMemberUpdate([REDACTED])")
    }
}

#[cfg(test)]
mod tests;
