//! Allocation-free single organization-member removal.
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
            assert_eq!((org, member), ("org", "member"));
            self.step("target")?;
            Ok(self.target.map(|row| OrganizationMemberRemovalRecord {
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
}
