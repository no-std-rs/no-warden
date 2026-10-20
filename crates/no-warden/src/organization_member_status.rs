//! Independently authored organization-member revoke/restore business rules.
//! Storage, HTTP guards, policy configuration and events remain adapter concerns.

use crate::{
    ApiError, ErrorKind, VaultService, organization_collections::OrganizationCollectionStorage,
};

/// Owned scoped metadata; no wrapped organization key or account secret is needed.
/// Provider handles need not implement Clone, Debug or Serialize.
pub struct OrganizationMemberStatusRecord<I> {
    pub membership_id: I,
    pub organization_id: I,
    pub user_id: I,
    pub role: i32,
    pub status: i32,
}
impl<I> core::fmt::Debug for OrganizationMemberStatusRecord<I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OrganizationMemberStatusRecord([REDACTED])")
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrganizationMemberStatusOperation {
    Revoke,
    Restore,
}

/// Trusted restore-policy result for the proposed status. Richer providers resolve
/// required 2FA (including configured enrollment fallback), other-org SingleOrg,
/// then this-org SingleOrg rules. No policies are implied by an Allowed result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrganizationMemberRestorationPolicy {
    Allowed,
    TwoFactorRequired,
    OtherOrganizationPolicy,
    SingleOrganizationPolicy,
}
impl OrganizationMemberRestorationPolicy {
    /// Static public markers. Adapters may append the membership ID to reproduce
    /// configured dynamic policy messages; internal Debug never exposes that ID.
    pub const fn error(self) -> Option<ApiError> {
        let message = match self {
            Self::Allowed => return None,
            Self::TwoFactorRequired => "Cannot restore because 2FA is required",
            Self::OtherOrganizationPolicy => {
                "Cannot restore because another organization policy forbids it"
            }
            Self::SingleOrganizationPolicy => {
                "Cannot restore because the organization policy forbids being part of other organization"
            }
        };
        Some(ApiError::invalid("restorePolicy", message))
    }
}

/// Immutable sealed transition. It changes only status and the recipient revision;
/// the existing encrypted key, ACLs and account/device/session authority survive.
pub struct ValidatedOrganizationMemberStatus<'a, I> {
    owner: &'a str,
    target: &'a OrganizationMemberStatusRecord<I>,
    operation: OrganizationMemberStatusOperation,
    status: i32,
}
impl<'a, I: AsRef<str>> ValidatedOrganizationMemberStatus<'a, I> {
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
    pub const fn previous_status(&self) -> i32 {
        self.target.status
    }
    pub const fn status(&self) -> i32 {
        self.status
    }
    pub const fn operation(&self) -> OrganizationMemberStatusOperation {
        self.operation
    }
    /// Every eligible Owner target requires the count, even Invited/Accepted Owners.
    pub const fn requires_owner_count(&self) -> bool {
        matches!(self.operation, OrganizationMemberStatusOperation::Revoke) && self.target.role == 0
    }
    /// Unknown raw roles follow the source's below-Admin policy comparison too.
    pub const fn requires_restoration_policy(&self) -> bool {
        matches!(self.operation, OrganizationMemberStatusOperation::Restore)
            && self.status > 0
            && self.target.role != 0
            && self.target.role != 1
    }
}
impl<I> core::fmt::Debug for ValidatedOrganizationMemberStatus<'_, I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ValidatedOrganizationMemberStatus([REDACTED])")
    }
}

/// Opt-in status transitions; existing organization/removal providers are unchanged.
/// Run the existing confirmed Admin/Owner preflight before HTTP UUID guards, then
/// hold the authenticated operation context through service and commit. Lookup scopes
/// both organization and membership IDs and returns owned metadata.
///
/// Restore policy observes the proposed status, before any persistence. Only non-Owner,
/// non-Admin roles with resulting status >0 need policy checks. Resolve configured
/// policy side effects explicitly; default no-policy adapters return Allowed.
///
/// Commit must atomically recheck the current confirmed Admin/Owner actor, target
/// identity/org/user/role/old status, self prohibition, Owner hierarchy, applicable
/// live confirmed-Owner count and restore policy. Count only role0/status2, but apply
/// the <=1 guard to EVERY eligible Owner revoke, even target status0/1. Store exactly
/// plan.status() and advance recipient revision even restoring ordinary Invited0 to0.
/// Preserve membership ID/key/role/access_all, direct/group grants, inviter metadata,
/// global invitation marker, account credentials/keys, sessions/devices, personal vault,
/// organization definitions and all foreign state. Do not delete or re-confirm links.
/// Errors roll back the entire local write; this is stronger than upstream's revision
/// attempt then save. Events happen after a successful source save; notification/event
/// delivery, policy enrollment and transport behavior remain adapter responsibilities.
pub trait OrganizationMemberStatusStorage: OrganizationCollectionStorage {
    type Id: AsRef<str>;
    fn status_member(
        &mut self,
        organization: &str,
        member: &str,
    ) -> Result<Option<OrganizationMemberStatusRecord<Self::Id>>, Self::Error>;
    fn status_confirmed_owner_count(&mut self, organization: &str) -> Result<u64, Self::Error>;
    fn restoration_policy(
        &mut self,
        plan: &ValidatedOrganizationMemberStatus<'_, Self::Id>,
    ) -> Result<OrganizationMemberRestorationPolicy, Self::Error>;
    fn set_organization_member_status(
        &mut self,
        plan: &ValidatedOrganizationMemberStatus<'_, Self::Id>,
    ) -> Result<(), Self::Error>;
}
impl<T: OrganizationMemberStatusStorage + ?Sized> OrganizationMemberStatusStorage for &mut T {
    type Id = T::Id;
    fn status_member(
        &mut self,
        org: &str,
        member: &str,
    ) -> Result<Option<OrganizationMemberStatusRecord<Self::Id>>, Self::Error> {
        (**self).status_member(org, member)
    }
    fn status_confirmed_owner_count(&mut self, org: &str) -> Result<u64, Self::Error> {
        (**self).status_confirmed_owner_count(org)
    }
    fn restoration_policy(
        &mut self,
        plan: &ValidatedOrganizationMemberStatus<'_, Self::Id>,
    ) -> Result<OrganizationMemberRestorationPolicy, Self::Error> {
        (**self).restoration_policy(plan)
    }
    fn set_organization_member_status(
        &mut self,
        plan: &ValidatedOrganizationMemberStatus<'_, Self::Id>,
    ) -> Result<(), Self::Error> {
        (**self).set_organization_member_status(plan)
    }
}
fn invalid(message: &'static str) -> ApiError {
    ApiError::new(ErrorKind::InvalidRequest, message)
}
impl<S: OrganizationMemberStatusStorage> VaultService<S> {
    pub fn revoke_org_member(
        &mut self,
        owner: &str,
        organization: &str,
        member: &str,
    ) -> Result<(), ApiError> {
        self.change_org_member_status(
            owner,
            organization,
            member,
            OrganizationMemberStatusOperation::Revoke,
        )
    }
    pub fn restore_org_member(
        &mut self,
        owner: &str,
        organization: &str,
        member: &str,
    ) -> Result<(), ApiError> {
        self.change_org_member_status(
            owner,
            organization,
            member,
            OrganizationMemberStatusOperation::Restore,
        )
    }
    fn change_org_member_status(
        &mut self,
        owner: &str,
        organization: &str,
        member: &str,
        operation: OrganizationMemberStatusOperation,
    ) -> Result<(), ApiError> {
        let actor_role = self.org_member_admin_role(owner, organization)?;
        let target = self
            .storage_mut()
            .status_member(organization, member)
            .map_err(S::map_error)?
            .ok_or_else(|| invalid("User not found in organization"))?;
        if target.organization_id.as_ref() != organization
            || target.membership_id.as_ref() != member
        {
            return Err(invalid("User not found in organization"));
        }
        let status = match operation {
            OrganizationMemberStatusOperation::Revoke if target.status <= -1 => {
                return Err(invalid("User is already revoked"));
            }
            OrganizationMemberStatusOperation::Restore if target.status >= 1 => {
                return Err(invalid("User is already active"));
            }
            // The guards make each arithmetic operation safe for ALL signed i32 values.
            OrganizationMemberStatusOperation::Revoke => target.status - 128,
            OrganizationMemberStatusOperation::Restore if target.status < 0 => target.status + 128,
            OrganizationMemberStatusOperation::Restore => target.status,
        };
        if target.user_id.as_ref() == owner {
            return Err(invalid(match operation {
                OrganizationMemberStatusOperation::Revoke => "You cannot revoke yourself",
                OrganizationMemberStatusOperation::Restore => "You cannot restore yourself",
            }));
        }
        if target.role == 0 && actor_role != 0 {
            return Err(invalid(match operation {
                OrganizationMemberStatusOperation::Revoke => "Only owners can revoke other owners",
                OrganizationMemberStatusOperation::Restore => {
                    "Only owners can restore other owners"
                }
            }));
        }
        let plan = ValidatedOrganizationMemberStatus {
            owner,
            target: &target,
            operation,
            status,
        };
        if plan.requires_owner_count()
            && self
                .storage_mut()
                .status_confirmed_owner_count(organization)
                .map_err(S::map_error)?
                <= 1
        {
            return Err(invalid(
                "Organization must have at least one confirmed owner",
            ));
        }
        if plan.requires_restoration_policy() {
            if let Some(error) = self
                .storage_mut()
                .restoration_policy(&plan)
                .map_err(S::map_error)?
                .error()
            {
                return Err(error);
            }
        }
        self.storage_mut()
            .set_organization_member_status(&plan)
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
    use OrganizationMemberRestorationPolicy as Policy;
    use OrganizationMemberStatusOperation as Operation;
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
        policy: Policy,
        policy_status: Option<i32>,
        fail: Option<&'static str>,
        stale: bool,
        calls: Vec<&'static str>,
        revision: u64,
        preserved: [u64; 10],
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
                owners: 2,
                policy: Policy::Allowed,
                policy_status: None,
                fail: None,
                stale: false,
                calls: Vec::new(),
                revision: 7,
                preserved: [11, 22, 33, 44, 55, 66, 77, 88, 99, 111],
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
        fn state(&self) -> (Option<i32>, u64, [u64; 10]) {
            (self.target.map(|t| t.status), self.revision, self.preserved)
        }
    }
    impl Storage for Memory {
        type Error = ();
        fn map_error(_: ()) -> ApiError {
            ApiError::new(ErrorKind::Conflict, "Member status provider conflict")
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

    impl OrganizationMemberStatusStorage for Memory {
        type Id = Id;
        fn status_member(
            &mut self,
            org: &str,
            member: &str,
        ) -> Result<Option<OrganizationMemberStatusRecord<Id>>, ()> {
            assert_eq!((org, member), ("org", "member"));
            self.step("target")?;
            Ok(self.target.map(|t| OrganizationMemberStatusRecord {
                membership_id: Id(t.member.to_string()),
                organization_id: Id(t.org.to_string()),
                user_id: Id(t.user.to_string()),
                role: t.role,
                status: t.status,
            }))
        }
        fn status_confirmed_owner_count(&mut self, org: &str) -> Result<u64, ()> {
            assert_eq!(org, "org");
            self.step("owners")?;
            Ok(self.owners)
        }
        fn restoration_policy(
            &mut self,
            plan: &ValidatedOrganizationMemberStatus<'_, Id>,
        ) -> Result<Policy, ()> {
            self.step("policy")?;
            assert_eq!(plan.operation(), Operation::Restore);
            assert!(plan.requires_restoration_policy());
            self.policy_status = Some(plan.status());
            Ok(self.policy)
        }
        fn set_organization_member_status(
            &mut self,
            plan: &ValidatedOrganizationMemberStatus<'_, Id>,
        ) -> Result<(), ()> {
            self.step("commit")?;
            let actor = self.actor.ok_or(())?.membership;
            let t = self.target.ok_or(())?;
            let expected = match plan.operation() {
                Operation::Revoke if t.status >= 0 => t.status - 128,
                Operation::Restore if t.status < 0 => t.status + 128,
                Operation::Restore if t.status == 0 => 0,
                _ => return Err(()),
            };
            if self.stale
                || actor.user_id != plan.owner()
                || actor.organization_id != plan.organization()
                || actor.status != 2
                || !matches!(actor.role, 0 | 1)
                || t.member != plan.membership_id()
                || t.org != plan.organization()
                || t.user != plan.user_id()
                || t.role != plan.role()
                || t.status != plan.previous_status()
                || expected != plan.status()
                || t.user == plan.owner()
                || (t.role == 0 && actor.role != 0)
                || (plan.requires_owner_count() && self.owners <= 1)
                || (plan.requires_restoration_policy() && self.policy != Policy::Allowed)
            {
                return Err(());
            }
            assert_eq!(
                format!("{plan:?}"),
                "ValidatedOrganizationMemberStatus([REDACTED])"
            );
            self.target.as_mut().unwrap().status = plan.status();
            self.revision += 1;
            Ok(())
        }
    }
    fn act(m: &mut Memory, operation: Operation) -> Result<(), ApiError> {
        let mut service = VaultService::new(m);
        match operation {
            Operation::Revoke => service.revoke_org_member("actor", "org", "member"),
            Operation::Restore => service.restore_org_member("actor", "org", "member"),
        }
    }
    fn error(m: &mut Memory, operation: Operation, message: &str) {
        let before = m.state();
        let error = act(m, operation).unwrap_err();
        assert_eq!((error.status_code(), error.message), (400, message));
        assert_eq!(m.state(), before);
    }
    #[test]
    fn member_status_authentication_binds_confirmed_owner_or_admin_before_target() {
        let mut m = Memory::new();
        assert_eq!(
            VaultService::new(&mut m)
                .revoke_org_member("", "org", "member")
                .unwrap_err()
                .kind,
            ErrorKind::Unauthorized
        );
        assert!(m.calls.is_empty());
        for (role, status) in [(2, 2), (3, 2), (4, 2), (0, 0), (0, 1), (1, -126)] {
            let mut m = Memory::new();
            let actor = &mut m.actor.as_mut().unwrap().membership;
            actor.role = role;
            actor.status = status;
            assert_eq!(
                act(&mut m, Operation::Revoke).unwrap_err().kind,
                ErrorKind::Unauthorized
            );
            assert_eq!(m.calls, ["actor"]);
        }
        for foreign in [false, true] {
            let mut m = Memory::new();
            let actor = &mut m.actor.as_mut().unwrap().membership;
            if foreign {
                actor.user_id = "foreign"
            } else {
                actor.organization_id = "foreign"
            };
            assert_eq!(
                act(&mut m, Operation::Restore).unwrap_err().kind,
                ErrorKind::Unauthorized
            );
            assert_eq!(m.calls, ["actor"]);
        }
    }
    #[test]
    fn member_status_scoped_target_and_eligibility_precede_self_or_hierarchy() {
        for target in [
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
                org: "other",
                user: "recipient",
                role: 2,
                status: 2,
            }),
        ] {
            let mut m = Memory::new();
            m.target = target;
            error(&mut m, Operation::Revoke, "User not found in organization");
            assert_eq!(m.calls, ["actor", "target"]);
        }
        for (operation, status, message) in [
            (Operation::Revoke, -1, "User is already revoked"),
            (Operation::Revoke, -126, "User is already revoked"),
            (Operation::Restore, 1, "User is already active"),
            (Operation::Restore, 2, "User is already active"),
        ] {
            let mut m = Memory::new();
            let target = m.target.as_mut().unwrap();
            target.user = "actor";
            target.role = 0;
            target.status = status;
            error(&mut m, operation, message);
            assert_eq!(m.calls, ["actor", "target"]);
        }
    }
    #[test]
    fn member_status_signed_arithmetic_preserves_source_raw_status_rules() {
        for status in [0, 1, 2, 127, 128, 129, i32::MAX] {
            let mut m = Memory::new();
            m.target.as_mut().unwrap().status = status;
            act(&mut m, Operation::Revoke).unwrap();
            assert_eq!(m.target.unwrap().status, status - 128);
        }
        for status in [i32::MIN, -128, -127, -126, -1, 0] {
            let mut m = Memory::new();
            m.target.as_mut().unwrap().status = status;
            act(&mut m, Operation::Restore).unwrap();
            assert_eq!(
                m.target.unwrap().status,
                if status < 0 { status + 128 } else { status }
            );
            assert_eq!(m.revision, 8);
        }
    }
    #[test]
    fn member_status_self_prohibition_precedes_owner_only_hierarchy() {
        for (operation, status, message) in [
            (Operation::Revoke, 2, "You cannot revoke yourself"),
            (Operation::Restore, -126, "You cannot restore yourself"),
        ] {
            let mut m = Memory::new();
            m.actor.as_mut().unwrap().membership.role = 1;
            let target = m.target.as_mut().unwrap();
            target.user = "actor";
            target.role = 0;
            target.status = status;
            error(&mut m, operation, message);
            assert_eq!(m.calls, ["actor", "target"]);
        }
    }
    #[test]
    fn member_status_admin_can_change_admin_or_manager_but_not_owner() {
        for (operation, status, owner_message) in [
            (Operation::Revoke, 2, "Only owners can revoke other owners"),
            (
                Operation::Restore,
                -126,
                "Only owners can restore other owners",
            ),
        ] {
            for role in [1, 2, 3, 4] {
                let mut m = Memory::new();
                m.actor.as_mut().unwrap().membership.role = 1;
                let target = m.target.as_mut().unwrap();
                target.role = role;
                target.status = status;
                act(&mut m, operation).unwrap();
                assert!(!m.calls.contains(&"owners"));
            }
            let mut m = Memory::new();
            m.actor.as_mut().unwrap().membership.role = 1;
            let target = m.target.as_mut().unwrap();
            target.role = 0;
            target.status = status;
            error(&mut m, operation, owner_message);
            assert_eq!(m.calls, ["actor", "target"]);
        }
    }
    #[test]
    fn member_status_every_eligible_owner_revoke_checks_live_confirmed_owner_count() {
        for status in [0, 1, 2, 99] {
            for owners in [0, 1, 2] {
                let mut m = Memory::new();
                m.owners = owners;
                let target = m.target.as_mut().unwrap();
                target.role = 0;
                target.status = status;
                if owners <= 1 {
                    error(
                        &mut m,
                        Operation::Revoke,
                        "Organization must have at least one confirmed owner",
                    );
                } else {
                    act(&mut m, Operation::Revoke).unwrap();
                    assert_eq!(m.target.unwrap().status, status - 128);
                }
                assert!(m.calls.contains(&"owners"));
            }
        }
        let mut m = Memory::new();
        m.target.as_mut().unwrap().role = 0;
        m.target.as_mut().unwrap().status = -126;
        m.owners = 0;
        act(&mut m, Operation::Restore).unwrap();
        assert!(!m.calls.contains(&"owners"));
    }
    #[test]
    fn member_status_invited_restore_is_noop_status_with_revision_and_policy_exemptions() {
        for (role, status) in [(2, 0), (3, 0), (0, -126), (1, -126)] {
            let mut m = Memory::new();
            m.policy = Policy::TwoFactorRequired;
            let target = m.target.as_mut().unwrap();
            target.role = role;
            target.status = status;
            act(&mut m, Operation::Restore).unwrap();
            assert_eq!(m.revision, 8);
            assert!(!m.calls.contains(&"policy"));
            assert_eq!(
                m.target.unwrap().status,
                if status < 0 { status + 128 } else { status }
            );
        }
    }
    #[test]
    fn member_status_policy_observes_restored_state_and_rejects_before_commit() {
        for role in [2, 3, 4, -9] {
            for policy in [
                Policy::TwoFactorRequired,
                Policy::OtherOrganizationPolicy,
                Policy::SingleOrganizationPolicy,
            ] {
                let mut m = Memory::new();
                m.policy = policy;
                m.target.as_mut().unwrap().status = -127;
                m.target.as_mut().unwrap().role = role;
                let before = m.state();
                let error = act(&mut m, Operation::Restore).unwrap_err();
                assert_eq!(error, policy.error().unwrap());
                assert_eq!(error.field, Some("restorePolicy"));
                assert_eq!(m.policy_status, Some(1));
                assert_eq!(m.calls, ["actor", "target", "policy"]);
                assert_eq!(m.state(), before);
            }
        }
    }
    #[test]
    fn member_status_provider_failures_and_stale_commit_remain_typed_and_nonmutating() {
        for stage in ["actor", "target", "owners", "policy", "commit"] {
            let mut m = Memory::new();
            m.fail = Some(stage);
            let operation = if stage == "policy" {
                m.target.as_mut().unwrap().status = -126;
                Operation::Restore
            } else {
                m.target.as_mut().unwrap().role = 0;
                m.owners = 2;
                Operation::Revoke
            };
            let before = m.state();
            let error = act(&mut m, operation).unwrap_err();
            assert_eq!(
                (error.kind, error.message),
                (ErrorKind::Conflict, "Member status provider conflict")
            );
            assert_eq!(m.state(), before);
        }
        let mut m = Memory::new();
        m.stale = true;
        let before = m.state();
        assert_eq!(
            act(&mut m, Operation::Revoke).unwrap_err().kind,
            ErrorKind::Conflict
        );
        assert_eq!(m.state(), before);
    }
    #[test]
    fn member_status_roundtrip_keeps_identity_and_preserved_keys_grants_and_authority() {
        let mut m = Memory::new();
        let before = m.preserved;
        act(&mut m, Operation::Revoke).unwrap();
        assert_eq!(m.target.unwrap().status, -126);
        act(&mut m, Operation::Restore).unwrap();
        let target = m.target.unwrap();
        assert_eq!(
            (
                target.member,
                target.org,
                target.user,
                target.role,
                target.status
            ),
            ("member", "org", "recipient", 2, 2)
        );
        assert_eq!(m.preserved, before);
        assert_eq!(m.revision, 9);
    }
    #[test]
    fn member_status_owned_handles_forward_and_debug_redacts_internal_metadata() {
        let mut m = Memory::new();
        let row = m.status_member("org", "member").unwrap().unwrap();
        assert_eq!(
            format!("{row:?}"),
            "OrganizationMemberStatusRecord([REDACTED])"
        );
        let mut forward = &mut m;
        let mut service = VaultService::new(&mut forward);
        service.revoke_org_member("actor", "org", "member").unwrap();
        service
            .restore_org_member("actor", "org", "member")
            .unwrap();
        assert_eq!(service.storage_mut().target.unwrap().status, 2);
        let markers = [
            (
                Policy::TwoFactorRequired,
                "Cannot restore because 2FA is required",
            ),
            (
                Policy::OtherOrganizationPolicy,
                "Cannot restore because another organization policy forbids it",
            ),
            (
                Policy::SingleOrganizationPolicy,
                "Cannot restore because the organization policy forbids being part of other organization",
            ),
        ];
        assert_eq!(Policy::Allowed.error(), None);
        for (policy, message) in markers {
            assert_eq!(policy.error().unwrap().message, message);
        }
    }
}
